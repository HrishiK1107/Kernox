"""
Kernox — HTTP Event Transport

Sends events to backend API via HTTP POST with:
  - Buffered queue (batch up to 50 events or flush every 2 seconds)
  - Exponential backoff retry (1s → 2s → 4s → max 30s)
  - Local fallback file if backend unreachable for 60s
"""

import json
import os
import queue
import threading
import time
from urllib.request import Request, urlopen
from urllib.error import URLError

from agent.logging_config import logger


class HTTPTransport:
    """
    Thread-safe HTTP event transport with batching and retry.
    """

    BATCH_SIZE = 50
    FLUSH_INTERVAL_SEC = 2
    MAX_RETRY_DELAY_SEC = 30
    FALLBACK_TIMEOUT_SEC = 60
    FALLBACK_FILE = "/var/kernox/events_buffer.jsonl"

    def __init__(self, backend_url: str):
        self._url = backend_url
        self._queue: queue.Queue = queue.Queue(maxsize=10000)
        self._thread: threading.Thread | None = None
        self._running = False
        self._retry_delay = 1
        self._last_success = time.time()

    def start(self) -> None:
        """Start the background sender thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._sender_loop,
            name="kernox-http-transport",
            daemon=True,
        )
        self._thread.start()
        logger.info("HTTP transport started → %s", self._url)

    def stop(self) -> None:
        """Flush remaining events and stop."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        # Drain any remaining events to fallback
        remaining = self._drain_queue()
        if remaining:
            self._write_fallback(remaining)
            logger.info("Flushed %d events to fallback on shutdown", len(remaining))

    def enqueue(self, event: dict) -> None:
        """Add an event to the send queue."""
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            logger.warning("Event queue full, dropping event")

    def _sender_loop(self) -> None:
        """Background thread: collect events and send in batches."""
        while self._running:
            batch = self._collect_batch()
            if not batch:
                time.sleep(0.1)
                continue

            success = self._send_batch(batch)
            if success:
                self._retry_delay = 1
                self._last_success = time.time()
            else:
                # Re-queue failed events
                for event in batch:
                    try:
                        self._queue.put_nowait(event)
                    except queue.Full:
                        break

                # Check if we've been failing too long
                if time.time() - self._last_success > self.FALLBACK_TIMEOUT_SEC:
                    failed = self._drain_queue()
                    if failed:
                        self._write_fallback(failed)
                        logger.warning(
                            "Backend unreachable for %ds, wrote %d events to fallback",
                            self.FALLBACK_TIMEOUT_SEC, len(failed),
                        )
                    self._last_success = time.time()  # reset timer

                # Exponential backoff
                time.sleep(min(self._retry_delay, self.MAX_RETRY_DELAY_SEC))
                self._retry_delay = min(self._retry_delay * 2, self.MAX_RETRY_DELAY_SEC)

    def _collect_batch(self) -> list[dict]:
        """Collect up to BATCH_SIZE events or wait FLUSH_INTERVAL."""
        batch = []
        deadline = time.time() + self.FLUSH_INTERVAL_SEC

        while len(batch) < self.BATCH_SIZE and time.time() < deadline:
            try:
                event = self._queue.get(timeout=0.1)
                batch.append(event)
            except queue.Empty:
                if batch:
                    break
                continue

        return batch

    def _send_batch(self, batch: list[dict]) -> bool:
        """POST a batch of events to the backend."""
        try:
            payload = json.dumps(batch, default=str, ensure_ascii=True).encode("utf-8")
            req = Request(
                self._url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Kernox-Agent/1.0",
                },
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                if resp.status == 200 or resp.status == 201:
                    return True
                logger.warning("Backend returned HTTP %d", resp.status)
                return False
        except URLError as e:
            logger.debug("Backend connection failed: %s", e)
            return False
        except Exception as e:
            logger.warning("HTTP send error: %s", e)
            return False

    def _drain_queue(self) -> list[dict]:
        """Drain all events from the queue."""
        events = []
        while not self._queue.empty():
            try:
                events.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return events

    def _write_fallback(self, events: list[dict]) -> None:
        """Write events to local fallback file."""
        try:
            os.makedirs(os.path.dirname(self.FALLBACK_FILE), exist_ok=True)
            with open(self.FALLBACK_FILE, "a") as f:
                for event in events:
                    f.write(json.dumps(event, default=str) + "\n")
        except OSError as e:
            logger.error("Failed to write fallback file: %s", e)
