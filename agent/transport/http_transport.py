"""
Kernox — HTTP Event Transport

Sends events to backend API via HTTP POST with:
  - HMAC-SHA256 signature (X-Signature header)
  - Individual event sending (matches backend's single-event endpoint)
  - Buffered queue with background sender thread
  - Exponential backoff retry (1s → 2s → 4s → max 30s)
  - Local fallback file if backend unreachable for 60s
"""

import hashlib
import hmac
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
    Thread-safe HTTP event transport with HMAC signing and retry.
    Sends events individually to match the backend's POST /api/v1/events.
    """

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

        # Load HMAC secret
        from agent.config import HMAC_SECRET
        self._hmac_secret = HMAC_SECRET

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
        """Background thread: dequeue events and send individually."""
        while self._running:
            try:
                event = self._queue.get(timeout=self.FLUSH_INTERVAL_SEC)
            except queue.Empty:
                continue

            success = self._send_event(event)
            if success:
                self._retry_delay = 1
                self._last_success = time.time()
            else:
                # Re-queue failed event
                try:
                    self._queue.put_nowait(event)
                except queue.Full:
                    pass

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

    def _send_event(self, event: dict) -> bool:
        """POST a single event to the backend with HMAC signature."""
        try:
            payload = json.dumps(event, default=str, ensure_ascii=True).encode("utf-8")

            # Compute HMAC-SHA256 signature
            signature = hmac.new(
                self._hmac_secret.encode(),
                payload,
                hashlib.sha256,
            ).hexdigest()

            req = Request(
                self._url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Kernox-Agent/1.0",
                    "X-Signature": signature,
                },
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                if resp.status in (200, 201, 202):
                    logger.debug("Event sent: %s (HTTP %d)", event.get("event_id", "?"), resp.status)
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
