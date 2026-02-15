from fastapi.testclient import TestClient
from datetime import datetime, timezone
from uuid import uuid4
import hmac
import hashlib
import json

from app.main import app
from app.services.endpoint_registry import endpoint_registry
from app.core.config import settings


client = TestClient(app)


def build_event(event_id: str):
    return {
        "event_id": event_id,
        "schema_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": {
            "endpoint_id": "node-rate",
            "hostname": "ubuntu"
        },
        "event_type": "process_start",
        "severity": "low",
        "process": {
            "pid": 123,
            "ppid": 1,
            "name": "bash"
        },
        "file": None,
        "network": None,
        "auth": None,
        "signature": None
    }


def test_rate_limit_blocks_after_threshold():

    secret = "secret-rate-123456"
    endpoint_registry.register("node-rate", "ubuntu", secret)

    # Lower rate limit temporarily for test
    settings.MAX_EVENTS_PER_MINUTE = 2

    event_ids = [str(uuid4()), str(uuid4()), str(uuid4())]

    for i, event_id in enumerate(event_ids):
        payload = build_event(event_id)
        raw = json.dumps(payload).encode()

        hashed_secret = hashlib.sha256(secret.encode()).hexdigest()
        signature = hmac.new(
            secret.encode(),
            raw,
            hashlib.sha256
        ).hexdigest()

        response = client.post(
            "/api/v1/events",
            data=raw,
            headers={
                "Content-Type": "application/json",
                "X-Signature": signature,
            },
        )

        if i < 2:
            assert response.status_code == 202
        else:
            assert response.status_code == 429
