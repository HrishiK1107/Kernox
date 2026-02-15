from fastapi.testclient import TestClient
from uuid import uuid4
from datetime import datetime, timezone
import hmac
import hashlib
import json

from app.main import app
from app.services.endpoint_registry import endpoint_registry


client = TestClient(app)


def build_event(event_id: str):
    return {
        "event_id": event_id,
        "schema_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": {
            "endpoint_id": "node-replay",
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


def test_replay_protection():

    secret = "secret-replay-123456"
    endpoint_registry.register("node-replay", "ubuntu", secret)

    event_id = str(uuid4())
    payload = build_event(event_id)
    raw = json.dumps(payload).encode()

    hashed_secret = hashlib.sha256(secret.encode()).hexdigest()
     
    signature = hmac.new(
        secret.encode(),
        raw,
        hashlib.sha256
    ).hexdigest()

    # First request
    response1 = client.post(
        "/api/v1/events",
        data=raw,
        headers={
            "Content-Type": "application/json",
            "X-Signature": signature,
        },
    )

    assert response1.status_code == 202

    # Second request (replay)
    response2 = client.post(
        "/api/v1/events",
        data=raw,
        headers={
            "Content-Type": "application/json",
            "X-Signature": signature,
        },
    )

    assert response2.status_code == 409
    assert response2.json()["detail"] == "Duplicate event_id"
