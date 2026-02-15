from fastapi.testclient import TestClient
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import hmac
import hashlib
import json

from app.main import app
from app.services.endpoint_registry import endpoint_registry

client = TestClient(app)


def build_event(event_id: str, timestamp: str):
    return {
        "event_id": event_id,
        "schema_version": "1.0",
        "timestamp": timestamp,
        "endpoint": {
            "endpoint_id": "node-drift",
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


def test_timestamp_within_drift_passes():
    secret = "secret-drift-123456"
    endpoint_registry.register("node-drift", "ubuntu", secret)

    now = datetime.now(timezone.utc).isoformat()
    event_id = str(uuid4())
    payload = build_event(event_id, now)
    raw = json.dumps(payload).encode()

    hashed_secret = hashlib.sha256(secret.encode()).hexdigest()

    signature = hmac.new(
        hashed_secret.encode(),
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

    assert response.status_code == 202


def test_timestamp_outside_drift_fails():
    secret = "secret-drift-123456"
    endpoint_registry.register("node-drift", "ubuntu", secret)

    old_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    event_id = str(uuid4())
    payload = build_event(event_id, old_time)
    raw = json.dumps(payload).encode()

    hashed_secret = hashlib.sha256(secret.encode()).hexdigest()

    signature = hmac.new(
        hashed_secret.encode(),
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

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid timestamp drift"
