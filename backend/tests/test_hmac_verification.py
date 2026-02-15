from fastapi.testclient import TestClient
from datetime import datetime, timezone
from uuid import uuid4
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
            "endpoint_id": "node-hmac",
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


def test_valid_hmac_passes():

    secret = "supersecretkey123"
    endpoint_registry.register("node-hmac", "ubuntu", secret)

    event_id = str(uuid4())
    payload = build_event(event_id)

    raw = json.dumps(payload).encode()

    # 🔐 IMPORTANT: use hashed secret as HMAC key
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


def test_invalid_hmac_fails():

    secret = "supersecretkey123"
    endpoint_registry.register("node-hmac", "ubuntu", secret)

    event_id = str(uuid4())
    payload = build_event(event_id)

    raw = json.dumps(payload).encode()

    # Use wrong signature intentionally
    response = client.post(
        "/api/v1/events",
        data=raw,
        headers={
            "Content-Type": "application/json",
            "X-Signature": "bad_signature",
        },
    )

    assert response.status_code == 401
