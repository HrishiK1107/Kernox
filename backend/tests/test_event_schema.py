import pytest
from uuid import uuid4
from datetime import datetime

from app.schemas.event_schema import Event


def valid_base_event():
    return {
        "event_id": str(uuid4()),
        "schema_version": "1.0",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoint": {
            "endpoint_id": "node-1",
            "hostname": "ubuntu"
        },
        "event_type": "process_start",
        "severity": "low",
        "process": {
            "pid": 123,
            "ppid": 1,
            "name": "bash",
        },
        "file": None,
        "network": None,
        "auth": None,
        "signature": None,
    }


def test_valid_event_passes():
    event = Event(**valid_base_event())
    assert event.endpoint.endpoint_id == "node-1"


def test_multiple_payloads_fail():
    data = valid_base_event()
    data["file"] = {"path": "/tmp/x", "operation": "write"}

    with pytest.raises(Exception):
        Event(**data)


def test_no_payload_fails():
    data = valid_base_event()
    data["process"] = None

    with pytest.raises(Exception):
        Event(**data)


def test_invalid_schema_version_fails():
    data = valid_base_event()
    data["schema_version"] = "2.0"

    with pytest.raises(Exception):
        Event(**data)


def test_extra_field_fails():
    data = valid_base_event()
    data["unexpected"] = "bad"

    with pytest.raises(Exception):
        Event(**data)
