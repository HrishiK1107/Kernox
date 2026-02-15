from datetime import datetime
from enum import Enum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class EventType(str, Enum):
    process_start = "process_start"
    process_exit = "process_exit"
    file_write = "file_write"
    file_delete = "file_delete"
    network_connect = "network_connect"
    auth_failure = "auth_failure"
    privilege_escalation = "privilege_escalation"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# ─────────────────────────────────────────────
# NESTED MODELS
# ─────────────────────────────────────────────

class Endpoint(BaseModel):
    endpoint_id: str = Field(..., min_length=3, max_length=128)
    hostname: str = Field(..., min_length=1, max_length=255)

    model_config = {"extra": "forbid"}


class ProcessInfo(BaseModel):
    pid: int
    ppid: int
    name: str
    path: str | None = None
    user: str | None = None

    model_config = {"extra": "forbid"}


class FileInfo(BaseModel):
    path: str
    operation: str

    model_config = {"extra": "forbid"}


class NetworkInfo(BaseModel):
    source_ip: str
    destination_ip: str
    destination_port: int

    model_config = {"extra": "forbid"}


class AuthInfo(BaseModel):
    username: str
    method: str
    success: bool

    model_config = {"extra": "forbid"}


# ─────────────────────────────────────────────
# MAIN EVENT MODEL
# ─────────────────────────────────────────────

class Event(BaseModel):
    event_id: UUID
    schema_version: Literal["1.0"]

    timestamp: datetime

    endpoint: Endpoint
    event_type: EventType
    severity: Severity

    process: ProcessInfo | None = None
    file: FileInfo | None = None
    network: NetworkInfo | None = None
    auth: AuthInfo | None = None

    signature: str | None = None

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def validate_single_event_payload(self):
        payloads = [self.process, self.file, self.network, self.auth]
        non_null = sum(p is not None for p in payloads)

        if non_null != 1:
            raise ValueError(
                "Exactly one of process, file, network, or auth must be provided"
            )

        return self
