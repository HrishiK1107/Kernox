import logging
import hmac
import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Request, status, HTTPException
from fastapi.responses import JSONResponse

from app.schemas.event_schema import Event
from app.services.endpoint_registry import endpoint_registry
from app.services.event_guard import event_guard
from app.services.rate_limiter import rate_limiter
from app.core.config import settings


router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(request: Request, event: Event):

    # ─────────────────────────────────────────────
    # 1️⃣ TRUST CHECK
    # ─────────────────────────────────────────────
    if not endpoint_registry.is_registered(event.endpoint.endpoint_id):
        logger.warning(
            f"Rejected event from unregistered endpoint | "
            f"endpoint={event.endpoint.endpoint_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unregistered endpoint",
        )

    # ─────────────────────────────────────────────
    # 2️⃣ HMAC SIGNATURE VERIFICATION
    # ─────────────────────────────────────────────
    signature = request.headers.get("X-Signature")

    if not signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing signature",
        )

    raw_body = await request.body()

    endpoint_id = event.endpoint.endpoint_id
    endpoint = endpoint_registry._endpoints.get(endpoint_id)

    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unregistered endpoint",
        )

    # Using secret_hash as HMAC key (unchanged logic)
    secret_key = endpoint["secret_hash"]

    expected_signature = hmac.new(
        secret_key.encode(),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        logger.warning(
            "invalid_signature",
            extra={
                "extra_data": {
                    "event": "invalid_signature",
                    "endpoint_id": endpoint_id,
                }
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid signature",
        )

    # ─────────────────────────────────────────────
    # 3️⃣ RATE LIMITING
    # ─────────────────────────────────────────────
    if not rate_limiter.is_allowed(event.endpoint.endpoint_id):
        logger.warning(
            f"Rate limit exceeded | endpoint={event.endpoint.endpoint_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )

    # SECOND HMAC CHECK (kept exactly as-is)
    secret = endpoint_registry.get_secret(event.endpoint.endpoint_id)

    raw_body = await request.body()

    expected_signature = hmac.new(
        secret.encode(),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        logger.warning(
            f"Invalid signature | endpoint={event.endpoint.endpoint_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid signature",
        )

    # ─────────────────────────────────────────────
    # 4️⃣ REPLAY PROTECTION
    # ─────────────────────────────────────────────
    if event_guard.is_duplicate(str(event.event_id)):
        logger.warning(
            f"Replay detected | event_id={event.event_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Duplicate event_id",
        )

    event_guard.record(str(event.event_id))

    # ─────────────────────────────────────────────
    # 5️⃣ TIMESTAMP DRIFT VALIDATION
    # ─────────────────────────────────────────────
    now = datetime.now(timezone.utc)
    event_time = event.timestamp

    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    drift = abs((now - event_time).total_seconds())

    if drift > settings.MAX_TIMESTAMP_DRIFT_SECONDS:
        logger.warning(
            f"Rejected event due to timestamp drift | "
            f"event_id={event.event_id} | drift={drift}s"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid timestamp drift",
        )

    # ─────────────────────────────────────────────
    # 6️⃣ ACCEPT EVENT
    # ─────────────────────────────────────────────
    logger.info(
        "Event accepted",
        extra={
            "extra_data": {
                "event": "event_accepted",
                "event_id": str(event.event_id),
                "endpoint_id": event.endpoint.endpoint_id,
            },
        }
    )

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "status": "accepted",
            "event_id": str(event.event_id),
        },
    )
