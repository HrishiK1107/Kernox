from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError

from app.core.config import settings
from app.core.logging import configure_logging
from app.core.exceptions import validation_exception_handler
from app.core.security import SecurityMiddleware
from app.api.v1 import health
from app.api.v1 import endpoints
from app.core.https_middleware import HTTPSMiddleware
from app.core.logging_config import setup_logging
from app.core.security_headers import SecurityHeadersMiddleware
from app.api.routes import events_read
from app.api.v1.events import router as events_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.campaigns import router as campaigns_router


configure_logging()
setup_logging()

app = FastAPI(title=settings.APP_NAME)

app.add_middleware(SecurityMiddleware)
app.add_middleware(HTTPSMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(events_read.router, prefix=settings.API_V1_PREFIX)
app.include_router(events_router, prefix=settings.API_V1_PREFIX)
app.add_exception_handler(RequestValidationError, validation_exception_handler)

app.include_router(health.router, prefix=settings.API_V1_PREFIX, tags=["health"])

app.include_router(
    events_read.router,
    prefix=settings.API_V1_PREFIX,
    tags=["events"],
)

app.include_router(endpoints.router, prefix=settings.API_V1_PREFIX, tags=["endpoints"])

app.include_router(
    alerts_router,
    prefix=settings.API_V1_PREFIX,
    tags=["alerts"],
)

app.include_router(alerts_router, prefix=settings.API_V1_PREFIX, tags=["alerts"])

app.include_router(
    campaigns_router,
    prefix=settings.API_V1_PREFIX,
    tags=["campaigns"],
)
