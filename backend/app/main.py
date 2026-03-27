from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

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
from app.api.v1.analytics import router as analytics_router


configure_logging()
setup_logging()

app = FastAPI(
    title=settings.APP_NAME,
    description="Kernox — Real-time endpoint security backend. "
                "Ingests eBPF agent events, runs detection rules, "
                "correlates alerts, and provides analytics.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite dev server
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SecurityMiddleware)
app.add_middleware(HTTPSMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


# ─────────────────────────────────────────────
# Root route (dashboard / welcome)
# ─────────────────────────────────────────────
@app.get("/", tags=["root"])
async def root():
    return {
        "name": settings.APP_NAME,
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "health": f"{settings.API_V1_PREFIX}/health",
        "endpoints": {
            "events": f"{settings.API_V1_PREFIX}/events",
            "alerts": f"{settings.API_V1_PREFIX}/alerts",
            "campaigns": f"{settings.API_V1_PREFIX}/campaigns",
            "analytics": f"{settings.API_V1_PREFIX}/analytics",
            "endpoints": f"{settings.API_V1_PREFIX}/endpoints",
        },
    }


# ─────────────────────────────────────────────
# Exception handlers
# ─────────────────────────────────────────────
app.add_exception_handler(RequestValidationError, validation_exception_handler)


# ─────────────────────────────────────────────
# API v1 routes
# ─────────────────────────────────────────────
app.include_router(health.router, prefix=settings.API_V1_PREFIX, tags=["health"])
app.include_router(events_router, prefix=settings.API_V1_PREFIX, tags=["events"])
app.include_router(events_read.router, prefix=settings.API_V1_PREFIX, tags=["events"])
app.include_router(endpoints.router, prefix=settings.API_V1_PREFIX, tags=["endpoints"])
app.include_router(alerts_router, prefix=settings.API_V1_PREFIX, tags=["alerts"])
app.include_router(campaigns_router, prefix=settings.API_V1_PREFIX, tags=["campaigns"])
app.include_router(analytics_router, prefix=settings.API_V1_PREFIX, tags=["analytics"])
