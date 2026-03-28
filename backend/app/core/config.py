from pydantic_settings import BaseSettings
from pydantic import ConfigDict
import os


class Settings(BaseSettings):
    # ─────────────────────────────────────────────
    # App Identity
    # ─────────────────────────────────────────────
    APP_NAME: str = "Kernox Backend"
    APP_ENV: str = "development"
    API_V1_PREFIX: str = "/api/v1"

    # ─────────────────────────────────────────────
    # Security Controls
    # ─────────────────────────────────────────────
    MAX_TIMESTAMP_DRIFT_SECONDS: int = 300
    MAX_REQUEST_SIZE: int = 1_048_576
    MAX_EVENTS_PER_MINUTE: int = 50000
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # ─────────────────────────────────────────────
    # HTTPS Enforcement
    # ─────────────────────────────────────────────
    ENV: str = "development"
    ENFORCE_HTTPS: bool = False

    # ─────────────────────────────────────────────
    # Database
    # ─────────────────────────────────────────────
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./test.db")

    # Pydantic v2 config
    model_config = ConfigDict(
        env_file=".env",
        extra="forbid",
    )


settings = Settings()
