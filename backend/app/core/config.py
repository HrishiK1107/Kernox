from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ─────────────────────────────────────────────
    # App Identity
    # ─────────────────────────────────────────────
    APP_NAME: str = "Kernox Backend"
    APP_ENV: str = "development"  # development | production
    API_V1_PREFIX: str = "/api/v1"

    # ─────────────────────────────────────────────
    # Security Controls
    # ─────────────────────────────────────────────
    MAX_TIMESTAMP_DRIFT_SECONDS: int = 300  # 5 minutes
    MAX_REQUEST_SIZE: int = 1_048_576  # 1MB
    MAX_EVENTS_PER_MINUTE: int = 60
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # ─────────────────────────────────────────────
    # HTTPS Enforcement
    # ─────────────────────────────────────────────
    ENV: str = "development"  # development | production
    ENFORCE_HTTPS: bool = False

    class Config:
        env_file = ".env"
        extra = "forbid"


settings = Settings()
