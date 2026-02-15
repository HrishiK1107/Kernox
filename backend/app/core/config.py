from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_ENV: str = "development"
    APP_NAME: str = "Kernox Backend"
    API_V1_PREFIX: str = "/api/v1"
    MAX_TIMESTAMP_DRIFT_SECONDS: int = 300  # 5 minutes
    MAX_REQUEST_SIZE: int = 1048576  # 1MB

    class Config:
        env_file = ".env"
        extra = "forbid"

settings = Settings()
