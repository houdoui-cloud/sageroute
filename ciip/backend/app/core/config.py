from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from environment variables (prefix CIIP_)."""

    model_config = SettingsConfigDict(env_prefix="CIIP_", env_file=".env", extra="ignore")

    env: str = "development"
    database_url: str = "postgresql+psycopg://ciip:ciip@localhost:5432/ciip"
    # Empty string disables Redis; an in-memory store is used instead (tests, dev).
    redis_url: str = "redis://localhost:6379/0"

    jwt_secret: str = "change-me-dev-only-secret-at-least-32-bytes!!"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 15
    refresh_token_days: int = 7

    # Fernet key (urlsafe base64, 32 bytes) used to encrypt reporter PII at rest.
    data_encryption_key: str = "Y2lpcC1kZW1vLWtleS1kby1ub3QtdXNlLWluLXByb2Q="

    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:8080"]

    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b"
    ollama_timeout_seconds: float = 60.0
    # When false the assistant only uses the deterministic rules engine.
    ai_use_ollama: bool = True

    login_max_attempts: int = 5
    login_lock_minutes: int = 15
    public_rate_limit_per_hour: int = 20

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str) and not value.startswith("["):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.is_production and "change-me" in settings.jwt_secret:
        raise RuntimeError("CIIP_JWT_SECRET must be set in production")
    return settings
