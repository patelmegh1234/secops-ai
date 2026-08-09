"""
Core application configuration via pydantic-settings.
All secrets are loaded from environment variables / .env file.
Never hardcode values here.
"""

from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────
    app_name: str = "SecOps-AI"
    app_env: Literal["development", "staging", "production"] = "development"
    app_port: int = 8000
    secret_key: str = Field(min_length=32)
    debug: bool = False

    # ── Database ──────────────────────────────────────────────────
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:password@localhost:5432/secops_ai"
    )
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # ── Redis ─────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── JWT ───────────────────────────────────────────────────────
    jwt_secret_key: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60

    # ── GitHub ────────────────────────────────────────────────────
    github_token: str
    github_webhook_secret: str
    github_default_owner: str = ""

    # ── OpenAI ───────────────────────────────────────────────────
    openai_api_key: str
    openai_primary_model: str = "gpt-4o"
    openai_secondary_model: str = "gpt-4o-mini"

    # ── Anthropic (optional fallback) ─────────────────────────────
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-5"

    # ── Slack ─────────────────────────────────────────────────────
    slack_bot_token: str
    slack_signing_secret: str
    slack_alert_channel_id: str
    slack_app_base_url: str = "http://localhost:8000"

    # ── Rate Limiting ─────────────────────────────────────────────
    rate_limit_webhooks: str = "30/minute"
    rate_limit_api: str = "100/minute"

    # ── CORS ──────────────────────────────────────────────────────
    allowed_origins: str = "http://localhost:3000"

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, v: str) -> str:
        return v  # kept as comma-separated string; parsed in cors middleware

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    # ── Docker Sandbox ────────────────────────────────────────────
    sandbox_timeout_seconds: int = 30
    sandbox_memory_limit: str = "512m"
    sandbox_cpu_quota: int = 50000
    sandbox_base_image: str = "python:3.11-slim"

    # ── Celery ────────────────────────────────────────────────────
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"
    celery_task_max_retries: int = 2
    celery_task_retry_delay_seconds: int = 5

    # ── Logging ───────────────────────────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    # ── Observability (Phase 3.4 / 3.5) ────────────────────────────
    sentry_dsn: str = ""  # Empty = Sentry disabled. Set to your Sentry project DSN in prod.

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings instance — call this everywhere."""
    return Settings()  # type: ignore[call-arg]
