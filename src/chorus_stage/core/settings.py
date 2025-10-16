"""Application configuration powered by Pydantic settings."""
from __future__ import annotations

from pydantic import ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration object for Chorus."""

    # App meta
    app_name: str = "Chorus Stage"
    app_version: str = "0.0.1"
    admin_email: str | None = None

    # Database
    database_url: str = "postgresql+asyncpg://chorus:is-cool@localhost:5432/chorus"

    # Optional convenience: expose sync URL for tools that need it (derived)
    @property
    def database_url_sync(self) -> str:
        """Return a sync-friendly connection string if available."""
        # Convert asyncpg → psycopg2 for sync tools; otherwise return as-is.
        if self.database_url.startswith("postgresql+asyncpg"):
            return self.database_url.replace("postgresql+asyncpg", "postgresql+psycopg2", 1)
        return self.database_url

    # Container defaults (not required for the app, but handy if you spin up compose)
    postgres_db: str | None = None
    postgres_user: str | None = None
    postgres_password: str | None = None

    # Feed & moderation knobs (timestamp-free)
    recent_window_size: int = 50                  # N most-recent posts for rising/controversial
    controversial_min_total: int = 5              # minimum total votes to consider controversial
    token_epoch_size: int = 10_000                # posts per moderation-token reset epoch
    harmful_hide_threshold: float = 0.02          # fraction of community members required to hide
    clear_threshold: float = 0.6                  # fraction voting "not harmful" to clear
    min_community_denominator: int = 50           # floor for tiny communities and user profiles

    # Validators
    @field_validator("database_url")
    @classmethod
    def _ensure_async_driver(cls, v: str) -> str:
        """Encourage using the async driver for the application engine."""
        # The app uses an async engine; encourage async driver in env.
        if v.startswith("postgresql://"):
            # Gentle nudge; don’t mutate silently, just warn in logs.
            print("[settings] WARNING: DATABASE_URL is sync; prefer postgresql+asyncpg:// for the app")
        return v

    @field_validator("recent_window_size", "controversial_min_total", "token_epoch_size", "min_community_denominator")
    @classmethod
    def _positive_int(cls, v: int, info: ValidationInfo) -> int:
        """Validate that integer configuration values are positive."""
        if v <= 0:
            raise ValueError(f"{info.field_name} must be > 0")
        return v

    @field_validator("harmful_hide_threshold", "clear_threshold")
    @classmethod
    def _ratio_0_1(cls, v: float, info: ValidationInfo) -> float:
        """Ensure ratio-based fields fall within (0, 1]."""
        if not (0.0 < v <= 1.0):
            raise ValueError(f"{info.field_name} must be in (0, 1]")
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="",
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()  # type: ignore

# Backwards-compatible aliases for settings used in tests.
HARMFUL_HIDE_THRESHOLD = settings.harmful_hide_threshold
