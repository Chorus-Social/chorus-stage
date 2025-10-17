"""Application settings and configuration."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    app_name: str = Field(default="Chorus Stage", alias="APP_NAME")
    app_version: str = Field(default="0.1.0", alias="APP_VERSION")
    admin_email: str | None = Field(default=None, alias="ADMIN_EMAIL")

    secret_key: str = Field(
        default="CHANGE_ME_IN_PRODUCTION_USE_ENVIRONMENT_VARIABLE",
        alias="SECRET_KEY",
    )
    debug: bool = Field(default=False, alias="DEBUG")

    database_url: str = Field(default="sqlite:///./chorus.db", alias="DATABASE_URL")
    sql_debug: bool = Field(default=False, alias="SQL_DEBUG")

    postgres_db: str | None = Field(default=None, alias="POSTGRES_DB")
    postgres_user: str | None = Field(default=None, alias="POSTGRES_USER")
    postgres_password: str | None = Field(default=None, alias="POSTGRES_PASSWORD")

    redis_url: str = Field(default="redis://localhost:6379", alias="REDIS_URL")

    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(
        default=60 * 24 * 30,
        alias="ACCESS_TOKEN_EXPIRE_MINUTES",
    )
    login_challenge: str = Field(default="test_nonce_value", alias="LOGIN_CHALLENGE")

    pow_difficulty_post: int = Field(default=20, alias="POW_DIFFICULTY_POST")
    pow_difficulty_vote: int = Field(default=15, alias="POW_DIFFICULTY_VOTE")
    pow_difficulty_message: int = Field(default=18, alias="POW_DIFFICULTY_MESSAGE")
    pow_difficulty_moderate: int = Field(default=16, alias="POW_DIFFICULTY_MODERATE")

    recent_window_size: int = Field(default=50, alias="RECENT_WINDOW_SIZE")
    controversial_min_total: int = Field(
        default=5,
        alias="CONTROVERSIAL_MIN_TOTAL",
    )
    token_epoch_size: int = Field(default=10_000, alias="TOKEN_EPOCH_SIZE")
    harmful_hide_threshold: float = Field(default=0.02, alias="HARMFUL_HIDE_THRESHOLD")
    clear_threshold: float = Field(default=0.6, alias="CLEAR_THRESHOLD")

    model_config = SettingsConfigDict(
        env_file=".env",
        validate_assignment=True,
        extra="ignore",
    )

    @property
    def database_url_sync(self) -> str:
        """Return a sync-compatible database URL for tooling."""
        if str(self.database_url).startswith("postgresql+asyncpg"):
            return str(self.database_url).replace("postgresql+asyncpg", "postgresql+psycopg", 1)
        return self.database_url

    @property
    def moderation_thresholds(self) -> dict[str, float]:
        """Return moderation thresholds as a convenience dictionary."""
        return {
            "min_votes": float(self.controversial_min_total),
            "hide_ratio": self.harmful_hide_threshold,
        }


settings = Settings()
