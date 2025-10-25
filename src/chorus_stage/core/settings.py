"""Application settings and configuration.

This module defines all configuration options for the Chorus Stage application.
Settings are loaded from environment variables with sensible defaults.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    This class defines all configuration options for the Chorus Stage application.
    Settings can be overridden via environment variables or .env files.
    """

    # Application metadata
    app_name: str = Field(default="Chorus Stage", alias="APP_NAME")
    app_version: str = Field(default="0.1.0", alias="APP_VERSION")
    admin_email: str | None = Field(default=None, alias="ADMIN_EMAIL")

    # Security and authentication
    secret_key: str = Field(alias="SECRET_KEY")
    debug: bool = Field(default=False, alias="DEBUG")

    # Database configuration
    database_url: str = Field(default="sqlite:///./chorus.db", alias="DATABASE_URL")
    test_database_url: str | None = Field(default=None, alias="TEST_DATABASE_URL")
    use_testing_database: bool = Field(default=False, alias="USE_TEST_DATABASE")
    preserve_test_data: bool = Field(default=False, alias="PRESERVE_TEST_DATA")
    ascii_art_enabled: bool = Field(default=True, alias="ASCII_ART_ENABLED")
    ascii_art_line_delay: float = Field(default=0.05, alias="ASCII_ART_LINE_DELAY")
    sql_debug: bool = Field(default=False, alias="SQL_DEBUG")

    # Redis configuration for caching and replay protection
    redis_url: str = Field(default="redis://localhost:6379", alias="REDIS_URL")

    # JWT authentication settings
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(
        default=60 * 24 * 30,
        alias="ACCESS_TOKEN_EXPIRE_MINUTES",
    )
    login_challenge: str = Field(default="test_nonce_value", alias="LOGIN_CHALLENGE")

    # Proof-of-Work difficulty settings (leading zero bits required)
    pow_difficulty_post: int = Field(default=20, alias="POW_DIFFICULTY_POST")
    pow_difficulty_vote: int = Field(default=15, alias="POW_DIFFICULTY_VOTE")
    pow_difficulty_message: int = Field(default=18, alias="POW_DIFFICULTY_MESSAGE")
    pow_difficulty_moderate: int = Field(default=16, alias="POW_DIFFICULTY_MODERATE")
    pow_difficulty_register: int = Field(default=18, alias="POW_DIFFICULTY_REGISTER")
    pow_difficulty_login: int = Field(default=16, alias="POW_DIFFICULTY_LOGIN")

    # Adaptive PoW leases to smooth UX after a successful solve
    pow_enable_leases: bool = Field(default=True, alias="POW_ENABLE_LEASES")
    pow_lease_seconds: int = Field(default=120, alias="POW_LEASE_SECONDS")
    pow_lease_actions: int = Field(default=3, alias="POW_LEASE_ACTIONS")

    # Content moderation settings
    recent_window_size: int = Field(default=50, alias="RECENT_WINDOW_SIZE")
    controversial_min_total: int = Field(
        default=5,
        alias="CONTROVERSIAL_MIN_TOTAL",
    )
    token_epoch_size: int = Field(default=10_000, alias="TOKEN_EPOCH_SIZE")
    harmful_hide_threshold: float = Field(default=0.2, alias="HARMFUL_HIDE_THRESHOLD")
    clear_threshold: float = Field(default=0.6, alias="CLEAR_THRESHOLD")
    moderation_min_community_size: int = Field(
        default=25,
        alias="MODERATION_MIN_COMMUNITY_SIZE",
    )

    # Harmful vote cool-downs (anti-harassment throttling)
    harmful_vote_author_cooldown_seconds: int = Field(
        default=900, alias="HARMFUL_VOTE_AUTHOR_COOLDOWN_SECONDS"
    )
    harmful_vote_post_cooldown_seconds: int = Field(
        default=120, alias="HARMFUL_VOTE_POST_COOLDOWN_SECONDS"
    )

    # Moderation trigger cool-down (limit rapid case creation)
    moderation_trigger_cooldown_seconds: int = Field(
        default=60, alias="MODERATION_TRIGGER_COOLDOWN_SECONDS"
    )

    # Chorus Bridge integration settings
    bridge_enabled: bool = Field(default=False, alias="CHORUS_BRIDGE_ENABLED")
    bridge_base_url: str | None = Field(default=None, alias="CHORUS_BRIDGE_BASE_URL")
    bridge_instance_id: str = Field(
        default="stage-local",
        alias="CHORUS_BRIDGE_INSTANCE_ID",
    )
    bridge_shared_secret: str | None = Field(
        default=None,
        alias="CHORUS_BRIDGE_SHARED_SECRET",
    )
    bridge_audience: str = Field(
        default="chorus-bridge",
        alias="CHORUS_BRIDGE_JWT_AUD",
    )
    bridge_token_ttl_seconds: int = Field(
        default=300,
        alias="CHORUS_BRIDGE_TOKEN_TTL_SECONDS",
    )
    bridge_http_timeout_seconds: float = Field(
        default=10.0,
        alias="CHORUS_BRIDGE_HTTP_TIMEOUT_SECONDS",
    )
    bridge_pull_interval_seconds: float = Field(
        default=2.0,
        alias="CHORUS_BRIDGE_PULL_INTERVAL_SECONDS",
    )
    bridge_outbound_batch_size: int = Field(
        default=10,
        alias="CHORUS_BRIDGE_OUTBOUND_BATCH_SIZE",
    )
    bridge_outbound_max_retries: int = Field(
        default=5,
        alias="CHORUS_BRIDGE_OUTBOUND_MAX_RETRIES",
    )
    bridge_mtls_enabled: bool = Field(
        default=False,
        alias="CHORUS_BRIDGE_MTLS_ENABLED",
    )
    bridge_client_cert: str | None = Field(
        default=None,
        alias="CHORUS_BRIDGE_CLIENT_CERT",
    )
    bridge_client_key: str | None = Field(
        default=None,
        alias="CHORUS_BRIDGE_CLIENT_KEY",
    )
    bridge_ca_cert: str | None = Field(
        default=None,
        alias="CHORUS_BRIDGE_CA_CERT",
    )
    bridge_instance_private_key: str | None = Field(
        default=None,
        alias="CHORUS_BRIDGE_INSTANCE_PRIVATE_KEY",
    )

    # CORS configuration for web frontend access
    cors_origins: list[str] = Field(
        default=["*"],
        alias="CORS_ORIGINS",
    )
    cors_allow_credentials: bool = Field(default=True, alias="CORS_ALLOW_CREDENTIALS")
    cors_allow_methods: list[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        alias="CORS_ALLOW_METHODS",
    )
    cors_allow_headers: list[str] = Field(
        default=["*"],
        alias="CORS_ALLOW_HEADERS",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        validate_assignment=True,
        extra="ignore",
    )

    @property
    def database_url_sync(self) -> str:
        """Return a sync-compatible database URL for tooling.
        
        Converts asyncpg URLs to psycopg for synchronous database operations
        like Alembic migrations.
        
        Returns:
            Database URL compatible with synchronous database drivers
        """
        url = self.effective_database_url
        if url.startswith("postgresql+asyncpg"):
            return url.replace("postgresql+asyncpg", "postgresql+psycopg", 1)
        return url

    @property
    def effective_database_url(self) -> str:
        """Return the database URL respecting testing overrides.
        
        Returns:
            The active database URL (test database if in testing mode, otherwise production)
        """
        if self.use_testing_database and self.test_database_url:
            return self.test_database_url
        return self.database_url

    @property
    def moderation_thresholds(self) -> dict[str, float]:
        """Return moderation thresholds as a convenience dictionary.
        
        Returns:
            Dictionary with moderation threshold values for content filtering
        """
        return {
            "min_votes": float(self.controversial_min_total),
            "hide_ratio": self.harmful_hide_threshold,
        }

    @property
    def settings(self) -> "Settings":
        """Provide self-reference for legacy imports expecting a module attribute.
        
        Returns:
            Self-reference for backward compatibility
        """
        return self


settings = Settings()  # type: ignore[call-arg]