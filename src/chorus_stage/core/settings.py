"""Settings management using pydantic-settings.

Load `.env` or environment variables at runtime.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_env: str = "dev"
    app_name: str = "chorus"
    app_host: str = "0.0.0.0"
    app_port: int = 8080

    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/chorus"
    redis_url: str = "redis://localhost:6379/0"

    server_signing_key_hex: str = "0"*64  # placeholder

    pow_difficulty_post: int = 20
    pow_difficulty_vote: int = 16
    pow_difficulty_read: int = 8

    model_config = SettingsConfigDict(env_file=".env", env_prefix="", case_sensitive=False)

settings = Settings()
