"""Application configuration via Pydantic Settings.

This module defines the `Settings` class which centralizes configuration for
the Chorus Stage application. Values are read from environment variables and
optionally from an `.env` file (see `model_config`). Use an instance of
`Settings` to access typed configuration values throughout the app.

Example:
    from chorus_stage.core.config import Settings
    settings = Settings()
    print(settings.database_url)
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed application settings.

    Attributes:
        app_name (str): Human-friendly application name (default: "Chorus Stage").
        database_url (str): Database connection URL. Required.
        admin_email (str): Administrator email address. Required.
        items_per_user (int): Default pagination / quota per user (default: 50).

    Notes:
        - Values are loaded from environment variables by default. The
          `model_config` below instructs Pydantic to also read an `.env` file
          at the project root if present.
    """

    app_name: str = "Chorus Stage"
    database_url: str
    admin_email: str
    items_per_user: int = 50

    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
