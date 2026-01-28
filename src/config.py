"""
Flask application configuration classes.

Supports three environments: Development, Production, and Testing.
Configuration values are read from environment variables where appropriate.
"""

import os
from typing import Optional


class Config:
    """Base configuration class with common settings."""

    # Flask core settings - no default value, must be explicitly set
    SECRET_KEY: str = os.environ.get("FLASK_SECRET_KEY") or ""

    # Database settings - PostgreSQL by default
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL", "postgresql://noc:noc@localhost:5432/noc_toolkit"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # Session settings
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"

    # Application settings
    NOC_ENCRYPTION_KEY: Optional[str] = os.environ.get("NOC_ENCRYPTION_KEY")
    NOC_TOOLKIT_DATA_DIR: str = os.environ.get("NOC_TOOLKIT_DATA_DIR", "data")
    WLC_DASHBOARD_KEY: Optional[str] = os.environ.get("WLC_DASHBOARD_KEY")

    # Timezone settings
    DEFAULT_TIMEZONE: str = "America/Chicago"


class DevelopmentConfig(Config):
    """Development configuration with debugging enabled."""

    DEBUG: bool = True
    TESTING: bool = False

    # Allow insecure cookies in development
    SESSION_COOKIE_SECURE: bool = False

    # Development database (can use SQLite for convenience)
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL", "sqlite:///noc_toolkit_dev.db"
    )

    # Development secret key (only if not set via env var)
    SECRET_KEY: str = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-change-in-prod")


class ProductionConfig(Config):
    """Production configuration with security hardened settings."""

    DEBUG: bool = False
    TESTING: bool = False

    # Require SECRET_KEY in production - validated in create_app()
    # No default value - will raise RuntimeError in create_app if not set
    SECRET_KEY: str = os.environ.get("FLASK_SECRET_KEY") or ""

    # Strict security settings
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Strict"


class TestingConfig(Config):
    """Testing configuration for unit and integration tests."""

    DEBUG: bool = False
    TESTING: bool = True

    # Use in-memory SQLite for fast tests
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"

    # Disable CSRF for testing
    WTF_CSRF_ENABLED: bool = False

    # Testing secret key
    SECRET_KEY: str = "test-secret-key-for-testing-only"

    # Allow insecure cookies in testing
    SESSION_COOKIE_SECURE: bool = False


# Configuration mapping for easy access
config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}


def get_config(config_name: Optional[str] = None) -> type:
    """
    Get configuration class by name.

    Args:
        config_name: Configuration environment name. If None, uses
                    FLASK_ENV environment variable or defaults to 'development'.

    Returns:
        Configuration class for the specified environment.
    """
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    return config.get(config_name, DevelopmentConfig)
