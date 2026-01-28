"""
Flask Application Factory.

This module provides the create_app() factory function for creating
and configuring the Flask application instance.
"""

import os
from typing import Optional

from flask import Flask, redirect, request, url_for
from flask_migrate import Migrate

from src.config import get_config, ProductionConfig
from src.models import db

# Global migrate instance for CLI commands
migrate = Migrate()


def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Create and configure the Flask application.

    This factory function creates a Flask application instance configured
    for the specified environment. It initializes all extensions, registers
    blueprints, and sets up error handlers.

    Args:
        config_name: Configuration environment name ('development', 'production',
                    'testing'). If None, uses FLASK_ENV environment variable
                    or defaults to 'development'.

    Returns:
        Configured Flask application instance.

    Raises:
        RuntimeError: If SECRET_KEY is not set in production mode.
    """
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # Load configuration
    config_class = get_config(config_name)
    app.config.from_object(config_class)

    # Validate production configuration
    if config_class == ProductionConfig:
        if not app.config.get("SECRET_KEY"):
            raise RuntimeError(
                "FLASK_SECRET_KEY environment variable must be set in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

    # Initialize extensions (to be implemented in future stories)
    _init_extensions(app)

    # Register blueprints (to be implemented in future stories)
    _register_blueprints(app)

    # Register error handlers
    _register_error_handlers(app)

    # Register request handlers (including first-run middleware)
    _register_request_handlers(app)

    # Add health check endpoint
    @app.route("/health")
    def health_check() -> dict:
        """Health check endpoint for container orchestration."""
        return {"status": "healthy", "service": "noc-toolkit"}

    return app


def _init_extensions(app: Flask) -> None:
    """
    Initialize Flask extensions.

    Args:
        app: Flask application instance.
    """
    # Initialize Flask-SQLAlchemy
    db.init_app(app)

    # Initialize Flask-Migrate for database migrations
    migrate.init_app(app, db)


def _register_blueprints(app: Flask) -> None:
    """
    Register application blueprints.

    Args:
        app: Flask application instance.
    """
    from src.blueprints.auth import auth_bp
    from src.blueprints.admin import admin_bp
    from src.blueprints.wlc import wlc_bp
    from src.blueprints.solarwinds import solarwinds_bp
    from src.blueprints.config import config_bp
    from src.blueprints.bulk_ssh import bulk_ssh_bp
    from src.blueprints.certs import certs_bp
    from src.blueprints.jobs import jobs_bp
    from src.blueprints.kb import kb_bp
    from src.blueprints.setup import setup_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(wlc_bp)
    app.register_blueprint(solarwinds_bp)
    app.register_blueprint(config_bp)
    app.register_blueprint(bulk_ssh_bp)
    app.register_blueprint(certs_bp)
    app.register_blueprint(jobs_bp)
    app.register_blueprint(kb_bp)
    app.register_blueprint(setup_bp)


def _register_error_handlers(app: Flask) -> None:
    """
    Register error handlers for the application.

    Args:
        app: Flask application instance.
    """

    @app.errorhandler(404)
    def not_found_error(error):
        """Handle 404 Not Found errors."""
        return {"error": "Not Found", "status": 404}, 404

    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 Internal Server errors."""
        return {"error": "Internal Server Error", "status": 500}, 500


def _register_request_handlers(app: Flask) -> None:
    """
    Register request handlers and middleware.

    Args:
        app: Flask application instance.
    """
    from src.blueprints.setup.routes import is_first_run

    @app.before_request
    def check_first_run():
        """
        Redirect all routes to setup wizard if no users exist.

        Excluded routes:
        - /setup (the setup wizard itself)
        - /health (health check endpoint)
        - /static/* (static files)
        """
        # Skip check for excluded routes
        if request.endpoint in ("setup.setup_wizard", "health_check", "static"):
            return None

        # Skip for static file requests
        if request.path.startswith("/static/"):
            return None

        # Check if this is first run
        try:
            if is_first_run():
                return redirect(url_for("setup.setup_wizard"))
        except Exception:
            # If database check fails, allow request to proceed
            # This handles cases where DB isn't initialized yet
            pass

        return None
