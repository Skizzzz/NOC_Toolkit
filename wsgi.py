"""
WSGI entry point for production deployment.

This module provides the WSGI application object for production servers
like Gunicorn. It creates the Flask app using the production configuration.

Usage with Gunicorn:
    gunicorn wsgi:application --workers 4 --bind 0.0.0.0:5000

Usage with Docker:
    The docker-entrypoint.sh script uses this module to start the application.
"""

from src.app import create_app

# Create the application with production configuration
application = create_app("production")

# Alias for convenience (some WSGI servers expect 'app')
app = application

if __name__ == "__main__":
    # For development/testing only - use gunicorn in production
    application.run()
