"""
Jobs Blueprint.

Provides routes for the unified jobs center - monitoring and managing
all background jobs across tools.
"""

from .routes import jobs_bp

__all__ = ["jobs_bp"]
