"""
SolarWinds blueprint package.

Provides routes for SolarWinds node inventory, hardware/software inventory
dashboard, and API endpoints.
"""

from .routes import solarwinds_bp

__all__ = ["solarwinds_bp"]
