"""
Setup blueprint for first-run wizard.

Provides initial admin user setup on first application run.
"""

from .routes import setup_bp

__all__ = ["setup_bp"]
