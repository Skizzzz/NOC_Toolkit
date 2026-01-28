"""
Auth blueprint package.

Provides authentication routes (login, logout, profile).
"""

from .routes import auth_bp

__all__ = ["auth_bp"]
