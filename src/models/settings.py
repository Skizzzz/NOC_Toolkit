"""
Settings models for NOC Toolkit.

These models handle application-wide and page-specific settings.
"""

from datetime import datetime

# Import the shared db instance from the models package
from . import db


class AppSettings(db.Model):
    """Application-wide settings model."""

    __tablename__ = "app_settings"

    # Singleton pattern: only one row allowed (id=1)
    id = db.Column(
        db.Integer,
        primary_key=True,
        default=1,
    )
    timezone = db.Column(db.String(100), default="America/Chicago")
    updated_at = db.Column(db.DateTime, nullable=True, onupdate=datetime.utcnow)

    __table_args__ = (
        db.CheckConstraint("id = 1", name="singleton_app_settings"),
    )

    def __repr__(self) -> str:
        return f"<AppSettings timezone={self.timezone}>"

    @classmethod
    def get_settings(cls) -> "AppSettings":
        """Get the singleton settings instance, creating if needed."""
        settings = cls.query.first()
        if settings is None:
            settings = cls(id=1)
            db.session.add(settings)
            db.session.commit()
        return settings


class PageSettings(db.Model):
    """Page visibility settings model."""

    __tablename__ = "page_settings"

    page_key = db.Column(db.String(100), primary_key=True)
    page_name = db.Column(db.String(255), nullable=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    category = db.Column(db.String(100), nullable=True)
    updated_at = db.Column(db.DateTime, nullable=True, onupdate=datetime.utcnow)

    # Indexes
    __table_args__ = (
        db.Index("idx_page_settings_category", "category"),
        db.Index("idx_page_settings_enabled", "enabled"),
    )

    def __repr__(self) -> str:
        status = "enabled" if self.enabled else "disabled"
        return f"<PageSettings {self.page_key} ({status})>"

    @classmethod
    def is_page_enabled(cls, page_key: str) -> bool:
        """Check if a page is enabled."""
        page = cls.query.filter_by(page_key=page_key).first()
        if page is None:
            # If page doesn't exist in settings, assume enabled
            return True
        return page.enabled

    @classmethod
    def get_all_pages(cls) -> list:
        """Get all page settings."""
        return cls.query.order_by(cls.category, cls.page_name).all()

    @classmethod
    def set_page_enabled(cls, page_key: str, enabled: bool) -> bool:
        """Enable or disable a page. Returns True if successful."""
        page = cls.query.filter_by(page_key=page_key).first()
        if page is None:
            return False
        page.enabled = enabled
        page.updated_at = datetime.utcnow()
        db.session.commit()
        return True
