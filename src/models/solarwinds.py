"""
SolarWinds models for NOC Toolkit.

These models handle SolarWinds integration settings and node inventory.
"""

from datetime import datetime
from typing import Optional

# Import the shared db instance from the models package
from . import db


class SolarWindsSettings(db.Model):
    """SolarWinds integration settings model."""

    __tablename__ = "solarwinds_settings"

    # Singleton pattern: only one row allowed (id=1)
    id = db.Column(db.Integer, primary_key=True, default=1)
    base_url = db.Column(db.Text, nullable=True)
    username = db.Column(db.Text, nullable=True)
    password = db.Column(db.Text, nullable=True)  # Encrypted
    verify_ssl = db.Column(db.Boolean, default=True)
    updated = db.Column(db.DateTime, nullable=True)
    last_poll_ts = db.Column(db.DateTime, nullable=True)
    last_poll_status = db.Column(db.String(50), nullable=True)
    last_poll_message = db.Column(db.Text, nullable=True)

    __table_args__ = (
        db.CheckConstraint("id = 1", name="singleton_solarwinds_settings"),
    )

    def __repr__(self) -> str:
        return f"<SolarWindsSettings url={self.base_url}>"

    @classmethod
    def get_settings(cls) -> "SolarWindsSettings":
        """Get the singleton settings instance, creating if needed."""
        settings = cls.query.first()
        if settings is None:
            settings = cls(id=1)
            db.session.add(settings)
            db.session.commit()
        return settings

    @property
    def is_configured(self) -> bool:
        """Check if SolarWinds is configured with required fields."""
        return bool(self.base_url and self.username and self.password)


class SolarWindsNode(db.Model):
    """SolarWinds node model for network device inventory."""

    __tablename__ = "solarwinds_nodes"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    node_id = db.Column(db.String(100), nullable=True)
    caption = db.Column(db.String(255), nullable=True)
    organization = db.Column(db.String(255), nullable=True)
    vendor = db.Column(db.String(100), nullable=True)
    model = db.Column(db.String(100), nullable=True)
    version = db.Column(db.String(100), nullable=True)
    hardware_version = db.Column(db.String(100), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 can be up to 45 chars
    status = db.Column(db.String(50), nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    extra_json = db.Column(db.Text, nullable=True)

    # Indexes
    __table_args__ = (
        db.Index("idx_solarwinds_node_id", "node_id"),
        db.Index("idx_solarwinds_caption", "caption"),
        db.Index("idx_solarwinds_vendor", "vendor"),
        db.Index("idx_solarwinds_model", "model"),
        db.Index("idx_solarwinds_version", "version"),
        db.Index("idx_solarwinds_hw_version", "hardware_version"),
    )

    def __repr__(self) -> str:
        return f"<SolarWindsNode {self.caption} ({self.ip_address})>"

    @property
    def is_up(self) -> bool:
        """Check if node status indicates it is up."""
        if self.status is None:
            return False
        return self.status.lower() in ("up", "online", "1")

    @classmethod
    def get_by_node_id(cls, node_id: str) -> Optional["SolarWindsNode"]:
        """Get a node by its SolarWinds node ID."""
        return cls.query.filter_by(node_id=node_id).first()

    @classmethod
    def search(
        cls,
        query: Optional[str] = None,
        vendor: Optional[str] = None,
        model: Optional[str] = None,
    ) -> list:
        """Search nodes with optional filters."""
        q = cls.query

        if query:
            search_term = f"%{query}%"
            q = q.filter(
                db.or_(
                    cls.caption.ilike(search_term),
                    cls.ip_address.ilike(search_term),
                    cls.organization.ilike(search_term),
                )
            )

        if vendor:
            q = q.filter(cls.vendor == vendor)

        if model:
            q = q.filter(cls.model == model)

        return q.order_by(cls.caption).all()
