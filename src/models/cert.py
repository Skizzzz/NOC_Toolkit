"""
Certificate and ISE Node models for NOC Toolkit.

These models handle certificate tracking and ISE node management for certificate syncing.
"""

from datetime import datetime
from typing import Optional

# Import the shared db instance from the models package
from . import db


class Certificate(db.Model):
    """Certificate model for tracking SSL/TLS certificates."""

    __tablename__ = "certificates"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cn = db.Column(db.Text, nullable=True)  # Common Name
    expires = db.Column(db.Text, nullable=True)  # Expiration date as ISO string
    issued_to = db.Column(db.Text, nullable=True)
    issued_by = db.Column(db.Text, nullable=True)
    used_by = db.Column(db.Text, nullable=True)  # Service/application using the cert
    notes = db.Column(db.Text, nullable=True)
    devices = db.Column(db.Text, nullable=True)  # Comma-separated list of devices
    source_type = db.Column(db.Text, nullable=True)  # e.g., "manual", "ise", "upload"
    source_ip = db.Column(db.Text, nullable=True)
    source_hostname = db.Column(db.Text, nullable=True)
    uploaded = db.Column(db.Text, nullable=True)  # Upload timestamp as ISO string
    updated = db.Column(db.Text, nullable=True)  # Last update timestamp as ISO string
    serial = db.Column(db.Text, nullable=True)  # Certificate serial number

    # Indexes
    __table_args__ = (
        db.Index("idx_certificates_cn", "cn"),
        db.Index("idx_certificates_expires", "expires"),
        db.Index("idx_certificates_serial", "serial"),
    )

    def __repr__(self) -> str:
        return f"<Certificate {self.cn} (expires={self.expires})>"

    @property
    def is_expired(self) -> bool:
        """Check if the certificate has expired."""
        if not self.expires:
            return False
        try:
            # Parse the expiration date - assumes ISO format
            exp_date = datetime.fromisoformat(self.expires.replace("Z", "+00:00"))
            return datetime.utcnow() > exp_date.replace(tzinfo=None)
        except (ValueError, AttributeError):
            return False

    @property
    def days_until_expiry(self) -> Optional[int]:
        """Calculate days until certificate expires. Returns negative if expired."""
        if not self.expires:
            return None
        try:
            exp_date = datetime.fromisoformat(self.expires.replace("Z", "+00:00"))
            delta = exp_date.replace(tzinfo=None) - datetime.utcnow()
            return delta.days
        except (ValueError, AttributeError):
            return None

    @classmethod
    def get_by_serial(cls, serial: str) -> Optional["Certificate"]:
        """Get a certificate by its serial number."""
        return cls.query.filter_by(serial=serial).first()

    @classmethod
    def get_expiring_soon(cls, days: int = 30) -> list:
        """Get certificates expiring within the specified number of days."""
        from datetime import timedelta

        threshold = (datetime.utcnow() + timedelta(days=days)).isoformat()
        return (
            cls.query.filter(cls.expires <= threshold)
            .order_by(cls.expires)
            .all()
        )


class ISENode(db.Model):
    """ISE Node model for managing Cisco ISE nodes for certificate syncing."""

    __tablename__ = "ise_nodes"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    hostname = db.Column(db.Text, nullable=True, index=True)
    ip = db.Column(db.Text, nullable=True)
    username = db.Column(db.Text, nullable=True)
    password_encrypted = db.Column(db.Text, nullable=True)  # Encrypted password
    enabled = db.Column(db.Integer, default=1)  # 1=enabled, 0=disabled
    last_sync = db.Column(db.Text, nullable=True)  # Last sync timestamp as ISO string
    last_sync_status = db.Column(db.Text, nullable=True)  # e.g., "success", "error"
    last_sync_message = db.Column(db.Text, nullable=True)  # Sync result message
    created = db.Column(db.Text, nullable=True)
    updated = db.Column(db.Text, nullable=True)
    version = db.Column(db.Text, nullable=True)  # ISE version

    def __repr__(self) -> str:
        return f"<ISENode {self.hostname} ({self.ip})>"

    @property
    def is_enabled(self) -> bool:
        """Check if the node is enabled for syncing."""
        return self.enabled == 1

    @property
    def last_sync_success(self) -> bool:
        """Check if the last sync was successful."""
        return self.last_sync_status == "success"

    def enable(self) -> None:
        """Enable the node for syncing."""
        self.enabled = 1

    def disable(self) -> None:
        """Disable the node from syncing."""
        self.enabled = 0

    def update_sync_status(
        self, status: str, message: Optional[str] = None
    ) -> None:
        """Update the sync status after a sync attempt."""
        self.last_sync = datetime.utcnow().isoformat()
        self.last_sync_status = status
        self.last_sync_message = message
        self.updated = datetime.utcnow().isoformat()

    @classmethod
    def get_enabled(cls) -> list:
        """Get all enabled ISE nodes."""
        return cls.query.filter_by(enabled=1).order_by(cls.hostname).all()

    @classmethod
    def get_by_hostname(cls, hostname: str) -> Optional["ISENode"]:
        """Get an ISE node by hostname."""
        return cls.query.filter_by(hostname=hostname).first()


class CertSyncSettings(db.Model):
    """Certificate sync settings model (singleton)."""

    __tablename__ = "cert_sync_settings"

    # Singleton pattern: only one row allowed (id=1)
    id = db.Column(db.Integer, primary_key=True, default=1)
    enabled = db.Column(db.Integer, default=0)  # 1=enabled, 0=disabled
    interval_hours = db.Column(db.Integer, default=24)  # Sync interval in hours
    last_sync_ts = db.Column(db.Text, nullable=True)  # Last sync timestamp
    last_sync_status = db.Column(db.Text, nullable=True)  # e.g., "success", "error"
    last_sync_message = db.Column(db.Text, nullable=True)

    __table_args__ = (
        db.CheckConstraint("id = 1", name="singleton_cert_sync_settings"),
    )

    def __repr__(self) -> str:
        return f"<CertSyncSettings enabled={self.enabled} interval={self.interval_hours}h>"

    @classmethod
    def get_settings(cls) -> "CertSyncSettings":
        """Get the singleton settings instance, creating if needed."""
        settings = cls.query.first()
        if settings is None:
            settings = cls(id=1)
            db.session.add(settings)
            db.session.commit()
        return settings

    @property
    def is_enabled(self) -> bool:
        """Check if certificate syncing is enabled."""
        return self.enabled == 1

    def enable(self) -> None:
        """Enable certificate syncing."""
        self.enabled = 1

    def disable(self) -> None:
        """Disable certificate syncing."""
        self.enabled = 0

    def update_sync_status(
        self, status: str, message: Optional[str] = None
    ) -> None:
        """Update the sync status after a sync attempt."""
        self.last_sync_ts = datetime.utcnow().isoformat()
        self.last_sync_status = status
        self.last_sync_message = message
