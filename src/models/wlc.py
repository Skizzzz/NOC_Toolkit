"""
WLC (Wireless LAN Controller) models for NOC Toolkit.

These models handle WLC dashboard settings, polling samples, and AP inventory.
"""

from datetime import datetime
from typing import Optional

# Import the shared db instance from the models package
from . import db


class WLCDashboardSettings(db.Model):
    """WLC Dashboard settings model for polling configuration."""

    __tablename__ = "wlc_dashboard_settings"

    # Singleton pattern: only one row allowed (id=1)
    id = db.Column(db.Integer, primary_key=True, default=1)
    enabled = db.Column(db.Boolean, default=False)
    hosts_json = db.Column(db.Text, nullable=True)
    username = db.Column(db.Text, nullable=True)
    password = db.Column(db.Text, nullable=True)  # Encrypted
    secret = db.Column(db.Text, nullable=True)  # Encrypted
    interval_sec = db.Column(db.Integer, default=600)
    updated = db.Column(db.DateTime, nullable=True)
    last_poll_ts = db.Column(db.DateTime, nullable=True)
    last_poll_status = db.Column(db.String(50), nullable=True)
    last_poll_message = db.Column(db.Text, nullable=True)
    validation_json = db.Column(db.Text, nullable=True)
    poll_summary_json = db.Column(db.Text, nullable=True)
    # Aruba controller settings
    aruba_hosts_json = db.Column(db.Text, nullable=True)
    aruba_enabled = db.Column(db.Boolean, default=False)

    __table_args__ = (
        db.CheckConstraint("id = 1", name="singleton_wlc_dashboard_settings"),
    )

    def __repr__(self) -> str:
        status = "enabled" if self.enabled else "disabled"
        return f"<WLCDashboardSettings ({status})>"

    @classmethod
    def get_settings(cls) -> "WLCDashboardSettings":
        """Get the singleton settings instance, creating if needed."""
        settings = cls.query.first()
        if settings is None:
            settings = cls(id=1)
            db.session.add(settings)
            db.session.commit()
        return settings


class WLCSample(db.Model):
    """WLC Dashboard sample model for storing polling data."""

    __tablename__ = "wlc_dashboard_samples"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ts = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    host = db.Column(db.String(255), nullable=False)
    total_clients = db.Column(db.Integer, nullable=True)
    ap_count = db.Column(db.Integer, nullable=True)
    ap_details_json = db.Column(db.Text, nullable=True)

    # Indexes
    __table_args__ = (
        db.Index("idx_wlc_dash_ts", "ts"),
        db.Index("idx_wlc_dash_host", "host"),
        db.UniqueConstraint("ts", "host", name="idx_wlc_dash_unique"),
    )

    def __repr__(self) -> str:
        return f"<WLCSample {self.host} at {self.ts} clients={self.total_clients}>"


class WLCSummerSettings(db.Model):
    """WLC Summer Guest SSID settings model."""

    __tablename__ = "wlc_summer_settings"

    # Singleton pattern: only one row allowed (id=1)
    id = db.Column(db.Integer, primary_key=True, default=1)
    enabled = db.Column(db.Boolean, default=False)
    hosts_json = db.Column(db.Text, nullable=True)
    username = db.Column(db.Text, nullable=True)
    password = db.Column(db.Text, nullable=True)  # Encrypted
    secret = db.Column(db.Text, nullable=True)  # Encrypted
    profile_names_json = db.Column(db.Text, nullable=True)
    wlan_ids_json = db.Column(db.Text, nullable=True)
    daily_time = db.Column(db.String(10), nullable=True)  # HH:MM format
    timezone = db.Column(db.String(100), nullable=True)
    updated = db.Column(db.DateTime, nullable=True)
    last_poll_ts = db.Column(db.DateTime, nullable=True)
    last_poll_status = db.Column(db.String(50), nullable=True)
    last_poll_message = db.Column(db.Text, nullable=True)
    validation_json = db.Column(db.Text, nullable=True)
    summary_json = db.Column(db.Text, nullable=True)

    __table_args__ = (
        db.CheckConstraint("id = 1", name="singleton_wlc_summer_settings"),
    )

    def __repr__(self) -> str:
        status = "enabled" if self.enabled else "disabled"
        return f"<WLCSummerSettings ({status})>"

    @classmethod
    def get_settings(cls) -> "WLCSummerSettings":
        """Get the singleton settings instance, creating if needed."""
        settings = cls.query.first()
        if settings is None:
            settings = cls(id=1)
            db.session.add(settings)
            db.session.commit()
        return settings


class WLCSummerSample(db.Model):
    """WLC Summer Guest SSID sample model for storing poll results."""

    __tablename__ = "wlc_summer_samples"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ts = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    host = db.Column(db.String(255), nullable=False)
    profile_name = db.Column(db.String(255), nullable=True)
    wlan_id = db.Column(db.Integer, nullable=True)
    ssid = db.Column(db.String(255), nullable=True)
    enabled = db.Column(db.Boolean, nullable=True)
    status_text = db.Column(db.String(255), nullable=True)
    raw_json = db.Column(db.Text, nullable=True)

    # Indexes
    __table_args__ = (
        db.Index("idx_wlc_summer_ts", "ts"),
        db.Index("idx_wlc_summer_host", "host"),
    )

    def __repr__(self) -> str:
        return f"<WLCSummerSample {self.host} wlan={self.wlan_id} ssid={self.ssid}>"


class APInventory(db.Model):
    """AP Inventory model for tracking access points across WLCs."""

    __tablename__ = "ap_inventory"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ap_name = db.Column(db.String(255), nullable=True)
    ap_ip = db.Column(db.String(45), nullable=True)  # IPv6 can be up to 45 chars
    ap_model = db.Column(db.String(100), nullable=True)
    ap_mac = db.Column(db.String(17), nullable=True)  # MAC address format
    ap_location = db.Column(db.Text, nullable=True)
    ap_state = db.Column(db.String(50), nullable=True)
    slots = db.Column(db.Text, nullable=True)  # JSON or comma-separated
    country = db.Column(db.String(10), nullable=True)
    wlc_host = db.Column(db.String(255), nullable=True)
    first_seen = db.Column(db.DateTime, nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)

    # Indexes
    __table_args__ = (
        db.UniqueConstraint("ap_mac", "wlc_host", name="idx_ap_inv_mac_wlc"),
        db.Index("idx_ap_inv_last_seen", "last_seen"),
        db.Index("idx_ap_inv_name", "ap_name"),
        db.Index("idx_ap_inv_wlc", "wlc_host"),
        db.Index("idx_ap_inv_model", "ap_model"),
    )

    def __repr__(self) -> str:
        return f"<APInventory {self.ap_name} ({self.ap_mac}) on {self.wlc_host}>"

    @property
    def is_active(self) -> bool:
        """Check if AP has been seen in the last 24 hours."""
        if self.last_seen is None:
            return False
        from datetime import timedelta
        return datetime.utcnow() - self.last_seen < timedelta(hours=24)


class APInventorySettings(db.Model):
    """AP Inventory settings model for cleanup configuration."""

    __tablename__ = "ap_inventory_settings"

    # Singleton pattern: only one row allowed (id=1)
    id = db.Column(db.Integer, primary_key=True, default=1)
    enabled = db.Column(db.Boolean, default=True)
    cleanup_days = db.Column(db.Integer, default=5)
    updated_at = db.Column(db.DateTime, nullable=True, onupdate=datetime.utcnow)

    __table_args__ = (
        db.CheckConstraint("id = 1", name="singleton_ap_inventory_settings"),
    )

    def __repr__(self) -> str:
        status = "enabled" if self.enabled else "disabled"
        return f"<APInventorySettings ({status}) cleanup={self.cleanup_days}d>"

    @classmethod
    def get_settings(cls) -> "APInventorySettings":
        """Get the singleton settings instance, creating if needed."""
        settings = cls.query.first()
        if settings is None:
            settings = cls(id=1)
            db.session.add(settings)
            db.session.commit()
        return settings
