"""
Config management models for NOC Toolkit.

These models handle change window scheduling and event logging for configuration changes.
"""

from datetime import datetime
from typing import Optional, List

from . import db


class ChangeWindow(db.Model):
    """ChangeWindow model for tracking scheduled configuration change windows."""

    __tablename__ = "change_windows"

    change_id = db.Column(db.String(255), primary_key=True)
    change_number = db.Column(db.String(100), nullable=True)  # External ticket/CR number
    scheduled = db.Column(db.DateTime, nullable=True)
    tool = db.Column(db.String(100), nullable=True)
    message = db.Column(db.Text, nullable=True)
    payload_json = db.Column(db.Text, nullable=True)  # JSON config data
    status = db.Column(
        db.String(50), nullable=False, default="scheduled"
    )  # scheduled|running|completed|failed|rolled_back|cancelled
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_by = db.Column(db.String(100), nullable=True)
    result_json = db.Column(db.Text, nullable=True)  # JSON result data

    # Relationships
    events = db.relationship(
        "ChangeEvent",
        back_populates="change_window",
        cascade="all, delete-orphan",
        lazy="dynamic",
        order_by="ChangeEvent.ts",
    )

    # Indexes
    __table_args__ = (
        db.Index("idx_change_windows_scheduled", "scheduled"),
        db.Index("idx_change_windows_status", "status"),
    )

    def __repr__(self) -> str:
        return f"<ChangeWindow {self.change_id} [{self.status}]>"

    @property
    def is_complete(self) -> bool:
        """Check if the change window has completed (success or failure)."""
        return self.status in ("completed", "failed", "rolled_back", "cancelled")

    def start(self) -> None:
        """Mark the change window as started."""
        self.status = "running"
        self.started_at = datetime.utcnow()

    def complete(self, result_json: Optional[str] = None) -> None:
        """Mark the change window as completed successfully."""
        self.status = "completed"
        self.completed_at = datetime.utcnow()
        if result_json:
            self.result_json = result_json

    def fail(self, result_json: Optional[str] = None) -> None:
        """Mark the change window as failed."""
        self.status = "failed"
        self.completed_at = datetime.utcnow()
        if result_json:
            self.result_json = result_json

    def rollback(self, result_json: Optional[str] = None) -> None:
        """Mark the change window as rolled back."""
        self.status = "rolled_back"
        self.completed_at = datetime.utcnow()
        if result_json:
            self.result_json = result_json

    def cancel(self) -> None:
        """Mark the change window as cancelled."""
        self.status = "cancelled"
        self.completed_at = datetime.utcnow()

    def add_event(self, event_type: str, message: str) -> "ChangeEvent":
        """Add an event to this change window."""
        event = ChangeEvent(
            change_id=self.change_id,
            ts=datetime.utcnow(),
            type=event_type,
            message=message,
        )
        db.session.add(event)
        return event

    @classmethod
    def list_changes(
        cls, limit: int = 200, status: Optional[str] = None
    ) -> List["ChangeWindow"]:
        """List change windows, optionally filtered by status."""
        query = cls.query.order_by(cls.scheduled.desc())
        if status:
            query = query.filter(cls.status == status)
        return query.limit(limit).all()

    @classmethod
    def fetch_due_changes(cls, now: datetime) -> List["ChangeWindow"]:
        """Fetch all scheduled change windows that are due to run."""
        return cls.query.filter(
            cls.status == "scheduled",
            cls.scheduled <= now,
        ).all()

    @classmethod
    def fetch_scheduled_by_tool(cls, tool: str) -> List["ChangeWindow"]:
        """Fetch all scheduled changes for a specific tool."""
        return cls.query.filter(
            cls.status == "scheduled",
            cls.tool == tool,
        ).all()


class ChangeEvent(db.Model):
    """ChangeEvent model for logging events during change window execution."""

    __tablename__ = "change_events"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    change_id = db.Column(
        db.String(255),
        db.ForeignKey("change_windows.change_id", ondelete="CASCADE"),
        nullable=False,
    )
    ts = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    type = db.Column(
        db.String(50), nullable=True
    )  # created|started|completed|failed|rolled_back|note
    message = db.Column(db.Text, nullable=True)

    # Relationships
    change_window = db.relationship("ChangeWindow", back_populates="events")

    # Indexes
    __table_args__ = (
        db.Index("idx_change_events_change", "change_id"),
        db.Index("idx_change_events_ts", "ts"),
    )

    def __repr__(self) -> str:
        return f"<ChangeEvent {self.id} ({self.type}) for change {self.change_id}>"
