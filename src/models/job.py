"""
Job and JobEvent models for NOC Toolkit.

These models handle background job tracking and event logging for long-running operations.
"""

from datetime import datetime
from typing import Optional

# Import the shared db instance from the models package
from . import db


class Job(db.Model):
    """Job model for tracking background operations."""

    __tablename__ = "jobs"

    job_id = db.Column(db.String(255), primary_key=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    tool = db.Column(db.String(100), nullable=True)
    params_json = db.Column(db.Text, nullable=True)
    done = db.Column(db.Boolean, nullable=False, default=False)
    cancelled = db.Column(db.Boolean, nullable=False, default=False)

    # Relationships
    events = db.relationship(
        "JobEvent",
        back_populates="job",
        cascade="all, delete-orphan",
        lazy="dynamic",
        order_by="JobEvent.ts",
    )

    # Indexes
    __table_args__ = (
        db.Index("idx_jobs_tool", "tool"),
        db.Index("idx_jobs_created", "created"),
    )

    def __repr__(self) -> str:
        status = "done" if self.done else ("cancelled" if self.cancelled else "running")
        return f"<Job {self.job_id} ({self.tool}) [{status}]>"

    @property
    def is_complete(self) -> bool:
        """Check if the job is complete (either done or cancelled)."""
        return self.done or self.cancelled

    def mark_done(self) -> None:
        """Mark the job as done."""
        self.done = True

    def mark_cancelled(self) -> None:
        """Mark the job as cancelled."""
        self.cancelled = True

    def add_event(
        self, event_type: str, payload_json: Optional[str] = None
    ) -> "JobEvent":
        """Add an event to this job."""
        event = JobEvent(
            job_id=self.job_id,
            ts=datetime.utcnow(),
            type=event_type,
            payload_json=payload_json,
        )
        db.session.add(event)
        return event


class JobEvent(db.Model):
    """JobEvent model for logging job progress and status changes."""

    __tablename__ = "job_events"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    job_id = db.Column(
        db.String(255),
        db.ForeignKey("jobs.job_id", ondelete="CASCADE"),
        nullable=False,
    )
    ts = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    type = db.Column(
        db.String(50), nullable=True
    )  # created|sample|error|done|cancelled|note
    payload_json = db.Column(db.Text, nullable=True)

    # Relationships
    job = db.relationship("Job", back_populates="events")

    # Indexes
    __table_args__ = (
        db.Index("idx_job_events_job", "job_id"),
        db.Index("idx_job_events_type", "type"),
        db.Index("idx_job_events_ts", "ts"),
    )

    def __repr__(self) -> str:
        return f"<JobEvent {self.id} ({self.type}) for job {self.job_id}>"
