"""
Bulk SSH models for NOC Toolkit.

These models handle bulk SSH job execution, results, templates, and scheduling.
"""

from datetime import datetime
from typing import Optional, List

from . import db


class BulkSSHJob(db.Model):
    """BulkSSHJob model for tracking bulk SSH command execution jobs."""

    __tablename__ = "bulk_ssh_jobs"

    job_id = db.Column(db.String(255), primary_key=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    username = db.Column(db.String(100), nullable=True)
    command = db.Column(db.Text, nullable=True)
    device_count = db.Column(db.Integer, nullable=False, default=0)
    completed_count = db.Column(db.Integer, nullable=False, default=0)
    success_count = db.Column(db.Integer, nullable=False, default=0)
    failed_count = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(50), nullable=False, default="running")
    done = db.Column(db.Boolean, nullable=False, default=False)

    # Relationships
    results = db.relationship(
        "BulkSSHResult",
        back_populates="job",
        cascade="all, delete-orphan",
        lazy="dynamic",
        order_by="BulkSSHResult.completed_at",
    )

    # Indexes
    __table_args__ = (
        db.Index("idx_bulk_ssh_jobs_created", "created"),
        db.Index("idx_bulk_ssh_jobs_username", "username"),
    )

    def __repr__(self) -> str:
        status = "done" if self.done else "running"
        return f"<BulkSSHJob {self.job_id} by {self.username} [{status}]>"

    @property
    def is_complete(self) -> bool:
        """Check if the job is complete."""
        return self.done

    @property
    def progress_percent(self) -> int:
        """Calculate completion percentage."""
        if self.device_count == 0:
            return 0
        return int((self.completed_count / self.device_count) * 100)

    def update_progress(
        self, completed: int, success: int, failed: int
    ) -> None:
        """Update job progress counters."""
        self.completed_count = completed
        self.success_count = success
        self.failed_count = failed

    def mark_done(self, status: str = "completed") -> None:
        """Mark the job as done with the given status."""
        self.done = True
        self.status = status


class BulkSSHResult(db.Model):
    """BulkSSHResult model for storing individual device results."""

    __tablename__ = "bulk_ssh_results"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    job_id = db.Column(
        db.String(255),
        db.ForeignKey("bulk_ssh_jobs.job_id", ondelete="CASCADE"),
        nullable=False,
    )
    device = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False)  # success|failed|timeout|error
    output = db.Column(db.Text, nullable=True)
    error = db.Column(db.Text, nullable=True)
    duration_ms = db.Column(db.Integer, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    job = db.relationship("BulkSSHJob", back_populates="results")

    # Indexes
    __table_args__ = (
        db.Index("idx_bulk_ssh_results_job", "job_id"),
        db.Index("idx_bulk_ssh_results_device", "device"),
    )

    def __repr__(self) -> str:
        return f"<BulkSSHResult {self.id} [{self.status}] for {self.device}>"


class BulkSSHTemplate(db.Model):
    """BulkSSHTemplate model for reusable command templates."""

    __tablename__ = "bulk_ssh_templates"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    command = db.Column(db.Text, nullable=False)
    variables = db.Column(db.Text, nullable=True)  # JSON list of variable definitions
    device_type = db.Column(db.String(100), nullable=True)
    category = db.Column(db.String(100), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=True, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(100), nullable=True)

    # Indexes
    __table_args__ = (
        db.Index("idx_bulk_ssh_templates_category", "category"),
        db.Index("idx_bulk_ssh_templates_name", "name"),
    )

    def __repr__(self) -> str:
        return f"<BulkSSHTemplate {self.id} '{self.name}'>"

    @classmethod
    def list_by_category(cls, category: Optional[str] = None) -> List["BulkSSHTemplate"]:
        """List templates, optionally filtered by category."""
        query = cls.query.order_by(cls.category, cls.name)
        if category:
            query = query.filter(cls.category == category)
        return query.all()


class BulkSSHSchedule(db.Model):
    """BulkSSHSchedule model for scheduled bulk SSH jobs."""

    __tablename__ = "bulk_ssh_schedules"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    command = db.Column(db.Text, nullable=False)
    hosts = db.Column(db.Text, nullable=False)  # JSON list or newline-separated
    device_type = db.Column(db.String(100), nullable=True)
    schedule_type = db.Column(db.String(50), nullable=False)  # once|daily|weekly
    schedule_time = db.Column(db.String(10), nullable=True)  # HH:MM format
    schedule_day = db.Column(db.Integer, nullable=True)  # 0-6 for weekly
    next_run = db.Column(db.DateTime, nullable=True)
    last_run = db.Column(db.DateTime, nullable=True)
    last_job_id = db.Column(db.String(255), nullable=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_by = db.Column(db.String(100), nullable=True)

    # Indexes
    __table_args__ = (
        db.Index("idx_bulk_ssh_schedules_next_run", "next_run"),
        db.Index("idx_bulk_ssh_schedules_enabled", "enabled"),
    )

    def __repr__(self) -> str:
        status = "enabled" if self.enabled else "disabled"
        return f"<BulkSSHSchedule {self.id} '{self.name}' [{status}]>"

    @classmethod
    def fetch_due_schedules(cls, now: datetime) -> List["BulkSSHSchedule"]:
        """Fetch all enabled schedules that are due to run."""
        return cls.query.filter(
            cls.enabled == True,
            cls.next_run <= now,
        ).all()

    def update_after_run(
        self, last_run: datetime, last_job_id: str, next_run: datetime
    ) -> None:
        """Update schedule after a run."""
        self.last_run = last_run
        self.last_job_id = last_job_id
        self.next_run = next_run
