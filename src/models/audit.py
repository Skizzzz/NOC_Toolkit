"""
AuditLog model for NOC Toolkit.

This model handles audit trail logging for security and compliance purposes.
"""

from datetime import datetime
from typing import Optional

# Import the shared db instance from the models package
from . import db


class AuditLog(db.Model):
    """AuditLog model for tracking user actions and security events."""

    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    username = db.Column(db.String(255), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 can be up to 45 chars
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)

    # Relationships
    user = db.relationship(
        "User",
        backref=db.backref("audit_logs", lazy="dynamic"),
    )

    # Indexes
    __table_args__ = (
        db.Index("idx_audit_log_user_id", "user_id"),
        db.Index("idx_audit_log_username", "username"),
        db.Index("idx_audit_log_timestamp", "timestamp"),
        db.Index("idx_audit_log_action", "action"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog {self.id}: {self.username} - {self.action}>"

    @classmethod
    def log(
        cls,
        username: str,
        action: str,
        user_id: Optional[int] = None,
        resource: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[str] = None,
    ) -> "AuditLog":
        """Create a new audit log entry.

        Args:
            username: The username performing the action
            action: The action being performed (e.g., 'login', 'logout', 'create', 'delete')
            user_id: Optional user ID if the user is known
            resource: Optional resource being acted upon
            ip_address: Optional IP address of the user
            details: Optional additional details as JSON or text

        Returns:
            The created AuditLog entry
        """
        entry = cls(
            user_id=user_id,
            username=username,
            action=action,
            resource=resource,
            ip_address=ip_address,
            details=details,
            timestamp=datetime.utcnow(),
        )
        db.session.add(entry)
        return entry
