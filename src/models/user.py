"""
User and Session models for NOC Toolkit.

These models handle user authentication and session management.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Import the shared db instance from the models package
from . import db


class User(db.Model):
    """User model for authentication and access control."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")
    created_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow
    )
    last_login = db.Column(db.DateTime, nullable=True)
    kb_access_level = db.Column(db.String(50), nullable=False, default="FSR")
    can_create_kb = db.Column(db.Boolean, nullable=False, default=False)

    # Relationships
    sessions = db.relationship(
        "Session", back_populates="user", cascade="all, delete-orphan"
    )
    kb_articles = db.relationship(
        "KBArticle",
        back_populates="author",
        foreign_keys="KBArticle.created_by",
        lazy="dynamic",
    )

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"

    def set_password(self, password: str) -> None:
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    def check_password(self, password: str) -> bool:
        """Check if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def update_last_login(self) -> None:
        """Update the last_login timestamp to now."""
        self.last_login = datetime.utcnow()

    @property
    def is_superadmin(self) -> bool:
        """Check if user has superadmin role."""
        return self.role == "superadmin"

    def can_view_kb_article(self, article_visibility: str) -> bool:
        """Check if user can view an article with given visibility level."""
        # Hierarchy: Admin > NOC > FSR
        levels = {"FSR": 1, "NOC": 2, "Admin": 3}
        user_level = levels.get(self.kb_access_level, 1)
        article_level = levels.get(article_visibility, 1)
        return user_level >= article_level

    def can_create_kb_articles(self) -> bool:
        """Check if user has permission to create knowledge base articles."""
        return self.can_create_kb or self.is_superadmin


class Session(db.Model):
    """Session model for tracking user sessions."""

    __tablename__ = "sessions"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    session_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 can be up to 45 chars
    user_agent = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

    # Relationships
    user = db.relationship("User", back_populates="sessions")

    def __repr__(self) -> str:
        return f"<Session {self.session_token[:8]}... for user_id={self.user_id}>"

    @property
    def is_expired(self) -> bool:
        """Check if the session has expired."""
        return datetime.utcnow() > self.expires_at
