"""
Knowledge Base models for NOC Toolkit.

These models handle knowledge base articles for internal documentation.
"""

from datetime import datetime
from typing import Optional, List

# Import the shared db instance from the models package
from . import db


class KBArticle(db.Model):
    """Knowledge Base article model for internal documentation."""

    __tablename__ = "kb_articles"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.Text, nullable=False)
    subject = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)
    visibility = db.Column(db.String(50), nullable=False, default="FSR")
    created_by = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow
    )
    updated_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    author = db.relationship(
        "User",
        back_populates="kb_articles",
        foreign_keys=[created_by],
    )

    # Indexes
    __table_args__ = (
        db.Index("idx_kb_articles_visibility", "visibility"),
        db.Index("idx_kb_articles_subject", "subject"),
    )

    def __repr__(self) -> str:
        return f"<KBArticle {self.id}: {self.title[:30]}...>"

    @property
    def visibility_level(self) -> int:
        """Return numeric visibility level for comparison. Higher = more restricted."""
        levels = {"FSR": 1, "NOC": 2, "Admin": 3}
        return levels.get(self.visibility, 1)

    def is_visible_to_user(self, user_kb_access_level: str) -> bool:
        """Check if article is visible to a user with the given access level."""
        levels = {"FSR": 1, "NOC": 2, "Admin": 3}
        user_level = levels.get(user_kb_access_level, 1)
        return user_level >= self.visibility_level

    def touch(self) -> None:
        """Update the updated_at timestamp to now."""
        self.updated_at = datetime.utcnow()

    @classmethod
    def get_by_id(cls, article_id: int) -> Optional["KBArticle"]:
        """Get an article by its ID."""
        return cls.query.get(article_id)

    @classmethod
    def get_visible_to_user(
        cls,
        user_kb_access_level: str,
        subject: Optional[str] = None,
        search_query: Optional[str] = None,
    ) -> List["KBArticle"]:
        """
        Get articles visible to a user with the given access level.

        Args:
            user_kb_access_level: User's KB access level (FSR, NOC, Admin)
            subject: Optional subject filter
            search_query: Optional search query for title/content

        Returns:
            List of visible KBArticle objects
        """
        # Determine which visibility levels the user can see
        levels = {"FSR": 1, "NOC": 2, "Admin": 3}
        user_level = levels.get(user_kb_access_level, 1)

        # Build list of allowed visibility values
        allowed_visibilities = [k for k, v in levels.items() if v <= user_level]

        q = cls.query.filter(cls.visibility.in_(allowed_visibilities))

        if subject:
            q = q.filter(cls.subject == subject)

        if search_query:
            search_term = f"%{search_query}%"
            q = q.filter(
                db.or_(
                    cls.title.ilike(search_term),
                    cls.content.ilike(search_term),
                )
            )

        return q.order_by(cls.updated_at.desc()).all()

    @classmethod
    def get_all_subjects(cls) -> List[str]:
        """Get a list of all unique subjects."""
        result = db.session.query(cls.subject).distinct().order_by(cls.subject).all()
        return [row[0] for row in result]

    @classmethod
    def get_recent(cls, limit: int = 10) -> List["KBArticle"]:
        """Get the most recently updated articles."""
        return cls.query.order_by(cls.updated_at.desc()).limit(limit).all()
