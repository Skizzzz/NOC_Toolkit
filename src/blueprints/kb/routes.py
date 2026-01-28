"""
Knowledge Base Blueprint Routes.

This module provides routes for the knowledge base feature including
article listing, creation, editing, viewing, and deletion.
"""

import sqlite3
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)

from src.core import (
    require_login,
    require_kb_create,
    require_page_enabled,
    get_kb_access_level,
    can_view_kb_article,
    log_audit,
)
from src.core.database import get_db_path

# Create the blueprint
kb_bp = Blueprint(
    "kb",
    __name__,
    template_folder="templates",
)


# ====================== Helper Functions ======================


def _get_kb_articles_for_user(user_id: int):
    """Get all KB articles visible to a user based on their access level."""
    access_level = get_kb_access_level(user_id) if user_id else "FSR"

    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get all articles and filter by visibility
    cursor.execute(
        """
        SELECT a.*, u.username as author_name
        FROM kb_articles a
        LEFT JOIN users u ON a.created_by = u.id
        ORDER BY a.updated_at DESC
    """
    )

    all_articles = cursor.fetchall()
    conn.close()

    # Filter based on user access level
    visible_articles = []
    for article in all_articles:
        if can_view_kb_article(access_level, article["visibility"]):
            visible_articles.append(dict(article))

    return visible_articles


def _get_kb_article(article_id: int):
    """Get a single KB article by ID."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT a.*, u.username as author_name
        FROM kb_articles a
        LEFT JOIN users u ON a.created_by = u.id
        WHERE a.id = ?
    """,
        (article_id,),
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def _create_kb_article(
    title: str, subject: str, content: str, visibility: str, created_by: int
) -> int:
    """Create a new KB article and return its ID."""
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO kb_articles (title, subject, content, visibility, created_by)
        VALUES (?, ?, ?, ?, ?)
    """,
        (title, subject, content, visibility, created_by),
    )
    article_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return article_id


def _update_kb_article(
    article_id: int, title: str, subject: str, content: str, visibility: str
):
    """Update an existing KB article."""
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE kb_articles
        SET title = ?, subject = ?, content = ?, visibility = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """,
        (title, subject, content, visibility, article_id),
    )
    conn.commit()
    conn.close()


def _delete_kb_article(article_id: int):
    """Delete a KB article."""
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()
    cursor.execute("DELETE FROM kb_articles WHERE id = ?", (article_id,))
    conn.commit()
    conn.close()


def _get_kb_subjects():
    """Get all unique subjects from KB articles."""
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT subject FROM kb_articles ORDER BY subject")
    subjects = [row[0] for row in cursor.fetchall()]
    conn.close()
    return subjects


def _can_user_create_kb(user_id: int) -> bool:
    """Check if a user can create KB articles based on their role."""
    if not user_id:
        return False
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return False
    role = row["role"]
    # KB_CREATE, NOC, and ADMIN roles can create articles
    return role in ("KB_CREATE", "NOC", "ADMIN", "superadmin")


# ====================== Routes ======================


@kb_bp.route("/knowledge-base")
@require_login
@require_page_enabled("knowledge_base")
def knowledge_base():
    """Knowledge Base main page - list all visible articles."""
    user_id = session.get("user_id")
    articles = _get_kb_articles_for_user(user_id)
    subjects = _get_kb_subjects()
    can_create = _can_user_create_kb(user_id)
    user_access_level = get_kb_access_level(user_id)

    # Filter by subject if provided
    subject_filter = request.args.get("subject", "")
    if subject_filter:
        articles = [a for a in articles if a["subject"] == subject_filter]

    # Search by title/content if provided
    search_query = request.args.get("q", "")
    if search_query:
        search_lower = search_query.lower()
        articles = [
            a
            for a in articles
            if search_lower in a["title"].lower()
            or search_lower in a["content"].lower()
        ]

    return render_template(
        "kb/knowledge_base.html",
        articles=articles,
        subjects=subjects,
        can_create=can_create,
        user_access_level=user_access_level,
        subject_filter=subject_filter,
        search_query=search_query,
    )


@kb_bp.route("/knowledge-base/create", methods=["GET", "POST"])
@require_login
@require_kb_create
def knowledge_base_create():
    """Create a new KB article."""
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        subject = request.form.get("subject", "").strip()
        content = request.form.get("content", "").strip()
        visibility = request.form.get("visibility", "FSR")

        if not title or not subject or not content:
            flash("Title, subject, and content are required.", "error")
            return render_template(
                "kb/knowledge_base_form.html",
                mode="create",
                article={
                    "title": title,
                    "subject": subject,
                    "content": content,
                    "visibility": visibility,
                },
                subjects=_get_kb_subjects(),
            )

        article_id = _create_kb_article(
            title, subject, content, visibility, session["user_id"]
        )
        log_audit(
            session.get("username", "unknown"),
            "kb_create",
            f"article:{article_id}",
            f"Created KB article: {title}",
        )
        flash("Knowledge base article created successfully.", "success")
        return redirect(url_for("kb.knowledge_base_view", article_id=article_id))

    return render_template(
        "kb/knowledge_base_form.html",
        mode="create",
        article={},
        subjects=_get_kb_subjects(),
    )


@kb_bp.route("/knowledge-base/<int:article_id>")
@require_login
def knowledge_base_view(article_id):
    """View a KB article."""
    article = _get_kb_article(article_id)
    if not article:
        flash("Article not found.", "error")
        return redirect(url_for("kb.knowledge_base"))

    # Check if user can view this article
    user_access_level = get_kb_access_level(session.get("user_id"))
    if not can_view_kb_article(user_access_level, article["visibility"]):
        flash("You don't have permission to view this article.", "error")
        return redirect(url_for("kb.knowledge_base"))

    can_edit = _can_user_create_kb(session.get("user_id"))

    return render_template(
        "kb/knowledge_base_article.html", article=article, can_edit=can_edit
    )


@kb_bp.route("/knowledge-base/<int:article_id>/edit", methods=["GET", "POST"])
@require_login
@require_kb_create
def knowledge_base_edit(article_id):
    """Edit a KB article."""
    article = _get_kb_article(article_id)
    if not article:
        flash("Article not found.", "error")
        return redirect(url_for("kb.knowledge_base"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        subject = request.form.get("subject", "").strip()
        content = request.form.get("content", "").strip()
        visibility = request.form.get("visibility", "FSR")

        if not title or not subject or not content:
            flash("Title, subject, and content are required.", "error")
            return render_template(
                "kb/knowledge_base_form.html",
                mode="edit",
                article={
                    "id": article_id,
                    "title": title,
                    "subject": subject,
                    "content": content,
                    "visibility": visibility,
                },
                subjects=_get_kb_subjects(),
            )

        _update_kb_article(article_id, title, subject, content, visibility)
        log_audit(
            session.get("username", "unknown"),
            "kb_update",
            f"article:{article_id}",
            f"Updated KB article: {title}",
        )
        flash("Knowledge base article updated successfully.", "success")
        return redirect(url_for("kb.knowledge_base_view", article_id=article_id))

    return render_template(
        "kb/knowledge_base_form.html",
        mode="edit",
        article=article,
        subjects=_get_kb_subjects(),
    )


@kb_bp.route("/knowledge-base/<int:article_id>/delete", methods=["POST"])
@require_login
@require_kb_create
def knowledge_base_delete(article_id):
    """Delete a KB article."""
    article = _get_kb_article(article_id)
    if not article:
        flash("Article not found.", "error")
        return redirect(url_for("kb.knowledge_base"))

    _delete_kb_article(article_id)
    log_audit(
        session.get("username", "unknown"),
        "kb_delete",
        f"article:{article_id}",
        f'Deleted KB article: {article["title"]}',
    )
    flash("Knowledge base article deleted.", "success")
    return redirect(url_for("kb.knowledge_base"))
