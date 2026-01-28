"""
Admin blueprint routes.

Provides user management, page settings, and application settings endpoints.
These routes are restricted to superadmin users only.
"""

import sqlite3

from flask import (
    Blueprint,
    render_template,
    request,
    session,
    redirect,
    url_for,
    flash,
)

from src.core.database import get_db_path
from src.core.security import (
    require_superadmin,
    log_audit,
    create_user,
)
from src.core.helpers import (
    get_all_page_settings,
    bulk_update_page_settings,
    load_app_settings,
    save_app_settings,
    US_TIMEZONES,
)

admin_bp = Blueprint(
    "admin",
    __name__,
    template_folder="templates",
    url_prefix="/admin",
)


@admin_bp.route("/users", methods=["GET", "POST"])
@require_superadmin
def admin_users():
    """User management (superadmin only)."""
    if request.method == "POST":
        action = request.form.get("action")

        if action == "create":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "user")
            kb_access_level = request.form.get("kb_access_level", "FSR")
            can_create_kb = 1 if request.form.get("can_create_kb") else 0

            if len(password) < 8:
                flash("Password must be at least 8 characters", "error")
            elif create_user(username, password, role):
                # Update KB permissions for the new user
                conn = sqlite3.connect(get_db_path())
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET kb_access_level = ?, can_create_kb = ? WHERE username = ?",
                    (kb_access_level, can_create_kb, username),
                )
                conn.commit()
                conn.close()
                log_audit(
                    session["username"],
                    "user_create",
                    resource=username,
                    user_id=session["user_id"],
                )
                flash(f"User '{username}' created successfully", "success")
            else:
                flash(f"Username '{username}' already exists", "error")

        elif action == "update_kb":
            user_id = request.form.get("user_id")
            kb_access_level = request.form.get("kb_access_level", "FSR")
            can_create_kb = 1 if request.form.get("can_create_kb") else 0

            conn = sqlite3.connect(get_db_path())
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET kb_access_level = ?, can_create_kb = ? WHERE id = ?",
                (kb_access_level, can_create_kb, user_id),
            )
            conn.commit()
            conn.close()
            flash("User KB permissions updated", "success")

    # Fetch all users including KB permissions
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, role, created_at, last_login, kb_access_level, can_create_kb "
        "FROM users ORDER BY id"
    )
    users = [
        {
            "id": r[0],
            "username": r[1],
            "role": r[2],
            "created_at": r[3],
            "last_login": r[4],
            "kb_access_level": r[5] or "FSR",
            "can_create_kb": r[6] or 0,
        }
        for r in cursor.fetchall()
    ]
    conn.close()

    return render_template("admin/admin_users.html", users=users)


@admin_bp.route("/page-settings", methods=["GET", "POST"])
@require_superadmin
def admin_page_settings():
    """Page visibility settings (superadmin only)."""
    if request.method == "POST":
        # Get all page keys from form and update settings
        all_pages = get_all_page_settings()
        updates = {}
        for page in all_pages:
            key = page["page_key"]
            # If checkbox is checked, it will be in form data
            enabled = request.form.get(f"page_{key}") == "on"
            updates[key] = enabled

        if bulk_update_page_settings(updates):
            log_audit(
                session["username"],
                "page_settings_update",
                user_id=session["user_id"],
            )
            flash("Page visibility settings updated.", "success")
        else:
            flash("Failed to update page settings.", "error")

        return redirect(url_for("admin.admin_page_settings"))

    # Group pages by category
    pages = get_all_page_settings()
    pages_by_category = {}
    for page in pages:
        cat = page.get("category") or "Other"
        if cat not in pages_by_category:
            pages_by_category[cat] = []
        pages_by_category[cat].append(page)

    return render_template(
        "admin/admin_page_settings.html", pages_by_category=pages_by_category
    )


@admin_bp.route("/settings", methods=["GET", "POST"])
@require_superadmin
def admin_settings():
    """Application-wide settings (superadmin only)."""
    if request.method == "POST":
        new_timezone = request.form.get("timezone", "America/Chicago")

        # Validate timezone is in our allowed list
        valid_timezones = [tz[0] for tz in US_TIMEZONES]
        if new_timezone not in valid_timezones:
            flash("Invalid timezone selected.", "error")
            return redirect(url_for("admin.admin_settings"))

        if save_app_settings(timezone=new_timezone):
            log_audit(
                session["username"],
                "app_settings_update",
                resource=f"timezone={new_timezone}",
                user_id=session["user_id"],
            )
            flash("Application settings updated successfully.", "success")
        else:
            flash("Failed to update application settings.", "error")

        return redirect(url_for("admin.admin_settings"))

    settings = load_app_settings()
    return render_template(
        "admin/admin_settings.html", settings=settings, timezones=US_TIMEZONES
    )
