"""
Authentication blueprint routes.

Provides login, logout, and profile management endpoints.
"""

from flask import (
    Blueprint,
    render_template,
    request,
    session,
    redirect,
    url_for,
    flash,
)

from src.core.security import (
    verify_user,
    update_last_login,
    log_audit,
    require_login,
    get_current_user,
    change_password,
)

auth_bp = Blueprint(
    "auth",
    __name__,
    template_folder="templates",
    url_prefix="",
)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """User login page."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = verify_user(username, password)
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            update_last_login(user["id"])
            log_audit(username, "login", user_id=user["id"])

            flash(f"Welcome back, {username}!", "success")
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("index"))
        else:
            log_audit(username or "unknown", "login_failed")
            flash("Invalid username or password", "error")

    return render_template("auth/login.html")


@auth_bp.route("/logout")
def logout():
    """User logout."""
    username = session.get("username", "unknown")
    log_audit(username, "logout", user_id=session.get("user_id"))
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/profile", methods=["GET", "POST"])
@require_login
def profile():
    """User profile and password change."""
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Verify current password
        user = verify_user(session["username"], current_password)
        if not user:
            flash("Current password is incorrect", "error")
        elif new_password != confirm_password:
            flash("New passwords do not match", "error")
        elif len(new_password) < 8:
            flash("Password must be at least 8 characters", "error")
        else:
            if change_password(session["user_id"], new_password):
                log_audit(
                    session["username"], "password_change", user_id=session["user_id"]
                )
                flash("Password changed successfully", "success")
            else:
                flash("Failed to change password", "error")

    return render_template("auth/profile.html", user=get_current_user())
