"""
Setup wizard blueprint routes.

Provides first-run setup wizard for creating initial admin user.
"""

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app,
)

from src.models import db, User


setup_bp = Blueprint(
    "setup",
    __name__,
    template_folder="templates",
    url_prefix="",
)


def is_first_run() -> bool:
    """
    Check if this is the first run (no users in database).

    Returns:
        True if no users exist in database, False otherwise.
    """
    try:
        user_count = db.session.query(User).count()
        return user_count == 0
    except Exception:
        # If database isn't initialized yet, treat as first run
        return True


@setup_bp.route("/setup", methods=["GET", "POST"])
def setup_wizard():
    """
    First-run setup wizard for creating admin user.

    Returns 404 if setup has already been completed.
    """
    # Return 404 if setup already complete
    if not is_first_run():
        return {"error": "Not Found", "status": 404}, 404

    errors = []

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validation
        if not username:
            errors.append("Username is required")
        elif len(username) < 3:
            errors.append("Username must be at least 3 characters")
        elif len(username) > 50:
            errors.append("Username must be 50 characters or less")

        if not password:
            errors.append("Password is required")
        elif len(password) < 12:
            errors.append("Password must be at least 12 characters")

        if password != confirm_password:
            errors.append("Passwords do not match")

        if not errors:
            try:
                # Create admin user
                admin_user = User(
                    username=username,
                    role="superadmin",
                    kb_access_level="Admin",
                    can_create_kb=True,
                )
                admin_user.set_password(password)

                db.session.add(admin_user)
                db.session.commit()

                current_app.logger.info(
                    f"Setup complete: Admin user '{username}' created"
                )

                flash("Setup complete! Please log in with your new admin account.", "success")
                return redirect(url_for("auth.login"))
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Setup failed: {e}")
                errors.append("An error occurred while creating the admin user. Please try again.")

    return render_template("setup/setup_wizard.html", errors=errors)
