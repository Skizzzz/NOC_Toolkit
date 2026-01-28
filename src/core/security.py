"""
Security utilities for NOC Toolkit.

Provides password encryption, authentication, and access control decorators.
"""

import os
import sqlite3
from functools import wraps
from typing import Optional, Callable, Any

from flask import session, redirect, url_for, flash, request
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

from .database import get_db_path, get_connection

# Encryption key for stored passwords (device credentials)
# In production, this should be stored in environment variable
ENCRYPTION_KEY: Optional[bytes] = None
_cipher: Optional[Fernet] = None


def _init_encryption() -> None:
    """Initialize encryption key and cipher."""
    global ENCRYPTION_KEY, _cipher

    if ENCRYPTION_KEY is not None:
        return

    env_key = os.environ.get("NOC_ENCRYPTION_KEY")
    if env_key:
        ENCRYPTION_KEY = env_key.encode() if isinstance(env_key, str) else env_key
    else:
        # Generate or load from file
        from .database import get_project_root

        key_file = get_project_root() / ".encryption_key"
        if key_file.exists():
            with open(key_file, "rb") as f:
                ENCRYPTION_KEY = f.read()
        else:
            ENCRYPTION_KEY = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(ENCRYPTION_KEY)
            os.chmod(str(key_file), 0o600)  # Read/write for owner only

    _cipher = Fernet(ENCRYPTION_KEY)


def get_cipher() -> Fernet:
    """Get the Fernet cipher instance, initializing if needed."""
    if _cipher is None:
        _init_encryption()
    assert _cipher is not None
    return _cipher


def encrypt_password(plaintext: str) -> str:
    """Encrypt a password for storage."""
    if not plaintext:
        return ""
    cipher = get_cipher()
    return cipher.encrypt(plaintext.encode()).decode()


def decrypt_password(encrypted: str) -> str:
    """Decrypt a stored password."""
    if not encrypted:
        return ""
    try:
        cipher = get_cipher()
        return cipher.decrypt(encrypted.encode()).decode()
    except Exception:
        return ""  # Return empty if decryption fails


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2 SHA256."""
    return generate_password_hash(password, method="pbkdf2:sha256")


def verify_password_hash(stored_hash: str, password: str) -> bool:
    """Verify a password against a stored hash."""
    return check_password_hash(stored_hash, password)


def create_user(username: str, password: str, role: str = "user") -> bool:
    """Create a new user."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        password_hash = hash_password(password)
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists


def verify_user(username: str, password: str) -> Optional[dict]:
    """Verify username and password, return user dict if valid."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    conn.close()

    if row and verify_password_hash(row[2], password):
        return {"id": row[0], "username": row[1], "role": row[3]}
    return None


def update_last_login(user_id: int) -> None:
    """Update user's last login timestamp."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,)
    )
    conn.commit()
    conn.close()


def log_audit(
    username: str,
    action: str,
    resource: Optional[str] = None,
    details: Optional[str] = None,
    user_id: Optional[int] = None,
) -> None:
    """Log an audit event."""
    conn = get_connection()
    cursor = conn.cursor()
    ip_address = request.remote_addr if request else None
    cursor.execute(
        "INSERT INTO audit_log (user_id, username, action, resource, ip_address, details) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, username, action, resource, ip_address, details),
    )
    conn.commit()
    conn.close()


def require_login(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator to require user login."""

    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if "user_id" not in session:
            flash("Please log in to access this page", "error")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def require_superadmin(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator to require superadmin role."""

    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if "user_id" not in session:
            flash("Please log in to access this page", "error")
            return redirect(url_for("login", next=request.url))

        # Check if user is superadmin
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session["user_id"],))
        row = cursor.fetchone()
        conn.close()

        if not row or row[0] != "superadmin":
            flash("Superadmin access required", "error")
            return redirect(url_for("index"))

        return f(*args, **kwargs)

    return decorated_function


def get_current_user() -> Optional[dict]:
    """Get current logged in user."""
    if "user_id" not in session:
        return None

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, role FROM users WHERE id = ?", (session["user_id"],)
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return {"id": row[0], "username": row[1], "role": row[2]}
    return None


def change_password(user_id: int, new_password: str) -> bool:
    """Change user password."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        password_hash = hash_password(new_password)
        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id)
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def get_kb_access_level(user_id: int) -> str:
    """Get user's knowledge base access level."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT kb_access_level FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else "FSR"


def can_user_create_kb(user_id: int) -> bool:
    """Check if user has permission to create knowledge base articles."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT can_create_kb, role FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return False
    # Superadmins can always create KB articles
    return row[0] == 1 or row[1] == "superadmin"


def can_view_kb_article(user_access_level: str, article_visibility: str) -> bool:
    """Check if user with given access level can view an article with given visibility."""
    # Hierarchy: Admin > NOC > FSR
    levels = {"FSR": 1, "NOC": 2, "Admin": 3}
    user_level = levels.get(user_access_level, 1)
    article_level = levels.get(article_visibility, 1)
    return user_level >= article_level


def require_kb_create(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator to require knowledge base create permission."""

    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if "user_id" not in session:
            flash("Please log in to access this page", "error")
            return redirect(url_for("login", next=request.url))

        if not can_user_create_kb(session["user_id"]):
            flash("You don't have permission to create knowledge base articles", "error")
            return redirect(url_for("knowledge_base"))

        return f(*args, **kwargs)

    return decorated_function


def require_page_enabled(page_key: str) -> Callable[..., Any]:
    """Decorator to check if a page is enabled before allowing access."""

    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(f)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            # Import here to avoid circular imports
            from .helpers import is_page_enabled

            if not is_page_enabled(page_key):
                flash("This page has been disabled by an administrator.", "error")
                return redirect(url_for("index"))
            return f(*args, **kwargs)

        return decorated_function

    return decorator
