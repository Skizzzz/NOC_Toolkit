"""
Security utilities for NOC Toolkit
Provides password encryption, authentication, and access control
"""

import os
import sqlite3
from functools import wraps
from typing import Optional
from flask import session, redirect, url_for, flash, request
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

# Database path
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "noc_toolkit.db")

# Encryption key for stored passwords (device credentials)
# In production, this should be stored in environment variable
ENCRYPTION_KEY = os.environ.get("NOC_ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    # Generate or load from file
    key_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".encryption_key")
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            ENCRYPTION_KEY = f.read()
    else:
        ENCRYPTION_KEY = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(ENCRYPTION_KEY)
        os.chmod(key_file, 0o600)  # Read/write for owner only

cipher = Fernet(ENCRYPTION_KEY)


def encrypt_password(plaintext: str) -> str:
    """Encrypt a password for storage"""
    if not plaintext:
        return ""
    return cipher.encrypt(plaintext.encode()).decode()


def decrypt_password(encrypted: str) -> str:
    """Decrypt a stored password"""
    if not encrypted:
        return ""
    try:
        return cipher.decrypt(encrypted.encode()).decode()
    except Exception:
        return ""  # Return empty if decryption fails


def init_security_db():
    """Initialize authentication tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # User authentication table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        )
    """)

    # Session management table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Audit log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT,
            ip_address TEXT,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )
    """)

    # Create indexes for audit_log for better query performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_username ON audit_log(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)")

    conn.commit()

    # Create default superadmin if no users exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_password = os.environ.get("NOC_ADMIN_PASSWORD", "admin123")
        password_hash = generate_password_hash(default_password, method='pbkdf2:sha256')
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", password_hash, "superadmin")
        )
        conn.commit()
        print(f"[SECURITY] Default superadmin created - username: admin, password: {default_password}")
        print("[SECURITY] CHANGE THIS PASSWORD IMMEDIATELY!")

    conn.close()


def create_user(username: str, password: str, role: str = "user") -> bool:
    """Create a new user"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists


def verify_user(username: str, password: str) -> Optional[dict]:
    """Verify username and password, return user dict if valid"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()

    if row and check_password_hash(row[2], password):
        return {"id": row[0], "username": row[1], "role": row[3]}
    return None


def update_last_login(user_id: int):
    """Update user's last login timestamp"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
        (user_id,)
    )
    conn.commit()
    conn.close()


def log_audit(username: str, action: str, resource: str = None, details: str = None, user_id: int = None):
    """Log an audit event"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    ip_address = request.remote_addr if request else None
    cursor.execute(
        "INSERT INTO audit_log (user_id, username, action, resource, ip_address, details) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, username, action, resource, ip_address, details)
    )
    conn.commit()
    conn.close()


def require_login(f):
    """Decorator to require user login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page", "error")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def require_superadmin(f):
    """Decorator to require superadmin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page", "error")
            return redirect(url_for("login", next=request.url))

        # Check if user is superadmin
        conn = sqlite3.connect(DB_PATH)
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
    """Get current logged in user"""
    if "user_id" not in session:
        return None

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, role FROM users WHERE id = ?",
        (session["user_id"],)
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return {"id": row[0], "username": row[1], "role": row[2]}
    return None


def change_password(user_id: int, new_password: str) -> bool:
    """Change user password"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, user_id)
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def migrate_existing_passwords():
    """Migrate plaintext passwords in wlc_dashboard_settings to encrypted"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Check if encryption has already been applied
        cursor.execute("SELECT id, password, secret FROM wlc_dashboard_settings LIMIT 1")
        row = cursor.fetchone()

        if row and row[1]:
            # Try to decrypt - if it fails, it's plaintext
            try:
                decrypt_password(row[1])
                print("[SECURITY] Passwords already encrypted")
                conn.close()
                return
            except Exception:
                # Plaintext detected, migrate
                print("[SECURITY] Migrating plaintext passwords to encrypted...")
                cursor.execute("SELECT id, password, secret FROM wlc_dashboard_settings")
                for row_id, password, secret in cursor.fetchall():
                    encrypted_pass = encrypt_password(password) if password else ""
                    encrypted_secret = encrypt_password(secret) if secret else ""
                    cursor.execute(
                        "UPDATE wlc_dashboard_settings SET password = ?, secret = ? WHERE id = ?",
                        (encrypted_pass, encrypted_secret, row_id)
                    )
                conn.commit()
                print("[SECURITY] Password migration complete")
    except Exception as e:
        print(f"[SECURITY] Migration error: {e}")

    conn.close()
