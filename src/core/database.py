"""
Database connection utilities for NOC Toolkit.

Provides database connection management, path resolution, and lock handling.
These utilities are used by blueprints and services for database operations.
"""

import os
import sqlite3
import threading
from pathlib import Path
from typing import Optional


# Determine data root directory
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DATA_ROOT = Path(
    os.environ.get("NOC_TOOLKIT_DATA_DIR", Path.home() / ".noc_toolkit")
).expanduser()
_DATA_ROOT.mkdir(parents=True, exist_ok=True)

# Determine database path
_env_db = os.environ.get("NOC_TOOLKIT_DB_PATH")
if _env_db:
    DB_PATH = str(Path(_env_db).expanduser())
else:
    new_path = _DATA_ROOT / "noc_toolkit.db"
    legacy_path = _PROJECT_ROOT / "noc_toolkit.db"
    if new_path.exists():
        DB_PATH = str(new_path)
    else:
        if legacy_path.exists():
            try:
                import shutil

                shutil.copy2(legacy_path, new_path)
                key_src = _PROJECT_ROOT / "wlc_dashboard.key"
                key_dst = _DATA_ROOT / "wlc_dashboard.key"
                if key_src.exists() and not key_dst.exists():
                    shutil.copy2(key_src, key_dst)
            except Exception:
                pass
        DB_PATH = str(new_path)

Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

# Thread-safe lock for database operations
_DB_LOCK = threading.Lock()


def get_db_path() -> str:
    """Return the current database path."""
    return DB_PATH


def get_project_root() -> Path:
    """Return the project root directory."""
    return _PROJECT_ROOT


def get_data_root() -> Path:
    """Return the data root directory."""
    return _DATA_ROOT


def get_db_lock() -> threading.Lock:
    """Return the database lock for thread-safe operations."""
    return _DB_LOCK


def get_connection(check_same_thread: bool = False) -> sqlite3.Connection:
    """
    Get a new database connection with row factory set.

    Args:
        check_same_thread: If False (default), allow connections across threads.

    Returns:
        A new sqlite3 Connection object with Row factory.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=check_same_thread)
    conn.row_factory = sqlite3.Row
    return conn


def execute_with_lock(
    query: str, params: tuple = (), commit: bool = True
) -> Optional[sqlite3.Cursor]:
    """
    Execute a query with thread-safe locking.

    Args:
        query: SQL query to execute.
        params: Parameters for the query.
        commit: Whether to commit after execution.

    Returns:
        The cursor after execution, or None on error.
    """
    try:
        with _DB_LOCK, get_connection() as conn:
            cursor = conn.execute(query, params)
            if commit:
                conn.commit()
            return cursor
    except Exception:
        return None


def execute_many_with_lock(
    query: str, params_list: list, commit: bool = True
) -> bool:
    """
    Execute a query with multiple parameter sets, thread-safe.

    Args:
        query: SQL query to execute.
        params_list: List of parameter tuples.
        commit: Whether to commit after execution.

    Returns:
        True on success, False on error.
    """
    try:
        with _DB_LOCK, get_connection() as conn:
            conn.executemany(query, params_list)
            if commit:
                conn.commit()
            return True
    except Exception:
        return False


def fetch_one(query: str, params: tuple = ()) -> Optional[sqlite3.Row]:
    """
    Execute a query and return a single row.

    Args:
        query: SQL query to execute.
        params: Parameters for the query.

    Returns:
        A single Row object, or None if not found or on error.
    """
    try:
        with _DB_LOCK, get_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.fetchone()
    except Exception:
        return None


def fetch_all(query: str, params: tuple = ()) -> list:
    """
    Execute a query and return all rows.

    Args:
        query: SQL query to execute.
        params: Parameters for the query.

    Returns:
        A list of Row objects, or empty list on error.
    """
    try:
        with _DB_LOCK, get_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.fetchall()
    except Exception:
        return []
