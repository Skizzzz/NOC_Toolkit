"""
Shared helper functions for NOC Toolkit.

Provides common utility functions used across blueprints and modules.
"""

from datetime import datetime
from typing import List, Dict, Optional
from zoneinfo import ZoneInfo

from .database import get_db_lock, get_connection


# Default timezone for the application
DEFAULT_APP_TIMEZONE = "America/Chicago"

# Common US timezones for the dropdown
US_TIMEZONES = [
    ("America/New_York", "Eastern (ET)"),
    ("America/Chicago", "Central (CT)"),
    ("America/Denver", "Mountain (MT)"),
    ("America/Phoenix", "Arizona (MST - no DST)"),
    ("America/Los_Angeles", "Pacific (PT)"),
    ("America/Anchorage", "Alaska (AKT)"),
    ("Pacific/Honolulu", "Hawaii (HST)"),
]


def now_iso(timespec: str = "seconds") -> str:
    """Return current datetime as ISO format string."""
    return datetime.now().isoformat(timespec=timespec)


def get_app_timezone() -> str:
    """Get the configured application timezone. Returns IANA timezone string."""
    try:
        with get_db_lock(), get_connection() as conn:
            row = conn.execute(
                "SELECT timezone FROM app_settings WHERE id=1"
            ).fetchone()
            if row and row[0]:
                return row[0]
    except Exception:
        pass
    return DEFAULT_APP_TIMEZONE


def get_app_timezone_info() -> ZoneInfo:
    """Get the configured application timezone as a ZoneInfo object."""
    return ZoneInfo(get_app_timezone())


def set_app_timezone(timezone: str) -> bool:
    """Set the application timezone."""
    try:
        # Validate timezone
        ZoneInfo(timezone)
        with get_db_lock(), get_connection() as conn:
            conn.execute(
                """INSERT INTO app_settings (id, timezone, updated_at) VALUES (1, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET timezone = ?, updated_at = ?""",
                (timezone, now_iso(), timezone, now_iso()),
            )
        return True
    except Exception:
        return False


def is_page_enabled(page_key: str) -> bool:
    """Check if a specific page is enabled."""
    try:
        with get_db_lock(), get_connection() as conn:
            row = conn.execute(
                "SELECT enabled FROM page_settings WHERE page_key = ?", (page_key,)
            ).fetchone()
            # If page not in settings, default to enabled
            return row[0] == 1 if row else True
    except Exception:
        return True  # Default to enabled on error


def get_enabled_pages() -> List[str]:
    """Get list of enabled page keys for navigation filtering."""
    try:
        with get_db_lock(), get_connection() as conn:
            rows = conn.execute(
                "SELECT page_key FROM page_settings WHERE enabled = 1"
            ).fetchall()
            return [row[0] for row in rows]
    except Exception:
        return []


def get_all_page_settings() -> List[Dict]:
    """Get all page settings for admin display."""
    try:
        with get_db_lock(), get_connection() as conn:
            rows = conn.execute(
                "SELECT page_key, page_name, enabled, category "
                "FROM page_settings ORDER BY category, page_name"
            ).fetchall()
            return [dict(row) for row in rows]
    except Exception:
        return []


def set_page_enabled(page_key: str, enabled: bool) -> bool:
    """Enable or disable a page."""
    try:
        with get_db_lock(), get_connection() as conn:
            conn.execute(
                "UPDATE page_settings SET enabled = ?, updated_at = ? WHERE page_key = ?",
                (1 if enabled else 0, now_iso(), page_key),
            )
            return True
    except Exception:
        return False


def bulk_update_page_settings(settings: Dict[str, bool]) -> bool:
    """Update multiple page settings at once. settings is {page_key: enabled}."""
    try:
        now = now_iso()
        with get_db_lock(), get_connection() as conn:
            for page_key, enabled in settings.items():
                conn.execute(
                    "UPDATE page_settings SET enabled = ?, updated_at = ? WHERE page_key = ?",
                    (1 if enabled else 0, now, page_key),
                )
            return True
    except Exception:
        return False


def load_app_settings() -> Dict:
    """Load all app settings from the database."""
    settings = {"timezone": DEFAULT_APP_TIMEZONE}
    try:
        with get_db_lock(), get_connection() as conn:
            row = conn.execute(
                "SELECT timezone FROM app_settings WHERE id=1"
            ).fetchone()
            if row:
                settings["timezone"] = row[0] or DEFAULT_APP_TIMEZONE
    except Exception:
        pass
    return settings


def format_datetime(
    dt: Optional[datetime], fmt: str = "%Y-%m-%d %H:%M:%S"
) -> str:
    """Format a datetime object to string, or return empty string if None."""
    if dt is None:
        return ""
    return dt.strftime(fmt)


def parse_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    """Parse an ISO format datetime string, or return None if invalid."""
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str)
    except (ValueError, TypeError):
        return None


def truncate_string(s: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate a string to max_length, adding suffix if truncated."""
    if len(s) <= max_length:
        return s
    return s[: max_length - len(suffix)] + suffix
