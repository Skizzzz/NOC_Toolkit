"""
Core utilities package for NOC Toolkit.

This package contains shared utilities used by blueprints and services:
- database: Database connection management
- security: Authentication and access control
- helpers: Common utility functions
"""

from .database import (
    DB_PATH,
    get_db_path,
    get_project_root,
    get_data_root,
    get_db_lock,
    get_connection,
    execute_with_lock,
    execute_many_with_lock,
    fetch_one,
    fetch_all,
)

from .security import (
    encrypt_password,
    decrypt_password,
    hash_password,
    verify_password_hash,
    create_user,
    verify_user,
    update_last_login,
    log_audit,
    require_login,
    require_superadmin,
    get_current_user,
    change_password,
    get_kb_access_level,
    can_user_create_kb,
    can_view_kb_article,
    require_kb_create,
    require_page_enabled,
)

from .helpers import (
    DEFAULT_APP_TIMEZONE,
    US_TIMEZONES,
    now_iso,
    get_app_timezone,
    get_app_timezone_info,
    set_app_timezone,
    is_page_enabled,
    get_enabled_pages,
    get_all_page_settings,
    set_page_enabled,
    bulk_update_page_settings,
    load_app_settings,
    save_app_settings,
    format_datetime,
    parse_datetime,
    truncate_string,
)

__all__ = [
    # database
    "DB_PATH",
    "get_db_path",
    "get_project_root",
    "get_data_root",
    "get_db_lock",
    "get_connection",
    "execute_with_lock",
    "execute_many_with_lock",
    "fetch_one",
    "fetch_all",
    # security
    "encrypt_password",
    "decrypt_password",
    "hash_password",
    "verify_password_hash",
    "create_user",
    "verify_user",
    "update_last_login",
    "log_audit",
    "require_login",
    "require_superadmin",
    "get_current_user",
    "change_password",
    "get_kb_access_level",
    "can_user_create_kb",
    "can_view_kb_article",
    "require_kb_create",
    "require_page_enabled",
    # helpers
    "DEFAULT_APP_TIMEZONE",
    "US_TIMEZONES",
    "now_iso",
    "get_app_timezone",
    "get_app_timezone_info",
    "set_app_timezone",
    "is_page_enabled",
    "get_enabled_pages",
    "get_all_page_settings",
    "set_page_enabled",
    "bulk_update_page_settings",
    "load_app_settings",
    "save_app_settings",
    "format_datetime",
    "parse_datetime",
    "truncate_string",
]
