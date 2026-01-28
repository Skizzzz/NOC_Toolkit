"""
Playwright fixtures and configuration for E2E tests.

This file provides browser automation fixtures using Playwright,
including authenticated sessions and page helpers.
"""

import os
import subprocess
import time
import socket
import tempfile
from contextlib import closing

import pytest
from playwright.sync_api import Page, BrowserContext

# Set up test database path BEFORE importing app
_test_db_dir = tempfile.mkdtemp(prefix="noc_toolkit_test_")
_test_db_path = os.path.join(_test_db_dir, "test_noc_toolkit.db")
os.environ["NOC_TOOLKIT_DB_PATH"] = _test_db_path
os.environ["NOC_TOOLKIT_DATA_DIR"] = _test_db_dir

# Import app fixtures from main conftest
from tests.conftest import app, db_session, admin_user, regular_user, page_settings


# E2E test marker - all tests in this directory are E2E tests
def pytest_collection_modifyitems(items):
    """Mark all tests in this directory as e2e tests."""
    for item in items:
        if "e2e" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)


def find_free_port() -> int:
    """Find a free port on localhost."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def app_port():
    """Get a free port for the test server."""
    return find_free_port()


@pytest.fixture(scope="session")
def base_url(app_port: int) -> str:
    """Base URL for E2E tests."""
    return f"http://localhost:{app_port}"


@pytest.fixture(scope="session")
def live_server(app, app_port: int):
    """
    Start a live Flask server for E2E tests.

    This fixture starts the Flask development server in a subprocess
    and ensures it's ready before yielding. The server is stopped
    when the test session ends.
    """
    import threading
    from werkzeug.serving import make_server

    # Create and configure the test database
    with app.app_context():
        from src.models import db
        db.create_all()

    # Start the server in a separate thread
    server = make_server("localhost", app_port, app)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    # Wait for server to be ready
    max_wait = 10  # seconds
    start_time = time.time()
    while time.time() - start_time < max_wait:
        try:
            with closing(socket.create_connection(("localhost", app_port), timeout=1)):
                break
        except (socket.error, ConnectionRefusedError):
            time.sleep(0.1)
    else:
        pytest.fail(f"Server did not start within {max_wait} seconds")

    yield server

    # Shutdown server
    server.shutdown()


@pytest.fixture(scope="function")
def seeded_db(app, live_server):
    """
    Seed the test database with initial data for E2E tests.

    Creates admin user and page settings needed for E2E testing.
    Seeds both SQLAlchemy models AND the SQLite database used by security.py.
    """
    import sqlite3
    from werkzeug.security import generate_password_hash

    # Get the SQLite database path that security.py uses
    db_path = os.environ.get("NOC_TOOLKIT_DB_PATH", _test_db_path)

    # Initialize security tables and seed users directly in SQLite
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT,
            kb_access_level TEXT NOT NULL DEFAULT 'FSR',
            can_create_kb INTEGER NOT NULL DEFAULT 0
        )
    """)

    # Create audit_log table
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

    # Create page_settings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS page_settings (
            page_key TEXT PRIMARY KEY,
            page_name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            category TEXT,
            updated_at TEXT
        )
    """)

    # Clear existing data
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM page_settings")

    # Create admin user
    admin_hash = generate_password_hash("TestPassword123!", method="pbkdf2:sha256")
    cursor.execute(
        "INSERT INTO users (username, password_hash, role, kb_access_level, can_create_kb) VALUES (?, ?, ?, ?, ?)",
        ("admin", admin_hash, "superadmin", "Admin", 1),
    )

    # Create regular user
    user_hash = generate_password_hash("TestPassword123!", method="pbkdf2:sha256")
    cursor.execute(
        "INSERT INTO users (username, password_hash, role, kb_access_level, can_create_kb) VALUES (?, ?, ?, ?, ?)",
        ("testuser", user_hash, "user", "FSR", 0),
    )

    # Create page settings (all enabled)
    pages = [
        ("wlc-dashboard", "WLC Dashboard", "WLC Tools"),
        ("ap-inventory", "AP Inventory", "WLC Tools"),
        ("solarwinds-nodes", "SolarWinds Nodes", "SolarWinds"),
        ("solarwinds-inventory", "SolarWinds Inventory", "SolarWinds"),
        ("bulk-ssh", "Bulk SSH", "SSH Tools"),
        ("phrase-search", "Phrase Search", "Config"),
        ("global-config", "Global Config", "Config"),
        ("cert-tracker", "Certificate Tracker", "Certificates"),
        ("ise-nodes", "ISE Nodes", "Certificates"),
        ("knowledge-base", "Knowledge Base", "Documentation"),
        ("changes", "Change Windows", "Config"),
    ]
    for key, name, category in pages:
        cursor.execute(
            "INSERT OR REPLACE INTO page_settings (page_key, page_name, enabled, category) VALUES (?, ?, ?, ?)",
            (key, name, 1, category),
        )

    conn.commit()
    conn.close()

    # Also seed SQLAlchemy models for any routes that use them
    with app.app_context():
        from src.models import db, User, PageSettings

        # Clear SQLAlchemy tables
        User.query.delete()
        PageSettings.query.delete()

        # Create admin user in SQLAlchemy
        admin = User(
            username="admin",
            role="superadmin",
            kb_access_level="Admin",
            can_create_kb=True,
        )
        admin.set_password("TestPassword123!")
        db.session.add(admin)

        # Create regular user in SQLAlchemy
        regular = User(
            username="testuser",
            role="user",
            kb_access_level="FSR",
            can_create_kb=False,
        )
        regular.set_password("TestPassword123!")
        db.session.add(regular)

        # Create page settings in SQLAlchemy
        for key, name, category in pages:
            page = PageSettings(
                page_key=key,
                page_name=name,
                enabled=True,
                category=category,
            )
            db.session.add(page)

        db.session.commit()

    yield

    # Cleanup after test
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM page_settings")
    conn.commit()
    conn.close()

    with app.app_context():
        from src.models import db, User, PageSettings
        User.query.delete()
        PageSettings.query.delete()
        db.session.commit()


@pytest.fixture
def page(
    browser: "BrowserContext",
    base_url: str,
    live_server,
    seeded_db,
) -> Page:
    """
    Create a new browser page for E2E tests.

    This fixture provides a fresh browser page pointing to the live
    test server with a seeded database.
    """
    page = browser.new_page()
    page.set_default_timeout(10000)  # 10 seconds
    yield page
    page.close()


@pytest.fixture
def authenticated_page(
    page: Page,
    base_url: str,
) -> Page:
    """
    Create an authenticated browser page.

    This fixture logs in as the admin user before returning the page.
    """
    # Navigate to login page
    page.goto(f"{base_url}/login")

    # Fill in login form
    page.fill('input[name="username"]', "admin")
    page.fill('input[name="password"]', "TestPassword123!")
    page.click('button[type="submit"]')

    # Wait for navigation to complete
    page.wait_for_load_state("networkidle")

    return page


@pytest.fixture
def user_authenticated_page(
    page: Page,
    base_url: str,
) -> Page:
    """
    Create an authenticated browser page for a regular user.

    This fixture logs in as a regular (non-admin) user before returning the page.
    """
    # Navigate to login page
    page.goto(f"{base_url}/login")

    # Fill in login form
    page.fill('input[name="username"]', "testuser")
    page.fill('input[name="password"]', "TestPassword123!")
    page.click('button[type="submit"]')

    # Wait for navigation to complete
    page.wait_for_load_state("networkidle")

    return page
