"""
E2E tests for the first-run setup wizard.

These tests verify the setup wizard behavior:
- Fresh database redirects to setup
- Setup wizard validates password requirements
- Setup wizard creates admin user and redirects to login

US-034: Create Setup Wizard E2E Tests
"""

import os
import sqlite3
import tempfile
import time
import socket
import threading
from contextlib import closing

import pytest
from playwright.sync_api import Page, expect, BrowserContext


def find_free_port() -> int:
    """Find a free port on localhost."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


@pytest.fixture(scope="function")
def fresh_db_app():
    """
    Create a Flask app with a fresh (empty) database for setup wizard testing.

    This fixture creates a completely isolated database without any users,
    simulating the first-run state.
    """
    # Create a unique temporary directory for this test's database
    test_db_dir = tempfile.mkdtemp(prefix="noc_setup_test_")
    test_db_path = os.path.join(test_db_dir, "fresh_test_noc_toolkit.db")

    # Set environment variables for this isolated database
    os.environ["NOC_TOOLKIT_DB_PATH"] = test_db_path
    os.environ["NOC_TOOLKIT_DATA_DIR"] = test_db_dir
    os.environ["FLASK_SECRET_KEY"] = "test-secret-key-for-setup-wizard-tests"

    # Import app after setting environment variables
    from src.app import create_app

    app = create_app("testing")

    # Initialize the database schema without any users
    with app.app_context():
        from src.models import db
        db.create_all()

        # Initialize SQLite tables for security.py
        conn = sqlite3.connect(test_db_path)
        cursor = conn.cursor()

        # Create users table (but leave it empty for first-run detection)
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

        conn.commit()
        conn.close()

    yield app

    # Cleanup
    import shutil
    try:
        shutil.rmtree(test_db_dir)
    except Exception:
        pass


@pytest.fixture(scope="function")
def fresh_app_port():
    """Get a free port for the fresh database test server."""
    return find_free_port()


@pytest.fixture(scope="function")
def fresh_base_url(fresh_app_port: int) -> str:
    """Base URL for fresh database E2E tests."""
    return f"http://localhost:{fresh_app_port}"


@pytest.fixture(scope="function")
def fresh_live_server(fresh_db_app, fresh_app_port: int):
    """
    Start a live Flask server with a fresh database for setup wizard tests.
    """
    from werkzeug.serving import make_server

    # Start the server in a separate thread
    server = make_server("localhost", fresh_app_port, fresh_db_app)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    # Wait for server to be ready
    max_wait = 10  # seconds
    start_time = time.time()
    while time.time() - start_time < max_wait:
        try:
            with closing(socket.create_connection(("localhost", fresh_app_port), timeout=1)):
                break
        except (socket.error, ConnectionRefusedError):
            time.sleep(0.1)
    else:
        pytest.fail(f"Fresh database server did not start within {max_wait} seconds")

    yield server

    # Shutdown server
    server.shutdown()


@pytest.fixture(scope="function")
def fresh_page(
    browser: BrowserContext,
    fresh_base_url: str,
    fresh_live_server,
) -> Page:
    """
    Create a new browser page for fresh database E2E tests.

    This fixture provides a browser page pointing to a live server
    with an empty database (no users).
    """
    page = browser.new_page()
    page.set_default_timeout(10000)  # 10 seconds
    yield page
    page.close()


class TestFreshDatabaseRedirectsToSetup:
    """Tests for redirecting to setup on first run."""

    def test_root_redirects_to_setup_on_fresh_database(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Root URL should redirect to /setup when no users exist."""
        fresh_page.goto(fresh_base_url + "/")
        fresh_page.wait_for_load_state("networkidle")

        # Should redirect to setup page
        assert "/setup" in fresh_page.url

    def test_login_redirects_to_setup_on_fresh_database(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Login page should redirect to /setup when no users exist."""
        fresh_page.goto(fresh_base_url + "/login")
        fresh_page.wait_for_load_state("networkidle")

        # Should redirect to setup page
        assert "/setup" in fresh_page.url

    def test_protected_page_redirects_to_setup_on_fresh_database(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Protected pages should redirect to /setup when no users exist."""
        fresh_page.goto(fresh_base_url + "/jobs")
        fresh_page.wait_for_load_state("networkidle")

        # Should redirect to setup page
        assert "/setup" in fresh_page.url

    def test_setup_page_loads_on_fresh_database(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup page should load successfully when no users exist."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        # Should stay on setup page
        assert "/setup" in fresh_page.url

        # Should display the setup wizard
        expect(fresh_page.locator("h1")).to_contain_text("Welcome to NOC Toolkit")

    def test_setup_page_displays_notice(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup page should display the one-time setup notice."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        # Should display setup notice
        notice = fresh_page.locator(".setup-notice")
        expect(notice).to_be_visible()
        expect(notice).to_contain_text("one-time setup")


class TestSetupWizardPasswordValidation:
    """Tests for setup wizard password validation."""

    def test_setup_validates_empty_username(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup should show error for empty username."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        # Remove required attribute to allow form submission
        fresh_page.evaluate('document.getElementById("username").removeAttribute("required")')

        # Fill in only passwords
        fresh_page.fill('input[name="password"]', "TestPassword123!")
        fresh_page.fill('input[name="confirm_password"]', "TestPassword123!")

        # Submit form
        fresh_page.click('button[type="submit"]')
        fresh_page.wait_for_load_state("networkidle")

        # Should show error
        error_list = fresh_page.locator(".error-list")
        expect(error_list).to_be_visible()
        expect(error_list).to_contain_text("Username is required")

    def test_setup_validates_short_username(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup should show error for username less than 3 characters."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        # Fill in short username
        fresh_page.fill('input[name="username"]', "ab")
        fresh_page.fill('input[name="password"]', "TestPassword123!")
        fresh_page.fill('input[name="confirm_password"]', "TestPassword123!")

        # Submit form
        fresh_page.click('button[type="submit"]')
        fresh_page.wait_for_load_state("networkidle")

        # Should show error
        error_list = fresh_page.locator(".error-list")
        expect(error_list).to_be_visible()
        expect(error_list).to_contain_text("Username must be at least 3 characters")

    def test_setup_validates_empty_password(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup should show error for empty password."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        # Remove required attribute to allow form submission
        fresh_page.evaluate('document.getElementById("password").removeAttribute("required")')
        fresh_page.evaluate('document.getElementById("confirm_password").removeAttribute("required")')

        # Fill in only username
        fresh_page.fill('input[name="username"]', "admin")

        # Submit form
        fresh_page.click('button[type="submit"]')
        fresh_page.wait_for_load_state("networkidle")

        # Should show error
        error_list = fresh_page.locator(".error-list")
        expect(error_list).to_be_visible()
        expect(error_list).to_contain_text("Password is required")

    def test_setup_validates_short_password(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup should show error for password less than 12 characters."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        # Fill in short password
        fresh_page.fill('input[name="username"]', "admin")
        fresh_page.fill('input[name="password"]', "short123")
        fresh_page.fill('input[name="confirm_password"]', "short123")

        # Submit form
        fresh_page.click('button[type="submit"]')
        fresh_page.wait_for_load_state("networkidle")

        # Should show error
        error_list = fresh_page.locator(".error-list")
        expect(error_list).to_be_visible()
        expect(error_list).to_contain_text("Password must be at least 12 characters")

    def test_setup_validates_password_mismatch(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup should show error when passwords do not match."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        # Fill in mismatched passwords
        fresh_page.fill('input[name="username"]', "admin")
        fresh_page.fill('input[name="password"]', "TestPassword123!")
        fresh_page.fill('input[name="confirm_password"]', "DifferentPassword456!")

        # Submit form
        fresh_page.click('button[type="submit"]')
        fresh_page.wait_for_load_state("networkidle")

        # Should show error
        error_list = fresh_page.locator(".error-list")
        expect(error_list).to_be_visible()
        expect(error_list).to_contain_text("Passwords do not match")

    def test_setup_password_strength_indicator_weak(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup should show weak password strength for short passwords."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        # Type a short password
        fresh_page.fill('input[name="password"]', "short")

        # Check password strength bar
        strength_bar = fresh_page.locator("#strengthBar")
        expect(strength_bar).to_have_class("password-strength-bar weak")

    def test_setup_password_strength_indicator_medium(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup should show medium password strength for adequate passwords."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        # Type a medium strength password (>= 12 chars, 2+ varieties)
        fresh_page.fill('input[name="password"]', "TestPassword12")

        # Check password strength bar
        strength_bar = fresh_page.locator("#strengthBar")
        expect(strength_bar).to_have_class("password-strength-bar medium")

    def test_setup_password_strength_indicator_strong(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup should show strong password strength for complex passwords."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        # Type a strong password (>= 16 chars, 3+ varieties)
        fresh_page.fill('input[name="password"]', "TestPassword123!Extra")

        # Check password strength bar
        strength_bar = fresh_page.locator("#strengthBar")
        expect(strength_bar).to_have_class("password-strength-bar strong")


class TestSetupWizardCreatesAdmin:
    """Tests for setup wizard creating admin user."""

    def test_setup_creates_admin_and_redirects_to_login(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup should create admin user and redirect to login on success."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        # Fill in valid credentials
        fresh_page.fill('input[name="username"]', "myadmin")
        fresh_page.fill('input[name="password"]', "SecurePassword123!")
        fresh_page.fill('input[name="confirm_password"]', "SecurePassword123!")

        # Submit form
        fresh_page.click('button[type="submit"]')
        fresh_page.wait_for_load_state("networkidle")

        # Should redirect to login page
        assert "/login" in fresh_page.url

        # Should show success flash message (login template uses flash-message class)
        flash = fresh_page.locator(".flash-message")
        expect(flash).to_be_visible()
        expect(flash).to_contain_text("Setup complete")

    def test_setup_creates_superadmin_user_in_database(
        self,
        fresh_page: Page,
        fresh_base_url: str,
        fresh_db_app,
    ):
        """Admin user created during setup should have superadmin role."""
        # Complete setup
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        fresh_page.fill('input[name="username"]', "setupadmin")
        fresh_page.fill('input[name="password"]', "SecurePassword123!")
        fresh_page.fill('input[name="confirm_password"]', "SecurePassword123!")
        fresh_page.click('button[type="submit"]')
        fresh_page.wait_for_load_state("networkidle")

        # Should be on login page
        assert "/login" in fresh_page.url

        # Verify user was created with correct role in SQLAlchemy
        with fresh_db_app.app_context():
            from src.models import User
            user = User.query.filter_by(username="setupadmin").first()
            assert user is not None
            assert user.role == "superadmin"
            assert user.kb_access_level == "Admin"
            assert user.can_create_kb is True

    def test_setup_returns_404_after_completion(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup page should return 404 after initial setup is complete."""
        # First complete setup
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        fresh_page.fill('input[name="username"]', "firstadmin")
        fresh_page.fill('input[name="password"]', "SecurePassword123!")
        fresh_page.fill('input[name="confirm_password"]', "SecurePassword123!")
        fresh_page.click('button[type="submit"]')
        fresh_page.wait_for_load_state("networkidle")

        # Now try to access setup again
        response = fresh_page.goto(fresh_base_url + "/setup")

        # Should return 404
        assert response.status == 404


class TestSetupWizardFormElements:
    """Tests for setup wizard form elements."""

    def test_setup_form_has_username_field(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup form should have a username input field."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        username_field = fresh_page.locator('input[name="username"]')
        expect(username_field).to_be_visible()
        expect(username_field).to_have_attribute("type", "text")
        expect(username_field).to_have_attribute("required", "")

    def test_setup_form_has_password_field(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup form should have a password input field."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        password_field = fresh_page.locator('input[name="password"]')
        expect(password_field).to_be_visible()
        expect(password_field).to_have_attribute("type", "password")
        expect(password_field).to_have_attribute("required", "")

    def test_setup_form_has_confirm_password_field(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup form should have a confirm password input field."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        confirm_field = fresh_page.locator('input[name="confirm_password"]')
        expect(confirm_field).to_be_visible()
        expect(confirm_field).to_have_attribute("type", "password")
        expect(confirm_field).to_have_attribute("required", "")

    def test_setup_form_has_submit_button(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup form should have a submit button."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        submit_button = fresh_page.locator('button[type="submit"]')
        expect(submit_button).to_be_visible()
        expect(submit_button).to_contain_text("Complete Setup")

    def test_setup_has_password_strength_indicator(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup form should have a password strength indicator."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        strength_bar = fresh_page.locator(".password-strength-bar")
        expect(strength_bar).to_be_attached()

    def test_setup_has_theme_toggle(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Setup page should have a theme toggle button."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        theme_toggle = fresh_page.locator("#themeToggle")
        expect(theme_toggle).to_be_visible()

    def test_setup_theme_toggle_works(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Theme toggle should change the theme."""
        fresh_page.goto(fresh_base_url + "/setup")
        fresh_page.wait_for_load_state("networkidle")

        # Check initial theme
        html = fresh_page.locator("html")
        initial_theme = html.get_attribute("data-theme")

        # Click theme toggle
        fresh_page.click("#themeToggle")

        # Theme should have changed
        new_theme = html.get_attribute("data-theme")
        assert initial_theme != new_theme


class TestSetupWizardHealthEndpoint:
    """Tests for health endpoint during setup state."""

    def test_health_endpoint_works_during_first_run(
        self,
        fresh_page: Page,
        fresh_base_url: str,
    ):
        """Health endpoint should work even when no users exist."""
        response = fresh_page.goto(fresh_base_url + "/health")

        # Health endpoint should return 200
        assert response.status == 200
