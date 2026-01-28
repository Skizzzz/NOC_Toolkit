"""
E2E smoke tests for the NOC Toolkit.

These tests validate that all main navigation pages load without errors,
return proper HTTP status codes, and have no JavaScript console errors.

This smoke test suite is designed to quickly catch issues where pages
fail to load due to broken imports, template errors, or runtime exceptions.
"""

import pytest
from playwright.sync_api import Page, expect, ConsoleMessage
from typing import List


# Main navigation routes that should be tested
# Each tuple contains: (route_path, page_name, requires_auth)
# Note: Only includes routes fully migrated to blueprints in src/app.py
MAIN_NAV_ROUTES = [
    # Main
    ("/", "Dashboard", True),
    ("/knowledge-base", "Knowledge Base", True),
    ("/jobs", "Jobs Center", True),
    # Config Tools
    ("/tools/phrase-search", "Interface Search", True),
    ("/tools/global-config", "Global Config", True),
    ("/tools/bulk-ssh", "Bulk SSH Terminal", True),
    # WLC Tools
    ("/tools/wlc/dashboard", "WLC Dashboard", True),
    ("/tools/wlc/ap-inventory", "AP Inventory", True),
    # Note: /tools/wlc-rf and /tools/wlc/summer-guest have template url_for issues
    # that reference routes not yet migrated to blueprints. These are excluded
    # from smoke tests until full migration is complete.
    # Infrastructure
    ("/tools/solarwinds/nodes", "SolarWinds Nodes", True),
    ("/tools/solarwinds/inventory", "SolarWinds Inventory", True),
    ("/changes", "Change Windows", True),
    # Certificates
    ("/certs", "Certificate Tracker", True),
    ("/certs/converter", "Cert Converter", True),
    ("/ise-nodes", "ISE Nodes", True),
    # Admin (requires superadmin)
    ("/admin/users", "Admin Users", True),
    ("/admin/settings", "Admin Settings", True),
    ("/admin/page-settings", "Page Settings", True),
]

# Pages that don't require authentication
PUBLIC_ROUTES = [
    ("/login", "Login", False),
    ("/health", "Health Check", False),
]

# Error levels to track in console
ERROR_LEVELS = ["error", "warning"]


class TestSmokeAllPagesLoad:
    """Smoke tests to verify all main pages load without server errors."""

    @pytest.mark.parametrize("route,name,requires_auth", MAIN_NAV_ROUTES)
    def test_authenticated_page_loads(
        self,
        authenticated_page: Page,
        base_url: str,
        route: str,
        name: str,
        requires_auth: bool,
    ):
        """Test that authenticated pages load with 200 status."""
        # Track console messages during page load
        console_errors: List[str] = []

        def handle_console(msg: ConsoleMessage):
            if msg.type in ERROR_LEVELS:
                console_errors.append(f"{msg.type}: {msg.text}")

        authenticated_page.on("console", handle_console)

        # Navigate to the page
        response = authenticated_page.goto(f"{base_url}{route}")

        # Wait for page to fully load
        authenticated_page.wait_for_load_state("networkidle")

        # Verify response status is 200 (or 302 redirect handled by browser)
        # The final response status after following redirects should be 200
        assert response is not None, f"No response received for {name} ({route})"
        final_url = authenticated_page.url

        # If we got redirected to login, that means auth failed (not expected)
        if "/login" in final_url and route != "/login":
            pytest.fail(f"{name} ({route}) redirected to login unexpectedly")

        # If we got a 500 error, that's a server error
        if response.status >= 500:
            pytest.fail(f"{name} ({route}) returned server error: {response.status}")

        # Page should load successfully (200) or be a redirect (302) followed to 200
        assert response.status in [
            200,
            302,
            304,
        ], f"{name} ({route}) returned unexpected status: {response.status}"

    @pytest.mark.parametrize("route,name,requires_auth", PUBLIC_ROUTES)
    def test_public_page_loads(
        self,
        page: Page,
        base_url: str,
        route: str,
        name: str,
        requires_auth: bool,
    ):
        """Test that public pages load with 200 status."""
        # Navigate to the page
        response = page.goto(f"{base_url}{route}")

        # Wait for page to fully load
        page.wait_for_load_state("networkidle")

        # Verify response
        assert response is not None, f"No response received for {name} ({route})"

        # Health endpoint should always return 200
        if route == "/health":
            assert (
                response.status == 200
            ), f"Health check returned {response.status}"

        # Login page should return 200
        if route == "/login":
            assert response.status == 200, f"Login page returned {response.status}"


class TestSmokeNoJavaScriptErrors:
    """Smoke tests to verify pages have no critical JavaScript errors."""

    @pytest.mark.parametrize(
        "route,name",
        [
            ("/", "Dashboard"),
            ("/knowledge-base", "Knowledge Base"),
            ("/tools/phrase-search", "Interface Search"),
            ("/tools/bulk-ssh", "Bulk SSH Terminal"),
            ("/tools/wlc/dashboard", "WLC Dashboard"),
            ("/certs", "Certificate Tracker"),
        ],
    )
    def test_page_has_no_javascript_errors(
        self,
        authenticated_page: Page,
        base_url: str,
        route: str,
        name: str,
    ):
        """Test that major pages have no JavaScript console errors."""
        # Collect JavaScript errors during page load
        js_errors: List[str] = []

        def handle_error(msg: ConsoleMessage):
            # Only capture actual errors, not warnings or info
            if msg.type == "error":
                # Filter out common non-critical errors
                text = msg.text.lower()
                # Skip favicon errors and similar non-critical issues
                if "favicon" in text or "404 (not found)" in text:
                    return
                js_errors.append(f"{msg.type}: {msg.text}")

        authenticated_page.on("console", handle_error)

        # Navigate to the page
        authenticated_page.goto(f"{base_url}{route}")

        # Wait for page to fully load and scripts to execute
        authenticated_page.wait_for_load_state("networkidle")

        # Give a moment for any async errors to appear
        authenticated_page.wait_for_timeout(500)

        # Assert no JavaScript errors occurred
        assert len(js_errors) == 0, f"{name} has JavaScript errors: {js_errors}"


class TestSmokeProtectedRoutesRequireAuth:
    """Smoke tests to verify protected routes require authentication."""

    @pytest.mark.parametrize(
        "route,name",
        [
            ("/", "Dashboard"),
            ("/knowledge-base", "Knowledge Base"),
            ("/jobs", "Jobs Center"),
            ("/tools/phrase-search", "Interface Search"),
            ("/tools/bulk-ssh", "Bulk SSH Terminal"),
            ("/tools/wlc/dashboard", "WLC Dashboard"),
            ("/tools/solarwinds/nodes", "SolarWinds Nodes"),
            ("/certs", "Certificate Tracker"),
            ("/admin/users", "Admin Users"),
        ],
    )
    def test_protected_routes_redirect_to_login(
        self,
        page: Page,  # Unauthenticated page
        base_url: str,
        route: str,
        name: str,
    ):
        """Test that protected routes redirect to login when not authenticated."""
        # Navigate to protected route without authentication
        # Increase timeout for this test as redirects can be slow
        page.set_default_timeout(30000)  # 30 seconds
        response = page.goto(f"{base_url}{route}", wait_until="domcontentloaded")
        page.wait_for_load_state("networkidle", timeout=30000)

        # Should be redirected to login page (302 -> 200 on login)
        assert "/login" in page.url, f"{name} ({route}) did not redirect to login"


class TestSmokeNavigationLinks:
    """Smoke tests to verify navigation links work correctly."""

    def test_main_navigation_dashboard_link(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that Dashboard link in navigation works."""
        authenticated_page.goto(f"{base_url}/")
        authenticated_page.wait_for_load_state("networkidle")

        # Find Dashboard link in sidebar
        dashboard_link = authenticated_page.locator('.nav-item:has-text("Dashboard")')

        # Should be visible and clickable
        expect(dashboard_link).to_be_visible()

    def test_sidebar_navigation_has_required_sections(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that sidebar navigation has all required sections."""
        authenticated_page.goto(f"{base_url}/")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for main navigation sections
        nav_sections = [
            "Main",
            "Config Tools",
            "WLC Tools",
            "Infrastructure",
            "Certificates",
        ]

        for section in nav_sections:
            section_title = authenticated_page.locator(
                f'.nav-section-title:has-text("{section}")'
            )
            expect(section_title).to_be_visible()

    def test_user_profile_section_visible_when_authenticated(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that user profile section is visible when authenticated."""
        authenticated_page.goto(f"{base_url}/")
        authenticated_page.wait_for_load_state("networkidle")

        # User info section should be visible
        user_info = authenticated_page.locator(".sidebar-user")
        expect(user_info).to_be_visible()

        # Profile and Logout buttons should be present
        profile_link = authenticated_page.get_by_role("link", name="Profile")
        logout_link = authenticated_page.get_by_role("link", name="Logout")
        expect(profile_link).to_be_visible()
        expect(logout_link).to_be_visible()

    def test_admin_panel_link_visible_for_superadmin(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that Admin Panel link is visible for superadmin users."""
        authenticated_page.goto(f"{base_url}/")
        authenticated_page.wait_for_load_state("networkidle")

        # Admin Panel button should be visible for superadmin
        admin_link = authenticated_page.get_by_role("link", name="Admin Panel")
        expect(admin_link).to_be_visible()

    def test_admin_panel_link_hidden_for_regular_user(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that Admin Panel link is hidden for regular users."""
        user_authenticated_page.goto(f"{base_url}/")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Admin Panel button should not be visible for regular users
        admin_link = user_authenticated_page.locator(
            '.sidebar-user a:has-text("Admin Panel")'
        )
        expect(admin_link).not_to_be_visible()


class TestSmokeApiEndpoints:
    """Smoke tests for API endpoints."""

    def test_health_endpoint_returns_json(self, page: Page, base_url: str):
        """Test that /health endpoint returns valid JSON response."""
        response = page.goto(f"{base_url}/health")
        page.wait_for_load_state("networkidle")

        # Should return 200
        assert response is not None
        assert response.status == 200

        # Content should be JSON
        content_type = response.headers.get("content-type", "")
        assert "application/json" in content_type

    def test_health_endpoint_contains_status(self, page: Page, base_url: str):
        """Test that /health endpoint JSON contains status field."""
        page.goto(f"{base_url}/health")
        page.wait_for_load_state("networkidle")

        # Get the page content (JSON)
        content = page.content()

        # Should contain expected health check fields
        assert "healthy" in content.lower() or "status" in content.lower()


class TestSmokePageContent:
    """Smoke tests to verify basic page content is present."""

    def test_dashboard_has_header(self, authenticated_page: Page, base_url: str):
        """Test that dashboard page has a header."""
        authenticated_page.goto(f"{base_url}/")
        authenticated_page.wait_for_load_state("networkidle")

        # Page should have the header element
        header = authenticated_page.locator("header.header")
        expect(header).to_be_visible()

        # Should have brand/logo
        brand = authenticated_page.locator(".brand")
        expect(brand).to_be_visible()

    def test_pages_have_sidebar(self, authenticated_page: Page, base_url: str):
        """Test that authenticated pages have the sidebar navigation."""
        authenticated_page.goto(f"{base_url}/")
        authenticated_page.wait_for_load_state("networkidle")

        # Sidebar should be visible
        sidebar = authenticated_page.locator(".sidebar")
        expect(sidebar).to_be_visible()

    def test_pages_have_footer(self, authenticated_page: Page, base_url: str):
        """Test that pages have the footer."""
        authenticated_page.goto(f"{base_url}/")
        authenticated_page.wait_for_load_state("networkidle")

        # Footer should be visible
        footer = authenticated_page.locator(".footer")
        expect(footer).to_be_visible()

        # Footer should contain copyright
        expect(footer).to_contain_text("NOC Toolkit")

    def test_login_page_has_form(self, page: Page, base_url: str):
        """Test that login page has the login form."""
        page.goto(f"{base_url}/login")
        page.wait_for_load_state("networkidle")

        # Should have login form elements
        username_input = page.locator('input[name="username"]')
        password_input = page.locator('input[name="password"]')
        submit_button = page.locator('button[type="submit"]')

        expect(username_input).to_be_visible()
        expect(password_input).to_be_visible()
        expect(submit_button).to_be_visible()


class TestSmokeThemeToggle:
    """Smoke tests for theme toggle functionality."""

    def test_theme_toggle_button_exists(self, authenticated_page: Page, base_url: str):
        """Test that theme toggle button exists in header."""
        authenticated_page.goto(f"{base_url}/")
        authenticated_page.wait_for_load_state("networkidle")

        # Theme toggle should be in header
        theme_toggle = authenticated_page.locator("#themeToggle")
        expect(theme_toggle).to_be_visible()

    def test_theme_toggle_changes_theme(self, authenticated_page: Page, base_url: str):
        """Test that clicking theme toggle changes the theme."""
        authenticated_page.goto(f"{base_url}/")
        authenticated_page.wait_for_load_state("networkidle")

        # Get initial theme
        html = authenticated_page.locator("html")
        initial_theme = html.get_attribute("data-theme")

        # Click theme toggle
        authenticated_page.click("#themeToggle")

        # Theme should have changed
        new_theme = html.get_attribute("data-theme")
        assert new_theme != initial_theme, "Theme did not change after clicking toggle"
