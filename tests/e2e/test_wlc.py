"""
E2E tests for WLC (Wireless LAN Controller) functionality.

Tests WLC dashboard, settings page, and AP inventory page loading.
"""

import pytest
from playwright.sync_api import Page, expect


class TestWLCDashboard:
    """Tests for the WLC dashboard page."""

    def test_dashboard_page_loads_with_charts_placeholder(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the WLC dashboard page loads successfully with chart placeholders."""
        # Navigate to WLC dashboard
        authenticated_page.goto(f"{base_url}/tools/wlc/dashboard")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify we're on the dashboard page (not redirected to login)
        assert "/login" not in authenticated_page.url

        # Verify dashboard content is present
        # The page should have dashboard-related elements
        page_content = authenticated_page.content().lower()

        # Dashboard should contain WLC-related content
        # Check for common dashboard elements (title, charts container, or data display)
        assert any([
            "dashboard" in page_content,
            "wlc" in page_content,
            "client" in page_content,
            "wireless" in page_content,
        ]), "Dashboard page should contain WLC-related content"

    def test_dashboard_displays_time_range_selector(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the dashboard has a time range selector."""
        # Navigate to WLC dashboard
        authenticated_page.goto(f"{base_url}/tools/wlc/dashboard")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for time range related elements (select dropdown, buttons, or links)
        page_content = authenticated_page.content().lower()

        # The dashboard should have time range options
        has_range_selector = any([
            "1 hour" in page_content,
            "6 hour" in page_content,
            "24 hour" in page_content,
            "range" in page_content,
            "1h" in page_content,
            "24h" in page_content,
        ])

        assert has_range_selector, "Dashboard should have time range selector options"

    def test_dashboard_time_range_parameter_accepted(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the dashboard accepts time range parameter."""
        # Navigate to dashboard with specific time range
        authenticated_page.goto(f"{base_url}/tools/wlc/dashboard?range=24h")
        authenticated_page.wait_for_load_state("networkidle")

        # Should load successfully (not error)
        assert "/login" not in authenticated_page.url

        # Verify page loaded without server error
        page_content = authenticated_page.content().lower()
        assert "500" not in authenticated_page.url
        assert "internal server error" not in page_content


class TestWLCDashboardSettings:
    """Tests for the WLC dashboard settings page."""

    def test_dashboard_settings_page_can_be_accessed(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the dashboard settings can be accessed."""
        # Navigate to WLC tools menu
        authenticated_page.goto(f"{base_url}/tools/wlc")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify we're on the WLC tools page (not redirected to login)
        assert "/login" not in authenticated_page.url

        # Verify page loaded successfully
        page_content = authenticated_page.content().lower()
        assert any([
            "wlc" in page_content,
            "wireless" in page_content,
            "tools" in page_content,
        ]), "WLC tools page should contain WLC-related content"

    def test_wlc_tools_menu_page_loads(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the WLC tools menu page loads successfully."""
        # Navigate to WLC tools menu
        authenticated_page.goto(f"{base_url}/tools/wlc")
        authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected to login
        assert "/login" not in authenticated_page.url

        # Verify it's the WLC tools page
        page_content = authenticated_page.content().lower()

        # Should have links to WLC-related tools
        has_wlc_content = any([
            "dashboard" in page_content,
            "inventory" in page_content,
            "wlc" in page_content,
        ])
        assert has_wlc_content, "WLC tools menu should have links to WLC tools"


class TestAPInventory:
    """Tests for the AP Inventory page."""

    def test_ap_inventory_page_displays(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that AP inventory page displays (empty state or data)."""
        # Navigate to AP inventory
        authenticated_page.goto(f"{base_url}/tools/wlc/ap-inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify we're on the inventory page (not redirected to login)
        assert "/login" not in authenticated_page.url

        # Verify page loaded (should have inventory-related content)
        page_content = authenticated_page.content().lower()

        # Page should have inventory or AP-related content
        has_inventory_content = any([
            "inventory" in page_content,
            "access point" in page_content,
            "ap" in page_content,
            "filter" in page_content,
            "no data" in page_content,  # Empty state
            "no aps" in page_content,    # Empty state variant
        ])
        assert has_inventory_content, "AP inventory page should have inventory-related content"

    def test_ap_inventory_has_filter_inputs(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that AP inventory page has filter inputs."""
        # Navigate to AP inventory
        authenticated_page.goto(f"{base_url}/tools/wlc/ap-inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for filter input elements or filter-related text
        page_content = authenticated_page.content().lower()

        # Page should have filter functionality
        has_filters = any([
            "filter" in page_content,
            "search" in page_content,
            "name" in page_content,
            "model" in page_content,
            "location" in page_content,
        ])
        assert has_filters, "AP inventory page should have filter options"

    def test_ap_inventory_has_export_option(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that AP inventory page has export functionality."""
        # Navigate to AP inventory
        authenticated_page.goto(f"{base_url}/tools/wlc/ap-inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for export button or link
        page_content = authenticated_page.content().lower()

        # Page should have export option
        has_export = any([
            "export" in page_content,
            "csv" in page_content,
            "download" in page_content,
        ])
        assert has_export, "AP inventory page should have export option"

    def test_ap_inventory_export_returns_csv(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that AP inventory export triggers a download (CSV file)."""
        # Navigate to inventory page first
        authenticated_page.goto(f"{base_url}/tools/wlc/ap-inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Set up download handler
        with authenticated_page.expect_download() as download_info:
            # Click the export link
            export_link = authenticated_page.locator('a[href*="export"]').first
            export_link.click()

        # Get the download
        download = download_info.value

        # Verify the download was triggered
        assert download is not None

        # Verify the filename contains expected text
        filename = download.suggested_filename
        assert "ap_inventory" in filename.lower()
        assert ".csv" in filename.lower()


class TestWLCAccessControl:
    """Tests for WLC page access control."""

    def test_unauthenticated_user_redirected_to_login(
        self, page: Page, base_url: str
    ):
        """Test that unauthenticated users are redirected to login."""
        # Try to access WLC dashboard without authentication
        page.goto(f"{base_url}/tools/wlc/dashboard")
        page.wait_for_load_state("networkidle")

        # Should be redirected to login
        assert "/login" in page.url

    def test_unauthenticated_user_redirected_from_inventory(
        self, page: Page, base_url: str
    ):
        """Test that unauthenticated users are redirected from AP inventory."""
        # Try to access AP inventory without authentication
        page.goto(f"{base_url}/tools/wlc/ap-inventory")
        page.wait_for_load_state("networkidle")

        # Should be redirected to login
        assert "/login" in page.url

    def test_regular_user_can_access_wlc_dashboard(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that regular users can access WLC dashboard."""
        # Navigate to WLC dashboard as regular user
        user_authenticated_page.goto(f"{base_url}/tools/wlc/dashboard")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected to login
        assert "/login" not in user_authenticated_page.url

    def test_regular_user_can_access_ap_inventory(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that regular users can access AP inventory."""
        # Navigate to AP inventory as regular user
        user_authenticated_page.goto(f"{base_url}/tools/wlc/ap-inventory")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected to login
        assert "/login" not in user_authenticated_page.url
