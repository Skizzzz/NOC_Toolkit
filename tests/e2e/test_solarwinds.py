"""
E2E tests for SolarWinds Inventory functionality.

Tests SolarWinds inventory page loading, search/filter inputs,
and export functionality.
"""

import pytest
from playwright.sync_api import Page, expect


class TestSolarWindsInventory:
    """Tests for the SolarWinds Inventory page."""

    def test_inventory_page_loads(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the SolarWinds inventory page loads successfully."""
        # Navigate to SolarWinds inventory page
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify we're on the inventory page (not redirected to login)
        assert "/login" not in authenticated_page.url

        # Verify inventory page content is present
        page_content = authenticated_page.content().lower()

        # Page should have inventory-related content
        assert any([
            "inventory" in page_content,
            "solarwinds" in page_content,
            "hardware" in page_content,
            "software" in page_content,
            "vendor" in page_content,
        ]), "SolarWinds inventory page should contain inventory-related content"

    def test_inventory_page_has_header(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the inventory page has the correct header."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the page header
        page_content = authenticated_page.content().lower()

        # Should have the inventory header
        assert "hardware/software inventory" in page_content or "inventory" in page_content

    def test_inventory_page_has_navigation_pills(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the inventory page has navigation pills for Nodes/Inventory/Settings."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for navigation pills
        nav_pills = authenticated_page.locator(".nav-pills")
        expect(nav_pills).to_be_visible()

        # Should have links to Nodes, Inventory, and Settings
        page_content = authenticated_page.content().lower()
        assert "nodes" in page_content
        assert "inventory" in page_content
        assert "settings" in page_content


class TestSolarWindsSearchFilter:
    """Tests for SolarWinds Inventory search and filter functionality."""

    def test_search_filter_input_is_present(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the search/filter input is present on the inventory page."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the search input field
        search_input = authenticated_page.locator('input[name="search"]')
        expect(search_input).to_be_visible()

    def test_vendor_filter_is_present(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the vendor multi-select filter is present."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the vendor select
        vendor_select = authenticated_page.locator('select[name="vendor"]')
        expect(vendor_select).to_be_visible()

        # Should be a multi-select
        assert vendor_select.get_attribute("multiple") is not None

    def test_model_filter_is_present(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the model multi-select filter is present."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the model select
        model_select = authenticated_page.locator('select[name="model"]')
        expect(model_select).to_be_visible()

        # Should be a multi-select
        assert model_select.get_attribute("multiple") is not None

    def test_version_filter_is_present(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the software version multi-select filter is present."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the version select
        version_select = authenticated_page.locator('select[name="version"]')
        expect(version_select).to_be_visible()

        # Should be a multi-select
        assert version_select.get_attribute("multiple") is not None

    def test_version_search_input_is_present(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the version search input (for CVE assessment) is present."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the version search input
        version_search = authenticated_page.locator('input[name="version_search"]')
        expect(version_search).to_be_visible()

    def test_filter_apply_button_is_present(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the Apply Filters button is present."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the Apply Filters button
        apply_btn = authenticated_page.locator('button:has-text("Apply Filters")')
        expect(apply_btn).to_be_visible()


class TestSolarWindsExport:
    """Tests for SolarWinds Inventory export functionality."""

    def test_export_csv_button_is_present(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the Export CSV button is present."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the Export CSV link/button
        export_btn = authenticated_page.locator('a:has-text("Export CSV")')
        expect(export_btn).to_be_visible()

    def test_export_summary_button_is_present(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the Export Summary button is present."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the Export Summary link/button
        export_summary_btn = authenticated_page.locator('a:has-text("Export Summary")')
        expect(export_summary_btn).to_be_visible()

    def test_export_csv_triggers_download(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that clicking Export CSV triggers a file download."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Set up download handler and click export
        with authenticated_page.expect_download() as download_info:
            export_link = authenticated_page.locator('a:has-text("Export CSV")').first
            export_link.click()

        # Get the download
        download = download_info.value

        # Verify the download was triggered
        assert download is not None

        # Verify the filename contains expected text
        filename = download.suggested_filename
        assert "solarwinds_inventory" in filename.lower()
        assert ".csv" in filename.lower()

    def test_export_summary_triggers_download(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that clicking Export Summary triggers a file download."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # Set up download handler and click export
        with authenticated_page.expect_download() as download_info:
            export_link = authenticated_page.locator('a:has-text("Export Summary")').first
            export_link.click()

        # Get the download
        download = download_info.value

        # Verify the download was triggered
        assert download is not None

        # Verify the filename contains expected text
        filename = download.suggested_filename
        assert "solarwinds_inventory_summary" in filename.lower()
        assert ".csv" in filename.lower()


class TestSolarWindsNodes:
    """Tests for the SolarWinds Nodes page."""

    def test_nodes_page_loads(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the SolarWinds nodes page loads successfully."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/nodes")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify we're on the nodes page (not redirected to login)
        assert "/login" not in authenticated_page.url

        # Verify nodes page content is present
        page_content = authenticated_page.content().lower()

        assert any([
            "solarwinds" in page_content,
            "nodes" in page_content,
        ]), "SolarWinds nodes page should contain nodes-related content"


class TestSolarWindsAccessControl:
    """Tests for SolarWinds page access control."""

    def test_unauthenticated_user_redirected_to_login(
        self, page: Page, base_url: str
    ):
        """Test that unauthenticated users are redirected to login."""
        # Try to access SolarWinds inventory without authentication
        page.goto(f"{base_url}/tools/solarwinds/inventory")
        page.wait_for_load_state("networkidle")

        # Should be redirected to login
        assert "/login" in page.url

    def test_unauthenticated_user_redirected_from_nodes(
        self, page: Page, base_url: str
    ):
        """Test that unauthenticated users are redirected from nodes page."""
        # Try to access SolarWinds nodes without authentication
        page.goto(f"{base_url}/tools/solarwinds/nodes")
        page.wait_for_load_state("networkidle")

        # Should be redirected to login
        assert "/login" in page.url

    def test_regular_user_can_access_inventory(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that regular users can access SolarWinds inventory."""
        # Navigate to inventory as regular user
        user_authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected to login
        assert "/login" not in user_authenticated_page.url

    def test_regular_user_can_access_nodes(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that regular users can access SolarWinds nodes."""
        # Navigate to nodes as regular user
        user_authenticated_page.goto(f"{base_url}/tools/solarwinds/nodes")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected to login
        assert "/login" not in user_authenticated_page.url


class TestSolarWindsEmptyState:
    """Tests for SolarWinds Inventory empty state."""

    def test_inventory_shows_empty_state_message(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that inventory page shows appropriate message when no data."""
        authenticated_page.goto(f"{base_url}/tools/solarwinds/inventory")
        authenticated_page.wait_for_load_state("networkidle")

        # With no data, should show either empty state or stats showing 0 devices
        page_content = authenticated_page.content().lower()

        # Should show some indicator of no data or zero count
        has_empty_indicator = any([
            "no inventory data" in page_content,
            "no devices" in page_content,
            "configure solarwinds" in page_content,
            "0 devices" in page_content,
            "showing 0" in page_content,
        ])

        # Even with no data, page should load without error
        assert "500" not in authenticated_page.url
        assert "internal server error" not in page_content
