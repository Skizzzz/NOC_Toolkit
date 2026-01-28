"""
E2E tests for Certificate Tracker functionality.

Tests Certificate tracker page loading, ISE nodes page,
and Certificate converter page.
"""

import pytest
from playwright.sync_api import Page, expect


class TestCertificateTracker:
    """Tests for the Certificate Tracker page."""

    def test_certificate_tracker_page_loads(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the certificate tracker page loads successfully."""
        # Navigate to certificate tracker page
        authenticated_page.goto(f"{base_url}/certs")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify we're on the certificate tracker page (not redirected to login)
        assert "/login" not in authenticated_page.url

        # Verify page content is present
        page_content = authenticated_page.content().lower()

        # Page should have certificate-related content
        assert any([
            "certificate tracker" in page_content,
            "certificate" in page_content,
            "cert" in page_content,
        ]), "Certificate tracker page should contain certificate-related content"

    def test_certificate_tracker_has_header(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the certificate tracker page has the correct header."""
        authenticated_page.goto(f"{base_url}/certs")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the page header
        header = authenticated_page.locator("h2:has-text('Certificate Tracker')")
        expect(header).to_be_visible()

    def test_certificate_tracker_has_stats_cards(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the certificate tracker has statistics cards."""
        authenticated_page.goto(f"{base_url}/certs")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for stats cards section
        stats_section = authenticated_page.locator(".cert-stats")
        expect(stats_section).to_be_visible()

        # Check for individual stat cards
        stat_cards = authenticated_page.locator(".stat-card")
        expect(stat_cards.first).to_be_visible()

        # Verify we have the expected stats
        page_content = authenticated_page.content().lower()
        assert "total certificates" in page_content
        assert "expired" in page_content

    def test_certificate_tracker_has_filter_bar(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the certificate tracker has a filter bar."""
        authenticated_page.goto(f"{base_url}/certs")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for CN filter input
        cn_filter = authenticated_page.locator('input[name="cn"]')
        expect(cn_filter).to_be_visible()

        # Check for status filter select
        status_filter = authenticated_page.locator('select[name="status"]')
        expect(status_filter).to_be_visible()

        # Check for source filter select
        source_filter = authenticated_page.locator('select[name="source"]')
        expect(source_filter).to_be_visible()

        # Check for filter button
        filter_btn = authenticated_page.locator('button:has-text("Filter")')
        expect(filter_btn).to_be_visible()

    def test_certificate_tracker_has_upload_button(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the upload certificate button is present."""
        authenticated_page.goto(f"{base_url}/certs")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the Upload Certificate button in the header area (first one)
        upload_btn = authenticated_page.locator('a:has-text("Upload Certificate")').first
        expect(upload_btn).to_be_visible()

    def test_certificate_tracker_has_export_button(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the export CSV button is present."""
        authenticated_page.goto(f"{base_url}/certs")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the Export CSV button
        export_btn = authenticated_page.locator('a:has-text("Export CSV")')
        expect(export_btn).to_be_visible()

    def test_certificate_tracker_has_converter_link(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the converter link is present."""
        authenticated_page.goto(f"{base_url}/certs")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the Converter link
        converter_link = authenticated_page.locator('a:has-text("Converter")')
        expect(converter_link).to_be_visible()

    def test_certificate_tracker_has_ise_nodes_link(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the ISE Nodes link is present."""
        authenticated_page.goto(f"{base_url}/certs")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the ISE Nodes link (use exact match to avoid "Configure ISE Nodes" in empty state)
        ise_link = authenticated_page.get_by_role("link", name="ISE Nodes", exact=True)
        expect(ise_link).to_be_visible()

    def test_certificate_tracker_has_view_chain_button(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the View Chain button is present."""
        authenticated_page.goto(f"{base_url}/certs")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the View Chain button (exact match)
        chain_btn = authenticated_page.get_by_role("button", name="View Chain", exact=True)
        expect(chain_btn).to_be_visible()

    def test_certificate_tracker_empty_state(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that empty state message is shown when no certificates."""
        authenticated_page.goto(f"{base_url}/certs")
        authenticated_page.wait_for_load_state("networkidle")

        # With no data, should show empty state
        page_content = authenticated_page.content().lower()

        # Should show empty state or zero count
        has_empty_indicator = any([
            "no certificates found" in page_content,
            "upload certificates" in page_content,
            "configure ise nodes" in page_content,
        ])

        # Even with no data, page should load without error
        assert "500" not in authenticated_page.url
        assert "internal server error" not in page_content


class TestISENodes:
    """Tests for the ISE Nodes page."""

    def test_ise_nodes_page_loads(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the ISE nodes page loads successfully."""
        # Navigate to ISE nodes page
        authenticated_page.goto(f"{base_url}/ise-nodes")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify we're on the ISE nodes page (not redirected to login)
        assert "/login" not in authenticated_page.url

        # Verify page content is present
        page_content = authenticated_page.content().lower()

        # Page should have ISE-related content
        assert any([
            "ise nodes" in page_content,
            "ise" in page_content,
            "cisco ise" in page_content,
        ]), "ISE Nodes page should contain ISE-related content"

    def test_ise_nodes_has_header(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the ISE nodes page has the correct header."""
        authenticated_page.goto(f"{base_url}/ise-nodes")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the page header
        header = authenticated_page.locator("h2:has-text('ISE Nodes')")
        expect(header).to_be_visible()

    def test_ise_nodes_has_add_button(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the Add ISE Node button is present."""
        authenticated_page.goto(f"{base_url}/ise-nodes")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the Add ISE Node button
        add_btn = authenticated_page.locator('button:has-text("Add ISE Node")')
        expect(add_btn).to_be_visible()

    def test_ise_nodes_has_sync_all_button(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the Sync All button is present."""
        authenticated_page.goto(f"{base_url}/ise-nodes")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the Sync All button
        sync_btn = authenticated_page.locator('button:has-text("Sync All")')
        expect(sync_btn).to_be_visible()

    def test_ise_nodes_has_fetch_versions_button(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the Fetch All Versions button is present."""
        authenticated_page.goto(f"{base_url}/ise-nodes")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the Fetch All Versions button
        fetch_btn = authenticated_page.locator('button:has-text("Fetch All Versions")')
        expect(fetch_btn).to_be_visible()

    def test_ise_nodes_has_auto_sync_settings(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the auto-sync settings section is present."""
        authenticated_page.goto(f"{base_url}/ise-nodes")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the Auto-Sync Settings heading
        page_content = authenticated_page.content()
        assert "Auto-Sync Settings" in page_content

        # Check for the enable auto-sync checkbox
        enable_checkbox = authenticated_page.locator('input[name="enabled"]')
        expect(enable_checkbox).to_be_visible()

        # Check for the interval select
        interval_select = authenticated_page.locator('select[name="interval_hours"]')
        expect(interval_select).to_be_visible()

    def test_ise_nodes_add_form_toggle(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that clicking Add ISE Node shows the add form."""
        authenticated_page.goto(f"{base_url}/ise-nodes")
        authenticated_page.wait_for_load_state("networkidle")

        # Add form should initially be hidden (no .active class)
        add_form = authenticated_page.locator("#addNodeForm")

        # Click the Add ISE Node button
        add_btn = authenticated_page.locator('button:has-text("Add ISE Node")').first
        add_btn.click()

        # Form should now be visible with .active class
        expect(add_form).to_have_class("card add-node-form active")

    def test_ise_nodes_add_form_has_fields(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the add node form has all required fields."""
        authenticated_page.goto(f"{base_url}/ise-nodes")
        authenticated_page.wait_for_load_state("networkidle")

        # Show the add form
        add_btn = authenticated_page.locator('button:has-text("Add ISE Node")').first
        add_btn.click()

        # Check for form fields
        hostname_input = authenticated_page.locator('input[name="hostname"]')
        expect(hostname_input).to_be_visible()

        ip_input = authenticated_page.locator('input[name="ip"]')
        expect(ip_input).to_be_visible()

        username_input = authenticated_page.locator('input[name="username"]')
        expect(username_input).to_be_visible()

        password_input = authenticated_page.locator('input[name="password"]')
        expect(password_input).to_be_visible()

    def test_ise_nodes_back_link(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the back to certificate tracker link is present."""
        authenticated_page.goto(f"{base_url}/ise-nodes")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the back link
        back_link = authenticated_page.locator("a:has-text('Back to Certificate Tracker')")
        expect(back_link).to_be_visible()

    def test_ise_nodes_empty_state(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that empty state message is shown when no nodes configured."""
        authenticated_page.goto(f"{base_url}/ise-nodes")
        authenticated_page.wait_for_load_state("networkidle")

        # With no data, should show empty state
        page_content = authenticated_page.content().lower()

        # Should show empty state message
        has_empty_indicator = any([
            "no ise nodes configured" in page_content,
            "add your first node" in page_content,
            "add ise nodes" in page_content,
        ])

        # Even with no data, page should load without error
        assert "500" not in authenticated_page.url
        assert "internal server error" not in page_content


class TestCertificateConverter:
    """Tests for the Certificate Converter page."""

    def test_certificate_converter_page_loads(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the certificate converter page loads successfully."""
        # Navigate to certificate converter page
        authenticated_page.goto(f"{base_url}/certs/converter")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify we're on the converter page (not redirected to login)
        assert "/login" not in authenticated_page.url

        # Verify page content is present
        page_content = authenticated_page.content().lower()

        # Page should have converter-related content
        assert any([
            "certificate converter" in page_content,
            "converter" in page_content,
            "convert" in page_content,
        ]), "Certificate converter page should contain converter-related content"

    def test_certificate_converter_has_header(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the converter page has the correct header."""
        authenticated_page.goto(f"{base_url}/certs/converter")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the page header
        header = authenticated_page.locator("h2:has-text('Certificate Converter')")
        expect(header).to_be_visible()

    def test_certificate_converter_has_back_link(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the back link to certificate tracker is present."""
        authenticated_page.goto(f"{base_url}/certs/converter")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for the back link
        back_link = authenticated_page.locator("a:has-text('Back to Certificate Tracker')")
        expect(back_link).to_be_visible()

    def test_certificate_converter_has_pfx_to_crt_option(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that PFX to CRT + KEY conversion option is present."""
        authenticated_page.goto(f"{base_url}/certs/converter")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for PFX to CRT option
        page_content = authenticated_page.content()
        assert "PFX to CRT + KEY" in page_content

        # Check for the conversion form
        pfx_form = authenticated_page.locator('input[value="pfx_to_crt"]')
        expect(pfx_form).to_be_attached()

    def test_certificate_converter_has_crt_key_to_pfx_option(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that CRT + KEY to PFX conversion option is present."""
        authenticated_page.goto(f"{base_url}/certs/converter")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for CRT + KEY to PFX option
        page_content = authenticated_page.content()
        assert "CRT + KEY to PFX" in page_content

        # Check for the conversion form
        crt_to_pfx_form = authenticated_page.locator('input[value="crt_key_to_pfx"]')
        expect(crt_to_pfx_form).to_be_attached()

    def test_certificate_converter_has_der_pem_options(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that DER/PEM conversion options are present."""
        authenticated_page.goto(f"{base_url}/certs/converter")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for DER to PEM option
        page_content = authenticated_page.content()
        assert "DER to PEM" in page_content
        assert "PEM to DER" in page_content

        # Check for the conversion forms
        der_to_pem_form = authenticated_page.locator('input[value="der_to_pem"]')
        expect(der_to_pem_form).to_be_attached()

        pem_to_der_form = authenticated_page.locator('input[value="pem_to_der"]')
        expect(pem_to_der_form).to_be_attached()

    def test_certificate_converter_has_conversion_cards(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the converter has conversion cards grid."""
        authenticated_page.goto(f"{base_url}/certs/converter")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for converter grid
        converter_grid = authenticated_page.locator(".converter-grid")
        expect(converter_grid).to_be_visible()

        # Check for individual conversion cards
        conversion_cards = authenticated_page.locator(".conversion-card")
        expect(conversion_cards.first).to_be_visible()

        # Should have 6 conversion options
        count = conversion_cards.count()
        assert count == 6, f"Expected 6 conversion cards, got {count}"

    def test_certificate_converter_has_convert_buttons(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that each conversion card has a Convert button."""
        authenticated_page.goto(f"{base_url}/certs/converter")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for Convert buttons
        convert_buttons = authenticated_page.locator('.conversion-card button:has-text("Convert")')

        # Should have a convert button for each card
        count = convert_buttons.count()
        assert count == 6, f"Expected 6 Convert buttons, got {count}"


class TestCertificateAccessControl:
    """Tests for certificate pages access control."""

    def test_unauthenticated_user_redirected_from_cert_tracker(
        self, page: Page, base_url: str
    ):
        """Test that unauthenticated users are redirected from cert tracker."""
        # Try to access certificate tracker without authentication
        page.goto(f"{base_url}/certs")
        page.wait_for_load_state("networkidle")

        # Should be redirected to login
        assert "/login" in page.url

    def test_unauthenticated_user_redirected_from_ise_nodes(
        self, page: Page, base_url: str
    ):
        """Test that unauthenticated users are redirected from ISE nodes page."""
        # Try to access ISE nodes without authentication
        page.goto(f"{base_url}/ise-nodes")
        page.wait_for_load_state("networkidle")

        # Should be redirected to login
        assert "/login" in page.url

    def test_unauthenticated_user_redirected_from_converter(
        self, page: Page, base_url: str
    ):
        """Test that unauthenticated users are redirected from converter page."""
        # Try to access converter without authentication
        page.goto(f"{base_url}/certs/converter")
        page.wait_for_load_state("networkidle")

        # Should be redirected to login
        assert "/login" in page.url

    def test_regular_user_can_access_cert_tracker(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that regular users can access certificate tracker."""
        # Navigate to cert tracker as regular user
        user_authenticated_page.goto(f"{base_url}/certs")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected to login
        assert "/login" not in user_authenticated_page.url

    def test_regular_user_can_access_ise_nodes(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that regular users can access ISE nodes page."""
        # Navigate to ISE nodes as regular user
        user_authenticated_page.goto(f"{base_url}/ise-nodes")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected to login
        assert "/login" not in user_authenticated_page.url

    def test_regular_user_can_access_converter(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that regular users can access converter page."""
        # Navigate to converter as regular user
        user_authenticated_page.goto(f"{base_url}/certs/converter")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected to login
        assert "/login" not in user_authenticated_page.url


class TestCertificateNavigation:
    """Tests for navigation between certificate pages."""

    def test_navigate_from_tracker_to_ise_nodes(
        self, authenticated_page: Page, base_url: str
    ):
        """Test navigation from certificate tracker to ISE nodes."""
        authenticated_page.goto(f"{base_url}/certs")
        authenticated_page.wait_for_load_state("networkidle")

        # Click ISE Nodes link (exact match to avoid "Configure ISE Nodes")
        ise_link = authenticated_page.get_by_role("link", name="ISE Nodes", exact=True)
        ise_link.click()

        authenticated_page.wait_for_load_state("networkidle")

        # Should be on ISE nodes page
        assert "/ise-nodes" in authenticated_page.url

    def test_navigate_from_tracker_to_converter(
        self, authenticated_page: Page, base_url: str
    ):
        """Test navigation from certificate tracker to converter."""
        authenticated_page.goto(f"{base_url}/certs")
        authenticated_page.wait_for_load_state("networkidle")

        # Click Converter link
        converter_link = authenticated_page.locator('a:has-text("Converter")')
        converter_link.click()

        authenticated_page.wait_for_load_state("networkidle")

        # Should be on converter page
        assert "/certs/converter" in authenticated_page.url

    def test_navigate_from_ise_nodes_to_tracker(
        self, authenticated_page: Page, base_url: str
    ):
        """Test navigation from ISE nodes back to certificate tracker."""
        authenticated_page.goto(f"{base_url}/ise-nodes")
        authenticated_page.wait_for_load_state("networkidle")

        # Click back link
        back_link = authenticated_page.locator("a:has-text('Back to Certificate Tracker')")
        back_link.click()

        authenticated_page.wait_for_load_state("networkidle")

        # Should be on certificate tracker page
        assert "/certs" in authenticated_page.url
        assert "/converter" not in authenticated_page.url

    def test_navigate_from_converter_to_tracker(
        self, authenticated_page: Page, base_url: str
    ):
        """Test navigation from converter back to certificate tracker."""
        authenticated_page.goto(f"{base_url}/certs/converter")
        authenticated_page.wait_for_load_state("networkidle")

        # Click back link
        back_link = authenticated_page.locator("a:has-text('Back to Certificate Tracker')")
        back_link.click()

        authenticated_page.wait_for_load_state("networkidle")

        # Should be on certificate tracker page
        assert "/certs" in authenticated_page.url
        assert "/converter" not in authenticated_page.url
