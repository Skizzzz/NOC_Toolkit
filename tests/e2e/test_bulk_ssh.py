"""
E2E Tests for Bulk SSH functionality.

Tests cover:
- Bulk SSH main page loads
- Templates page loads with template list
- Schedules page loads
- Access control for unauthenticated users
"""

import pytest
from playwright.sync_api import Page, expect


class TestBulkSSHMainPage:
    """Tests for the main Bulk SSH terminal page."""

    def test_bulk_ssh_page_loads(self, authenticated_page: Page, base_url: str):
        """Test that the Bulk SSH page loads successfully."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh")
        authenticated_page.wait_for_load_state("networkidle")

        # Check page title or header
        expect(authenticated_page.locator("h2")).to_contain_text("Bulk SSH Terminal")

    def test_bulk_ssh_page_has_device_selection_section(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the device selection section is present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for device selection section header
        expect(authenticated_page.locator("h3:has-text('Device Selection')")).to_be_visible()

    def test_bulk_ssh_page_has_device_list_textarea(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the device list textarea is present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for device list textarea
        device_list = authenticated_page.locator("#deviceListText")
        expect(device_list).to_be_visible()
        expect(device_list).to_have_attribute("name", "device_list")

    def test_bulk_ssh_page_has_authentication_section(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the authentication section is present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for authentication section header
        expect(authenticated_page.locator("h3:has-text('Authentication')")).to_be_visible()

        # Check for username and password fields
        expect(authenticated_page.locator("#username")).to_be_visible()
        expect(authenticated_page.locator("#password")).to_be_visible()

    def test_bulk_ssh_page_has_command_section(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the command section is present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for command section header
        expect(authenticated_page.locator("h3:has-text('Command')")).to_be_visible()

        # Check for command textarea
        expect(authenticated_page.locator("#command")).to_be_visible()

    def test_bulk_ssh_page_has_options_section(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the options section is present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for options section header
        expect(authenticated_page.locator("h3:has-text('Options')")).to_be_visible()

        # Check for device type selector
        expect(authenticated_page.locator("#deviceType")).to_be_visible()

    def test_bulk_ssh_page_has_execute_button(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the execute button is present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for execute button
        execute_btn = authenticated_page.locator("#executeBtn")
        expect(execute_btn).to_be_visible()
        expect(execute_btn).to_contain_text("Execute on All Devices")

    def test_bulk_ssh_page_has_templates_link(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the link to templates page is present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for templates link
        templates_link = authenticated_page.locator("a:has-text('Manage Templates')")
        expect(templates_link).to_be_visible()

    def test_bulk_ssh_page_has_device_input_tabs(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that device input tabs are present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for paste list tab
        paste_tab = authenticated_page.locator(".device-tab:has-text('Paste List')")
        expect(paste_tab).to_be_visible()

        # Check for inventory tab
        inventory_tab = authenticated_page.locator(".device-tab:has-text('From Inventory')")
        expect(inventory_tab).to_be_visible()


class TestBulkSSHTemplates:
    """Tests for the Bulk SSH templates page."""

    def test_templates_page_loads(self, authenticated_page: Page, base_url: str):
        """Test that the templates page loads successfully."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/templates")
        authenticated_page.wait_for_load_state("networkidle")

        # Check page title
        expect(authenticated_page.locator("h2")).to_contain_text("Command Templates")

    def test_templates_page_has_create_section(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the create template section is present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/templates")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for create form header
        create_header = authenticated_page.locator(".create-form-header")
        expect(create_header).to_be_visible()
        expect(create_header).to_contain_text("Create New Template")

    def test_templates_page_has_back_link(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the back to Bulk SSH link is present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/templates")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for back link
        back_link = authenticated_page.locator("a:has-text('Back to Bulk SSH')")
        expect(back_link).to_be_visible()

    def test_templates_page_shows_empty_state_or_list(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the templates page shows either empty state or template list."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/templates")
        authenticated_page.wait_for_load_state("networkidle")

        # Page should show either empty state OR template cards
        empty_state = authenticated_page.locator(".empty-state")
        templates_grid = authenticated_page.locator(".templates-grid")

        # One of these should be visible
        empty_visible = empty_state.count() > 0 and empty_state.is_visible()
        grid_visible = templates_grid.count() > 0 and templates_grid.is_visible()

        assert empty_visible or grid_visible, "Neither empty state nor templates grid is visible"

    def test_templates_page_has_seed_button_when_empty(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that seed defaults button is present when no templates exist."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/templates")
        authenticated_page.wait_for_load_state("networkidle")

        # If empty state is shown, seed button should be present
        empty_state = authenticated_page.locator(".empty-state")
        if empty_state.count() > 0 and empty_state.is_visible():
            seed_btn = authenticated_page.locator("button:has-text('Seed Default Templates')").first
            expect(seed_btn).to_be_visible()

    def test_templates_page_create_form_toggle_works(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that clicking the create form header expands the form."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/templates")
        authenticated_page.wait_for_load_state("networkidle")

        # Click to expand create form
        create_header = authenticated_page.locator(".create-form-header")
        create_header.click()

        # Form body should be visible
        form_body = authenticated_page.locator(".create-form-body")
        expect(form_body).to_be_visible()

        # Check form fields are present
        expect(authenticated_page.locator("#name")).to_be_visible()
        expect(authenticated_page.locator("#command")).to_be_visible()

    def test_templates_page_has_breadcrumbs(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that breadcrumbs navigation is present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/templates")
        authenticated_page.wait_for_load_state("networkidle")

        # Check breadcrumbs
        breadcrumbs = authenticated_page.locator(".breadcrumbs")
        expect(breadcrumbs).to_be_visible()
        expect(breadcrumbs).to_contain_text("Bulk SSH Terminal")
        expect(breadcrumbs).to_contain_text("Templates")


class TestBulkSSHSchedules:
    """Tests for the Bulk SSH schedules page."""

    def test_schedules_page_loads(self, authenticated_page: Page, base_url: str):
        """Test that the schedules page loads successfully."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/schedules")
        authenticated_page.wait_for_load_state("networkidle")

        # Check page title
        expect(authenticated_page.locator("h2")).to_contain_text("Scheduled Jobs")

    def test_schedules_page_has_create_button(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the create schedule button is present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/schedules")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for create button (in the page header area, not the modal)
        create_btn = authenticated_page.locator(".page-header button:has-text('Create Schedule')")
        expect(create_btn).to_be_visible()

    def test_schedules_page_has_back_link(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the back to Bulk SSH link is present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/schedules")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for back link
        back_link = authenticated_page.locator("a:has-text('Back to Bulk SSH')")
        expect(back_link).to_be_visible()

    def test_schedules_page_shows_empty_state_or_list(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the schedules page shows either empty state or schedule list."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/schedules")
        authenticated_page.wait_for_load_state("networkidle")

        # Page should show either empty state OR schedule cards
        empty_state = authenticated_page.locator(".empty-state")
        schedules_list = authenticated_page.locator(".schedules-list")

        empty_visible = empty_state.count() > 0 and empty_state.is_visible()
        list_visible = schedules_list.count() > 0 and schedules_list.is_visible()

        assert empty_visible or list_visible, "Neither empty state nor schedules list is visible"

    def test_schedules_page_create_modal_opens(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that clicking create button opens the modal."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/schedules")
        authenticated_page.wait_for_load_state("networkidle")

        # Click create button
        create_btn = authenticated_page.locator("button:has-text('Create Schedule')").first
        create_btn.click()

        # Modal should be visible
        modal = authenticated_page.locator("#createModal")
        expect(modal).to_have_class("modal-overlay active")

        # Check modal title
        expect(authenticated_page.locator(".modal-header h3")).to_contain_text("Create Scheduled Job")

    def test_schedules_page_modal_has_form_fields(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the create modal has all required form fields."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/schedules")
        authenticated_page.wait_for_load_state("networkidle")

        # Open modal
        create_btn = authenticated_page.locator("button:has-text('Create Schedule')").first
        create_btn.click()

        # Check form fields
        expect(authenticated_page.locator("input[name='name']")).to_be_visible()
        expect(authenticated_page.locator("textarea[name='device_list']")).to_be_visible()
        expect(authenticated_page.locator("textarea[name='command']")).to_be_visible()
        expect(authenticated_page.locator("input[name='username']")).to_be_visible()
        expect(authenticated_page.locator("input[name='password']")).to_be_visible()

    def test_schedules_page_modal_has_schedule_type_options(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the modal has schedule type options."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/schedules")
        authenticated_page.wait_for_load_state("networkidle")

        # Open modal
        create_btn = authenticated_page.locator("button:has-text('Create Schedule')").first
        create_btn.click()

        # Check schedule type options
        expect(authenticated_page.locator(".schedule-type-option:has-text('One-time')")).to_be_visible()
        expect(authenticated_page.locator(".schedule-type-option:has-text('Daily')")).to_be_visible()
        expect(authenticated_page.locator(".schedule-type-option:has-text('Weekly')")).to_be_visible()

    def test_schedules_page_modal_can_close(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the modal can be closed."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/schedules")
        authenticated_page.wait_for_load_state("networkidle")

        # Open modal
        create_btn = authenticated_page.locator("button:has-text('Create Schedule')").first
        create_btn.click()

        # Close modal using cancel button
        cancel_btn = authenticated_page.locator(".modal-footer button:has-text('Cancel')")
        cancel_btn.click()

        # Modal should not have active class
        modal = authenticated_page.locator("#createModal")
        expect(modal).not_to_have_class("modal-overlay active")

    def test_schedules_page_has_breadcrumbs(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that breadcrumbs navigation is present."""
        authenticated_page.goto(f"{base_url}/tools/bulk-ssh/schedules")
        authenticated_page.wait_for_load_state("networkidle")

        # Check breadcrumbs
        breadcrumbs = authenticated_page.locator(".breadcrumbs")
        expect(breadcrumbs).to_be_visible()
        expect(breadcrumbs).to_contain_text("Bulk SSH Terminal")
        expect(breadcrumbs).to_contain_text("Schedules")


class TestBulkSSHAccessControl:
    """Tests for Bulk SSH access control."""

    def test_unauthenticated_user_redirected_from_bulk_ssh(
        self, page: Page, base_url: str
    ):
        """Test that unauthenticated users are redirected to login."""
        page.goto(f"{base_url}/tools/bulk-ssh")
        page.wait_for_load_state("networkidle")

        # Should be redirected to login
        assert "/login" in page.url

    def test_unauthenticated_user_redirected_from_templates(
        self, page: Page, base_url: str
    ):
        """Test that unauthenticated users are redirected from templates page."""
        page.goto(f"{base_url}/tools/bulk-ssh/templates")
        page.wait_for_load_state("networkidle")

        # Should be redirected to login
        assert "/login" in page.url

    def test_unauthenticated_user_redirected_from_schedules(
        self, page: Page, base_url: str
    ):
        """Test that unauthenticated users are redirected from schedules page."""
        page.goto(f"{base_url}/tools/bulk-ssh/schedules")
        page.wait_for_load_state("networkidle")

        # Should be redirected to login
        assert "/login" in page.url

    def test_regular_user_can_access_bulk_ssh(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that regular users can access the Bulk SSH page."""
        user_authenticated_page.goto(f"{base_url}/tools/bulk-ssh")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected to login
        assert "/login" not in user_authenticated_page.url

        # Page should load successfully
        expect(user_authenticated_page.locator("h2")).to_contain_text("Bulk SSH Terminal")

    def test_regular_user_can_access_templates(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that regular users can access the templates page."""
        user_authenticated_page.goto(f"{base_url}/tools/bulk-ssh/templates")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected to login
        assert "/login" not in user_authenticated_page.url

        # Page should load successfully
        expect(user_authenticated_page.locator("h2")).to_contain_text("Command Templates")

    def test_regular_user_can_access_schedules(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that regular users can access the schedules page."""
        user_authenticated_page.goto(f"{base_url}/tools/bulk-ssh/schedules")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected to login
        assert "/login" not in user_authenticated_page.url

        # Page should load successfully
        expect(user_authenticated_page.locator("h2")).to_contain_text("Scheduled Jobs")
