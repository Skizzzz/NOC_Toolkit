"""
E2E tests for admin functionality.

Tests user management, page settings, and access control for the NOC Toolkit.
"""

import pytest
from playwright.sync_api import Page, expect


class TestCreateUser:
    """Tests for creating new users."""

    def test_create_new_user(self, authenticated_page: Page, base_url: str):
        """Test that admin can create a new user."""
        # Navigate to admin users page
        authenticated_page.goto(f"{base_url}/admin/users")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify we're on the admin users page
        expect(authenticated_page.locator("h2.section-title")).to_contain_text(
            "User Management"
        )

        # Fill in the create user form
        # The form is inside a <details> element that should be open by default
        authenticated_page.fill('input[name="username"]', "newuser123")
        authenticated_page.fill('input[name="password"]', "SecurePass123!")
        authenticated_page.select_option('select[name="role"]', "user")
        authenticated_page.select_option('select[name="kb_access_level"]', "NOC")

        # Click create user button
        authenticated_page.click('button[type="submit"]:has-text("Create User")')
        authenticated_page.wait_for_load_state("networkidle")

        # Verify success message (base.html uses .flash class without category distinction)
        flash_message = authenticated_page.locator(".flash")
        expect(flash_message).to_be_visible()
        expect(flash_message).to_contain_text("newuser123")
        expect(flash_message).to_contain_text("created successfully")

        # Verify user appears in the table
        user_table = authenticated_page.locator("table.simple-table")
        expect(user_table).to_contain_text("newuser123")

    def test_create_user_with_short_password_shows_error(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that creating a user with a short password shows an error."""
        # Navigate to admin users page
        authenticated_page.goto(f"{base_url}/admin/users")
        authenticated_page.wait_for_load_state("networkidle")

        # Fill in form with short password
        authenticated_page.fill('input[name="username"]', "shortpwuser")
        # Note: HTML5 minlength validation prevents submission, so we need to bypass it
        # by removing the minlength attribute before filling
        authenticated_page.evaluate(
            "document.querySelector('input[name=\"password\"]').removeAttribute('minlength')"
        )
        authenticated_page.fill('input[name="password"]', "short")  # Less than 8 chars
        authenticated_page.select_option('select[name="role"]', "user")

        # Click create user button
        authenticated_page.click('button[type="submit"]:has-text("Create User")')
        authenticated_page.wait_for_load_state("networkidle")

        # Verify error message about password length (base.html uses .flash class)
        # The server-side validation should show the error
        flash_messages = authenticated_page.locator(".flash")
        # Check the last flash message (the login welcome message may also be present)
        page_content = authenticated_page.content()
        assert "Password must be at least 8 characters" in page_content, \
            f"Expected password error message in page content"

    def test_create_user_with_duplicate_username_shows_error(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that creating a user with an existing username shows an error."""
        # Navigate to admin users page
        authenticated_page.goto(f"{base_url}/admin/users")
        authenticated_page.wait_for_load_state("networkidle")

        # Try to create a user with the existing 'admin' username
        authenticated_page.fill('input[name="username"]', "admin")
        authenticated_page.fill('input[name="password"]', "SecurePass123!")
        authenticated_page.select_option('select[name="role"]', "user")

        # Click create user button
        authenticated_page.click('button[type="submit"]:has-text("Create User")')
        authenticated_page.wait_for_load_state("networkidle")

        # Verify error message about duplicate username (base.html uses .flash class)
        flash_message = authenticated_page.locator(".flash")
        expect(flash_message).to_be_visible()
        expect(flash_message).to_contain_text("already exists")


class TestEditUserRole:
    """Tests for editing user roles and permissions."""

    def test_edit_user_kb_permissions(self, authenticated_page: Page, base_url: str):
        """Test that admin can edit a user's KB access level."""
        # Navigate to admin users page
        authenticated_page.goto(f"{base_url}/admin/users")
        authenticated_page.wait_for_load_state("networkidle")

        # Find the testuser row and update their KB permissions
        # The testuser is created by the seeded_db fixture
        user_rows = authenticated_page.locator("tr.user-row")

        # Find the row for testuser
        testuser_row = None
        for i in range(user_rows.count()):
            row = user_rows.nth(i)
            if "testuser" in row.inner_text():
                testuser_row = row
                break

        assert testuser_row is not None, "testuser not found in users table"

        # Change KB access level from FSR to NOC
        kb_select = testuser_row.locator('select[name="kb_access_level"]')
        kb_select.select_option("NOC")

        # Click the Save button for this row
        save_button = testuser_row.locator('button[type="submit"]:has-text("Save")')
        save_button.click()
        authenticated_page.wait_for_load_state("networkidle")

        # Verify success message (base.html uses .flash class)
        flash_message = authenticated_page.locator(".flash")
        expect(flash_message).to_be_visible()
        expect(flash_message).to_contain_text("KB permissions updated")

        # Verify the change persisted
        authenticated_page.reload()
        authenticated_page.wait_for_load_state("networkidle")

        # Find testuser row again and verify the select value
        user_rows = authenticated_page.locator("tr.user-row")
        for i in range(user_rows.count()):
            row = user_rows.nth(i)
            if "testuser" in row.inner_text():
                kb_select = row.locator('select[name="kb_access_level"]')
                expect(kb_select).to_have_value("NOC")
                break

    def test_toggle_user_kb_create_permission(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that admin can toggle a user's KB create permission."""
        # Navigate to admin users page
        authenticated_page.goto(f"{base_url}/admin/users")
        authenticated_page.wait_for_load_state("networkidle")

        # Find the testuser row
        user_rows = authenticated_page.locator("tr.user-row")
        testuser_row = None
        for i in range(user_rows.count()):
            row = user_rows.nth(i)
            if "testuser" in row.inner_text():
                testuser_row = row
                break

        assert testuser_row is not None, "testuser not found in users table"

        # Toggle the can_create_kb checkbox (should be unchecked initially for testuser)
        create_checkbox = testuser_row.locator('input[name="can_create_kb"]')

        # Check if it's currently unchecked and check it
        if not create_checkbox.is_checked():
            create_checkbox.check()
        else:
            create_checkbox.uncheck()

        # Save the change
        save_button = testuser_row.locator('button[type="submit"]:has-text("Save")')
        save_button.click()
        authenticated_page.wait_for_load_state("networkidle")

        # Verify success message (base.html uses .flash class)
        flash_message = authenticated_page.locator(".flash")
        expect(flash_message).to_be_visible()


class TestTogglePageVisibility:
    """Tests for page visibility settings."""

    def test_toggle_page_visibility(self, authenticated_page: Page, base_url: str):
        """Test that admin can toggle page visibility."""
        # Navigate to page settings
        authenticated_page.goto(f"{base_url}/admin/page-settings")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify we're on the page settings page
        expect(authenticated_page.locator("h2.section-title")).to_contain_text(
            "Page Visibility Settings"
        )

        # Find a page toggle (e.g., bulk-ssh)
        # The checkbox is hidden (opacity:0) inside a toggle-switch, so we click the slider
        bulk_ssh_checkbox = authenticated_page.locator('input[name="page_bulk-ssh"]')
        bulk_ssh_toggle = authenticated_page.locator(
            'input[name="page_bulk-ssh"] + span.toggle-slider'
        )

        # Get current state
        was_checked = bulk_ssh_checkbox.is_checked()

        # Toggle it by clicking the visible slider
        bulk_ssh_toggle.click()

        # Save changes
        authenticated_page.click('button[type="submit"]:has-text("Save Changes")')
        authenticated_page.wait_for_load_state("networkidle")

        # Verify success message (base.html uses .flash class)
        flash_message = authenticated_page.locator(".flash")
        expect(flash_message).to_be_visible()
        expect(flash_message).to_contain_text("Page visibility settings updated")

        # Reload and verify change persisted
        authenticated_page.reload()
        authenticated_page.wait_for_load_state("networkidle")

        bulk_ssh_checkbox = authenticated_page.locator('input[name="page_bulk-ssh"]')
        if was_checked:
            expect(bulk_ssh_checkbox).not_to_be_checked()
        else:
            expect(bulk_ssh_checkbox).to_be_checked()

        # Toggle back to original state for cleanup
        bulk_ssh_toggle = authenticated_page.locator(
            'input[name="page_bulk-ssh"] + span.toggle-slider'
        )
        bulk_ssh_toggle.click()
        authenticated_page.click('button[type="submit"]:has-text("Save Changes")')
        authenticated_page.wait_for_load_state("networkidle")

    def test_enable_all_pages_button(self, authenticated_page: Page, base_url: str):
        """Test that the 'Enable All' button works."""
        # Navigate to page settings
        authenticated_page.goto(f"{base_url}/admin/page-settings")
        authenticated_page.wait_for_load_state("networkidle")

        # First disable a page to have something to enable
        # The checkbox is hidden, so click the slider instead
        bulk_ssh_toggle = authenticated_page.locator(
            'input[name="page_bulk-ssh"] + span.toggle-slider'
        )
        bulk_ssh_checkbox = authenticated_page.locator('input[name="page_bulk-ssh"]')

        # Disable it first if it's enabled
        if bulk_ssh_checkbox.is_checked():
            bulk_ssh_toggle.click()

        # Click Enable All
        authenticated_page.click('button:has-text("Enable All")')

        # Verify bulk-ssh is now checked (after Enable All)
        expect(bulk_ssh_checkbox).to_be_checked()

        # Save and verify
        authenticated_page.click('button[type="submit"]:has-text("Save Changes")')
        authenticated_page.wait_for_load_state("networkidle")

        flash_message = authenticated_page.locator(".flash")
        expect(flash_message).to_be_visible()

    def test_disable_all_pages_button(self, authenticated_page: Page, base_url: str):
        """Test that the 'Disable All' button works."""
        # Navigate to page settings
        authenticated_page.goto(f"{base_url}/admin/page-settings")
        authenticated_page.wait_for_load_state("networkidle")

        # Click Disable All
        authenticated_page.click('button:has-text("Disable All")')

        # Verify all toggles are unchecked
        all_checkboxes = authenticated_page.locator('.toggle-switch input[type="checkbox"]')
        for i in range(all_checkboxes.count()):
            expect(all_checkboxes.nth(i)).not_to_be_checked()

        # Don't save - re-enable all to restore state
        authenticated_page.click('button:has-text("Enable All")')
        authenticated_page.click('button[type="submit"]:has-text("Save Changes")')
        authenticated_page.wait_for_load_state("networkidle")


class TestAdminAccessControl:
    """Tests for admin page access control."""

    def test_non_admin_cannot_access_admin_users_page(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that non-admin users cannot access the admin users page."""
        # user_authenticated_page is logged in as 'testuser' (regular user)
        # Try to access admin users page
        user_authenticated_page.goto(f"{base_url}/admin/users")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Should be redirected to login or show unauthorized
        # The @require_superadmin decorator should block access
        page_content = user_authenticated_page.content().lower()

        # Check that we're either redirected to login or see an unauthorized message
        # or are not on the admin users page
        assert (
            "/login" in user_authenticated_page.url
            or "unauthorized" in page_content
            or "forbidden" in page_content
            or "access denied" in page_content
            or "user management" not in page_content
        ), "Non-admin user should not be able to access admin users page"

    def test_non_admin_cannot_access_page_settings(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that non-admin users cannot access page settings."""
        # Try to access page settings
        user_authenticated_page.goto(f"{base_url}/admin/page-settings")
        user_authenticated_page.wait_for_load_state("networkidle")

        page_content = user_authenticated_page.content().lower()

        # Should be redirected or blocked
        assert (
            "/login" in user_authenticated_page.url
            or "unauthorized" in page_content
            or "forbidden" in page_content
            or "access denied" in page_content
            or "page visibility settings" not in page_content
        ), "Non-admin user should not be able to access page settings"

    def test_non_admin_cannot_access_app_settings(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that non-admin users cannot access app settings."""
        # Try to access app settings
        user_authenticated_page.goto(f"{base_url}/admin/settings")
        user_authenticated_page.wait_for_load_state("networkidle")

        page_content = user_authenticated_page.content().lower()

        # Should be redirected or blocked
        assert (
            "/login" in user_authenticated_page.url
            or "unauthorized" in page_content
            or "forbidden" in page_content
            or "access denied" in page_content
            or "application settings" not in page_content
        ), "Non-admin user should not be able to access app settings"

    def test_unauthenticated_user_cannot_access_admin_pages(
        self, page: Page, base_url: str
    ):
        """Test that unauthenticated users are redirected to login."""
        # Try to access admin pages without being logged in
        page.goto(f"{base_url}/admin/users")
        page.wait_for_load_state("networkidle")

        # Should be redirected to login
        assert "/login" in page.url, "Unauthenticated user should be redirected to login"

    def test_admin_can_access_all_admin_pages(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that admin users can access all admin pages."""
        # Test admin/users
        authenticated_page.goto(f"{base_url}/admin/users")
        authenticated_page.wait_for_load_state("networkidle")
        assert "/login" not in authenticated_page.url
        expect(authenticated_page.locator("h2.section-title")).to_contain_text(
            "User Management"
        )

        # Test admin/page-settings
        authenticated_page.goto(f"{base_url}/admin/page-settings")
        authenticated_page.wait_for_load_state("networkidle")
        assert "/login" not in authenticated_page.url
        expect(authenticated_page.locator("h2.section-title")).to_contain_text(
            "Page Visibility Settings"
        )

        # Test admin/settings
        authenticated_page.goto(f"{base_url}/admin/settings")
        authenticated_page.wait_for_load_state("networkidle")
        assert "/login" not in authenticated_page.url
        # App settings page should have timezone setting
        expect(authenticated_page.locator("form")).to_be_visible()
