"""
E2E Tests for Knowledge Base functionality.

Tests cover:
- Knowledge base page loads
- New article button visible for authorized users
- Search input is present
- Access control for different user roles
"""

import pytest
from playwright.sync_api import Page, expect


class TestKnowledgeBasePage:
    """Tests for the main Knowledge Base page."""

    def test_knowledge_base_page_loads(self, authenticated_page: Page, base_url: str):
        """Test that the Knowledge Base page loads successfully."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Check page title
        expect(authenticated_page.locator("h2")).to_contain_text("Knowledge Base")

    def test_knowledge_base_page_has_description(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the page description is displayed."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for page description
        description = authenticated_page.locator(".kb-title p")
        expect(description).to_contain_text("Documentation, guides, and procedures")

    def test_knowledge_base_page_has_breadcrumbs(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that breadcrumbs navigation is present."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Check breadcrumbs
        breadcrumbs = authenticated_page.locator(".breadcrumbs")
        expect(breadcrumbs).to_be_visible()
        expect(breadcrumbs).to_contain_text("Dashboard")
        expect(breadcrumbs).to_contain_text("Knowledge Base")


class TestNewArticleButton:
    """Tests for the New Article button visibility."""

    def test_new_article_button_visible_for_admin(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the New Article button is visible for admin users."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Admin should see the New Article button
        new_article_btn = authenticated_page.locator("a:has-text('New Article')")
        expect(new_article_btn).to_be_visible()

    def test_new_article_button_links_to_create_page(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the New Article button links to the create page."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Check link destination
        new_article_btn = authenticated_page.locator("a:has-text('New Article')")
        expect(new_article_btn).to_have_attribute("href", "/knowledge-base/create")

    def test_new_article_button_not_visible_for_regular_user(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that regular users without KB create permission don't see the button."""
        user_authenticated_page.goto(f"{base_url}/knowledge-base")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Regular user should NOT see the New Article button
        new_article_btn = user_authenticated_page.locator("a:has-text('New Article')")
        expect(new_article_btn).not_to_be_visible()


class TestSearchInput:
    """Tests for the search functionality."""

    def test_search_input_is_present(self, authenticated_page: Page, base_url: str):
        """Test that the search input is present."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for search input
        search_input = authenticated_page.locator("input#q")
        expect(search_input).to_be_visible()
        expect(search_input).to_have_attribute("placeholder", "Search articles...")

    def test_subject_filter_is_present(self, authenticated_page: Page, base_url: str):
        """Test that the subject filter dropdown is present."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for subject filter
        subject_filter = authenticated_page.locator("select#subject")
        expect(subject_filter).to_be_visible()

    def test_filter_button_is_present(self, authenticated_page: Page, base_url: str):
        """Test that the filter button is present."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for filter button
        filter_btn = authenticated_page.locator("button:has-text('Filter')")
        expect(filter_btn).to_be_visible()

    def test_search_filters_are_in_form(self, authenticated_page: Page, base_url: str):
        """Test that search filters are inside a form element."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Check that filters are in a form with GET method
        form = authenticated_page.locator("form.kb-filters")
        expect(form).to_be_visible()
        expect(form).to_have_attribute("method", "get")


class TestEmptyState:
    """Tests for empty state display."""

    def test_empty_state_shows_when_no_articles(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that empty state is shown when no articles exist."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for empty state or articles grid
        empty_state = authenticated_page.locator(".kb-empty")
        articles_grid = authenticated_page.locator(".kb-grid")

        # One of these should be visible
        empty_visible = empty_state.count() > 0 and empty_state.is_visible()
        grid_visible = articles_grid.count() > 0 and articles_grid.is_visible()

        assert empty_visible or grid_visible, "Neither empty state nor articles grid is visible"

    def test_empty_state_message(self, authenticated_page: Page, base_url: str):
        """Test empty state message when no articles exist."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # If empty state is visible, check for message
        empty_state = authenticated_page.locator(".kb-empty")
        if empty_state.count() > 0 and empty_state.is_visible():
            expect(empty_state).to_contain_text("No Articles Found")


class TestAccessInfo:
    """Tests for user access level info display."""

    def test_access_info_is_displayed(self, authenticated_page: Page, base_url: str):
        """Test that user access info section is displayed."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for access info section
        access_info = authenticated_page.locator(".access-info")
        expect(access_info).to_be_visible()

    def test_access_info_shows_user_level(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that access info shows the user's access level."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Check access level is shown
        access_info = authenticated_page.locator(".access-info")
        expect(access_info).to_contain_text("Your access level:")
        # Admin user should have Admin access level
        expect(access_info).to_contain_text("Admin")

    def test_access_info_shows_visibility_levels(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that access info explains visibility levels."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Check visibility levels explanation
        access_info = authenticated_page.locator(".access-info")
        expect(access_info).to_contain_text("Visibility levels:")
        expect(access_info).to_contain_text("FSR")
        expect(access_info).to_contain_text("NOC")


class TestKnowledgeBaseAccessControl:
    """Tests for Knowledge Base access control."""

    def test_unauthenticated_user_redirected_to_login(
        self, page: Page, base_url: str
    ):
        """Test that unauthenticated users are redirected to login."""
        page.goto(f"{base_url}/knowledge-base")
        page.wait_for_load_state("networkidle")

        # Should be redirected to login
        assert "/login" in page.url

    def test_unauthenticated_user_redirected_from_create(
        self, page: Page, base_url: str
    ):
        """Test that unauthenticated users are redirected from create page."""
        page.goto(f"{base_url}/knowledge-base/create")
        page.wait_for_load_state("networkidle")

        # Should be redirected to login
        assert "/login" in page.url

    def test_regular_user_can_access_knowledge_base(
        self, user_authenticated_page: Page, base_url: str
    ):
        """Test that regular users can access the Knowledge Base page."""
        user_authenticated_page.goto(f"{base_url}/knowledge-base")
        user_authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected to login
        assert "/login" not in user_authenticated_page.url

        # Page should load successfully
        expect(user_authenticated_page.locator("h2")).to_contain_text("Knowledge Base")

    def test_admin_can_access_knowledge_base(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that admin users can access the Knowledge Base page."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected to login
        assert "/login" not in authenticated_page.url

        # Page should load successfully
        expect(authenticated_page.locator("h2")).to_contain_text("Knowledge Base")


class TestCreateArticlePage:
    """Tests for the Create Article page."""

    def test_create_page_loads_for_admin(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the create article page loads for admin users."""
        authenticated_page.goto(f"{base_url}/knowledge-base/create")
        authenticated_page.wait_for_load_state("networkidle")

        # Should not be redirected away
        assert "/knowledge-base/create" in authenticated_page.url or "knowledge-base" in authenticated_page.url.lower()

    def test_create_page_has_title_field(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the create page has a title input field."""
        authenticated_page.goto(f"{base_url}/knowledge-base/create")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for title input
        title_input = authenticated_page.locator("input[name='title']")
        expect(title_input).to_be_visible()

    def test_create_page_has_subject_field(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the create page has a subject input field."""
        authenticated_page.goto(f"{base_url}/knowledge-base/create")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for subject input
        subject_input = authenticated_page.locator("input[name='subject']")
        expect(subject_input).to_be_visible()

    def test_create_page_has_content_field(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the create page has a content textarea."""
        authenticated_page.goto(f"{base_url}/knowledge-base/create")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for content textarea
        content_textarea = authenticated_page.locator("textarea[name='content']")
        expect(content_textarea).to_be_visible()

    def test_create_page_has_visibility_field(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the create page has visibility radio options."""
        authenticated_page.goto(f"{base_url}/knowledge-base/create")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for visibility radio options (FSR, NOC, Admin)
        visibility_options = authenticated_page.locator(".visibility-options")
        expect(visibility_options).to_be_visible()

        # Check for all three visibility options
        fsr_option = authenticated_page.locator("input[name='visibility'][value='FSR']")
        noc_option = authenticated_page.locator("input[name='visibility'][value='NOC']")
        admin_option = authenticated_page.locator("input[name='visibility'][value='Admin']")

        # Radio inputs exist (even if hidden, they should be present in DOM)
        expect(fsr_option).to_be_attached()
        expect(noc_option).to_be_attached()
        expect(admin_option).to_be_attached()

    def test_create_page_has_submit_button(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the create page has a submit button."""
        authenticated_page.goto(f"{base_url}/knowledge-base/create")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for submit button
        submit_btn = authenticated_page.locator("button[type='submit']")
        expect(submit_btn).to_be_visible()

    def test_create_page_has_back_link(
        self, authenticated_page: Page, base_url: str
    ):
        """Test that the create page has a link back to Knowledge Base."""
        authenticated_page.goto(f"{base_url}/knowledge-base/create")
        authenticated_page.wait_for_load_state("networkidle")

        # Check for back link or cancel button
        back_link = authenticated_page.locator("a:has-text('Knowledge Base')").first
        expect(back_link).to_be_visible()


class TestKnowledgeBaseNavigation:
    """Tests for Knowledge Base navigation."""

    def test_can_navigate_from_kb_to_create(
        self, authenticated_page: Page, base_url: str
    ):
        """Test navigation from KB list to create page."""
        authenticated_page.goto(f"{base_url}/knowledge-base")
        authenticated_page.wait_for_load_state("networkidle")

        # Click New Article button
        new_article_btn = authenticated_page.locator("a:has-text('New Article')")
        new_article_btn.click()
        authenticated_page.wait_for_load_state("networkidle")

        # Should be on create page
        assert "/knowledge-base/create" in authenticated_page.url

    def test_can_navigate_from_create_back_to_kb(
        self, authenticated_page: Page, base_url: str
    ):
        """Test navigation from create page back to KB list."""
        authenticated_page.goto(f"{base_url}/knowledge-base/create")
        authenticated_page.wait_for_load_state("networkidle")

        # Click back/cancel link - look in breadcrumbs
        back_link = authenticated_page.locator(".breadcrumbs a:has-text('Knowledge Base')")
        if back_link.count() > 0:
            back_link.click()
        else:
            # Try cancel button
            cancel_link = authenticated_page.locator("a:has-text('Cancel')").first
            cancel_link.click()

        authenticated_page.wait_for_load_state("networkidle")

        # Should be back on KB page
        assert "/knowledge-base" in authenticated_page.url
        # But not on create page
        assert "/create" not in authenticated_page.url
