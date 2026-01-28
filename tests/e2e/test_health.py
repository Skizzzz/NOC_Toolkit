"""
Basic health check E2E test for NOC Toolkit.

This test verifies that the test infrastructure is working correctly
by testing the health endpoint.
"""

import pytest


def test_health_endpoint(page, base_url):
    """Test that the health endpoint returns successfully."""
    response = page.goto(f"{base_url}/health")

    # Verify successful response
    assert response is not None
    assert response.status == 200

    # Verify response content
    content = page.content()
    assert "healthy" in content


def test_login_page_loads(page, base_url):
    """Test that the login page loads successfully."""
    page.goto(f"{base_url}/login")

    # Wait for page to load
    page.wait_for_load_state("networkidle")

    # Check that login form elements exist
    username_input = page.locator('input[name="username"]')
    password_input = page.locator('input[name="password"]')
    submit_button = page.locator('button[type="submit"]')

    assert username_input.is_visible()
    assert password_input.is_visible()
    assert submit_button.is_visible()
