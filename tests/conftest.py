"""
Pytest configuration and fixtures for NOC Toolkit tests.

This file provides shared fixtures for all tests, including:
- Flask application factory
- Test client
- Database setup/teardown
- Test data seeding
"""

import os
import pytest
from typing import Generator

# Set testing environment before importing app
os.environ["FLASK_ENV"] = "testing"

from src.app import create_app
from src.models import db, User, PageSettings


@pytest.fixture(scope="session")
def app():
    """
    Create a Flask application configured for testing.

    This fixture creates a single application instance for the entire
    test session with an in-memory SQLite database.
    """
    application = create_app("testing")

    # Create application context and database tables
    with application.app_context():
        db.create_all()
        yield application
        db.drop_all()


@pytest.fixture(scope="function")
def app_context(app):
    """
    Provide a fresh application context for each test function.
    """
    with app.app_context():
        yield app


@pytest.fixture(scope="function")
def client(app):
    """
    Create a test client for the Flask application.

    This fixture provides a test client that can be used to make
    requests to the application without running a server.
    """
    return app.test_client()


@pytest.fixture(scope="function")
def db_session(app) -> Generator:
    """
    Create a clean database session for each test.

    This fixture creates all tables before the test and clears
    them after, ensuring test isolation.
    """
    with app.app_context():
        db.create_all()
        yield db.session
        db.session.rollback()
        # Clean up all tables
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()


@pytest.fixture
def admin_user(db_session) -> User:
    """
    Create an admin user for testing.

    Returns a superadmin user with full permissions.
    """
    user = User(
        username="admin",
        role="superadmin",
        kb_access_level="Admin",
        can_create_kb=True,
    )
    user.set_password("TestPassword123!")
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def regular_user(db_session) -> User:
    """
    Create a regular user for testing.

    Returns a standard user with limited permissions.
    """
    user = User(
        username="testuser",
        role="user",
        kb_access_level="FSR",
        can_create_kb=False,
    )
    user.set_password("TestPassword123!")
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def page_settings(db_session) -> list[PageSettings]:
    """
    Create default page settings for testing.

    Returns a list of PageSettings with all pages enabled.
    """
    pages = [
        PageSettings(page_key="wlc-dashboard", page_name="WLC Dashboard", enabled=True, category="WLC Tools"),
        PageSettings(page_key="ap-inventory", page_name="AP Inventory", enabled=True, category="WLC Tools"),
        PageSettings(page_key="solarwinds-nodes", page_name="SolarWinds Nodes", enabled=True, category="SolarWinds"),
        PageSettings(page_key="solarwinds-inventory", page_name="SolarWinds Inventory", enabled=True, category="SolarWinds"),
        PageSettings(page_key="bulk-ssh", page_name="Bulk SSH", enabled=True, category="SSH Tools"),
        PageSettings(page_key="phrase-search", page_name="Phrase Search", enabled=True, category="Config"),
        PageSettings(page_key="global-config", page_name="Global Config", enabled=True, category="Config"),
        PageSettings(page_key="cert-tracker", page_name="Certificate Tracker", enabled=True, category="Certificates"),
        PageSettings(page_key="ise-nodes", page_name="ISE Nodes", enabled=True, category="Certificates"),
        PageSettings(page_key="knowledge-base", page_name="Knowledge Base", enabled=True, category="Documentation"),
        PageSettings(page_key="changes", page_name="Change Windows", enabled=True, category="Config"),
    ]
    for page in pages:
        db_session.add(page)
    db_session.commit()
    return pages
