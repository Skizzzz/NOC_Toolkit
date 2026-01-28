#!/usr/bin/env python3
"""
Database initialization script for NOC Toolkit.

This script initializes the database for first-time setup:
1. Creates all tables using Alembic migrations
2. Stamps the database with the current migration version
3. Seeds initial data (page settings, app settings)

Usage:
    python scripts/init_db.py

Environment Variables:
    DATABASE_URL: PostgreSQL connection string (optional, defaults to config)
    FLASK_ENV: Application environment (development|production|testing)
"""

import os
import sys

# Add project root to path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from flask_migrate import upgrade, stamp
from src.app import create_app
from src.models import db


def init_database() -> bool:
    """
    Initialize the database with migrations and seed data.

    Returns:
        True if successful, False otherwise
    """
    # Determine environment
    env = os.environ.get("FLASK_ENV", "development")
    print(f"Initializing database for environment: {env}")

    # Create Flask app
    app = create_app(env)

    with app.app_context():
        try:
            # Run all migrations to create tables
            print("Running database migrations...")
            upgrade()

            # Stamp the database with the current migration version
            print("Stamping database with current migration version...")
            stamp()

            # Seed initial data
            print("Seeding initial data...")
            seed_initial_data()

            print("Database initialization complete!")
            return True

        except Exception as e:
            print(f"Error initializing database: {e}")
            import traceback
            traceback.print_exc()
            return False


def seed_initial_data() -> None:
    """
    Seed the database with initial required data.

    This includes:
    - Page settings for all available pages
    - App settings with default values
    """
    from src.models import AppSettings, PageSettings

    # Seed app settings (singleton)
    existing_settings = AppSettings.query.first()
    if not existing_settings:
        print("  Creating default app settings...")
        settings = AppSettings(id=1, timezone="America/Chicago")
        db.session.add(settings)
    else:
        print("  App settings already exist, skipping...")

    # Seed page settings
    default_pages = [
        # WLC Tools
        ("wlc-dashboard", "WLC Dashboard", True, "WLC"),
        ("wlc-ap-inventory", "AP Inventory", True, "WLC"),
        ("wlc-summer-guest", "Summer Guest SSID", True, "WLC"),
        ("wlc-rf", "WLC RF Analysis", True, "WLC"),
        ("wlc-rf-troubleshoot", "WLC RF Troubleshoot", True, "WLC"),
        ("wlc-clients-troubleshoot", "WLC Clients Troubleshoot", True, "WLC"),
        # SolarWinds Tools
        ("solarwinds-nodes", "SolarWinds Nodes", True, "SolarWinds"),
        ("solarwinds-inventory", "SolarWinds Inventory", True, "SolarWinds"),
        # Config Tools
        ("phrase-search", "Phrase Search", True, "Config"),
        ("global-config", "Global Config", True, "Config"),
        ("changes", "Change Windows", True, "Config"),
        # SSH Tools
        ("bulk-ssh", "Bulk SSH", True, "SSH"),
        # Certificate Tools
        ("cert-tracker", "Certificate Tracker", True, "Certs"),
        ("cert-converter", "Certificate Converter", True, "Certs"),
        ("cert-chain", "Certificate Chain", True, "Certs"),
        ("ise-nodes", "ISE Nodes", True, "Certs"),
        # Other Tools
        ("jobs", "Jobs Center", True, "System"),
        ("knowledge-base", "Knowledge Base", True, "KB"),
        ("audit-logs", "Audit Logs", True, "System"),
    ]

    pages_created = 0
    for page_key, page_name, enabled, category in default_pages:
        existing = PageSettings.query.filter_by(page_key=page_key).first()
        if not existing:
            page = PageSettings(
                page_key=page_key,
                page_name=page_name,
                enabled=enabled,
                category=category,
            )
            db.session.add(page)
            pages_created += 1

    if pages_created > 0:
        print(f"  Created {pages_created} page settings...")
    else:
        print("  Page settings already exist, skipping...")

    # Commit all changes
    db.session.commit()


def reset_database() -> bool:
    """
    Reset the database by dropping all tables and reinitializing.

    WARNING: This will delete all data!

    Returns:
        True if successful, False otherwise
    """
    env = os.environ.get("FLASK_ENV", "development")

    # Safety check - don't allow reset in production without explicit override
    if env == "production" and not os.environ.get("ALLOW_DB_RESET"):
        print("ERROR: Cannot reset database in production without ALLOW_DB_RESET=1")
        return False

    print(f"WARNING: This will delete ALL data in the {env} database!")
    confirm = input("Type 'RESET' to confirm: ")
    if confirm != "RESET":
        print("Reset cancelled.")
        return False

    app = create_app(env)

    with app.app_context():
        try:
            print("Dropping all tables...")
            db.drop_all()

            print("Recreating tables...")
            return init_database()

        except Exception as e:
            print(f"Error resetting database: {e}")
            return False


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NOC Toolkit Database Initialization")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset database (WARNING: deletes all data)",
    )
    args = parser.parse_args()

    if args.reset:
        success = reset_database()
    else:
        success = init_database()

    sys.exit(0 if success else 1)
