#!/usr/bin/env python3
"""
Test database seeding script for NOC Toolkit.

This script creates test data in the database for manual testing
or E2E test preparation. It can be run standalone or imported
as a module.

Usage:
    python tests/seed_test_data.py              # Seed test data
    python tests/seed_test_data.py --reset      # Clear and reseed
    python tests/seed_test_data.py --clear      # Clear data only
"""

import os
import sys
import argparse
from datetime import datetime, timedelta

# Add project root to path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Set testing environment
os.environ.setdefault("FLASK_ENV", "testing")


def create_test_users(db_session):
    """Create test users with various roles and permissions."""
    from src.models import User

    users_data = [
        {
            "username": "admin",
            "password": "TestPassword123!",
            "role": "superadmin",
            "kb_access_level": "Admin",
            "can_create_kb": True,
        },
        {
            "username": "noc_user",
            "password": "TestPassword123!",
            "role": "user",
            "kb_access_level": "NOC",
            "can_create_kb": True,
        },
        {
            "username": "fsr_user",
            "password": "TestPassword123!",
            "role": "user",
            "kb_access_level": "FSR",
            "can_create_kb": False,
        },
        {
            "username": "readonly_user",
            "password": "TestPassword123!",
            "role": "user",
            "kb_access_level": "FSR",
            "can_create_kb": False,
        },
    ]

    users = []
    for data in users_data:
        user = User(
            username=data["username"],
            role=data["role"],
            kb_access_level=data["kb_access_level"],
            can_create_kb=data["can_create_kb"],
        )
        user.set_password(data["password"])
        db_session.add(user)
        users.append(user)

    db_session.commit()
    print(f"Created {len(users)} test users")
    return users


def create_page_settings(db_session):
    """Create default page settings with all pages enabled."""
    from src.models import PageSettings

    pages_data = [
        ("wlc-dashboard", "WLC Dashboard", "WLC Tools"),
        ("ap-inventory", "AP Inventory", "WLC Tools"),
        ("wlc-rf", "WLC RF Analysis", "WLC Tools"),
        ("wlc-summer-guest", "Summer Guest", "WLC Tools"),
        ("solarwinds-nodes", "SolarWinds Nodes", "SolarWinds"),
        ("solarwinds-inventory", "SolarWinds Inventory", "SolarWinds"),
        ("bulk-ssh", "Bulk SSH", "SSH Tools"),
        ("phrase-search", "Phrase Search", "Config"),
        ("global-config", "Global Config", "Config"),
        ("changes", "Change Windows", "Config"),
        ("cert-tracker", "Certificate Tracker", "Certificates"),
        ("ise-nodes", "ISE Nodes", "Certificates"),
        ("cert-converter", "Certificate Converter", "Certificates"),
        ("cert-chain", "Certificate Chain", "Certificates"),
        ("knowledge-base", "Knowledge Base", "Documentation"),
        ("jobs", "Job Center", "System"),
        ("audit-logs", "Audit Logs", "System"),
    ]

    pages = []
    for key, name, category in pages_data:
        page = PageSettings(
            page_key=key,
            page_name=name,
            enabled=True,
            category=category,
        )
        db_session.add(page)
        pages.append(page)

    db_session.commit()
    print(f"Created {len(pages)} page settings")
    return pages


def create_app_settings(db_session):
    """Create default application settings."""
    from src.models import AppSettings

    settings = AppSettings(
        id=1,
        timezone="America/Chicago",
    )
    db_session.add(settings)
    db_session.commit()
    print("Created app settings")
    return settings


def create_kb_articles(db_session, users):
    """Create sample knowledge base articles."""
    from src.models import KBArticle

    # Get admin user for author
    admin = next((u for u in users if u.role == "superadmin"), users[0])

    articles_data = [
        {
            "title": "Getting Started with NOC Toolkit",
            "subject": "Documentation",
            "content": "# Getting Started\n\nWelcome to NOC Toolkit. This guide will help you...",
            "visibility": "FSR",
        },
        {
            "title": "Bulk SSH Best Practices",
            "subject": "SSH Tools",
            "content": "# Bulk SSH Best Practices\n\nWhen executing commands across multiple devices...",
            "visibility": "NOC",
        },
        {
            "title": "Admin Configuration Guide",
            "subject": "Administration",
            "content": "# Admin Configuration Guide\n\nThis guide covers advanced configuration...",
            "visibility": "Admin",
        },
    ]

    articles = []
    for data in articles_data:
        article = KBArticle(
            title=data["title"],
            subject=data["subject"],
            content=data["content"],
            visibility=data["visibility"],
            created_by=admin.id,
        )
        db_session.add(article)
        articles.append(article)

    db_session.commit()
    print(f"Created {len(articles)} knowledge base articles")
    return articles


def create_bulk_ssh_templates(db_session):
    """Create sample bulk SSH templates."""
    from src.models import BulkSSHTemplate

    templates_data = [
        {
            "name": "Show Version",
            "description": "Display device version information",
            "command": "show version",
            "category": "Diagnostics",
            "variables": "[]",
        },
        {
            "name": "Show Running Config",
            "description": "Display current running configuration",
            "command": "show running-config",
            "category": "Configuration",
            "variables": "[]",
        },
        {
            "name": "Interface Status",
            "description": "Show interface status and statistics",
            "command": "show interface {{interface}}",
            "category": "Diagnostics",
            "variables": '[{"name": "interface", "description": "Interface name (e.g., GigabitEthernet0/1)"}]',
        },
    ]

    templates = []
    for data in templates_data:
        template = BulkSSHTemplate(
            name=data["name"],
            description=data["description"],
            command=data["command"],
            category=data["category"],
            variables=data["variables"],
        )
        db_session.add(template)
        templates.append(template)

    db_session.commit()
    print(f"Created {len(templates)} bulk SSH templates")
    return templates


def create_certificates(db_session):
    """Create sample certificate entries."""
    from src.models import Certificate

    now = datetime.utcnow()

    certs_data = [
        {
            "common_name": "*.example.com",
            "serial_number": "1234567890ABCDEF",
            "issuer": "DigiCert SHA2 Extended Validation Server CA",
            "not_before": now - timedelta(days=365),
            "not_after": now + timedelta(days=365),
            "source": "Manual Upload",
        },
        {
            "common_name": "api.example.com",
            "serial_number": "FEDCBA0987654321",
            "issuer": "Let's Encrypt Authority X3",
            "not_before": now - timedelta(days=30),
            "not_after": now + timedelta(days=60),  # Expiring soon
            "source": "ISE Node: ise-primary",
        },
        {
            "common_name": "expired.example.com",
            "serial_number": "EXPIRED123456789",
            "issuer": "DigiCert Global Root CA",
            "not_before": now - timedelta(days=730),
            "not_after": now - timedelta(days=1),  # Already expired
            "source": "Manual Upload",
        },
    ]

    certs = []
    for data in certs_data:
        cert = Certificate(
            common_name=data["common_name"],
            serial_number=data["serial_number"],
            issuer=data["issuer"],
            not_before=data["not_before"],
            not_after=data["not_after"],
            source=data["source"],
        )
        db_session.add(cert)
        certs.append(cert)

    db_session.commit()
    print(f"Created {len(certs)} certificate entries")
    return certs


def seed_all(app):
    """Seed all test data."""
    from src.models import db

    with app.app_context():
        users = create_test_users(db.session)
        create_page_settings(db.session)
        create_app_settings(db.session)
        create_kb_articles(db.session, users)
        create_bulk_ssh_templates(db.session)
        create_certificates(db.session)
        print("\nTest data seeding complete!")


def clear_all(app):
    """Clear all test data from the database."""
    from src.models import db

    with app.app_context():
        # Delete in order to respect foreign key constraints
        tables = [
            "kb_articles",
            "sessions",
            "bulk_ssh_templates",
            "bulk_ssh_schedules",
            "bulk_ssh_results",
            "bulk_ssh_jobs",
            "certificates",
            "ise_nodes",
            "users",
            "page_settings",
            "app_settings",
        ]

        for table_name in tables:
            try:
                db.session.execute(db.text(f"DELETE FROM {table_name}"))
            except Exception as e:
                print(f"Warning: Could not clear {table_name}: {e}")

        db.session.commit()
        print("Cleared all test data")


def main():
    """Main entry point for the seeding script."""
    parser = argparse.ArgumentParser(description="Seed test data for NOC Toolkit")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Clear existing data before seeding",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear data without reseeding",
    )
    args = parser.parse_args()

    # Import app after setting environment
    from src.app import create_app

    app = create_app("testing")

    # Create tables if they don't exist
    with app.app_context():
        from src.models import db
        db.create_all()

    if args.clear:
        clear_all(app)
    elif args.reset:
        clear_all(app)
        seed_all(app)
    else:
        seed_all(app)


if __name__ == "__main__":
    main()
