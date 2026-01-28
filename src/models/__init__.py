"""
Database models for NOC Toolkit.

This package contains SQLAlchemy models for all database entities.
The db instance is created here and should be initialized with the Flask app
using db.init_app(app) in the application factory.
"""

from flask_sqlalchemy import SQLAlchemy

# Create the shared SQLAlchemy instance
db = SQLAlchemy()

# Import models after db is created to avoid circular imports
# These imports make the models available when importing from src.models
from .user import User, Session
from .settings import AppSettings, PageSettings
from .job import Job, JobEvent
from .audit import AuditLog
from .wlc import (
    WLCDashboardSettings,
    WLCSample,
    WLCSummerSettings,
    WLCSummerSample,
    APInventory,
    APInventorySettings,
)
from .solarwinds import SolarWindsSettings, SolarWindsNode
from .bulk_ssh import BulkSSHJob, BulkSSHResult, BulkSSHTemplate, BulkSSHSchedule
from .config import ChangeWindow, ChangeEvent
from .cert import Certificate, ISENode, CertSyncSettings
from .kb import KBArticle

__all__ = [
    "db",
    "User",
    "Session",
    "AppSettings",
    "PageSettings",
    "Job",
    "JobEvent",
    "AuditLog",
    "WLCDashboardSettings",
    "WLCSample",
    "WLCSummerSettings",
    "WLCSummerSample",
    "APInventory",
    "APInventorySettings",
    "SolarWindsSettings",
    "SolarWindsNode",
    "BulkSSHJob",
    "BulkSSHResult",
    "BulkSSHTemplate",
    "BulkSSHSchedule",
    "ChangeWindow",
    "ChangeEvent",
    "Certificate",
    "ISENode",
    "CertSyncSettings",
    "KBArticle",
]
