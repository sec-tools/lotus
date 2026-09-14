"""
Database models for Lotus BDAAS.

Re-exports ORM models from main.py. New code can import from here:
    from backend.models import Settings, Repo, Finding

Models are defined in main.py because they share the same Base/engine
with the app initialization. This module provides a clean import path
and serves as a reference for the database schema.
"""

# Re-export all models from main for clean import paths
from backend.main import (  # noqa: F401
    Base,
    Settings,
    Repo,
    Finding,
    Report,
    NotificationSettings,
    ScanJob,
    HarnessRun,
)
