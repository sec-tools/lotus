"""
Pydantic schemas for Lotus BDAAS API request/response validation.

Re-exports schemas from main.py. New code can import from here:
    from backend.schemas import SettingsUpdate, RepoCreate, FindingOut

Schemas define API contracts (what requests/responses look like).
Models define database structure (what data looks like in the DB).
"""

# Re-export all schemas from main for clean import paths
from backend.main import (  # noqa: F401
    SettingsUpdate,
    SettingsOut,
    RepoCreate,
    RepoOut,
    FindingCreate,
    FindingOut,
    ReportCreate,
    ReportOut,
    HarnessCreate,
    ValidationRequest,
    KeyTest,
)
