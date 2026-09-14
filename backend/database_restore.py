"""Offline validation and transactional database restore primitives.

These functions do not select platform paths or credentials, stop work, or
start audits. The API owns maintenance admission and mandatory rollback copies.
"""
from __future__ import annotations

import re
import sqlite3
import time
from datetime import datetime
from contextlib import closing
from pathlib import Path
from typing import Dict, Set


class InvalidBackup(ValueError):
    pass


def validate_sqlite_backup(path: str, schema: Dict[str, Set[str]]) -> None:
    """Require compatible tables and only exact application-owned triggers."""
    # The upload is a closed, private single-file snapshot. Immutable reads
    # avoid attempting to create WAL sidecars for an uploaded WAL-mode header.
    connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        connection.execute("PRAGMA trusted_schema=OFF")
        objects = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall()
        from backend.audit_metadata_cache import SQLITE_TRIGGER_SQL
        expected_triggers = SQLITE_TRIGGER_SQL if 'scan_job_metadata' in schema else {}
        triggers = {name: (table, sql) for kind, name, table, sql in objects if kind == 'trigger'}
        if (any(kind == 'view' for kind, _, _, _ in objects)
                or triggers != {name: ('scan_jobs', sql) for name, sql in expected_triggers.items()}):
            raise InvalidBackup("Backup contains unsupported triggers or views")
        tables = {name: sql for kind, name, _, sql in objects if kind == "table"}
        if set(tables) != set(schema):
            raise InvalidBackup("Backup must contain the complete Lotus schema for this application version")
        for name, sql in tables.items():
            if re.search(r"\bVIRTUAL\s+TABLE\b", sql or "", re.I):
                raise InvalidBackup("Backup contains an unsupported virtual table")
            # Table identifiers come from application metadata, never input.
            columns = {row[1] for row in connection.execute(f'PRAGMA table_info("{name}")')}
            if columns != schema[name]:
                raise InvalidBackup(f"Backup table {name} is incompatible with this application version")
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise InvalidBackup("Backup failed integrity check")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise InvalidBackup("Backup failed relationship integrity check")
        for name in ("settings", "notification_settings"):
            if connection.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0] != 1:
                raise InvalidBackup(f"Backup must contain exactly one {name} row")
    except sqlite3.Error as exc:
        raise InvalidBackup(f"Uploaded file is not a valid compatible SQLite backup: {str(exc)[:160]}") from exc
    finally:
        connection.close()


def prepare_sqlite_restore(path: str) -> None:
    """Old process ownership must not resurrect workers after an import."""
    now = datetime.utcnow().isoformat(sep=" ")
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("DELETE FROM scan_leases")
        connection.execute(
            "UPDATE scan_jobs SET status='interrupted', control='cancel', lease_token='', "
            "lease_owner='', lease_expires_at=NULL, heartbeat_at=NULL, finished_at=? "
            "WHERE status IN ('queued', 'running', 'paused')", (now,),
        )
        connection.execute(
            "UPDATE repos SET status='interrupted' WHERE status IN ('queued', 'running', 'scanning', 'paused', 'monitoring')"
        )
        # Continuous polling is an action, so imported policy is paused until
        # the user explicitly re-enrolls it after inspecting the restored data.
        connection.execute("UPDATE repos SET mode='one-time' WHERE mode='continuous'")
        connection.execute(
            "UPDATE harness_runs SET status='stopped', lease_owner='', lease_expires_at=NULL, heartbeat_at=NULL, finished_at=? "
            "WHERE status IN ('pending', 'running', 'paused')", (now,),
        )
        connection.execute("UPDATE harness_runs SET lease_owner='', lease_expires_at=NULL, heartbeat_at=NULL")
        connection.execute("UPDATE audit_decisions SET status='expired' WHERE status='pending'")
        # Imported projections are disposable hints, never trusted metadata.
        # New generations also prevent reuse of an old process-LRU entry.
        connection.execute("DELETE FROM scan_job_metadata")
        connection.execute("INSERT INTO scan_job_metadata (job_id, generation) SELECT id, lower(hex(randomblob(32))) FROM scan_jobs")
        connection.commit()
        connection.execute("PRAGMA journal_mode=DELETE")


def restore_sqlite_backup(path: str, engine, *, timeout: float = 120) -> None:
    """Replace content inside SQLite's transaction, preserving live WAL handles.

    Replacing an inode while its WAL/SHM and pooled connections remain open can
    corrupt the restored image or split readers between two databases. SQLite's
    backup API holds the destination write transaction and rolls back partial
    copies if interrupted; existing readers see a complete old or new image.
    """
    source = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    destination = engine.raw_connection()
    deadline = time.monotonic() + timeout
    try:
        driver = getattr(destination, "driver_connection", None)
        if driver is None:
            driver = destination.connection

        def check_deadline(status, remaining, total):
            if status != sqlite3.SQLITE_DONE and time.monotonic() >= deadline:
                raise TimeoutError("Database restore timed out waiting for exclusive write access")

        source.backup(driver, pages=256, progress=check_deadline, sleep=0.05)
    finally:
        destination.close()
        source.close()


def validate_postgres_archive(listing: str, schema: Dict[str, Set[str]]) -> None:
    """Refuse unrelated tables and executable extensions before pg_restore."""
    tables = set()
    allowed = (
        "TABLE DATA", "SEQUENCE SET", "SEQUENCE OWNED BY", "FK CONSTRAINT",
        "DEFAULT ACL", "DATABASE PROPERTIES", "ENCODING", "STDSTRINGS", "SEARCHPATH",
        "SCHEMA", "TABLE", "SEQUENCE", "CONSTRAINT", "INDEX", "DEFAULT", "COMMENT", "ACL",
    )
    for line in listing.splitlines():
        if not line.strip() or line.lstrip().startswith(";"):
            continue
        match = re.match(r"^\d+;\s+\d+\s+\d+\s+(.*)$", line.strip())
        if not match:
            raise InvalidBackup("PostgreSQL archive has an invalid table of contents")
        entry = match.group(1)
        # pg_restore below emits data only. These known object references are
        # expected in our archive, but their uploaded DDL is never executed.
        cache_object = re.fullmatch(
            r'(?:FUNCTION public lotus_invalidate_metadata\(\)|TRIGGER public scan_jobs lotus_metadata_(?:insert|update|delete)) [^\s]+',
            entry,
        )
        if cache_object and 'scan_job_metadata' in schema:
            continue
        kind = next((kind for kind in allowed if entry.startswith(kind + " ")), None)
        if kind is None:
            raise InvalidBackup("PostgreSQL archive contains unsupported schema objects")
        parts = entry[len(kind):].strip().split()
        if kind in {"TABLE", "TABLE DATA"}:
            if len(parts) < 2 or parts[0] != "public" or parts[1] not in schema:
                raise InvalidBackup("PostgreSQL archive contains tables outside the Lotus schema")
            if kind == "TABLE":
                tables.add(parts[1])
        elif kind == "SCHEMA":
            if len(parts) < 2 or parts[1] != "public":
                raise InvalidBackup("PostgreSQL archive contains an unsupported schema")
        elif kind in {"ENCODING", "STDSTRINGS", "SEARCHPATH"}:
            continue
        elif kind in {"COMMENT", "ACL", "DEFAULT ACL", "DATABASE PROPERTIES"}:
            # Restore ignores ACLs/ownership/comments; database properties are
            # never applied because --create is deliberately absent.
            continue
        elif not parts or parts[0] != "public":
            raise InvalidBackup("PostgreSQL archive contains objects outside the public schema")
    if tables != set(schema):
        raise InvalidBackup("PostgreSQL backup must contain the complete Lotus schema")


def _postgres_lines(script):
    """Share PostgreSQL LF/CRLF boundaries without interpreting data controls.

    str.splitlines treats vertical tabs and Unicode separators as line ends;
    COPY does not. Validation and filtering must see identical boundaries.
    """
    parts = script.split('\n')
    for index, part in enumerate(parts):
        yield part + ('\n' if index < len(parts) - 1 else ''), part.removesuffix('\r')


def validate_postgres_data(script: str, schema: Dict[str, Set[str]]) -> None:
    """Only restore COPY data to known columns; never execute uploaded DDL."""
    seen = set()
    copying = False
    dump_settings = {
        "statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout", "transaction_timeout",
        "client_encoding", "standard_conforming_strings", "check_function_bodies", "xmloption",
        "client_min_messages", "row_security", "default_tablespace", "default_table_access_method",
    }
    sequences = {f"{table}_{column}_seq" for table, columns in schema.items()
                 for column in columns if column == "id" or column.endswith("_id")}
    for _, line in _postgres_lines(script):
        if copying:
            if line == r"\.":
                copying = False
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        match = re.fullmatch(r"COPY public\.([a-z_]+) \(([^)]+)\) FROM stdin;", stripped)
        if match:
            table, fields = match.groups()
            columns = {field.strip().strip('"') for field in fields.split(",")}
            if table not in schema or columns != schema[table] or table in seen:
                raise InvalidBackup("PostgreSQL backup contains incompatible table columns")
            seen.add(table)
            copying = True
        elif re.fullmatch(r"\\(?:un)?restrict [A-Za-z0-9]+", stripped):
            # Modern pg_dump brackets output with psql's restricted mode.
            continue
        elif re.fullmatch(r"SET [a-z_]+ = (?:[A-Za-z0-9_]+|'[^'\n]*');", stripped):
            if stripped.split()[1] not in dump_settings:
                raise InvalidBackup("PostgreSQL backup contains an unsupported session setting")
        elif stripped == "SELECT pg_catalog.set_config('search_path', '', false);":
            continue
        elif re.fullmatch(
            r"SELECT pg_catalog\.setval\('public\.([a-z_]+)', [0-9]+, (?:true|false)\);", stripped,
        ):
            sequence = re.search(r"'public\.([a-z_]+)'", stripped).group(1)
            if sequence not in sequences:
                raise InvalidBackup("PostgreSQL backup contains an unknown sequence")
        else:
            raise InvalidBackup("PostgreSQL backup contains unsupported executable statements")
    if copying or seen != set(schema):
        raise InvalidBackup("PostgreSQL backup contains incomplete table data")


def prepare_postgres_restore_data(script: str, schema: Dict[str, Set[str]]) -> str:
    """Validate the complete dump, then omit disposable cache COPY rows.

    Trusted destination triggers populate cache generations while scan_jobs
    loads. Importing the old cache afterwards would conflict with those rows
    and could restore stale projections. All other COPY bytes remain exact.
    """
    validate_postgres_data(script, schema)
    copying = omit = False
    result = []
    for raw, line in _postgres_lines(script):
        stripped = line.strip()
        if not copying and stripped.startswith('COPY public.'):
            copying = True
            omit = stripped.startswith('COPY public.scan_job_metadata (')
        if not omit:
            result.append(raw)
        if copying and line == r'\.':
            copying = omit = False
    return ''.join(result)
