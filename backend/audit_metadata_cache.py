"""Disposable audit projections bound to an opaque database write generation.

Triggers invalidate on every output write, including SQL outside the ORM. GETs
remain read-only: they consume a persisted projection or a bounded process LRU.
The optional prewarm command persists the same strictly validated projection.
Neither cache is evidence; callers retain their original full proof validator.
"""
from __future__ import annotations

from collections import OrderedDict
import json
import threading
import weakref

from sqlalchemy import Column, ForeignKey, Integer, MetaData, Table, Text, event, select, text, update
from sqlalchemy.exc import SQLAlchemyError

PROJECTION_VERSION = 1
MAX_ENTRY_BYTES = 4 * 1024 * 1024
MAX_PROCESS_BYTES = 32 * 1024 * 1024
MAX_PROCESS_ENTRIES = 256
_LOCK = threading.RLock()
_MEMORY = weakref.WeakKeyDictionary()

# Shared with offline backup validation. Names alone must never authorize an
# uploaded trigger: its complete SQL must match the application definition.
SQLITE_TRIGGER_SQL = {
    'lotus_metadata_' + operation: 'CREATE TRIGGER lotus_metadata_' + operation + ' ' + body
    for operation, body in (
        ('insert', 'AFTER INSERT ON scan_jobs BEGIN INSERT OR REPLACE INTO scan_job_metadata (job_id, generation) VALUES (NEW.id, lower(hex(randomblob(32)))); END'),
        ('update', 'AFTER UPDATE OF output ON scan_jobs BEGIN INSERT INTO scan_job_metadata (job_id, generation) VALUES (NEW.id, lower(hex(randomblob(32)))) ON CONFLICT(job_id) DO UPDATE SET generation=excluded.generation, projection_version=NULL, projection_json=NULL, projection_error=NULL; END'),
        ('delete', 'AFTER DELETE ON scan_jobs BEGIN DELETE FROM scan_job_metadata WHERE job_id=OLD.id; END'),
    )
}


def declare_table(metadata: MetaData) -> Table:
    table = Table('scan_job_metadata', metadata,
        Column('job_id', Integer, ForeignKey('scan_jobs.id', ondelete='CASCADE'), primary_key=True),
        Column('generation', Text, nullable=False),
        Column('projection_version', Integer),
        Column('projection_json', Text),
        Column('projection_error', Text))
    event.listen(table, 'after_create', lambda _table, connection, **_: install(connection, table))
    return table


def install(connection, table):
    """Install without parsing or modifying any audit output or progress row."""
    dialect = connection.dialect.name
    if dialect == 'sqlite':
        for sql in SQLITE_TRIGGER_SQL.values():
            connection.execute(text(sql.replace('CREATE TRIGGER ', 'CREATE TRIGGER IF NOT EXISTS ', 1)))
        connection.execute(text('INSERT OR IGNORE INTO scan_job_metadata (job_id, generation) SELECT id, lower(hex(randomblob(32))) FROM scan_jobs'))
    elif dialect == 'postgresql':
        connection.execute(text('''CREATE OR REPLACE FUNCTION lotus_invalidate_metadata() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                DELETE FROM public.scan_job_metadata WHERE job_id = OLD.id;
                RETURN OLD;
            END IF;
            INSERT INTO public.scan_job_metadata (job_id, generation) VALUES (NEW.id, gen_random_uuid()::text)
            ON CONFLICT(job_id) DO UPDATE SET generation=excluded.generation, projection_version=NULL, projection_json=NULL, projection_error=NULL;
            RETURN NEW;
        END $$'''))
        for operation, event_sql in [('insert', 'INSERT'), ('update', 'UPDATE OF output'), ('delete', 'DELETE')]:
            connection.execute(text('DROP TRIGGER IF EXISTS lotus_metadata_' + operation + ' ON scan_jobs'))
            connection.execute(text('CREATE TRIGGER lotus_metadata_' + operation + ' AFTER ' + event_sql + ' ON scan_jobs FOR EACH ROW EXECUTE FUNCTION lotus_invalidate_metadata()'))
        connection.execute(text('INSERT INTO scan_job_metadata (job_id, generation) SELECT id, gen_random_uuid()::text FROM scan_jobs ON CONFLICT(job_id) DO NOTHING'))
    else:
        raise ValueError('Audit metadata caching requires SQLite or PostgreSQL16')


def install_existing(engine, table):
    with engine.begin() as connection:
        table.create(connection, checkfirst=True)
        install(connection, table)


def _table():
    from backend.main import SCAN_JOB_METADATA
    return SCAN_JOB_METADATA


def _read(db, job_id):
    # The narrow savepoint also supports old external fixtures whose ScanJob
    # table predates this disposable cache, without poisoning a PG transaction.
    try:
        with db.no_autoflush, db.connection().begin_nested():
            return db.execute(select(_table()).where(_table().c.job_id == int(job_id))).mappings().first()
    except SQLAlchemyError:
        return None


def _decode(payload, error):
    if error is not None:
        raise ValueError(error)
    if not isinstance(payload, str) or len(payload.encode('utf-8')) > MAX_ENTRY_BYTES:
        return None
    try:
        decoded = json.loads(payload)
        return decoded if isinstance(decoded, dict) else None
    except (TypeError, ValueError):
        return None


def _remember(engine, key, payload, error):
    size = len(payload.encode('utf-8')) if payload is not None else len(error.encode('utf-8'))
    if size > MAX_ENTRY_BYTES:
        return
    with _LOCK:
        entries = _MEMORY.setdefault(engine, OrderedDict())
        entries.pop(key, None)
        entries[key] = (payload, error, size)
        while len(entries) > MAX_PROCESS_ENTRIES or sum(item[2] for item in entries.values()) > MAX_PROCESS_BYTES:
            entries.popitem(last=False)


def read_through(db, job_id, project):
    """Return exact metadata; cache only against a database-enforced generation.

    Never commit, autoflush, repair, or update the caller's database. Entries
    too large for the memory budget use the original strict projection path.
    A cache miss therefore preserves all metadata presence/type/error semantics.
    """
    row = _read(db, job_id)
    if row is None:
        return project()
    key = (int(job_id), row['generation'], PROJECTION_VERSION)
    engine = db.get_bind()
    if row['projection_version'] == PROJECTION_VERSION:
        result = _decode(row['projection_json'], row['projection_error'])
        if result is not None:
            return result
    with _LOCK:
        entries = _MEMORY.get(engine, {})
        memory = entries.get(key)
        if memory:
            entries.move_to_end(key)
    if memory:
        result = _decode(memory[0], memory[1])
        if result is not None:
            return result
    try:
        result = project()
    except ValueError as exc:
        # Preserve the existing ValueError boundary without repeatedly parsing
        # a known malformed record. TypeError stays uncached so its helper
        # exception type is never changed on a later read.
        current = _read(db, job_id)
        if current is not None and current['generation'] == row['generation']:
            _remember(engine, key, None, str(exc))
        raise
    current = _read(db, job_id)
    if current is not None and current['generation'] == row['generation']:
        _remember(engine, key, json.dumps(result, separators=(',', ':'), ensure_ascii=False), None)
    return result


def prewarm_job(db, job_id, project):
    """Populate in an explicitly owned transaction; caller commits/rolls back.

    The generation compare-and-set rejects a concurrent output rewrite. A
    failed attempt is left cold rather than associating stale data with a new
    artifact. This helper never changes ScanJob or Finding data.
    """
    row = _read(db, job_id)
    if row is None:
        return 'unavailable'
    try:
        result = project()
        payload, error = json.dumps(result, separators=(',', ':'), ensure_ascii=False), None
    except ValueError as exc:
        payload, error = None, str(exc)
    if len((payload or error).encode('utf-8')) > MAX_ENTRY_BYTES:
        return 'oversize'
    table = _table()
    changed = db.execute(update(table).where(table.c.job_id == int(job_id), table.c.generation == row['generation']).values(
        projection_version=PROJECTION_VERSION, projection_json=payload, projection_error=error)).rowcount
    return ('malformed' if error is not None else 'ready') if changed == 1 else 'changed'
