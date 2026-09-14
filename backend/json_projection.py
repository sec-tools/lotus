"""Read selected fields from stored JSON without materializing unrelated artifacts.

These are read-only SQL expressions for the shipped SQLite/PostgreSQL16 stores.
Paths are controller-authored field names, never arbitrary SQL or a client query.
Missing fields stay absent; JSON null and malformed container values stay distinct.
"""
from __future__ import annotations

import json
import re
import threading
from functools import wraps
from collections.abc import Iterable

from sqlalchemy import Integer, Text, and_, case, cast, func, literal, or_, select, true
from sqlalchemy.dialects.postgresql import JSONB

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


# JSON1 retains the stored TEXT and a parsed copy while a cursor is active.
# Serializing SQLite projections prevents concurrent API readers multiplying
# that temporary heap. Async routes must run these synchronous database reads
# in an owned worker, including the lifetime of their private Session.
_SQLITE_PROJECTION_LOCK = threading.RLock()


def _sqlite_projection_scope(function):
    @wraps(function)
    def read(db, *args, **kwargs):
        if db.get_bind().dialect.name != "sqlite":
            return function(db, *args, **kwargs)
        with _SQLITE_PROJECTION_LOCK, db.no_autoflush:
            # Connection-level SAVEPOINT starts a real SQLite read snapshot
            # even under sqlite3 legacy transaction mode. Session.begin_nested
            # would flush the caller's pending ORM changes as a side effect.
            # An existing outer write transaction stays owned by its caller.
            with db.connection().begin_nested():
                return function(db, *args, **kwargs)
    return read


def _path(value):
    result = tuple(value)
    if not result or any(not isinstance(key, str) or not _NAME.fullmatch(key) for key in result):
        raise ValueError("Projection paths must contain controller-authored JSON field names")
    return result


def _sqlite_path(parts):
    return "$." + ".".join(parts)


def _document(db, column):
    dialect = db.get_bind().dialect.name
    if dialect == "sqlite":
        return dialect, case((func.json_valid(column), column), else_="{}")
    if dialect == "postgresql":
        # Enterprise manifests pin PostgreSQL16, whose input validator also
        # safely handles old malformed TEXT columns before a JSONB cast.
        return dialect, cast(case((func.pg_input_is_valid(column, "jsonb"), column), else_="{}"), JSONB)
    raise ValueError("JSON metadata projection requires SQLite or PostgreSQL16")


def _prepared_document(db, column, predicate):
    dialect, document = _document(db, column)
    if dialect == "postgresql":
        # Every field must reuse one parsed JSONB value. Repeating the cast in
        # a wide SELECT allocates one full document per expression on PostgreSQL.
        source = select(document.label("document")).select_from(column.table).where(predicate).cte(
            "projection_document").prefix_with("MATERIALIZED", dialect="postgresql")
        return dialect, source.c.document, source, true()
    return dialect, document, column.table, predicate


def _member(document, parts):
    result = document
    for name in parts:
        result = result[name]
    return result


def _ancestor_guard(dialect, document, parts):
    """Reject truthy malformed parents without selecting their full contents."""
    if dialect == "sqlite":
        location = _sqlite_path(parts)
        kind, value = func.json_type(document, location), func.json_extract(document, location)
        return case(
            (kind.is_(None), True), (kind.in_(["object", "null", "false"]), True),
            (kind == "true", False),
            (kind == "array", func.json_array_length(value) == 0),
            (kind == "text", func.length(value) == 0),
            else_=value == 0,
        )
    value = _member(document, parts)
    return case(
        (value.is_(None), True), (func.jsonb_typeof(value) == "object", True),
        else_=value.in_([cast(literal(raw), JSONB) for raw in ("null", "false", "0", '""', "[]")]),
    )


def _fields(db, column, paths, omit_paths=(), object_paths=(), *, prepared=None):
    dialect, document = prepared if prepared is not None else _document(db, column)
    omissions = [_path(value) for value in omit_paths]
    shells = set(map(_path, object_paths))
    expressions = []
    for index, parts in enumerate(paths):
        nested = [value[len(parts):] for value in omissions if value[:len(parts)] == parts and len(value) > len(parts)]
        if dialect == "sqlite":
            location = _sqlite_path(parts)
            kind = func.json_type(document, location)
            value = func.json_extract(document, location)
            if nested:
                value = case((kind == "object", func.json_remove(value, *[_sqlite_path(p) for p in nested])), else_=value)
        else:
            member = _member(document, parts)
            kind = func.jsonb_typeof(member)
            original = member
            for nested_path in nested:
                from sqlalchemy.dialects.postgresql import array
                containers = [func.jsonb_typeof(_member(original, nested_path[:size])) == "object"
                              for size in range(len(nested_path))]
                member = case((and_(*containers), member.op("#-")(array(list(nested_path)))), else_=member)
            value = cast(member, Text)
        if parts in shells:
            value = case((kind == "object", "{}"), else_=value)
        expressions.extend([kind.label("type_" + str(index)), value.label("value_" + str(index))])
    return dialect, expressions


def _decode(kind, value, dialect):
    if kind is None:
        return False, None
    if dialect == "postgresql":
        return True, json.loads(value) if value is not None else None
    if kind == "null":
        return True, None
    if kind in {"true", "false"}:
        return True, kind == "true"
    if kind in {"array", "object"}:
        return True, json.loads(value)
    return True, value


def _put(output, parts, value):
    cursor = output
    for key in parts[:-1]:
        # A separately selected scalar/null parent is retained as malformed,
        # rather than repaired into a container by a nested child selection.
        if key in cursor and not isinstance(cursor[key], dict):
            return
        cursor = cursor.setdefault(key, {})
    cursor[parts[-1]] = value


@_sqlite_projection_scope
def read_json_projection(db, column, predicate, paths: Iterable[tuple[str, ...]], *, omit_paths=(), object_paths=()) -> dict:
    """Read one exact row, preserving field presence and selected JSON types.

    Example: read_json_projection(db, ScanJob.output, ScanJob.id == job_id,
        [("target_snapshot",), ("audit_plan", "target_snapshot")]).
    ``omit_paths`` strips nested heavy fields only inside selected containers;
    it never serializes a redacted copy of the entire stored audit document.
    ``object_paths`` returns an empty shell for selected object containers;
    separately requested descendants fill it while preserving empty-object
    versus absent/null semantics without loading the container's other fields.
    """
    object_paths = tuple(map(_path, object_paths))
    omit_paths = tuple(map(_path, omit_paths))
    selected = sorted(set(_path(path) for path in [*paths, *object_paths]), key=lambda path: (len(path), path))
    if not selected:
        return {}
    dialect, document, source, scope_predicate = _prepared_document(db, column, predicate)
    _, expressions = _fields(db, column, selected, omit_paths, object_paths, prepared=(dialect, document))
    ancestors = sorted({path[:size] for path in selected for size in range(1, len(path)) if path[:size] not in selected})
    guards = [_ancestor_guard(dialect, document, path).label("ancestor_" + str(index)) for index, path in enumerate(ancestors)]
    duplicate_guards = []
    if dialect == "sqlite":
        # Parse once, retaining only structural metadata needed by the selected
        # paths. Per-path json_each cursors each retained a full parsed document
        # and exhausted the controller heap on large audit records.
        checked = sorted({path[:size] for path in [*selected, *omit_paths] for size in range(1, len(path) + 1)})
        names = sorted({part for path in checked for part in path})
        tree = func.json_tree(document).table_valued("id", "parent", "key")
        structure = select(tree.c.id, tree.c.parent, tree.c.key).select_from(column.table).join(tree, true()).where(
            predicate, or_(tree.c.parent.is_(None), tree.c.key.in_(names)),
        ).cte("projection_structure").prefix_with("MATERIALIZED", dialect="sqlite")
        # Use decoded keys and parent identities, not fullkey text: JSON1 can
        # spell the same key as x or "\\u0078", while a literal "x.y" is not
        # the nested x.y path. This also catches duplicate selected ancestors.
        for index, path in enumerate(checked):
            root = structure.alias()
            scope, parent = root, root
            for part in path:
                child = structure.alias()
                scope = scope.join(child, and_(child.c.parent == parent.c.id, child.c.key == part))
                parent = child
            count = select(func.count()).select_from(scope).where(root.c.parent.is_(None)).scalar_subquery()
            duplicate_guards.append((count <= 1).label("unique_" + str(index)))
    if dialect == "sqlite":
        # Finish the structural cursor before opening the value cursor. Keeping
        # both alive in one wide SELECT retains two full JSON1 document parses.
        # The enclosing read SAVEPOINT binds both statements to one snapshot.
        checked = db.execute(select(*duplicate_guards).select_from(source).where(scope_predicate)).first()
        if checked is None:
            return {}
        if any(not value for value in checked):
            raise ValueError("Stored JSON contains duplicate selected field names")
        values = db.execute(select(*expressions, *guards).select_from(source).where(scope_predicate)).first()
        row = tuple(values) + tuple(checked) if values is not None else None
    else:
        row = db.execute(select(*expressions, *guards).select_from(source).where(scope_predicate)).first()
    if row is None:
        return {}
    for index, ancestor in enumerate(ancestors):
        if not row[len(expressions) + index]:
            raise ValueError("Stored JSON has a malformed parent at " + ".".join(ancestor))
    if any(not value for value in row[len(expressions) + len(guards):]):
        raise ValueError("Stored JSON contains duplicate selected field names")
    result = {}
    for index, parts in enumerate(selected):
        present, value = _decode(row[index * 2], row[index * 2 + 1], dialect)
        if present:
            _put(result, parts, value)
    return result


@_sqlite_projection_scope
def read_json_array_projection(db, column, predicate, path, fields, *, limit=None, offset=0,
                               string_limits=None, object_paths=()) -> list[dict]:
    """Return selected fields of object rows, without their source/log payloads.

    Optional pagination counts object rows, preserving their original order.
    String limits clip only selected JSON strings in SQL; other recorded types
    retain their meaning. Object shells retain malformed parent types while
    avoiding unrequested nested artifacts. Defaults preserve the full projection.
    """
    for name, value in (("limit", limit), ("offset", offset)):
        if (value is None and name == "limit"):
            continue
        if type(value) is not int or value < 0:
            raise ValueError(name + " must be a nonnegative integer")
    shells = set(map(_path, object_paths))
    selected = sorted(set(_path(value) for value in fields) | shells, key=lambda p: (len(p), p))
    caps = {_path(key): value for key, value in (string_limits or {}).items()}
    if any(key not in selected or type(value) is not int or value < 0 for key, value in caps.items()):
        raise ValueError("String limits require selected paths and nonnegative integer caps")
    path = _path(path)
    dialect, document, source, scope_predicate = _prepared_document(db, column, predicate)
    guards = [_ancestor_guard(dialect, document, path[:size]) for size in range(1, len(path))]
    if dialect == "sqlite":
        for size in range(1, len(path) + 1):
            parent = path[:size - 1]
            members = func.json_each(document, _sqlite_path(parent) if parent else "$").table_valued("key")
            guards.append(select(func.count()).select_from(members).where(members.c.key == path[size - 1]).scalar_subquery() <= 1)
    if guards:
        checked = db.execute(select(*guards).select_from(source).where(scope_predicate)).first()
        if checked is not None and any(not value for value in checked):
            raise ValueError("Stored JSON has a malformed or duplicate array path")
    if dialect == "sqlite":
        member = func.json_extract(document, _sqlite_path(path))
        value = case((func.json_type(document, _sqlite_path(path)) == "array", member), else_="[]")
        rows = func.json_each(value).table_valued("key", "value", "type")
        expressions = []
        for index, parts in enumerate(selected):
            kind = func.json_type(rows.c.value, _sqlite_path(parts))
            field = func.json_extract(rows.c.value, _sqlite_path(parts))
            if parts in caps:
                field = case((kind == "text", func.substr(field, 1, caps[parts])), else_=field)
            if parts in shells:
                field = case((kind == "object", "{}"), else_=field)
            expressions.extend([kind.label("type_" + str(index)), field.label("value_" + str(index))])
        row_guards = [_ancestor_guard(dialect, rows.c.value, parts[:size])
                      for parts in selected for size in range(1, len(parts)) if parts[:size] not in selected]
        for parts in {parts[:size] for parts in selected for size in range(1, len(parts) + 1)}:
            members = func.json_each(rows.c.value, _sqlite_path(parts[:-1]) if parts[:-1] else "$").table_valued("key")
            row_guards.append(select(func.count()).select_from(members).where(members.c.key == parts[-1]).scalar_subquery() <= 1)
        query = select(*expressions, *row_guards).select_from(source).join(rows, true()).where(scope_predicate, rows.c.type == "object").order_by(cast(rows.c.key, Integer))
    else:
        member = _member(document, path)
        value = case((func.jsonb_typeof(member) == "array", member), else_=cast(literal("[]"), JSONB))
        rows = func.jsonb_array_elements(value).table_valued("value", with_ordinality="ordinality").render_derived()
        expressions = []
        row_value = cast(rows.c.value, JSONB)
        for index, parts in enumerate(selected):
            field = _member(row_value, parts)
            kind = func.jsonb_typeof(field)
            encoded = cast(field, Text)
            if parts in caps:
                encoded = case((kind == "string", cast(func.to_jsonb(func.substr(field.astext, 1, caps[parts])), Text)), else_=encoded)
            if parts in shells:
                encoded = case((kind == "object", "{}"), else_=encoded)
            expressions.extend([kind.label("type_" + str(index)), encoded.label("value_" + str(index))])
        row_guards = [_ancestor_guard(dialect, row_value, parts[:size])
                      for parts in selected for size in range(1, len(parts)) if parts[:size] not in selected]
        query = select(*expressions, *row_guards).select_from(source).join(rows, true()).where(scope_predicate, func.jsonb_typeof(row_value) == "object").order_by(rows.c.ordinality)
    if limit is not None:
        query = query.limit(limit)
    if offset:
        query = query.offset(offset)
    result = []
    for row in db.execute(query):
        if any(not value for value in row[len(expressions):]):
            raise ValueError("Stored JSON array has malformed or duplicate selected fields")
        projected = {}
        for index, parts in enumerate(selected):
            present, value = _decode(row[index * 2], row[index * 2 + 1], dialect)
            if present:
                _put(projected, parts, value)
        result.append(projected)
    return result


@_sqlite_projection_scope
def read_json_member_projection(db, column, predicate, path, key):
    """Read one dynamic object member with a bound key, never a JSON path.

    Return (present, value) so an explicitly stored null remains distinguishable
    from an absent member. Parent paths are controller-authored; object keys may
    contain punctuation and are compared as data. SQLite rejects ambiguous
    selected keys, matching the strict field projection contract.
    """
    path = _path(path)
    if not isinstance(key, str) or len(key) > 4096:
        raise ValueError("Selected object key must be a bounded string")
    dialect, document, source, scope_predicate = _prepared_document(db, column, predicate)
    guards = [_ancestor_guard(dialect, document, path[:size]) for size in range(1, len(path))]
    if dialect == "sqlite":
        for size in range(1, len(path) + 1):
            members = func.json_each(document, _sqlite_path(path[:size - 1]) if size > 1 else "$").table_valued("key")
            guards.append(select(func.count()).select_from(members).where(members.c.key == path[size - 1]).scalar_subquery() <= 1)
    if guards:
        row = db.execute(select(*guards).select_from(source).where(scope_predicate)).first()
        if row is not None and any(not value for value in row):
            raise ValueError("Stored JSON has a malformed or duplicate object path")
    if dialect == "sqlite":
        members = func.json_each(document, _sqlite_path(path)).table_valued("key", "value", "type")
        query = select(members.c.type, members.c.value).select_from(source).join(members, true()).where(
            scope_predicate, func.json_type(document, _sqlite_path(path)) == "object", members.c.key == key).limit(2)
        rows = db.execute(query).all()
        if len(rows) > 1:
            raise ValueError("Stored JSON contains duplicate selected object keys")
        return _decode(*rows[0], dialect) if rows else (False, None)
    parent = _member(document, path)
    member = parent[key]
    row = db.execute(select(func.jsonb_typeof(member), cast(member, Text)).select_from(source).where(
        scope_predicate, func.jsonb_typeof(parent) == "object")).first()
    return _decode(*row, dialect) if row else (False, None)
