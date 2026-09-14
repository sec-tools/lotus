"""Validated JSON object spans for preserving large terminal audit artifacts.

Only object field boundaries are indexed. The standard decoder validates every
value with an object-pairs hook that discards nested dictionaries; untouched
values then stream directly from their original text. This avoids retaining the
nested evidence graph, but is not a constant-memory JSON parser: a large scalar,
flat primitive array or wide object-pairs list can still allocate in the stdlib
validator. Callers own the original TEXT and the one final encoded result.

Non-object or malformed legacy documents are refused explicitly. Callers choose
whether to retain their legacy fallback; this module never replaces evidence
with an empty object on parse failure.
"""
from __future__ import annotations

import io
import json
from collections.abc import Mapping
from dataclasses import dataclass
from json.decoder import WHITESPACE

# At most 64 KiB of UTF-8 bytes per write, including non-BMP source characters.
_COPY_CHARS = 16 * 1024
_DECODER = json.JSONDecoder()
_DISCARD_DECODER = json.JSONDecoder(object_pairs_hook=lambda pairs: None)
_ENCODER = json.JSONEncoder()  # Match json.dumps defaults, including NaN.


class InvalidJSONView(ValueError):
    """The document cannot safely use the object-span path."""


@dataclass(frozen=True)
class _Field:
    key: str
    start: int
    end: int


def _write_text(stream, value: str) -> None:
    for start in range(0, len(value), _COPY_CHARS):
        stream.write(value[start:start + _COPY_CHARS].encode('utf-8', 'surrogatepass'))


def _write_span(stream, raw: str, start: int, end: int) -> None:
    while start < end:
        next_start = min(end, start + _COPY_CHARS)
        stream.write(raw[start:next_start].encode('utf-8', 'surrogatepass'))
        start = next_start


class ObjectView:
    """An immutable object index over owned JSON text; duplicate keys are last-wins.

    ``get`` decodes only the selected value (use max_chars for a caller's small
    metadata bound). ``child`` indexes an object in the same string; it returns
    None for missing/non-object fields, without changing their original value.
    """

    def __init__(self, raw: str, *, _start: int = 0, _end: int | None = None):
        if not isinstance(raw, str):
            raise InvalidJSONView('JSON object view requires text')
        self.raw = raw
        self.start = _start
        self.end = len(raw) if _end is None else _end
        if (type(self.start) is not int or type(self.end) is not int
                or not 0 <= self.start <= self.end <= len(raw)):
            raise InvalidJSONView('Invalid JSON object boundary')
        self._fields: list[_Field] = []
        self._last: dict[str, _Field] = {}
        try:
            self._index()
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            # Do not include source snippets or provider payloads in errors.
            raise InvalidJSONView('Invalid JSON object document') from exc

    def _space(self, position: int) -> int:
        if not self.start <= position <= self.end:
            raise InvalidJSONView('JSON token exceeds object boundary')
        return WHITESPACE.match(self.raw, position, self.end).end()

    def _index(self) -> None:
        position = self._space(self.start)
        if position >= self.end or self.raw[position] != '{':
            raise InvalidJSONView('JSON document is not an object')
        position = self._space(position + 1)
        if position < self.end and self.raw[position] == '}':
            self.close = position
        else:
            while True:
                if position >= self.end or self.raw[position] != '"':
                    raise InvalidJSONView('JSON object key is missing')
                key, position = _DECODER.raw_decode(self.raw, position)
                position = self._space(position)
                if position >= self.end or self.raw[position] != ':':
                    raise InvalidJSONView('JSON object separator is missing')
                position = self._space(position + 1)
                start = position
                ignored, position = _DISCARD_DECODER.raw_decode(self.raw, position)
                del ignored
                if position > self.end:
                    raise InvalidJSONView('JSON value exceeds object boundary')
                field = _Field(key, start, position)
                self._fields.append(field)
                self._last[key] = field
                position = self._space(position)
                if position < self.end and self.raw[position] == '}':
                    self.close = position
                    break
                if position >= self.end or self.raw[position] != ',':
                    raise InvalidJSONView('JSON object delimiter is missing')
                position = self._space(position + 1)
        if self._space(self.close + 1) != self.end:
            raise InvalidJSONView('JSON document has trailing content')

    def has(self, key: str) -> bool:
        return key in self._last

    def get(self, key: str, default=None, *, max_chars: int | None = None):
        field = self._last.get(key)
        if field is None:
            return default
        if max_chars is not None and field.end - field.start > max_chars:
            raise InvalidJSONView('Selected JSON value exceeds its metadata bound')
        # raw_decode avoids making another selected-value text copy.
        value, end = _DECODER.raw_decode(self.raw, field.start)
        if end != field.end:
            raise InvalidJSONView('Selected JSON value boundary changed')
        return value

    def child(self, key: str) -> ObjectView | None:
        field = self._last.get(key)
        if field is None or self.raw[field.start] != '{':
            return None
        return ObjectView(self.raw, _start=field.start, _end=field.end)

    def truthy(self, key: str) -> bool:
        """Match bool(json.loads(document).get(key)) without decoding containers."""
        field = self._last.get(key)
        if field is None:
            return False
        first = self.raw[field.start]
        if first == '"':
            return field.end - field.start != 2
        if first in '{[':
            inner = self._space(field.start + 1)
            return self.raw[inner] != ('}' if first == '{' else ']')
        return bool(self.get(key))

    def patch(self, replacements: Mapping) -> ObjectPatch:
        return ObjectPatch(self, replacements)


class ObjectPatch:
    """Overlay values, including JSON null, while preserving all other raw spans.

    A replacement can itself be ObjectPatch. Nested patches write to the same
    stream, so a details overlay never constructs a second whole audit string.
    """

    def __init__(self, view: ObjectView, replacements: Mapping):
        if not isinstance(view, ObjectView) or not isinstance(replacements, Mapping):
            raise TypeError('Object patch requires a view and replacement mapping')
        if any(not isinstance(key, str) for key in replacements):
            raise TypeError('Object patch keys must be strings')
        self.view = view
        self.replacements = dict(replacements)

    def _write_value(self, stream, value, active) -> None:
        if isinstance(value, ObjectPatch):
            value._write_to(stream, active)
        else:
            for text in _ENCODER.iterencode(value):
                _write_text(stream, text)

    def _write_to(self, stream, active: set[int]) -> None:
        if id(self) in active:
            raise ValueError('Circular JSON object patch')
        active.add(id(self))
        try:
            view = self.view
            position = view.start
            # Replace only the last duplicate. Earlier raw occurrences remain
            # valid and the new last value has exactly json.loads semantics.
            edits = sorted((view._last[key] for key in self.replacements if key in view._last),
                           key=lambda field: field.start)
            for field in edits:
                _write_span(stream, view.raw, position, field.start)
                self._write_value(stream, self.replacements[field.key], active)
                position = field.end
            _write_span(stream, view.raw, position, view.close)
            populated = bool(view._fields)
            for key, value in self.replacements.items():
                if key in view._last:
                    continue
                if populated:
                    stream.write(b', ')
                _write_text(stream, _ENCODER.encode(key))
                stream.write(b': ')
                self._write_value(stream, value, active)
                populated = True
            _write_span(stream, view.raw, view.close, view.end)
        finally:
            active.remove(id(self))

    def write_to(self, binary_stream) -> None:
        """Write UTF-8 chunks (surrogatepass preserves Python JSON text semantics)."""
        self._write_to(binary_stream, set())

    def dumps(self) -> str:
        buffer = io.BytesIO()
        self.write_to(buffer)
        return buffer.getvalue().decode('utf-8', 'surrogatepass')
