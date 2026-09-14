"""Public validation errors that never include submitted values or contexts."""
from __future__ import annotations

from typing import get_args

from pydantic_core import ErrorType


_ERROR_TYPES = frozenset(get_args(ErrorType))
_MESSAGES = {
    "missing": "Field required",
    "json_invalid": "Invalid JSON body",
    "string_too_long": "String exceeds the allowed length",
    "string_too_short": "String is shorter than the allowed length",
    "string_pattern_mismatch": "String does not match the required format",
    "greater_than": "Value must exceed the lower limit",
    "greater_than_equal": "Value is below the allowed minimum",
    "less_than": "Value must be below the upper limit",
    "less_than_equal": "Value exceeds the allowed maximum",
    "extra_forbidden": "Unexpected field",
}


def public_validation_errors(request, exc):
    """Keep schema-owned field names; discard input, ctx and validator messages.

Custom validator messages may interpolate credentials. Nested mapping keys in
locations can also be user input, so expose only the top-level declared field.
"""
    route = request.scope.get("route")
    body_field = getattr(route, "body_field", None)
    body_model = (getattr(body_field, "type_", None)
                  or getattr(getattr(body_field, "field_info", None), "annotation", None))
    fields = getattr(body_model, "model_fields", {})
    names = {"body": set(fields)}
    names["body"].update(field.alias for field in fields.values() if isinstance(field.alias, str))
    dependant = getattr(route, "dependant", None)
    for location in ("query", "path", "header", "cookie"):
        names[location] = {field.alias for field in getattr(dependant, location + "_params", ())}
    public = []
    for error in exc.errors():
        location = error.get("loc", ())
        origin = location[0] if location and location[0] in names else "body"
        safe_location = [origin]
        if len(location) > 1 and isinstance(location[1], str) and location[1] in names[origin]:
            safe_location.append(location[1])
        kind = error.get("type", "value_error")
        kind = kind if kind in _ERROR_TYPES else "value_error"
        public.append({"loc": safe_location, "msg": _MESSAGES.get(kind, "Invalid value or type"), "type": kind})
    return public
