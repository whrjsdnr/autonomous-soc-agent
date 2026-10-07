"""Shared immutable JSON object snapshots, without execution dependencies."""

import json
from typing import Final

from pydantic import JsonValue, TypeAdapter

# Reuse only compiled schema; never cache payloads or artifact verification results.
_JSON_OBJECT: Final[TypeAdapter[dict[str, JsonValue]]] = TypeAdapter(dict[str, JsonValue])


def canonical_json_object(value: object) -> str:
    """Accept only JSON-compatible objects; preserve array order and value types."""
    payload = (
        _JSON_OBJECT.validate_json(value, strict=True)
        if isinstance(value, str)
        else _JSON_OBJECT.validate_python(value, strict=True)
    )
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
