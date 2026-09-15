"""Shared immutable JSON object snapshots, without execution dependencies."""

import json

from pydantic import JsonValue, TypeAdapter


def canonical_json_object(value: object) -> str:
    """Accept only JSON-compatible objects; preserve array order and value types."""
    adapter = TypeAdapter(dict[str, JsonValue])
    payload = (
        adapter.validate_json(value, strict=True)
        if isinstance(value, str)
        else adapter.validate_python(value, strict=True)
    )
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
