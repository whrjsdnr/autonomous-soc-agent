"""Exact content digests, including all evidence and timestamps; not authentication."""

import hashlib

from pydantic import BaseModel

from soc_agent._json import canonical_json_object
from soc_agent.state import IncidentState


def content_digest(value: BaseModel) -> str:
    return hashlib.sha256(canonical_json_object(value.model_dump(mode="json")).encode()).hexdigest()


def state_fingerprint(state: IncidentState) -> str:
    validated = IncidentState.model_validate(state.model_dump(warnings=False))
    return content_digest(validated)
