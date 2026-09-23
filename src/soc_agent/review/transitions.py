"""Explicit minimal v1 policy for incident metadata, independent of Tool PolicyEngine."""

from soc_agent.review.errors import StateTransitionDenied
from soc_agent.review.models import StateChangeRequest
from soc_agent.state import IncidentState, IncidentStatus


def validate_changes(state: IncidentState, request: StateChangeRequest) -> None:
    if request.target.incident_id != state.incident_id:
        raise StateTransitionDenied("State change incident mismatch")
    # Sequential lifecycle; assessment may request another investigation. CLOSED is terminal.
    permitted = (
        (IncidentStatus.NEW, IncidentStatus.TRIAGING),
        (IncidentStatus.TRIAGING, IncidentStatus.INVESTIGATING),
        (IncidentStatus.INVESTIGATING, IncidentStatus.ASSESSING),
        (IncidentStatus.ASSESSING, IncidentStatus.INVESTIGATING),
        (IncidentStatus.ASSESSING, IncidentStatus.CLOSED),
    )
    if state.status == IncidentStatus.CLOSED:
        raise StateTransitionDenied("CLOSED incidents cannot be changed under v1")
    for change in request.changes:
        if getattr(state, change.field) != change.before:
            raise StateTransitionDenied("Change before-value differs from current state")
        if change.field == "status" and (change.before, change.after) not in permitted:
            raise StateTransitionDenied("Status transition is not permitted under v1")
