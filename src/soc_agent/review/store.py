"""Atomic CAS reference store. Trusted infrastructure, not a user-facing mutation API."""

from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock
from typing import Protocol
from uuid import UUID, uuid4

from soc_agent.review.errors import AuthorizationAlreadyApplied, ReviewError, StaleSnapshotError
from soc_agent.review.identity import state_fingerprint
from soc_agent.review.models import ApplicationResult, StateAnchor, StoredIncident
from soc_agent.state import Evidence, IncidentState


class IncidentStateStore(Protocol):
    def load(self, incident_id: UUID) -> StoredIncident: ...

    def compare_and_apply(
        self,
        expected: StateAnchor,
        authorization_id: UUID,
        build: Callable[[StoredIncident], ApplicationResult],
    ) -> ApplicationResult:
        """Atomically check revision+digest and unused authorization, build and commit.

        Build must be pure and fully validate authorization. Any exception must leave
        state, authorization consumption and success audit unchanged. Durable adapters
        must commit all three together, with cross-process atomic CAS/unique constraints.
        """
        ...


@dataclass(frozen=True)
class _Data:
    states: dict[UUID, StoredIncident]
    consumed: frozenset[UUID]
    applications: tuple[ApplicationResult, ...]


class InMemoryIncidentStateStore:
    """One shared instance protects threads; no persistence or cross-process guarantee."""

    def __init__(self, states: tuple[IncidentState, ...]) -> None:
        self._lock = RLock()
        self._repository_id = uuid4()
        entries = {}
        for value in states:
            state = IncidentState.model_validate(value.model_dump(warnings=False))
            if state.incident_id in entries:
                raise ReviewError("Duplicate initial incident")
            entries[state.incident_id] = StoredIncident(
                state=state, anchor=self._anchor(state, revision=0)
            )
        self._data = _Data(entries, frozenset(), ())

    def _anchor(self, state: IncidentState, *, revision: int) -> StateAnchor:
        return StateAnchor(
            repository_id=self._repository_id,
            incident_id=state.incident_id,
            revision=revision,
            fingerprint=state_fingerprint(state),
        )

    def load(self, incident_id: UUID) -> StoredIncident:
        with self._lock:
            try:
                return self._data.states[incident_id]
            except KeyError as error:
                raise ReviewError("Unknown incident") from error

    def _current(self, expected: StateAnchor) -> StoredIncident:
        expected = StateAnchor.model_validate(expected.model_dump(warnings=False))
        current = self.load(expected.incident_id)
        if current.anchor != expected:
            raise StaleSnapshotError("Snapshot revision, repository or full content changed")
        return current

    def compare_and_apply(
        self,
        expected: StateAnchor,
        authorization_id: UUID,
        build: Callable[[StoredIncident], ApplicationResult],
    ) -> ApplicationResult:
        with self._lock:
            if authorization_id in self._data.consumed:
                raise AuthorizationAlreadyApplied("Authorization already applied")
            current = self._current(expected)
            result = ApplicationResult.model_validate(build(current).model_dump(warnings=False))
            anchor = self._anchor(result.incident_state, revision=current.anchor.revision + 1)
            if (
                result.incident_state.incident_id != current.state.incident_id
                or result.audit.resulting_snapshot != anchor
                or result.audit.authorization_id != authorization_id
                or result.audit.target.snapshot != expected
            ):
                raise ReviewError("Invalid atomic application result binding")
            entries = self._data.states | {
                current.state.incident_id: StoredIncident(
                    state=result.incident_state, anchor=anchor
                )
            }
            replacement = _Data(
                entries,
                self._data.consumed | {authorization_id},
                (*self._data.applications, result),
            )
            self._data = replacement
            return result

    def append_evidence(self, expected: StateAnchor, evidence: Evidence) -> StoredIncident:
        """Trusted ingestion CAS, using the existing append-only state API."""
        with self._lock:
            current = self._current(expected)
            state = current.state.add_evidence(evidence)
            entry = StoredIncident(
                state=state, anchor=self._anchor(state, revision=current.anchor.revision + 1)
            )
            self._data = _Data(
                self._data.states | {state.incident_id: entry},
                self._data.consumed,
                self._data.applications,
            )
            return entry

    def applications(self) -> tuple[ApplicationResult, ...]:
        with self._lock:
            return self._data.applications
