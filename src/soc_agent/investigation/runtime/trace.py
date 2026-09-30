"""Immutable explanatory lineage, never evidence or execution authority."""

from typing import Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.investigation.runtime.models import WorkflowResult, WorkflowStep
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash, StateAnchor


class TraceContent(Frozen):
    sequence: int = Field(strict=True, ge=1)
    snapshot: StateAnchor
    result: WorkflowResult
    previous_entry_id: Hash | None = None

    @model_validator(mode="after")
    def incident_binding(self) -> Self:
        if self.snapshot.incident_id != self.result.incident_id:
            raise ValueError("Trace result and snapshot incident differ")
        refs = [(ref.kind, ref.identity) for ref in self.result.references]
        if len(refs) != len(set(refs)):
            raise ValueError("Duplicate artifact reference")
        return self


class OrchestrationTraceEntry(Frozen):
    entry_id: Hash
    content: TraceContent

    @model_validator(mode="after")
    def exact_content(self) -> Self:
        if self.entry_id != content_digest(self.content):
            raise ValueError("Trace entry digest mismatch")
        return self


class OrchestrationTrace(Frozen):
    incident_id: UUID
    entries: tuple[OrchestrationTraceEntry, ...] = ()

    @model_validator(mode="after")
    def ordered_lineage(self) -> Self:
        previous = None
        for sequence, entry in enumerate(self.entries, start=1):
            content = entry.content
            if content.sequence != sequence or content.result.incident_id != self.incident_id:
                raise ValueError("Trace sequence or incident mismatch")
            if content.previous_entry_id != (previous.entry_id if previous else None):
                raise ValueError("Trace predecessor mismatch")
            if previous:
                last = previous.content
                if content.result == last.result and content.snapshot == last.snapshot:
                    raise ValueError("Duplicate consecutive result")
                if content.result.current_step != last.result.next_step:
                    raise ValueError("Trace workflow discontinuity")
                if (
                    content.snapshot.revision == last.snapshot.revision
                    and content.snapshot != last.snapshot
                ):
                    raise ValueError("Same revision has inconsistent snapshot binding")
                if (
                    content.snapshot.repository_id != last.snapshot.repository_id
                    or content.snapshot.revision < last.snapshot.revision
                ):
                    raise ValueError("Trace snapshot lineage mismatch")
            elif content.result.current_step != WorkflowStep.OBSERVE:
                raise ValueError("Trace must start at observation")
            previous = entry
        return self
