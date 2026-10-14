"""Read-only archive review manifests. No executor, approval minting, movement or deletion."""

from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.review.persistence.models import StorageError
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.security_ai.operational.authentication_investigation import read_authentication_view
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.state.evidence import UTCTimestamp, utc_now

Readiness = Literal[
    "READY_FOR_REVIEW",
    "PROTECTED",
    "INCOMPLETE_EVIDENCE",
    "INTEGRITY_FAILURE",
    "APPROVAL_REQUIRED",
    "BLOCKED",
]


class ArchiveRequest(Snapshot):
    incident_id: UUID
    source_event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=10000)
    expected_source_digests: tuple[Hash, ...] = Field(min_length=1, max_length=10000)

    @model_validator(mode="after")
    def unique_targets(self):
        if len(self.source_event_ids) != len(self.expected_source_digests) or len(
            set(self.source_event_ids)
        ) != len(self.source_event_ids):
            raise ValueError("ARCHIVE_TARGETS_REJECTED")
        return self


class ArchiveManifest(Snapshot):
    contract_version: Literal["soc-auth-archive-readiness:v1"] = "soc-auth-archive-readiness:v1"
    archive_candidate_id: Hash
    binding_digest: Hash
    source_event_ids: tuple[UUID, ...]
    expected_source_digests: tuple[Hash, ...]
    source_digests: tuple[Hash, ...]
    window_ids: tuple[Hash, ...]
    incident_ids: tuple[UUID, ...]
    provenance_references: tuple[Hash, ...]
    evidence_digest: Hash | None = None
    retention_status: Literal["PROTECTED", "UNVERIFIABLE"]
    readiness_status: Readiness
    blocking_reasons: tuple[str, ...] = Field(min_length=1)
    approval_requirement: Literal["NO_EXECUTION_APPROVAL_CONTRACT"] = (
        "NO_EXECUTION_APPROVAL_CONTRACT"
    )
    archive_execution_allowed: Literal[False] = False
    manifest_digest: Hash
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    def core(self):
        return self.model_dump(mode="json", exclude={"manifest_digest", "created_at"})

    @model_validator(mode="after")
    def validate_digest(self):
        if self.manifest_digest != content_digest_payload(self.core()):
            raise ValueError("ARCHIVE_MANIFEST_DIGEST_REJECTED")
        return self


def archive_manifest(pipeline: AuthenticationPipeline, request: ArchiveRequest) -> ArchiveManifest:
    """Caller holds existing writer lock. Local validation cannot clear external references."""
    request = ArchiveRequest.model_validate(request.model_dump())
    targets = sorted(
        zip(request.source_event_ids, request.expected_source_digests, strict=True),
        key=lambda x: str(x[0]),
    )
    key = {
        "binding": pipeline.digest,
        "incident": str(request.incident_id),
        "targets": [[str(e), d] for e, d in targets],
    }
    sources = []
    windows = []
    provenance = []
    evidence = None
    status = "PROTECTED"
    reasons = [
        "INCIDENT_BOUND",
        "PROVENANCE_REQUIRED",
        "EXTERNAL_EVIDENCE_REFERENCES_UNKNOWN",
        "NO_EXECUTION_APPROVAL_CONTRACT",
    ]
    integrity = "PROTECTED"
    try:
        if request.incident_id != pipeline.incident_id:
            status, reasons, integrity = "BLOCKED", ["INCIDENT_BINDING_MISMATCH"], "UNVERIFIABLE"
        else:
            with pipeline.queue.database.transaction(write=False) as c:
                pipeline._binding(c)
                rows = [
                    c.execute(
                        "SELECT * FROM realtime_events WHERE event_id=?", (str(e),)
                    ).fetchone()
                    for e, _ in targets
                ]
                if any(row is None for row in rows):
                    status, reasons = "INCOMPLETE_EVIDENCE", ["SOURCE_EVENT_MISSING"]
                elif any(row["status"] != "DONE" for row in rows):
                    status, reasons = "INCOMPLETE_EVIDENCE", ["QUEUE_PENDING_RETRY_OR_POISON"]
                else:
                    for row in rows:
                        pipeline.queue._decode(row)
            if status == "PROTECTED":
                view = read_authentication_view(pipeline)
                with pipeline.store.database.transaction(write=False) as c:
                    stored = [
                        pipeline.store._decode(row)
                        for row in c.execute(
                            "SELECT * FROM operational_sources WHERE incident_id=?",
                            (str(pipeline.incident_id),),
                        )
                    ]
                by_event = {s.header.event_id: s for s in stored}
                selected = [by_event.get(str(e)) for e, _ in targets]
                if any(s is None for s in selected):
                    status, reasons = "INCOMPLETE_EVIDENCE", ["AUTHENTICATION_SOURCE_MISSING"]
                elif any(
                    s.content_digest != d for s, (_, d) in zip(selected, targets, strict=True)
                ):
                    status, reasons, integrity = (
                        "INTEGRITY_FAILURE",
                        ["SOURCE_DIGEST_MISMATCH"],
                        "UNVERIFIABLE",
                    )
                else:
                    sources = sorted(s.content_digest for s in selected)
                    snapshots = pipeline.store.windows(pipeline.incident_id)
                    requested = {str(e) for e, _ in targets}
                    windows = sorted(
                        pipeline.store._window_key(w)
                        for w in snapshots
                        if requested.intersection(w.window.event_ids)
                    )
                    provenance = sorted(
                        w.provenance_reference
                        for w in view.authentication_window
                        if set(w.source_reference).intersection(sources)
                    )
                    evidence = view.evidence_digest
                    if not windows or not provenance:
                        status, reasons = (
                            "INCOMPLETE_EVIDENCE",
                            ["WINDOW_OR_PROVENANCE_MISSING_OR_QUARANTINED"],
                        )
    except StorageError:
        status, reasons, integrity = "BLOCKED", ["STORE_READ_FAILED"], "UNVERIFIABLE"
    except (ValueError, OSError, RuntimeError):
        status, reasons, integrity = (
            "INTEGRITY_FAILURE",
            ["LOCAL_REFERENCE_VALIDATION_FAILED"],
            "UNVERIFIABLE",
        )
    core = {
        "contract_version": "soc-auth-archive-readiness:v1",
        "archive_candidate_id": content_digest_payload(key),
        "binding_digest": pipeline.digest,
        "source_event_ids": [str(e) for e, _ in targets],
        "expected_source_digests": [d for _, d in targets],
        "source_digests": sources,
        "window_ids": windows,
        "incident_ids": [str(request.incident_id)],
        "provenance_references": provenance,
        "evidence_digest": evidence,
        "retention_status": integrity,
        "readiness_status": status,
        "blocking_reasons": reasons,
        "approval_requirement": "NO_EXECUTION_APPROVAL_CONTRACT",
        "archive_execution_allowed": False,
    }
    return ArchiveManifest.model_validate(core | {"manifest_digest": content_digest_payload(core)})
