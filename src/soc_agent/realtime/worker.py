"""Common events into the existing offline, governed SOC runtime."""

import json
from math import isfinite
from uuid import NAMESPACE_URL, UUID, uuid5

from soc_agent.application import compose_application
from soc_agent.deployment import DeploymentDescriptor
from soc_agent.desktop import OfflineDesktopClient, ReadReportInput
from soc_agent.external_runtime import CODE_PIN, CONTRACT, bind_features
from soc_agent.ingestion import EventIngestor
from soc_agent.realtime.models import CommonEvent
from soc_agent.review.models import Frozen
from soc_agent.review.persistence.models import StorageError
from soc_agent.security_ai.external.inference import InferenceUnavailable
from soc_agent.security_ai.external.metadata import reviewed_binding
from soc_agent.security_ai.external.runtime_store import RuntimeGovernanceStore
from soc_agent.state import Evidence, IncidentState
from soc_agent.tools import Tool, ToolMetadata, ToolPermission, ToolRegistry, ToolRiskLevel


class SourceReport(Frozen):
    event_id: UUID
    source_digest: str
    meaning: str = "retained source metadata; not an attack finding"


def composition(
    store: RuntimeGovernanceStore, *, profile="DESKTOP", artifacts=None, native_python=None
):
    ingestion = EventIngestor(store)

    async def read(value: ReadReportInput):
        incident = store.load(value.incident_id)
        sources = [e for e in incident.state.evidence if e.source == "common-event:v1"]
        if len(sources) != 1:
            raise ValueError("Common source record unavailable")
        event = CommonEvent.model_validate_json(sources[0].raw_data)
        if incident_id(event) != value.incident_id:
            raise ValueError("Common source incident mismatch")
        return SourceReport(event_id=event.event_id, source_digest=event.source_digest)

    registry = ToolRegistry()
    registry.register(
        Tool(
            ToolMetadata(
                name="read_local_source_report",
                description="Read minimized common source metadata only",
                permission=ToolPermission.SYSTEM_READ,
                risk_level=ToolRiskLevel.READ_ONLY,
            ),
            ReadReportInput,
            SourceReport,
            read,
        )
    )
    return compose_application(
        store,
        deployment=DeploymentDescriptor(profile=profile),
        registry=registry,
        llm_client=OfflineDesktopClient(),
        ingestion=ingestion,
        external_artifacts=artifacts,
        external_interpreter=native_python,
    )


def incident_id(event):
    if event.soc_event:
        return uuid5(
            NAMESPACE_URL,
            f"soc-agent:{event.soc_event.event_type}-event:{event.soc_event.event_id}",
        )
    return uuid5(NAMESPACE_URL, "soc-common-event:" + str(event.event_id))


def validate_features(event: CommonEvent) -> None:
    seen = set()
    for row in event.feature_payload:
        if not row.profiles or len(set(row.profiles)) != len(row.profiles):
            raise ValueError("Explicit unique model profiles required")
        values = json.loads(row.observation.feature_payload)
        if not isinstance(values, dict):
            raise ValueError("Named feature mapping required")
        for profile in row.profiles:
            if profile in seen:
                raise ValueError("Duplicate model result request")
            seen.add(profile)
            binding = reviewed_binding(
                profile, expected_code_identity=CODE_PIN, runtime_contract_digest=CONTRACT
            )
            if row.observation.feature_identity != binding.feature_identity:
                raise ValueError("Official ordered feature identity mismatch")
            if set(values) != set(binding.feature_identity.ordered_names):
                raise ValueError("Required feature names/count mismatch; no filling")
            if any(
                type(value) not in (int, float) or not isfinite(value) for value in values.values()
            ):
                raise ValueError("Finite numeric features required")


async def process(application, event: CommonEvent):
    event = CommonEvent.model_validate(event.model_dump())
    validate_features(event)
    service = application.service
    store = service.store
    incident = incident_id(event)
    if event.soc_event:
        service.ingest(event.soc_event)
    else:
        with store.database.transaction(write=False) as c:
            exists = c.execute(
                "SELECT 1 FROM incidents WHERE incident_id=?", (str(incident),)
            ).fetchone()
        if not exists:
            store.register(IncidentState(incident_id=incident))
    current = store.load(incident)
    eid = uuid5(NAMESPACE_URL, "common-source:" + str(event.event_id))
    if any(e.source == "common-event:v1" and e.evidence_id != eid for e in current.state.evidence):
        raise ValueError("Incident already bound to another common source")
    retained = next((e for e in current.state.evidence if e.evidence_id == eid), None)
    if retained:
        if CommonEvent.model_validate_json(retained.raw_data).source_digest != event.source_digest:
            raise ValueError("Common source evidence changed")
    else:
        store.append_evidence(
            current.anchor,
            Evidence(
                evidence_id=eid,
                incident_id=incident,
                source="common-event:v1",
                summary="Minimized source record; model outputs are not observations",
                raw_data=event.model_dump_json(),
                observed_at=event.event_timestamp,
                collected_at=event.ingestion_timestamp,
            ),
        )
    inference = "NOT_INFERABLE"
    if event.feature_payload:
        if store.boundary.binding(incident) is None:
            service.analyze_external(
                incident, bind_features(store, incident, list(event.feature_payload))
            )
        inference = "VALIDATED_FOR_ADVISORY"
    runtime = service.runtime_factory()
    with store.database.transaction(write=False) as c:
        exists = c.execute(
            "SELECT 1 FROM workflow_checkpoints WHERE incident_id=?", (str(incident),)
        ).fetchone()
    runtime.restore(incident) if exists else runtime.start(incident)
    for _ in range(32):
        result = await runtime.advance(incident)
        if result.waiting_for_human or result.terminal:
            return {
                "inference": inference,
                "incident_id": str(incident),
                "workflow": result.next_step.value,
                "human_boundary": result.waiting_for_human,
            }
    raise ValueError("Common runtime step budget exceeded")


async def drain(queue, application):
    while claim := queue.claim():
        try:
            outcome = await process(application, claim.event)
        except InferenceUnavailable:
            queue.fail(claim, "INFERENCE_UNAVAILABLE")
            raise
        except StorageError:
            queue.fail(claim, "STORAGE_FAILURE")
            raise
        except ValueError:
            queue.fail(claim, "INVALID_INPUT")
            raise
        except (OSError, RuntimeError):
            queue.fail(claim)
            raise
        queue.finish(claim, outcome)
