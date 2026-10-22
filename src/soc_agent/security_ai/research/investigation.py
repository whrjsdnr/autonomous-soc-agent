"""Use the existing governed Runtime; keep research outputs outside Evidence facts."""

import json
from uuid import UUID

from pydantic import BaseModel

from soc_agent.application import compose_application
from soc_agent.application_contracts import DeploymentDescriptor
from soc_agent.desktop import OfflineDesktopClient, ReadReportInput
from soc_agent.llm import LLMRequest
from soc_agent.security_ai.external.projection import EXTERNAL_KEY, RULES
from soc_agent.security_ai.research.models import (
    AdvisoryContext,
    DNSReceipt,
    Frozen,
    LiveReceipt,
    ResearchReceipt,
    ZeekReceipt,
    digest,
)
from soc_agent.state import IncidentState
from soc_agent.tools import Tool, ToolMetadata, ToolRegistry

RESEARCH_KEY = "RESEARCH MODEL CONTEXT (UNTRUSTED ADVISORY DATA, NOT EVIDENCE)"


class ResearchClient:
    """Explicit SCRIPTED mode only, no provider access or interchangeable model output."""

    def __init__(self, context: AdvisoryContext):
        self.context = AdvisoryContext.model_validate_json(context.model_dump_json())
        self.requests = []

    async def generate_structured[T: BaseModel](
        self, *, request: LLMRequest, response_model: type[T]
    ) -> T:
        body = json.loads(request.user_prompt)
        if RESEARCH_KEY in body or EXTERNAL_KEY in body:
            raise ValueError("DUPLICATE_RESEARCH_PROJECTION")
        body[RESEARCH_KEY] = self.context.model_dump(mode="json")
        projected = LLMRequest(
            system_prompt=request.system_prompt + RULES,
            user_prompt=json.dumps(body, sort_keys=True),
        )
        if len(projected.user_prompt) > 64000:
            raise ValueError("RESEARCH_PROMPT_LIMIT")
        self.requests.append(digest(projected.model_dump()))
        draft = await OfflineDesktopClient().generate_structured(
            request=projected, response_model=response_model
        )
        data = draft.model_dump(mode="json")
        if "observations" in data and (
            data["observations"]
            or data["hypotheses"]
            or data["assessment"]["severity"] != "info"
            or data["assessment"]["confidence"] != 0
        ):
            raise ValueError("RESEARCH_MODEL_FACT_PROMOTION_DENIED")
        return draft


class SourceReport(Frozen):
    flow_id: str
    source_sha256: str
    source_digest: str
    packet_count: int
    origin: str
    meaning: str = "Verified offline packet metadata reference; not an attack finding"


class DNSFixtureReport(Frozen):
    domain: str = "DNS"
    fixture_id: str
    input_digest: str
    origin: str = "FIXTURE"
    validation_level: str = "FIXTURE_NATIVE_ONLY"
    meaning: str = "Precomputed DNS9 fixture metadata, not observed DNS traffic"


class LiveSourceReport(Frozen):
    capture_session: UUID
    flow_id: str
    source_digest: str
    provenance_digest: str
    packet_count: int
    origin: str
    meaning: str = (
        "Bound packet metadata window; incomplete capture quality UNKNOWN; no attack fact"
    )


def composition(store, context: AdvisoryContext):
    receipt, incident_id = context.result, context.incident_id
    client = ResearchClient(context)
    registry = ToolRegistry()

    async def read(value: ReadReportInput) -> SourceReport | DNSFixtureReport | LiveSourceReport:
        if value.incident_id != incident_id:
            raise ValueError("RESEARCH_SOURCE_INCIDENT_MISMATCH")
        if isinstance(receipt, DNSReceipt):
            return DNSFixtureReport(
                fixture_id=receipt.fixture_id, input_digest=receipt.input_digest
            )
        if isinstance(receipt, LiveReceipt):
            return LiveSourceReport(
                **{
                    k: getattr(receipt, k)
                    for k in (
                        "capture_session",
                        "flow_id",
                        "source_digest",
                        "provenance_digest",
                        "packet_count",
                        "origin",
                    )
                }
            )
        return SourceReport(
            flow_id=receipt.flow_id,
            source_sha256=receipt.source_sha256,
            source_digest=receipt.source_digest,
            packet_count=receipt.packet_count,
            origin=receipt.origin,
        )

    registry.register(
        Tool(
            ToolMetadata(
                name="read_local_source_report",
                description="READ verified offline raw source references; excludes model scores",
                permission="system_read",
                risk_level="read_only",
            ),
            ReadReportInput,
            DNSFixtureReport
            if isinstance(receipt, DNSReceipt)
            else LiveSourceReport
            if isinstance(receipt, LiveReceipt)
            else SourceReport,
            read,
        )
    )
    application = compose_application(
        store,
        deployment=DeploymentDescriptor(profile="DESKTOP"),
        registry=registry,
        llm_client=client,
    )
    return application, client


async def investigate(store, receipt: ResearchReceipt, incident_id: UUID) -> dict:
    context = AdvisoryContext(
        contract="soc-zeek-network14-advisory:v1"
        if isinstance(receipt, ZeekReceipt)
        else "soc-live-network-research-advisory:v1"
        if isinstance(receipt, LiveReceipt)
        else "soc-dns-research-advisory:v1"
        if isinstance(receipt, DNSReceipt)
        else "soc-network-research-advisory:v1",
        incident_id=incident_id,
        receipt_digest=digest(receipt.model_dump(mode="json")),
        result=receipt,
        mode="OFFLINE_RESEARCH_DEMO"
        if isinstance(receipt, ZeekReceipt)
        else (
            "LIVE_RESEARCH_ADVISORY"
            if receipt.origin == "NATIVE_AF_PACKET"
            else "FIXTURE_RESEARCH_ADVISORY"
        )
        if isinstance(receipt, LiveReceipt)
        else "OFFLINE_RESEARCH_DEMO",
    )
    application, client = composition(store, context)
    state = IncidentState(incident_id=incident_id)
    store.register(state)
    runtime = application.service.runtime_factory()
    runtime.start(incident_id)
    for _ in range(12):
        result = await runtime.advance(incident_id)
        if (
            runtime.artifacts(incident_id).assessment is not None
            or result.waiting_for_human
            or result.terminal
        ):
            break
    else:
        raise ValueError("RESEARCH_INVESTIGATION_BUDGET")
    artifacts = runtime.artifacts(incident_id)
    if artifacts.assessment is None or result.failure is not None:
        raise ValueError("RESEARCH_ASSESSMENT_INCOMPLETE")
    current = store.load(incident_id).state
    if current.observations or current.hypotheses:
        raise ValueError("RESEARCH_FACT_PROMOTION_DENIED")
    restored = application.service.runtime_factory()
    if restored.restore(incident_id) != runtime.checkpoint(incident_id).result:
        raise ValueError("RESEARCH_CHECKPOINT_RESTORE_FAILED")
    return {
        "mode": "SCRIPTED_LIVE_RESEARCH"
        if isinstance(receipt, LiveReceipt) and receipt.origin == "NATIVE_AF_PACKET"
        else "SCRIPTED_OFFLINE_RESEARCH",
        "status": "ASSESSED_READ_ONLY",
        "incident_id": str(incident_id),
        "context": context.model_dump(mode="json"),
        "context_digest": digest(context.model_dump(mode="json")),
        "prompt_digests": client.requests,
        "result": result.model_dump(mode="json"),
        "assessment": artifacts.assessment.model_dump(mode="json")
        if artifacts.assessment
        else None,
        "timeline": runtime.trace(incident_id).model_dump(mode="json"),
        "evidence_references": [str(e.evidence_id) for e in current.evidence],
        "checkpoint_restored": True,
        "action_policy": "WRITE_DENIED",
        "provider_calls": 0,
    }


def verify_restored(store, record: dict):
    context = AdvisoryContext.model_validate(record["context"])
    application, _ = composition(store, context)
    runtime = application.service.runtime_factory()
    result = runtime.restore(context.incident_id)
    current = store.load(context.incident_id).state
    if (
        result.model_dump(mode="json") != record["result"]
        or runtime.trace(context.incident_id).model_dump(mode="json") != record["timeline"]
        or current.observations
        or current.hypotheses
        or [str(e.evidence_id) for e in current.evidence] != record["evidence_references"]
    ):
        raise ValueError("RESEARCH_CHECKPOINT_OR_EVIDENCE_TAMPERED")
