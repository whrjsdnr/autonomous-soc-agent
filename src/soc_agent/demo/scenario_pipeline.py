"""Fixture replay through the existing queue, aggregation and read-only investigator."""

from datetime import datetime
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

from soc_agent.demo.scenario_models import Scenario, journal_fixture
from soc_agent.realtime.models import CommonEvent, SourceIdentity
from soc_agent.realtime.queue import EventQueue
from soc_agent.review.identity import content_digest
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.native_authentication import (
    SCENARIO_COLLECTOR,
    SCENARIO_IDENTITY,
    project_journal,
)
from soc_agent.security_ai.operational.source_store import OperationalSourceStore


def fixture_event(
    scenario: Scenario, index: int, replay_run_id: UUID, *, timestamp: datetime | None = None
) -> CommonEvent:
    # Reuse the parser without claiming its projected kernel fields were observed live.
    row = journal_fixture(scenario, index, replay_run_id)
    if timestamp is not None:
        row["__REALTIME_TIMESTAMP"] = str(int(timestamp.timestamp() * 1e6))
    projected = project_journal(row, include_pam_failures=True)
    source = SourceIdentity(
        namespace=f"scenario:{scenario.scenario_id}:{scenario.fixture_identity}",
        generation=str(replay_run_id),
        record=projected.source.record,
    )
    return CommonEvent.model_validate(
        projected.model_dump()
        | {
            "schema_version": "soc-common-event:v2",
            "event_id": uuid5(NAMESPACE_URL, content_digest(source)),
            "platform": "validated_fixture",
            "provenance": "explicit_log_fixture",
            "collector_id": SCENARIO_COLLECTOR,
            "source": source.model_dump(),
        }
    )


def open_pipeline(directory: Path, incident: UUID, *, create: bool) -> AuthenticationPipeline:
    qpath, spath = directory / "queue.sqlite", directory / "sources.sqlite"
    if create:
        queue = EventQueue.create(qpath)
        store = OperationalSourceStore.create(
            spath, allowed_lateness_seconds=60, max_future_skew_seconds=5
        )
    else:
        queue = EventQueue(qpath)
        store = OperationalSourceStore(
            spath, allowed_lateness_seconds=60, max_future_skew_seconds=5
        )
    return AuthenticationPipeline(queue, store, incident, collector_identity=SCENARIO_IDENTITY)


def verify_network_dns_gate(directory: Path, incident: UUID, run_id: UUID) -> tuple[str, ...]:
    """Actual v3 source-chain validator on declared fixtures; never loads a model."""
    from soc_agent.demo.scenario_models import START
    from soc_agent.security_ai.operational.provenance import build_receipt, verify_receipt
    from soc_agent.security_ai.operational.source_records import (
        DNSQuerySource,
        FlowEndpoint,
        NetworkFlowSource,
        SourceHeader,
    )

    store = OperationalSourceStore.create(
        directory / "gates" / "sources.sqlite",
        allowed_lateness_seconds=60,
        max_future_skew_seconds=5,
    )
    receipts = []
    for kind in ("network", "dns"):
        header = SourceHeader(
            incident_id=incident,
            event_id=f"scenario-{run_id}-{kind}",
            source=SourceIdentity(
                namespace="scenario:model-gate", generation=str(run_id), record=kind
            ),
            collector_id="scenario-raw-input:v1",
            collector_version="1.0.0",
            observed_at=START,
        )
        if kind == "network":
            source = NetworkFlowSource(
                header=header,
                transport="tcp",
                endpoint_a=FlowEndpoint(address="192.0.2.1", port=40000),
                endpoint_b=FlowEndpoint(address="198.51.100.1", port=443),
                started_at=START,
                ended_at=START,
            )
        else:
            source = DNSQuerySource(
                header=header,
                query_name="fixture.example.",
                query_type=1,
                query_class=1,
                transaction_id=1,
            )
        store.ingest(
            source,
            expected_incident=incident,
            expected_source_digest=source.content_digest,
            received_at=START,
        )
        receipt = build_receipt(store, incident_id=incident, sources=(source,))
        verify_receipt(receipt, store, incident_id=incident, sources=(source,))
        if receipt.inference_status != "NOT_INFERABLE" or receipt.rule_status != "UNVERIFIED":
            raise ValueError("SCENARIO_MODEL_GATE_BYPASS")
        receipts.append(receipt.receipt_digest)
    return tuple(receipts)
