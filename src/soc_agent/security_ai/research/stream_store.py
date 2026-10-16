"""Flow-only durable handoff over existing Queue, SourceStore and Runtime audit.

Transient packet inputs are separate private files. They are not permanent
source records, and are purged only after a durable no-retry outcome.
"""

import json
import re
from datetime import UTC, datetime
from typing import Literal
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from pydantic import Field, model_validator

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.network_monitor import configure
from soc_agent.linux_runtime.service import initialize
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.realtime.models import CommonEvent, SourceIdentity, SourceMetadata
from soc_agent.realtime.queue import EventQueue, QueueFull
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.secure_storage import create_private_directory, validate_file
from soc_agent.security_ai.operational.network_capture.models import (
    CaptureConfig,
    FlowSummary,
    PacketObservation,
)
from soc_agent.security_ai.operational.provenance import build_receipt, verify_receipt
from soc_agent.security_ai.operational.source_records import (
    FlowEndpoint,
    NetworkFlowSource,
    SourceHeader,
)
from soc_agent.security_ai.operational.source_store import OperationalSourceStore
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.live_input import LiveRequest, lifecycle_eligible
from soc_agent.security_ai.research.models import Frozen, digest
from soc_agent.security_ai.research.service import write_new


class Envelope(Frozen):
    contract: Literal["soc-stream-flow-handoff:v1"] = "soc-stream-flow-handoff:v1"
    origin: Literal["NATIVE_AF_PACKET", "FIXTURE"]
    capture_session: UUID
    flow: FlowSummary
    identities: tuple[UUID, ...] = Field(min_length=1, max_length=128)
    packets: tuple[PacketObservation, ...] = Field(min_length=1, max_length=128)
    values: tuple[float, ...] = Field(min_length=14, max_length=14)
    counter_start: int = Field(ge=1)
    counter_end: int = Field(ge=1)

    @model_validator(mode="after")
    def binding(self):
        from soc_agent.security_ai.operational.network_capture.flows import Flow

        if (
            len(self.packets) != len(self.identities)
            or tuple(map(str, self.identities)) != self.flow.source_event_ids
            or self.counter_end < self.counter_start
        ):
            raise ValueError("STREAM_FLOW_REFERENCE_MISMATCH")
        rebuilt = Flow(self.packets[0], self.packets[0])
        for packet, identity in zip(self.packets, self.identities, strict=True):
            rebuilt.add(packet, str(identity))
        if rebuilt.summary(self.flow.close_reason) != self.flow:
            raise ValueError("STREAM_FLOW_COUNTER_MISMATCH")
        return self


class StreamStore:
    def __init__(self, directory, session, *, fixture=False, create=False):
        self.directory = directory
        self.session = session
        self.fixture = fixture
        runtime = directory / "runtime"
        if create:
            initialize(
                runtime,
                RuntimeConfig(incident_id=uuid4(), repeated_failures=5, multiple_accounts=3),
            )
            configure(
                runtime,
                CaptureConfig(
                    interface="lo",
                    origin="EXPLICIT_PACKET_FIXTURE" if fixture else "NATIVE_AF_PACKET",
                ),
            )
            create_private_directory(directory / "inputs")
        self.runtime = RuntimeStore(runtime)
        self.queue = EventQueue(runtime / "network/queue.sqlite")
        self.sources = OperationalSourceStore(
            runtime / "network/sources.sqlite",
            allowed_lateness_seconds=60,
            max_future_skew_seconds=5,
            capacity=10000,
        )
        self.incident = self.runtime.config.incident_id

    def _event(self, flow, envelope_digest):
        source = SourceIdentity(
            namespace=(
                "scenario:network:streaming:" if self.fixture else "linux:af_packet:streaming:"
            )
            + self.session.interface_id,
            generation=str(self.session.session_id),
            record=flow.flow_id,
        )
        return CommonEvent(
            schema_version="soc-common-event:v2" if self.fixture else "soc-common-event:v1",
            event_id=uuid5(NAMESPACE_URL, content_digest(source)),
            platform="validated_fixture" if self.fixture else "linux",
            collector_id="scenario-network-capture:v1"
            if self.fixture
            else "linux:af_packet:streaming:v1",
            event_type="os_record",
            event_timestamp=flow.ended_at,
            ingestion_timestamp=datetime.now(UTC),
            source=source,
            metadata=SourceMetadata(
                channel="AF_PACKET", provider="soc-managed-stream:v1", code="flow-handoff"
            ),
            normalized_fields=(("flow_id", flow.flow_id), ("input_digest", envelope_digest)),
            provenance="explicit_log_fixture" if self.fixture else "native_read_only",
        )

    def source(self, event, flow):
        return NetworkFlowSource(
            header=SourceHeader(
                incident_id=self.incident,
                event_id=str(event.event_id),
                source=event.source,
                collector_id=event.collector_id,
                collector_version="stream-v1",
                observed_at=flow.ended_at,
            ),
            transport=flow.transport,
            endpoint_a=FlowEndpoint(address=str(flow.source_address), port=flow.source_port),
            endpoint_b=FlowEndpoint(
                address=str(flow.destination_address), port=flow.destination_port
            ),
            started_at=flow.started_at,
            ended_at=flow.ended_at,
            reported_packet_count=flow.forward_packets + flow.backward_packets,
        )

    def commit(self, completed, window, *, enqueue=True) -> CommonEvent:
        counts = self.queue.counts()
        if (
            counts.get("PENDING", 0) + counts.get("CLAIMED", 0)
            >= self.session.policy.inference_capacity
        ):
            raise QueueFull("STREAM_INFERENCE_QUEUE_BACKPRESSURE")
        if sum(counts.values()) >= self.session.policy.max_flow_records:
            raise QueueFull("STREAM_FLOW_RETENTION_LIMIT")
        env = Envelope(
            origin="FIXTURE" if self.fixture else "NATIVE_AF_PACKET",
            capture_session=self.session.session_id,
            flow=completed.flow,
            identities=completed.identities,
            packets=completed.packets,
            values=completed.values,
            counter_start=window[0],
            counter_end=window[1],
        )
        if not lifecycle_eligible(env.flow.close_reason):
            raise ValueError("STREAM_INELIGIBLE_FLOW")
        if env.flow.interface_id != self.session.interface_id:
            raise ValueError("STREAM_INTERFACE_MISMATCH")
        event = self._event(env.flow, digest(env.model_dump(mode="json")))
        path = self.directory / "inputs" / ("input-" + env.flow.flow_id + ".json")
        write_new(path, env.model_dump(mode="json"))
        source = self.source(event, env.flow)
        self.sources.ingest(
            source,
            expected_incident=self.incident,
            expected_source_digest=source.content_digest,
            received_at=datetime.now(UTC),
        )
        receipt = build_receipt(self.sources, incident_id=self.incident, sources=(source,))
        self.runtime.event(
            "STREAM_FLOW_COMMITTED",
            dict(
                event_id=str(event.event_id),
                flow_id=env.flow.flow_id,
                input_digest=digest(env.model_dump(mode="json")),
                values=list(env.values),
                flow=env.flow.model_dump(mode="json"),
                counter_window=list(window),
                source_receipt=receipt.model_dump(mode="json"),
                source_assurance="LOCAL_WINDOW_VERIFIED_NOT_REMOTE_ATTESTATION",
            ),
        )
        if enqueue and not self.queue.enqueue(event):
            raise ValueError("STREAM_DUPLICATE_FLOW_HANDOFF")
        return event

    def load(self, event, profile):
        self.runtime.verify_audit()
        fields = dict(event.normalized_fields)
        path = self.input_path(event)
        env = Envelope.model_validate_json(read_local(path, 256 * 1024))
        if (
            digest(env.model_dump(mode="json")) != fields["input_digest"]
            or env.capture_session != self.session.session_id
            or env.flow.flow_id != fields["flow_id"]
            or env.origin != ("FIXTURE" if self.fixture else "NATIVE_AF_PACKET")
            or not lifecycle_eligible(env.flow.close_reason)
        ):
            raise ValueError("STREAM_INPUT_INTEGRITY_FAILED")
        source = self.source(event, env.flow)
        self.sources.load(source, expected_incident=self.incident)
        provenance = build_receipt(self.sources, incident_id=self.incident, sources=(source,))
        verify_receipt(provenance, self.sources, incident_id=self.incident, sources=(source,))
        binding = digest(
            dict(
                flow_event=event.source_digest,
                input_digest=fields["input_digest"],
                source_receipt=provenance.model_dump(mode="json"),
                counter_window=(env.counter_start, env.counter_end),
            )
        )
        request = LiveRequest(
            research_mode=True,
            origin=env.origin,
            profile=profile,
            invocation_id=uuid4(),
            capture_session=env.capture_session,
            flow_id=env.flow.flow_id,
            provenance_digest=binding,
            packet_event_ids=env.identities,
            packets=env.packets,
        )
        return request, env

    def input_path(self, event):
        fields = dict(event.normalized_fields)
        if any(
            not re.fullmatch(r"[a-f0-9]{64}", fields.get(k, ""))
            for k in ("flow_id", "input_digest")
        ):
            raise ValueError("STREAM_INPUT_REFERENCE_INVALID")
        return self.directory / "inputs" / ("input-" + fields["flow_id"] + ".json")

    def finish(self, claim, outcome):
        self.runtime.event(
            "STREAM_FLOW_OUTCOME",
            dict(
                event_id=str(claim.event.event_id),
                outcome=outcome,
                input_digest=dict(claim.event.normalized_fields)["input_digest"],
            ),
        )
        self.queue.finish(
            claim,
            {
                "inference": "NOT_INFERABLE",
                "incident_id": str(self.incident),
                "workflow": outcome,
                "human_boundary": "WRITE_DENIED",
            },
        )
        self.purge(claim.event)

    def purge(self, event):
        # Only queue DONE + matching durable audit authorize deletion of this
        # newly created transient file; immutable legacy sources are never pruned.
        self.runtime.verify_audit()
        with self.queue.database.transaction(write=False) as c:
            row = c.execute(
                "SELECT * FROM realtime_events WHERE event_id=?", (str(event.event_id),)
            ).fetchone()
            if (
                row is None
                or row["status"] != "DONE"
                or self.queue._decode(row).source_digest != event.source_digest
            ):
                raise ValueError("STREAM_PURGE_BEFORE_DURABLE_OUTCOME")
        fields = dict(event.normalized_fields)
        with self.runtime.database.transaction(write=False) as c:
            outcomes = [
                json.loads(r[0])["details"]
                for r in c.execute(
                    "SELECT payload FROM monitor_audit WHERE "
                    "json_extract(payload,'$.kind')='STREAM_FLOW_OUTCOME'"
                )
            ]
        if not any(
            o.get("event_id") == str(event.event_id)
            and o.get("input_digest") == fields["input_digest"]
            for o in outcomes
        ):
            raise ValueError("STREAM_PURGE_AUDIT_OUTCOME_MISSING")
        path = self.input_path(event)
        if path.exists():
            validate_file(path)
            body = json.loads(read_local(path, 256 * 1024))
            if digest(body) != fields["input_digest"]:
                raise ValueError("STREAM_PURGE_INPUT_MISMATCH")
            self.runtime.event(
                "STREAM_PACKET_METADATA_PURGED",
                dict(
                    event_id=str(event.event_id),
                    input_digest=fields["input_digest"],
                    historical_validation="SEALED_RECEIPTS_NO_PACKET_REPLAY",
                ),
            )
            path.unlink()

    def recover_no_retry(self):
        self.runtime.verify_audit()
        self.queue.recover()
        while claim := self.queue.claim():
            self.finish(claim, "UNKNOWN_CRASH_NO_RETRY")
        with self.queue.database.transaction(write=False) as c:
            done = [
                self.queue._decode(r)
                for r in c.execute("SELECT * FROM realtime_events WHERE status='DONE'")
            ]
        for event in done:
            self.purge(event)
        if list((self.directory / "inputs").glob("input-*.json")):
            raise ValueError("STREAM_ORPHAN_INPUT_REQUIRES_REVIEW")
        self.runtime.event(
            "STREAM_RESTART_GAP",
            {"automatic_capture_restart": False, "automatic_inference_retry": False},
        )
