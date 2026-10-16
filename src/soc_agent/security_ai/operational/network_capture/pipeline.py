"""Existing EventQueue + SourceStore + v3 receipt. No operational model input is issued."""

import json
from datetime import datetime
from uuid import NAMESPACE_URL, UUID, uuid5

from soc_agent.realtime.models import CommonEvent, SourceIdentity, SourceMetadata
from soc_agent.realtime.queue import EventQueue
from soc_agent.review.identity import content_digest
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.network_capture.flows import Flow, FlowTable
from soc_agent.security_ai.operational.network_capture.models import (
    CaptureConfig,
    DNSNativeEvent,
    FlowSummary,
    PacketObservation,
)
from soc_agent.security_ai.operational.provenance import build_receipt
from soc_agent.security_ai.operational.source_records import (
    FlowEndpoint,
    NetworkFlowSource,
    SourceHeader,
)
from soc_agent.security_ai.operational.source_store import OperationalSourceStore
from soc_agent.state.evidence import utc_now


class NetworkPipeline:
    def __init__(
        self,
        queue: EventQueue,
        sources: OperationalSourceStore,
        incident: UUID,
        config: CaptureConfig,
        identity: str,
        audit,
    ):
        self.queue, self.sources, self.incident = queue, sources, incident
        self.config, self.identity, self.audit = config, identity, audit
        self.table = FlowTable(config)
        self.generations: dict[str, str] = {}
        self.closed: set[str] = set()
        self.generated_flows = 0
        self.committed = {}
        self.audit.verify_audit()
        with self.audit.database.transaction(write=False) as c:
            for row in c.execute("SELECT payload FROM monitor_audit"):
                body = json.loads(row["payload"])
                if body["kind"] == "NETWORK_SOURCE_COMMITTED":
                    key = body["details"]["event_id"]
                    if key in self.committed:
                        raise ValueError("DUPLICATE_NETWORK_AUDIT_EVENT")
                    self.committed[key] = body["details"]["provenance"]

    def event(self, record: PacketObservation | FlowSummary, generation: str, sequence: int = 0):
        fixture = self.config.origin == "EXPLICIT_PACKET_FIXTURE"
        code = "packet" if isinstance(record, PacketObservation) else "flow"
        if record.interface_id != self.identity:
            raise ValueError("CAPTURE_INTERFACE_BINDING_MISMATCH")
        if isinstance(record, PacketObservation) and (
            (record.timestamp_origin == "FIXTURE") != fixture
        ):
            raise ValueError("CAPTURE_ORIGIN_MISMATCH")
        raw = record.model_dump_json()
        if len(raw) > 8192:
            raise ValueError("CAPTURE_RECORD_SIZE_LIMIT")
        namespace = (
            ("scenario:network:" if fixture else "linux:af_packet:") + self.identity + ":" + code
        )
        key = (
            str(sequence) + ":" + record.raw_frame_digest
            if code == "packet"
            else record.flow_id + ":" + content_digest_payload(record.model_dump(mode="json"))
        )
        source = SourceIdentity(namespace=namespace, generation=generation, record=key)
        stamp = record.timestamp if code == "packet" else record.ended_at
        return CommonEvent(
            schema_version="soc-common-event:v2" if fixture else "soc-common-event:v1",
            event_id=uuid5(NAMESPACE_URL, content_digest(source)),
            platform="validated_fixture" if fixture else "linux",
            collector_id="scenario-network-capture:v1" if fixture else "linux:af_packet:v1",
            event_type="os_record",
            event_timestamp=stamp,
            ingestion_timestamp=utc_now(),
            source=source,
            metadata=SourceMetadata(
                channel="AF_PACKET", provider="soc-linux-network:v1", code=code
            ),
            normalized_fields=tuple(
                (f"record_{i // 512:02}", raw[i : i + 512]) for i in range(0, len(raw), 512)
            ),
            provenance="explicit_log_fixture" if fixture else "native_read_only",
        )

    def decode(self, event: CommonEvent) -> PacketObservation | FlowSummary:
        event = CommonEvent.model_validate(event.model_dump())
        fixture = self.config.origin == "EXPLICIT_PACKET_FIXTURE"
        expected = "scenario-network-capture:v1" if fixture else "linux:af_packet:v1"
        if event.collector_id != expected or event.metadata.provider != "soc-linux-network:v1":
            raise ValueError("CAPTURE_COLLECTOR_BINDING_MISMATCH")
        fields = event.normalized_fields
        if [k for k, _ in fields] != [f"record_{i:02}" for i in range(len(fields))]:
            raise ValueError("CAPTURE_CHUNK_BINDING_MISMATCH")
        raw = "".join(v for _, v in fields)
        cls = PacketObservation if event.metadata.code == "packet" else FlowSummary
        record = cls.model_validate_json(raw)
        sequence = (
            int(event.source.record.split(":", 1)[0])
            if isinstance(record, PacketObservation)
            else 0
        )
        expected_event = self.event(record, event.source.generation, sequence)
        if expected_event.source_digest != event.source_digest:
            raise ValueError("CAPTURE_SOURCE_IDENTITY_MISMATCH")
        return record

    def packet(self, packet: PacketObservation, generation: str, sequence: int):
        event = self.event(packet, generation, sequence)
        new = self.queue.enqueue(event, cursor_source="network:last_persisted")
        if new:
            self.generations[str(event.event_id)] = generation
            for flow in self.table.add(packet, str(event.event_id)):
                self.emit(flow)
        return new

    def emit(self, flow: FlowSummary):
        if flow.flow_id in self.closed:
            return
        generation = self.generations[flow.source_event_ids[0]]
        if self.queue.enqueue(self.event(flow, generation)):
            self.generated_flows += 1
        self.closed.add(flow.flow_id)

    def flush(self, now: datetime, reason: str | None = None):
        for flow in self.table.expire(now, reason):
            self.emit(flow)

    def recover(self):
        self.queue.recover()
        self.table = FlowTable(self.config)
        completed = []
        events = []
        with self.queue.database.transaction(write=False) as c:
            for row in c.execute("SELECT * FROM realtime_events ORDER BY rowid"):
                event = self.queue._decode(row)
                events.append((event, self.decode(event)))
        self.closed = {r.flow_id for _, r in events if isinstance(r, FlowSummary)}
        for event, record in events:
            if isinstance(record, PacketObservation):
                self.generations[str(event.event_id)] = event.source.generation
                completed.extend(self.table.add(record, str(event.event_id)))
        # No raw packet replay exists after a process interruption. All reconstructed
        # open flows end as incomplete, even if shutdown was graceful.
        completed.extend(self.table.expire(utc_now(), "RESTART_GAP"))
        for flow in completed:
            self.emit(flow)
        self.generated_flows = 0  # recovered history is not new live Flow production

    def dns_event(self, event: CommonEvent) -> DNSNativeEvent | None:
        packet = self.decode(event)
        if not isinstance(packet, PacketObservation) or packet.dns is None:
            return None
        return DNSNativeEvent(
            event_id=content_digest_payload({"packet_event": str(event.event_id), "question": 0}),
            source_event_id=str(event.event_id),
            source=event.source,
            timestamp=packet.timestamp,
            source_address=packet.source_address,
            destination_address=packet.destination_address,
            source_port=packet.source_port,
            destination_port=packet.destination_port,
            transport=packet.transport,
            question=packet.dns,
        )

    def _source(self, event: CommonEvent, record: PacketObservation | FlowSummary):
        packet = isinstance(record, PacketObservation)
        return NetworkFlowSource(
            header=SourceHeader(
                incident_id=self.incident,
                event_id=str(event.event_id),
                source=event.source,
                collector_id=event.collector_id,
                collector_version="1",
                observed_at=event.event_timestamp,
            ),
            transport=record.transport,
            endpoint_a=FlowEndpoint(address=str(record.source_address), port=record.source_port),
            endpoint_b=FlowEndpoint(
                address=str(record.destination_address), port=record.destination_port
            ),
            started_at=record.timestamp if packet else record.started_at,
            ended_at=record.timestamp if packet else record.ended_at,
            reported_packet_count=1 if packet else record.forward_packets + record.backward_packets,
        )

    def audit_once(self, key: str, receipt):
        # One Runtime writer; audit+source+queue are separate transactions. A replay
        # resolves by event/digest, never by assuming a cross-DB atomic commit.
        payload = receipt.model_dump(mode="json")
        if key in self.committed:
            if self.committed[key] != payload:
                raise ValueError("NETWORK_AUDIT_BINDING_MISMATCH")
            return
        self.audit.event(
            "NETWORK_SOURCE_COMMITTED",
            {"event_id": key, "provenance": payload, "inference": "NOT_INFERABLE"},
        )
        self.committed[key] = payload

    def step(self):
        self.last_committed = None
        claim = self.queue.claim()
        if claim is None:
            return "IDLE"
        try:
            record = self.decode(claim.event)
            if isinstance(record, FlowSummary):
                rebuilt = None
                with self.queue.database.transaction(write=False) as c:
                    for identity in record.source_event_ids:
                        row = c.execute(
                            "SELECT * FROM realtime_events WHERE event_id=?", (identity,)
                        ).fetchone()
                        if row is None:
                            raise ValueError("FLOW_PACKET_REFERENCE_MISSING")
                        packet_event = self.queue._decode(row)
                        packet = self.decode(packet_event)
                        if (
                            not isinstance(packet, PacketObservation)
                            or packet_event.source.generation != claim.event.source.generation
                        ):
                            raise ValueError("FLOW_PACKET_BINDING_MISMATCH")
                        self.sources.load(
                            self._source(packet_event, packet), expected_incident=self.incident
                        )
                        if rebuilt is None:
                            rebuilt = Flow(packet, packet)
                        if FlowTable.key(rebuilt.first) != FlowTable.key(packet):
                            raise ValueError("FLOW_FIVE_TUPLE_MISMATCH")
                        rebuilt.add(packet, identity)
                if rebuilt is None or rebuilt.summary(record.close_reason) != record:
                    raise ValueError("FLOW_STATISTICS_MISMATCH")
            source = self._source(claim.event, record)
            self.sources.ingest(
                source,
                expected_incident=self.incident,
                expected_source_digest=source.content_digest,
                received_at=utc_now(),
            )
            receipt = build_receipt(self.sources, incident_id=self.incident, sources=(source,))
            self.audit_once(str(claim.event.event_id), receipt)
            self.queue.finish(
                claim,
                {
                    "inference": "NOT_INFERABLE",
                    "incident_id": str(self.incident),
                    "workflow": "DIAGNOSTIC_ONLY",
                    "human_boundary": "WRITE_DENIED",
                },
            )
            self.last_committed = (claim.event, record, receipt)
            return "STORED"
        except (ValueError, OSError):
            self.queue.fail(claim, "INVALID_INPUT")
            raise
