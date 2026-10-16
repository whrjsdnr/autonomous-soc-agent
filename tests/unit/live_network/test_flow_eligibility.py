"""Synthetic native-shaped/explicit FIXTURE arithmetic, not native capture evidence."""

from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest
from tests.live_flow_eligibility_support import (
    BASE_NS,
    fixture_observations,
    manual_features,
)
from tests.unit.live_network.test_parity import observation, request, wire

from soc_agent.security_ai.operational.network_capture.flows import FlowTable
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig
from soc_agent.security_ai.research.live_input import (
    LiveRequest,
    lifecycle_eligible,
    produce,
    producer_packets,
)
from soc_agent.security_ai.research.live_service import LiveMonitoring, bound_request


@pytest.mark.parametrize(
    "reason,allowed",
    [
        ("IDLE_TIMEOUT", True),
        ("ACTIVE_TIMEOUT", True),
        ("SHUTDOWN", False),
        ("PACKET_LIMIT", False),
        ("RESTART_GAP", False),
        ("UNKNOWN", False),
    ],
)
def test_close_reason_candidate_is_not_capture_authorization(reason, allowed):
    assert lifecycle_eligible(reason) is allowed


@pytest.mark.parametrize("kind", ["IDLE_TIMEOUT", "ACTIVE_TIMEOUT"])
def test_same_packet_segmentation_and_independent_network14_reference(kind):
    from ml.ctu13.flows import Flows
    from ml.ctu13.pcap import Record
    from ml.ctu13.pcap import parse_packet as offline_parse
    from ml.verified_producers.network_v1_1 import network_features
    from tests.live_flow_eligibility_support import packet_specs

    native = FlowTable(CaptureConfig(interface="lo"))
    offline = Flows()
    observed, recorded = [], []
    packets = fixture_observations(kind, native=True)
    for i, (packet, spec) in enumerate(zip(packets, packet_specs(kind), strict=True)):
        _, reverse, length, flags = spec
        frame = wire(reverse=reverse, length=length, flags=flags)
        raw = offline_parse(
            Record(i, packet.capture_timestamp_ns, len(frame), len(frame), frame), "a" * 64
        )
        observed.extend(native.add(packet, raw.event_id))
        recorded.extend(offline.add(raw))
    assert len(observed) == len(recorded) == 1
    flow = observed[0]
    assert flow.close_reason == recorded[0].closure == kind
    assert flow.source_event_ids == tuple(p.event_id for p in recorded[0].packets)
    assert flow.forward_packets == (2 if kind == "IDLE_TIMEOUT" else 3)
    assert flow.backward_packets == (1 if kind == "IDLE_TIMEOUT" else 3)
    assert flow.duration_seconds == (1 if kind == "IDLE_TIMEOUT" else 100)
    fixture = request(native=True).model_copy(
        update={
            "packets": packets[:-1],
            "packet_event_ids": tuple(uuid4() for _ in packets[:-1]),
        }
    )
    fixture = LiveRequest.model_validate(fixture.model_dump())
    native_vector = produce(fixture)
    offline_vector = network_features(
        recorded[0].packets, source_origin="OFFLINE_PCAP", source_identity="d" * 64
    )
    assert native_vector.values == offline_vector.values == manual_features(kind)
    assert len(native_vector.values) == 14 and native_vector.semantic_version == "1.1.0"
    assert native_vector.feature_digest != offline_vector.feature_digest  # Origins remain bound.


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_active_timeout_nanosecond_boundary(offset):
    table = FlowTable(CaptureConfig(interface="lo"))
    for i, packet in enumerate(fixture_observations("ACTIVE_TIMEOUT", native=True)[:-1]):
        assert not table.add(packet, str(i))
    end = observation(wire(), BASE_NS + 120_000_000_000 + offset)
    result = table.add(end, "boundary")
    assert bool(result) is (offset >= 0)
    if result:
        assert result[0].close_reason == "ACTIVE_TIMEOUT"
        assert result[0].duration_seconds == 100  # The boundary packet starts the next flow.


def test_short_shutdown_excluded_but_observed_singleton_timeout_is_valid_experimental_input():
    first = observation(wire(), BASE_NS, native=False)
    table = FlowTable(CaptureConfig(interface="lo"))
    table.add(first, "first")
    shutdown = table.expire(first.timestamp, "SHUTDOWN")[0]
    assert not lifecycle_eligible(shutdown.close_reason)
    value = request(native=False).model_copy(
        update={"packets": (first,), "packet_event_ids": (uuid4(),)}
    )
    vector = produce(LiveRequest.model_validate(value.model_dump()))
    assert vector.values == (0, 1, 0, 40, 0, 40, 40, 40, 0, 1, 0, 0, 0, 0)
    # No new minimum duration/reverse-packet rule is invented. Capture loss is a separate gate.


def test_capture_gap_and_duplicate_event_rejected_by_producer():
    from ml.verified_producers.network_v1_1 import network_features

    packets = producer_packets(request(native=False))
    with pytest.raises(ValueError, match="INCOMPLETE_CAPTURE"):
        network_features(
            packets, source_origin="FIXTURE", source_identity="d" * 64, capture_quality="KNOWN_GAP"
        )
    with pytest.raises(ValueError, match="DUPLICATE_EVENT"):
        network_features(
            (packets[0], packets[0]), source_origin="FIXTURE", source_identity="d" * 64
        )
    changed = (packets[0], replace(packets[1], timestamp_ns=packets[0].timestamp_ns - 1))
    with pytest.raises(ValueError, match="ORDER"):
        network_features(changed, source_origin="FIXTURE", source_identity="d" * 64)


@pytest.mark.parametrize("fault", ["gap", "unknown_counter", "drop"])
def test_timeout_label_cannot_bypass_capture_quality_gates(tmp_path, fault):
    service = LiveMonitoring(tmp_path)
    service.capture = SimpleNamespace(
        ready=True,
        counter_issue={"error": "COUNTER_UNAVAILABLE" if fault == "unknown_counter" else "DROP"}
        if fault != "gap"
        else None,
        reader_failed=lambda: False,
        closed=SimpleNamespace(is_set=lambda: False),
        completion_verified=lambda: fault != "gap",
    )
    service.monitor = SimpleNamespace(metrics={"finalization": "VERIFIED", "last_error": None})
    with pytest.raises(ValueError, match="AUTHENTICATED_SOURCE"):
        service.validate_native_source(request())
    assert service.demo is None and service.task is None


def test_missing_reverse_packet_reference_is_not_filled_with_synthetic_evidence(tmp_path):
    from tests.integration.live_network.test_research import persisted

    monitor, session, event, flow = persisted(tmp_path / "runtime")
    incomplete = flow.model_copy(
        update={"source_event_ids": (*flow.source_event_ids, str(uuid4()))}
    )
    with pytest.raises(ValueError, match="PACKET_NOT_COMMITTED"):
        bound_request(monitor, session, event, incomplete, "quality")


def test_lifecycle_display_unknown_pending_poison_and_session_isolation(tmp_path):
    from tests.integration.live_network.test_research import persisted

    service = LiveMonitoring(tmp_path / "empty")
    assert service.flow_eligibility()["eligible"] is None
    monitor, session, _, _ = persisted(tmp_path / "runtime")
    service.directory = tmp_path
    service.session = SimpleNamespace(session_id=session, interface_id=monitor.identity)
    assert service.flow_eligibility()["eligible"] == 1
    for status in ("PENDING", "CLAIMED", "POISON"):
        with monitor.pipeline.queue.database.transaction() as c:
            c.execute(
                "UPDATE realtime_events SET status=? "
                "WHERE json_extract(payload,'$.metadata.code')='flow'",
                (status,),
            )
        counts = service.flow_eligibility()
        assert counts["eligible"] == 0
        assert counts["pending"] == (0 if status == "POISON" else 1)
        assert counts["rejected"] == int(status == "POISON")
    service.session = SimpleNamespace(session_id=uuid4(), interface_id=monitor.identity)
    with pytest.raises(ValueError, match="SESSION_MISMATCH"):
        service.flow_eligibility()
