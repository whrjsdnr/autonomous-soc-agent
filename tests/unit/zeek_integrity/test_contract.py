"""No sockets or models: explicit same-handle fixture counters and metadata contracts."""

import copy
from uuid import uuid4

import pytest
from tests.zeek_producer_support import golden

from soc_agent.security_ai.collectors.finalization import Closed
from soc_agent.security_ai.collectors.integrity import (
    CounterSample,
    SessionReport,
    assess_session,
    counter_fixture,
    eligibility,
    offline_eligibility,
    validate_flow,
    zeek_counter,
)
from soc_agent.security_ai.collectors.packet_input import reference
from soc_agent.security_ai.collectors.packet_producer import aggregate

SESSION = uuid4()
PLAN, HANDLE = "a" * 64, "b" * 64


def sample(sequence, stage, received, dropped=0, **kw):
    return CounterSample(
        session_id=SESSION,
        plan_digest=PLAN,
        handle_id=HANDLE,
        sequence=sequence,
        stage=stage,
        query_ok=True,
        received=received,
        dropped=dropped,
        **kw,
    )


def verify(samples, semantics="CUMULATIVE"):
    return counter_fixture(
        tuple(samples), session=SESSION, plan=PLAN, handle=HANDLE, semantics=semantics
    )


@pytest.mark.parametrize(
    "semantics,values,expected",
    [
        ("CUMULATIVE", [0, 4, 9], 9),
        ("RESET_ON_READ", [2, 4, 3], 9),
        ("CUMULATIVE", [0, 0, 0], 0),
        ("RESET_ON_READ", [0, 0, 0], 0),
    ],
)
def test_same_handle_accounting_no_duplicate_count(semantics, values, expected):
    samples = [
        sample(i + 1, stage, n)
        for i, (stage, n) in enumerate(zip(("READY", "INTERVAL", "CLOSED"), values, strict=True))
    ]
    report = verify(samples, semantics)
    assert report.status == "VERIFIED" and report.reported_received == expected
    assert report.kernel_drops_verified == 0 and report.query_status == "VERIFIED"
    assert report.provenance == "SAME_HANDLE_FIXTURE"


@pytest.mark.parametrize(
    "change,expected",
    [
        ({"query_ok": None}, "UNVERIFIED"),
        ({"query_ok": False}, "FAILED"),
        ({"dropped": None}, "UNVERIFIED"),
        ({"received": None}, "UNVERIFIED"),
        ({"dropped": 1}, "FAILED"),
        ({"sequence": 4}, "FAILED"),
        ({"handle_id": "c" * 64}, "FAILED"),
        ({"plan_digest": "d" * 64}, "FAILED"),
        ({"session_id": uuid4()}, "FAILED"),
        ({"stage": "INTERVAL"}, "FAILED"),
    ],
)
def test_unknown_failure_missing_interval_and_source_change_fail_closed(change, expected):
    end = sample(2, "CLOSED", 1).model_copy(update=change)
    assert verify([sample(1, "READY", 0), end]).status == expected


def test_reset_not_silently_interpreted_as_cumulative_or_new_generation():
    report = verify([sample(1, "READY", 9), sample(2, "CLOSED", 1)])
    assert report.status == "FAILED" and report.reason == "COUNTER_RESET_OR_REGRESSION"
    assert verify([]).status == "UNVERIFIED"


def closed(**kw):
    return Closed(
        stop_reason="ZEEK_DONE",
        packet_records=0,
        network_events=0,
        dns_events=0,
        messages_before_closed=1,
        bytes_before_closed=42,
        omitted_packet_records=0,
        omitted_events=0,
        pkts_recvd=kw.get("received", 0),
        pkts_dropped=kw.get("drops", 0),
        pkts_link=kw.get("link", 0),
        bytes_recvd=0,
    )


@pytest.mark.parametrize("received", [0, 4096])
def test_zero_reported_drops_does_not_prove_query_success(received):
    report = zeek_counter(closed(received=received, link=8200))
    assert report.status == "UNVERIFIED" and report.reported_drops == 0
    assert report.reported_received == received and report.reported_link == 8200
    assert report.kernel_drops_verified is None and report.query_status == "UNKNOWN"


def test_actual_drop_and_no_counter_are_distinct():
    assert zeek_counter(closed(drops=87)).status == "FAILED"
    assert zeek_counter(None).status == "NOT_OBSERVED"
    assert zeek_counter(None).reported_drops is None


def result():
    return dict(
        plan_digest=PLAN,
        exit_code=0,
        cleanup_verified=True,
        container_absent=True,
        closed_detail=closed().model_dump(),
        protocol_finalized=True,
        stream_sha256="e" * 64,
    )


def test_process_stream_capture_and_counter_are_independent():
    r = assess_session(SESSION, PLAN, result(), protocol_verified=True, queue_depth=0)
    assert r.process == r.stream == "VERIFIED" and r.capture == "UNVERIFIED"
    assert r.counter.status == "UNVERIFIED" and r.gaps is None
    failed = assess_session(
        SESSION, PLAN, result(), protocol_verified=True, queue_depth=0, failed=True
    )
    assert failed.process == "VERIFIED" and failed.capture == "FAILED"


@pytest.mark.parametrize(
    "change,process",
    [
        ({"exit_code": 1}, "FAILED"),
        ({"exit_code": None}, "UNVERIFIED"),
        ({"exit_code": False}, "UNVERIFIED"),
        ({"cleanup_verified": False}, "FAILED"),
        ({"container_absent": False}, "UNVERIFIED"),
    ],
)
def test_exit_cleanup_counter_failure_classification(change, process):
    r = assess_session(SESSION, PLAN, result() | change, protocol_verified=True, queue_depth=0)
    assert r.process == process and r.capture != "VERIFIED"


@pytest.fixture
def flow(tmp_path):
    p = tmp_path / "input.pcap"
    golden(p)
    return aggregate(tuple(reference(p)), str(SESSION))["flows"][0]


def test_timeout_window_and_shutdown_are_separate(flow):
    f = validate_flow(flow, SESSION)
    assert f.feature_integrity == f.completeness == "VERIFIED"
    bad = copy.deepcopy(flow)
    bad["close_reason"] = "SHUTDOWN"
    bad["eligible"] = False
    f = validate_flow(bad, SESSION)
    assert f.feature_integrity == "VERIFIED" and f.completeness == "DEGRADED"
    assert (
        offline_eligibility(f, parity="VERIFIED", artifact="VERIFIED").decision
        == "BLOCKED_FLOW_INCOMPLETE"
    )


@pytest.mark.parametrize(
    "change",
    ["order", "digest", "value", "timestamp", "identity", "duplicate", "unsupported", "direction"],
)
def test_feature_and_source_tampering_cannot_be_promoted(flow, change):
    f = copy.deepcopy(flow)
    if change == "order":
        f["feature_names"].reverse()
    if change == "digest":
        f["values_digest"] = "0" * 64
    if change == "value":
        f["values"][0] += 0.1
    if change == "timestamp":
        f["packets"][1]["seconds"] = 0
    if change == "identity":
        f["packets"][1]["source_port"] += 1
    if change == "duplicate":
        f["packets"][1]["sequence"] = f["packets"][0]["sequence"]
    if change == "unsupported":
        f["packets"][0]["kind"] = "UNSUPPORTED"
    if change == "direction":
        f["packets"][0]["destination"] = f["packets"][0]["source"]
        f["packets"][0]["destination_port"] = f["packets"][0]["source_port"]
    assert validate_flow(f, SESSION).feature_integrity == "FAILED"


def test_all_prerequisites_cannot_enable_native_policy(flow):
    # Proposed successful counter fixture remains non-authoritative for actual Native.
    counter = verify([sample(1, "READY", 0), sample(2, "CLOSED", 4)])
    report = SessionReport(
        session_id=SESSION,
        plan_digest=PLAN,
        process="VERIFIED",
        stream="VERIFIED",
        counter=counter,
        capture="VERIFIED",
        flow_completeness="VERIFIED",
        gaps=0,
    )
    f = validate_flow(flow, SESSION)
    d = eligibility(report, f, parity="VERIFIED", artifact="VERIFIED")
    assert d.decision == "BLOCKED_POLICY" and d.blockers == ("BLOCKED_POLICY",)
    assert report.native_policy == "BLOCKED"
    assert offline_eligibility(f, parity="VERIFIED", artifact="VERIFIED").decision == "ELIGIBLE"
    assert (
        offline_eligibility(f, parity="UNVERIFIED", artifact="VERIFIED").decision
        == "BLOCKED_FEATURE_PARITY"
    )
    assert (
        offline_eligibility(f, parity="VERIFIED", artifact="FAILED").decision == "BLOCKED_ARTIFACT"
    )
