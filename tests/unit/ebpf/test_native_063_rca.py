"""Offline metadata reproductions; no authentication, kernel queries or packets."""

import copy
import ipaddress

import pytest
from tests.ebpf_support import plan
from tests.unit.ebpf_tc.test_supervisor import Operations, inventory

from soc_agent.security_ai.ebpf.clock import ClockContract, EventOrdering
from soc_agent.security_ai.ebpf.collector import EBPFCollector
from soc_agent.security_ai.ebpf.ring import ABI, decode
from soc_agent.security_ai.ebpf_tc.supervisor_engine import SupervisorCore

BASE = 530_711_000_000_000


def wire(stamp, sequence, *, cpu=0):
    return ABI.pack(
        7,
        stamp,
        sequence,
        1,
        cpu,
        54,
        40,
        33000,
        443,
        4,
        6,
        16,
        1,
        ipaddress.ip_address("192.0.2.1").packed + bytes(12),
        ipaddress.ip_address("192.0.2.2").packed + bytes(12),
    )


def collector(tmp_path):
    scope = plan(origin="TCX_STREAM_FIXTURE", clock="KERNEL_MONOTONIC_NS")
    value = EBPFCollector(tmp_path, scope)
    value.prepare_metadata()
    value.begin_metadata_stream(0, ClockContract(session_id=scope.session_id, domain=scope.clock))
    return value


@pytest.mark.parametrize(
    "inversion,rejected", [(10_000_000, False), (10_000_001, True), (194_004_499, True)]
)
def test_real_decoder_preserves_ns_and_existing_admission_boundary(inversion, rejected):
    scope = plan(origin="TCX_STREAM_FIXTURE", clock="KERNEL_MONOTONIC_NS")
    ordering = EventOrdering()
    maximum = 530_711_987_506_099
    ordering.observe(decode(wire(maximum, 1), scope, 1))
    original = wire(maximum - inversion, 1, cpu=1)
    event = decode(original, scope, 2)
    assert event.ns == maximum - inversion  # No seconds/float/wall-clock conversion.
    if rejected:
        with pytest.raises(ValueError, match="EBPF_REORDER_LATE_CAPTURE_GAP"):
            ordering.observe(event)
    else:
        ordering.observe(event)
    assert ordering.max_delta == inversion and ordering.lateness_ns == 10_000_000
    assert original == wire(maximum - inversion, 1, cpu=1)


def test_receiver_delay_alone_does_not_create_event_time_inversion(tmp_path):
    value = collector(tmp_path / "delayed-receiver")
    for sequence, receive in [(1, 0.01), (2, 0.204004499), (3, 0.4)]:
        value.ingest(wire(BASE + sequence * 10_000_000, sequence), monotonic=receive)
        value.drain()
    value.end_metadata_stream("CAPTURE_STOP")
    assert value.received == value.accepted == 3
    assert value.discarded == value.ordering.inversions == value.ordering.late == 0
    assert all(not f["eligible"] for f in value.flow.finalized)


def test_native_062_discard_domains_reconcile_without_inventing_kernel_loss(tmp_path):
    value = collector(tmp_path / "count-reproduction")
    # Synthetic single flow with the same accounting boundary: 186 admitted,
    # one pending event, then the late record (188). This is not recovered traffic.
    for sequence in range(1, 188):
        value.ingest(wire(BASE + sequence * 10_000_000, sequence), monotonic=1)
        value.drain()
    assert value.accepted == 186 and len(value.queue) == 1
    with pytest.raises(ValueError, match="EBPF_REORDER_LATE_CAPTURE_GAP"):
        value.ingest(wire(BASE + 187 * 10_000_000 - 194_004_499, 1, cpu=1), monotonic=1)
    value.end_metadata_stream("INCOMPLETE")
    assert value.discarded == 2  # One rejected record + one pending-at-abort record.
    for ordinal in range(189, 2434):
        value.discard_after_error(wire(BASE + ordinal * 10_000_000, ordinal - 1))
    assert value.received == 2433 and value.accepted == 186
    assert value.discarded == 2247 and value.post_error_discarded == 2245
    assert value.received == value.accepted + value.discarded
    assert value.overflow_rejected == 0 and value.loss is None
    assert value.last_error == "EBPF_REORDER_LATE_CAPTURE_GAP"
    assert value.store.verify_audit()
    assert all(not f["eligible"] for f in value.flow.finalized)


def test_clock_origin_mismatch_is_rejected_before_stream_preparation():
    with pytest.raises(ValueError, match="EBPF_CLOCK_ORIGIN_MISMATCH"):
        plan(origin="TCX_STREAM_FIXTURE", clock="FIXTURE_PCAP_EVENT_NS")


@pytest.mark.parametrize("mutation", ["extra_cgroup", "reused_id_new_tag", "changed_map_reference"])
def test_unknown_cgroup_program_changes_never_authorize_removal_or_clean_verdict(mutation):
    before = inventory()
    before["programs"]["rows"] = [dict(id=3, type="cgroup_device", tag="old", map_ids=[])]
    after = copy.deepcopy(before)
    if mutation == "extra_cgroup":
        after["programs"]["rows"] += [
            dict(id=6332, type="cgroup_device", tag="first"),
            dict(id=6336, type="cgroup_device", tag="second"),
        ]
    elif mutation == "reused_id_new_tag":
        after["programs"]["rows"][0]["tag"] = "different"
    else:
        after["programs"]["rows"][0]["map_ids"] = [77]
    ops = Operations()
    ops.inspect = lambda: copy.deepcopy(after)
    result = SupervisorCore(ops, "b" * 64, before).finish()
    assert result["cleanup"] == "CLEANUP_UNVERIFIED"
    assert "SUPERVISOR_RESOURCE_SET_CHANGED:programs" in result["failures"]
    assert before["programs"]["rows"][0]["tag"] == "old"
    assert all("detach" not in call and "remove" not in call for call in ops.calls)


def test_discard_causes_are_disjoint_and_first_error_is_immutable(tmp_path):
    value = collector(tmp_path / "reasons")
    for sequence in range(1, 188):
        value.ingest(wire(BASE + sequence * 10_000_000, sequence), monotonic=1)
        value.drain()
    with pytest.raises(ValueError, match="REORDER_LATE"):
        value.ingest(wire(BASE + 187 * 10_000_000 - 194_004_499, 1, cpu=1), monotonic=1)
    with pytest.raises(ValueError, match="SECONDARY_ERROR"):
        value.fail("SECONDARY_ERROR")
    assert value.last_error == "EBPF_REORDER_LATE_CAPTURE_GAP"
    value.end_metadata_stream("INCOMPLETE")
    for ordinal in range(189, 2434):
        value.discard_after_error(wire(BASE + ordinal * 10_000_000, ordinal - 1))
    account = value.snapshot()["ebpf"]["discard_accounting"]
    assert account["balanced"] and account["reason_sum"] == 2247
    assert account["reasons"] == dict(
        REORDER_REJECT=1, QUEUE_REJECT=0, ERROR_PENDING_ABORT=1, POST_ERROR_POLICY_DISCARD=2245
    )
    assert account["kernel_drop"] is None
    assert account["generation"] == value.plan.generation
    before = dict(account["reasons"])
    value.end_metadata_stream("INCOMPLETE")
    assert value.discard_accounting()["reasons"] == before


def test_previous_max_cpu_is_actual_event_provenance_not_global_sequence():
    scope = plan(origin="TCX_STREAM_FIXTURE", clock="KERNEL_MONOTONIC_NS")
    ordering = EventOrdering()
    ordering.observe(decode(wire(BASE + 200_000_000, 4, cpu=3), scope, 187))
    with pytest.raises(ValueError):
        ordering.observe(decode(wire(BASE + 5_995_501, 28, cpu=1), scope, 188))
    evidence = ordering.examples[-1]
    assert evidence["previous_max_cpu"] == 3
    assert evidence["previous_max_cpu_sequence"] == 4
    assert evidence["previous_max_delivery_sequence"] == 187
    assert evidence["inversion_ns"] == 194_004_499
    assert "global_sequence" not in evidence


def test_supervisor_preserves_first_error_and_separates_cleanup_failure():
    from tests.unit.ebpf_tc.test_supervisor import request

    ops = Operations("start")
    core = SupervisorCore(ops, "b" * 64, inventory())
    first, _ = core.dispatch(request("START_ZEEK"))

    def failed_stop():
        raise ValueError("SECONDARY_CLEANUP_ERROR")

    ops.stop = failed_stop
    later, _ = core.dispatch(request("STOP", 2))
    final = core.finish()
    assert later["error"] == final["first_error"] == first["error"]
    assert "SECONDARY_CLEANUP_ERROR" in final["failures"]
    assert final["control_errors"][-1]["error"] == "SECONDARY_CLEANUP_ERROR"
    assert final["cleanup"] == "CLEANUP_UNVERIFIED"


def test_changed_attach_target_blocks_cleanup_even_if_program_set_is_equal():
    before = inventory()
    before["cgroup_tree"] = {"rows": [{"path": "/sys/fs/cgroup/old", "programs": [{"id": 3}]}]}
    after = copy.deepcopy(before)
    after["cgroup_tree"]["rows"][0]["path"] = "/sys/fs/cgroup/new"
    ops = Operations()
    ops.inspect = lambda: after
    final = SupervisorCore(ops, "b" * 64, before).finish()
    assert final["cleanup"] == "CLEANUP_UNVERIFIED"
    assert "SUPERVISOR_RESOURCE_SET_CHANGED:cgroup_tree" in final["failures"]
    assert ops.calls == ["stop", "close"]


def test_timestamp_before_reservation_can_invert_without_ring_reordering():
    # Deterministic interleaving model, not an observed kernel scheduler trace.
    scope = plan(origin="TCX_STREAM_FIXTURE", clock="KERNEL_MONOTONIC_NS")
    captured_early = wire(BASE, 1, cpu=0)
    captured_later = wire(BASE + 194_004_499, 1, cpu=1)
    # CPU 0 reserves after CPU 1 despite having sampled its timestamp first.
    reservation_order = [captured_later, captured_early]
    ordering = EventOrdering()
    ordering.observe(decode(reservation_order[0], scope, 1))
    with pytest.raises(ValueError, match="REORDER_LATE_CAPTURE_GAP"):
        ordering.observe(decode(reservation_order[1], scope, 2))
    assert ordering.max_delta == 194_004_499
    assert ordering.examples[-1]["previous_max_cpu"] == 1
