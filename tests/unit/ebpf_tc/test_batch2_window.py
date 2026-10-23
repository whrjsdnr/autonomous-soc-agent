"""Synthetic CPU/clock contracts and actual Unix framing; no privileged capture."""

import copy
import hashlib
import socket
import struct
import subprocess

import pytest
from tests.unit.ebpf.test_batch1_flow import packet
from tests.unit.ebpf_tc.test_contracts import native_plan
from tests.unit.tcx_data.test_channel import frame

from soc_agent.security_ai.collectors.packet_producer import FlowAssembly
from soc_agent.security_ai.ebpf.input_eligibility import input_receipts
from soc_agent.security_ai.ebpf_native.contracts import local_controller
from soc_agent.security_ai.ebpf_tc.build import ROOT
from soc_agent.security_ai.ebpf_tc.capture_evidence import assess_capture
from soc_agent.security_ai.ebpf_tc.data_plane import PacketChannel
from soc_agent.security_ai.ebpf_tc.journal import RC_ROW, recover_native
from soc_agent.security_ai.ebpf_tc.window_evidence import (
    COUNTERS,
    CPU_WINDOW,
    accept_clock_sample,
    accept_cpu_window,
)
from soc_agent.security_ai.research.models import digest


def raw_window(cpu, phase, counts=None, *, cpus=2, before=None):
    before = before or (50 if phase == 1 else 40_000_000_000)
    return CPU_WINDOW.pack(cpu, phase | cpus << 16, before, before + 10, *(counts or [0] * 7))


def raw_clock(phase, n, *, generation=7, offset=10**15):
    before = 70 + n * 10 if phase == 1 else 40_000_000_030 + n * 10
    return struct.pack(
        "<10Q", 1, phase, generation, before, before + 1 + offset, before + 2, 0, 0, 0, 0
    )


def complete():
    windows, samples = [], []
    for phase in (1, 2):
        for cpu in range(2):
            counts = [3, 3, 0, 0, 0, 0, 0] if phase == 2 and cpu == 0 else None
            accept_cpu_window(windows, raw_window(cpu, phase, counts))
        for n in range(3):
            accept_clock_sample(samples, raw_clock(phase, n), 7)
    flow = FlowAssembly("session", compact=True, event_watermark=True)
    for p in (
        packet(1, 1000, kind="udp"),
        packet(2, 2000, reverse=True, kind="udp"),
        packet(3, 31_000_001_000, kind="udp", port=222),
    ):
        flow.add(p)
    flow.finish("CAPTURE_STOP")
    summary = dict(
        plan=dict(
            session_id="session", generation=7, program_sha256="a" * 64, source_digest="b" * 64
        ),
        plan_digest="c" * 64,
        received=3,
        accepted=3,
        cpu_sequence=dict(
            unrepresented_attempts=0,
            intervals={"0": dict(received=3, first_ns=1000, last_ns=31_000_001_000)},
        ),
        clock=dict(domain="KERNEL_MONOTONIC_NS"),
        ordering=dict(late_events=0),
        feature_tail=flow.finalized,
    )
    counter = dict(
        generation=7,
        retrieval="SUCCESS",
        delivered=3,
        totals=dict(zip(COUNTERS, [3, 3, 0, 0, 0, 0, 0], strict=True)),
    )
    delivery = dict(
        generation=7,
        callbacks=3,
        delivered=3,
        budget_excluded=0,
        invalid=0,
        send_failed=0,
        drain_result=0,
    )
    capture = assess_capture(
        counter,
        delivery,
        summary,
        closed=True,
        error=None,
        source=2,
        scope=dict(program_sha256="a" * 64, approval_digest="b" * 64),
        cpu_windows=windows,
        clock_samples=samples,
    )
    return summary, dict(capture_evidence=capture), windows, samples, counter, delivery


def test_scoped_fixture_window_and_timeout_input_eligible_do_not_run_or_authorize_ai():
    summary, transport, *_ = complete()
    capture = transport["capture_evidence"]
    assert capture["status"] == "VERIFIED"
    assert capture["kernel_wide_drops"] == "UNKNOWN"
    assert capture["source"] == "FIXTURE_NOT_NATIVE"
    assert capture["window_evidence"]["cpus"][1]["activity"] == "NO_OWNED_HOOK_ATTEMPTS"
    rows = input_receipts(summary, transport)
    assert rows[0]["input_state"] == "ELIGIBLE"
    assert rows[0]["source"] == "FIXTURE_NOT_NATIVE"
    assert rows[1]["input_state"] == "INCOMPLETE"  # STOP is not a timeout.
    assert all(not r["model_executed"] and r["native_ai"] == "BLOCKED" for r in rows)
    assert rows == input_receipts(summary, transport)
    for row in rows:
        assert row["receipt_digest"] == digest(
            {k: v for k, v in row.items() if k != "receipt_digest"}
        )


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "epoch",
        "domain",
        "counter",
        "ring",
        "budget",
        "unsupported",
        "clock_jump",
        "outside",
        "drain",
        "closed",
    ],
)
def test_incomplete_evidence_cannot_grant_input_eligibility(fault):
    p, _, w, clock, c, a = complete()
    if fault == "missing":
        w.pop()
    elif fault == "epoch":
        c["generation"] = 8
    elif fault == "domain":
        p["clock"]["domain"] = "WALL_CLOCK"
    elif fault == "counter":
        w[2]["counters"]["emitted"] = 2
    elif fault == "ring":
        w[2]["counters"]["ring_reservation_failures"] = 1
    elif fault == "budget":
        a["budget_excluded"] = 1
    elif fault == "unsupported":
        w[2]["counters"]["unsupported"] = 1
    elif fault == "clock_jump":
        clock[-1]["wall_ns"] += 10**9
    elif fault == "outside":
        p["cpu_sequence"]["intervals"]["0"]["last_ns"] = 50_000_000_000
    elif fault == "drain":
        a["drain_result"] = -11
    v = assess_capture(
        c,
        a,
        p,
        closed=fault != "closed",
        error=None,
        source=2,
        scope={},
        cpu_windows=w,
        clock_samples=clock,
    )
    assert v["status"] != "VERIFIED"
    assert all(not r["eligible"] for r in input_receipts(p, dict(capture_evidence=v)))


@pytest.mark.parametrize(
    "fault",
    [
        "nan",
        "digest",
        "duplicate",
        "provenance",
        "window_digest",
        "missing_values",
        "count",
        "late",
        "no_witness",
        "short_timeout",
    ],
)
def test_feature_flow_receipt_fail_closed(fault):
    p, t, *_ = complete()
    row = p["feature_tail"][0]
    if fault == "nan":
        row["values"][0] = float("nan")
    elif fault == "digest":
        row["values_digest"] = "0" * 64
    elif fault == "duplicate":
        p["feature_tail"].append(copy.deepcopy(row))
    elif fault == "provenance":
        t["capture_evidence"]["source_provenance"]["session"] = "other"
    elif fault == "window_digest":
        t["capture_evidence"]["window_evidence"]["digest"] = "0" * 64
    elif fault == "missing_values":
        del row["values"]
    elif fault == "count":
        row["packet_count"] += 1
    elif fault == "late":
        p["ordering"]["late_events"] = 1
    elif fault == "no_witness":
        row["lifecycle"]["timeout_witness_ns"] = None
    elif fault == "short_timeout":
        row["lifecycle"]["timeout_witness_ns"] = 3000
    assert not input_receipts(p, t)[0]["eligible"]


def test_window_sequence_duplicate_size_reset_and_clock_epoch_rejected():
    rows = []
    with pytest.raises(ValueError, match="SIZE"):
        accept_cpu_window(rows, b"x")
    accept_cpu_window(rows, raw_window(0, 1))
    with pytest.raises(ValueError, match="SEQUENCE"):
        accept_cpu_window(rows, raw_window(0, 1))
    with pytest.raises(ValueError, match="SCHEMA"):
        accept_cpu_window([], raw_window(0, 1, cpus=129))
    with pytest.raises(ValueError, match="EPOCH"):
        accept_clock_sample([], raw_clock(1, 0, generation=8), 7)


@pytest.mark.parametrize("kind,raw", [(7, raw_window(0, 1)), (8, raw_clock(1, 0))])
def test_real_credentialled_socket_and_hash_chained_journal_preserve_metadata(tmp_path, kind, raw):
    c = PacketChannel(native_plan(), "f" * 64, tmp_path / "channel")
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    c.channel, c.identity, c.source = left, local_controller(), 2
    c.prepare_adapter(7)
    try:
        right.send(frame(c, kind=kind, packet=raw))
        c.pump()
        assert c.cpu_windows if kind == 7 else c.clock_samples
        assert c.snapshot()["capture_evidence"]["status"] == "INCOMPLETE"
    finally:
        left.close()
        right.close()
    name = b"DATA_CPU_WINDOW" if kind == 7 else b"DATA_CLOCK_SAMPLE"
    body = RC_ROW.pack(bytes.fromhex("aa" * 32), name, raw, 1, 1, bytes(32), bytes(32))
    journal = tmp_path / "journal"
    journal.write_bytes(body[:-32] + hashlib.sha256(body[:-32]).digest())
    recovered = recover_native(journal, "aa" * 32)
    assert recovered["cpu_windows" if kind == 7 else "clock_samples"]
    assert not recovered["automatic_inference"]


def test_real_loader_snapshot_runs_only_unattached_and_never_truncates_cpus(tmp_path):
    source = tmp_path / "snapshot.c"
    source.write_text("""
#include "loader.c"
#include <assert.h>
static int possible=2,lookups,windows,clocks;
int libbpf_num_possible_cpus(void) {return possible;}
int bpf_object__find_map_fd_by_name(const struct bpf_object *o,const char *n)
 {(void)o;(void)n;return 10;}
int bpf_map_lookup_elem(int fd,const void *k,void *v)
 {(void)fd;(void)k;lookups++;memset(v,0,possible*sizeof(struct soc_counters));return 0;}
uint64_t soc_now(void) {static uint64_t n=100;return n++;}
int soc_data_cpu_window(struct soc_state *s,const struct soc_cpu_window *w)
 {(void)s;assert(w->cpu<2);windows++;return 0;}
int soc_data_clock_sample(struct soc_state *s,const uint64_t d[10])
 {(void)s;assert(d[0]==1);clocks++;return 0;}
int main(void) {
 struct runtime r={0};struct soc_state s={.context=&r};s.plan.hook=1;s.generation=7;
 s.attached=1;assert(cpu_window(&s,1)==-EPERM);assert(!lookups);
 s.attached=0;possible=129;assert(cpu_window(&s,1)==-E2BIG);assert(!lookups);
 possible=2;assert(!cpu_window(&s,1));assert(lookups==1 && windows==2 && clocks==3);
 return 0;
}
""")
    exe = tmp_path / "snapshot"
    subprocess.run(
        [
            "cc",
            "-O2",
            "-ffunction-sections",
            "-fdata-sections",
            "-I" + str(ROOT),
            str(source),
            "-Wl,--gc-sections",
            "-o",
            str(exe),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run([str(exe)], check=True, timeout=2)


@pytest.mark.parametrize("field,value", [("flow_id", None), ("packet_count", 0)])
def test_missing_flow_identity_or_zero_count_never_eligible(field, value):
    p, t, *_ = complete()
    p["feature_tail"][0][field] = value
    assert input_receipts(p, t)[0]["input_state"] == "INVALID"


def test_known_invalid_window_propagates_without_relabeling_as_missing_evidence():
    p, t, *_ = complete()
    window = t["capture_evidence"]["window_evidence"]
    window["status"] = "INVALID"
    window["digest"] = digest({k: v for k, v in window.items() if k != "digest"})
    assert input_receipts(p, t)[0]["input_state"] == "INVALID"


def test_native_ai_rca_does_not_erase_verified_input_capture_evidence():
    from soc_agent.security_ai.ebpf.eligibility import candidate_rca

    p, t, *_ = complete()
    r = candidate_rca(p, t)[0]
    assert "CAPTURE_INTEGRITY_UNVERIFIED" not in r["reasons"]
    assert "CLOCK_CALIBRATION_UNVERIFIED" not in r["reasons"]
    assert not r["eligible"] and r["native_ai"] == "BLOCKED"


def test_pinned_ordered_schema_matches_validated_packaged_contract():
    from soc_agent.security_ai.ebpf.input_eligibility import MODEL_ORDERED_NAMES_DIGEST
    from soc_agent.security_ai.research.environment import catalogue

    assert MODEL_ORDERED_NAMES_DIGEST == digest(catalogue()["feature_names"])


def test_full_authenticated_wire_to_window_flow_and_input_receipt(tmp_path):
    from tests.unit.tcx_data.test_pipeline import raw

    c = PacketChannel(native_plan(), "f" * 64, tmp_path / "complete-channel")
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    c.channel, c.identity, c.source = left, local_controller(), 2
    c.prepare_adapter(7)
    records = [(7, raw_window(cpu, 1)) for cpu in range(2)]
    records += [(8, raw_clock(1, n)) for n in range(3)]
    records += [
        (2, raw(ns, seq, proto=17, port=111 if seq < 3 else 222))
        for seq, ns in enumerate((1000, 2000, 31_000_001_000), 1)
    ]
    records += [
        (7, raw_window(cpu, 2, [3, 3, 0, 0, 0, 0, 0] if cpu == 0 else None)) for cpu in range(2)
    ]
    records += [(8, raw_clock(2, n)) for n in range(3)]
    records += [
        (5, struct.pack("<QQ7QII", 7, 40_000_000_100, 3, 3, 0, 0, 0, 0, 0, 1, 3)),
        (6, struct.pack("<9Qq", 1, 7, 3, 3, 0, 0, 0, 100, 40_000_000_000, 0)),
        (4, struct.pack("<Q", 7) + bytes(24) + struct.pack("<I", 1) + bytes(44)),
        (3, bytes(80)),
    ]
    try:
        for seq, (kind, payload) in enumerate(records, 1):
            right.send(frame(c, kind=kind, sequence=seq, packet=payload))
            c.pump()
        snapshot = c.snapshot()
        assert snapshot["capture_evidence"]["status"] == "VERIFIED"
        receipts = input_receipts(snapshot["processing"], snapshot)
        assert receipts[0]["input_state"] == "ELIGIBLE"
        assert receipts[1]["input_state"] == "INCOMPLETE"
        assert all(
            r["source"] == "FIXTURE_NOT_NATIVE" and not r["model_executed"] for r in receipts
        )
        assert snapshot["processing"]["accepted"] == 3
    finally:
        left.close()
        right.close()
