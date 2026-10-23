"""Ordinary-UID counter/window fixtures; never attach or generate traffic."""

import hashlib
import socket
import subprocess

import pytest
from tests.unit.ebpf_tc.test_contracts import native_plan
from tests.unit.tcx_data.test_channel import frame

from soc_agent.security_ai.ebpf_native.contracts import local_controller
from soc_agent.security_ai.ebpf_tc.build import ROOT
from soc_agent.security_ai.ebpf_tc.capture_evidence import (
    ACCOUNTING,
    assess_capture,
    decode_accounting,
)
from soc_agent.security_ai.ebpf_tc.data_plane import PacketChannel
from soc_agent.security_ai.ebpf_tc.journal import RC_ROW, recover_native


def accounting(**changes):
    values = dict(
        version=1,
        generation=7,
        callbacks=4108,
        delivered=4096,
        excluded=12,
        invalid=0,
        failed=0,
        start=100,
        stop=200,
        drain=0,
    )
    values.update(changes)
    return ACCOUNTING.pack(*values.values())


def inputs():
    counter = dict(
        generation=7,
        retrieval="SUCCESS",
        delivered=4096,
        totals=dict(
            observed=4114,
            emitted=4108,
            ring_reservation_failures=0,
            unsupported=0,
            malformed=0,
            disabled=6,
            budget=0,
        ),
    )
    processing = dict(
        plan=dict(
            generation=7,
            session_id="session",
            net_namespace="net:[1]",
            interface="lo",
            hook="INGRESS",
        ),
        received=4096,
        accepted=4096,
    )
    return counter, decode_accounting(accounting()), processing


def assess(c, a, p, **changes):
    args = dict(closed=True, error=None, source=2, scope=dict(approval_digest="a" * 64))
    args.update(changes)
    return assess_capture(c, a, p, **args)


def test_explicit_budget_exclusion_reconciles_without_granting_capture_integrity():
    c, a, p = inputs()
    v = assess(c, a, p)
    assert v["counter_reconciliation"] == "RECONCILED"
    assert "DELIVERY_BUDGET_EXCLUDED" in v["reasons"]
    assert v["status"] == "INCOMPLETE" and v["native_ai"] == "BLOCKED"
    assert v["source"] == "FIXTURE_NOT_NATIVE"
    assert v["source_provenance"]["generation"] == 7
    # Historical final snapshot without new accounting cannot be repaired.
    assert assess(c, None, p)["counter_reconciliation"] == "UNKNOWN"


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", 2),
        ("generation", 0),
        ("callbacks", 4109),
        ("delivered", 4097),
        ("stop", 99),
        ("start", 0),
        ("drain", 1),
    ],
)
def test_invalid_accounting_is_rejected(field, value):
    with pytest.raises(ValueError, match="TCX_ACCOUNTING_SCHEMA"):
        decode_accounting(accounting(**{field: value}))


@pytest.mark.parametrize("fault", ["epoch", "missing", "emitted", "ring", "receiver", "drain"])
def test_counter_domains_missing_or_losses_cannot_reconcile(fault):
    c, a, p = inputs()
    if fault == "epoch":
        c["generation"] = 8
    elif fault == "missing":
        del c["totals"]["observed"]
    elif fault == "emitted":
        c["totals"]["emitted"] += 1
    elif fault == "ring":
        c["totals"]["ring_reservation_failures"] = 1
    elif fault == "receiver":
        p["received"] -= 1
    else:
        a["drain_result"] = -11
    assert assess(c, a, p)["counter_reconciliation"] != "RECONCILED"


@pytest.mark.parametrize("closed,error", [(False, None), (True, "QUEUE_REJECT")])
def test_closed_or_stop_does_not_prove_capture_window(closed, error):
    c, a, p = inputs()
    value = assess(c, a, p, closed=closed, error=error)
    assert value["status"] == "INCOMPLETE"
    assert "ATOMIC_CAPTURE_WINDOW_NOT_ATTESTED" in value["reasons"]


def test_socket_accounting_generation_duplicate_and_journal_roundtrip(tmp_path):
    c = PacketChannel(native_plan(), "f" * 64, tmp_path / "channel")
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    c.channel, c.identity, c.source = left, local_controller(), 2
    c.prepare_adapter(7)
    try:
        right.send(frame(c, kind=6, packet=accounting()))
        c.pump()
        assert c.snapshot()["delivery_accounting"]["budget_excluded"] == 12
        right.send(frame(c, kind=6, sequence=2, packet=accounting()))
        with pytest.raises(ValueError, match="TCX_ACCOUNTING_SCOPE_OR_DUPLICATE"):
            c.pump()
    finally:
        left.close()
        right.close()
    raw = RC_ROW.pack(
        bytes.fromhex("aa" * 32),
        b"DATA_DELIVERY_ACCOUNTING",
        accounting(),
        1,
        1,
        bytes(32),
        bytes(32),
    )
    raw = raw[:-32] + hashlib.sha256(raw[:-32]).digest()
    journal = tmp_path / "journal"
    journal.write_bytes(raw)
    evidence = recover_native(journal, "aa" * 32)
    assert evidence["delivery_accounting"] == [decode_accounting(accounting())]
    assert not evidence["automatic_attach"]


def test_real_loader_callback_classifies_cap_error_and_cross_epoch(tmp_path):
    # Compile the actual callback with libbpf entry sections discarded by the linker.
    # No libbpf/kernel operation is invoked by this ordinary-UID executable.
    fixture = tmp_path / "callback.c"
    fixture.write_text("""
#include "loader.c"
#include <assert.h>
static int fail_send;
int soc_data_emit(struct soc_state *s,const void *body,size_t n) {
    (void)body;(void)n;if(fail_send)return -EAGAIN;s->data_packets_sent++;return 0;
}
int main(void) {
    struct runtime r={0};struct soc_state s={.context=&r,.generation=7};
    s.plan.events=2;s.plan.ifindex=1;s.plan.hook=1;s.data_packets_sent=100;
    struct soc_event e={.generation=7,.ifindex=1,.hook=1};
    assert(!emit(&s,&e,sizeof(e)));
    fail_send=1;assert(emit(&s,&e,sizeof(e))==-EAGAIN);
    fail_send=0;assert(!emit(&s,&e,sizeof(e)));
    e.generation=8;assert(emit(&s,&e,sizeof(e))==-EPROTO);
    assert(r.callbacks==4 && r.budget_excluded==1 && r.invalid==1 && r.send_failed==1);
    assert(s.data_packets_sent==101 && r.delivered==1 && s.packet_budget_reached);
    return 0;
}
""")
    exe = tmp_path / "callback"
    subprocess.run(
        [
            "cc",
            "-O2",
            "-ffunction-sections",
            "-fdata-sections",
            "-I" + str(ROOT),
            str(fixture),
            "-Wl,--gc-sections",
            "-o",
            str(exe),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run([str(exe)], check=True, timeout=2)


@pytest.mark.parametrize("excluded,budget_reason", [(12, True), (0, False), (None, False)])
def test_reconciled_failed_delivery_is_never_mislabeled_budget_exclusion(excluded, budget_reason):
    from tests.unit.ebpf_tc.test_phase_d import candidate_summary

    from soc_agent.security_ai.ebpf.eligibility import candidate_rca

    counter, _, _ = inputs()
    transport = dict(
        counter_evidence=counter,
        capture_evidence=dict(counter_reconciliation="RECONCILED"),
        delivery_accounting=dict(budget_excluded=excluded),
    )
    row = candidate_rca(candidate_summary(), transport)[0]
    assert ("CAPTURE_BUDGET_EXCLUDED" in row["reasons"]) is budget_reason
    assert ("EMITTED_DELIVERY_NOT_RECONCILED" in row["reasons"]) is not budget_reason
    assert not row["eligible"]
