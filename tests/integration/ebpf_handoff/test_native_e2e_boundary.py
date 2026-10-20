"""Reproduce the unqualified live packet/control boundary without kernel operations."""

import ipaddress

import pytest

from soc_agent.security_ai.ebpf.ring import ABI
from soc_agent.security_ai.ebpf_broker.contracts import Command
from soc_agent.security_ai.ebpf_tc.os_handoff import REPLY, AuthenticationFixture


def test_ring_record_is_not_a_successful_control_reply(session, monkeypatch):
    handoff, _ = session
    handoff.approve(handoff.approval)
    handoff.authenticate_fixture(AuthenticationFixture())
    # Actual ring ABI shape, independent of the control reply. Metadata only;
    # neither this injection nor the ordinary-UID peer loads a BPF program.
    packet = ABI.pack(
        1,
        1_000_000,
        1,
        handoff.plan.broker.application.scope.ifindex,
        0,
        54,
        40,
        12345,
        443,
        4,
        6,
        2,
        1,
        ipaddress.ip_address("192.0.2.1").packed + bytes(12),
        ipaddress.ip_address("192.0.2.2").packed + bytes(12),
    )
    assert len(packet) == 80 and REPLY.size == 72
    monkeypatch.setattr(handoff, "_packet", lambda **_credentials: packet)
    with pytest.raises(ValueError, match="HANDOFF_REPLY_SCHEMA"):
        handoff.command(Command(command="STATUS", plan_digest=handoff.plan.approval, sequence=1))
    assert handoff.ended and handoff.sequence == 0
    assert handoff.authentication == "REVOKED" and handoff.state == "ERROR"
    assert handoff.snapshot()["native_gate"] == "BLOCKED"
    assert not handoff.application._authenticated
    assert handoff.application.store.verify_audit()
