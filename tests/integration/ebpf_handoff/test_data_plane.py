"""Real ordinary-UID C producer → separate socket → shared parser/Network14 math."""

import asyncio
import json
import os
from pathlib import Path

import pytest
from tests.ebpf_support import parser
from tests.integration.ebpf.test_parity import frames
from tests.zeek_producer_support import golden

from soc_agent.security_ai.collectors.packet_input import reference
from soc_agent.security_ai.collectors.packet_producer import aggregate
from soc_agent.security_ai.ebpf_broker.contracts import Command
from soc_agent.security_ai.ebpf_tc.os_handoff import AuthenticationFixture


@pytest.mark.parametrize("scenario,tcp,ipv6", [("idle", True, False), ("active", False, True)])
def test_c_data_plane_golden_control_independence_and_recovery(
    session, tmp_path, scenario, tcp, ipv6
):
    h, _ = session
    pcap = tmp_path / "input.pcap"
    sha = golden(pcap, scenario, tcp=tcp, ipv6=ipv6)
    execute = parser(tmp_path)
    rows = tuple(frames(pcap))
    packets = []
    for i, (ns, frame) in enumerate(rows, 1):
        status, body = execute(frame, ns - rows[0][0] + 1_000_000_000, i)
        assert status == 0
        packets.append(body)
    h.approve(h.approval)
    h.authenticate_fixture(AuthenticationFixture(), packets=tuple(packets))
    h.data.prepare_adapter(7)
    result = h.command(Command(command="PREPARE", plan_digest=h.plan.approval, sequence=1))
    assert result["state"] == 3  # Never fabricate Kernel ACTIVE.
    h.command(Command(command="STATUS", plan_digest=h.plan.approval, sequence=2))
    actual = h.data.adapter
    expected = aggregate(tuple(reference(pcap)), str(actual.plan.session_id))
    assert [f["values"] for f in actual.flow.finalized] == [f["values"] for f in expected["flows"]]
    assert [f["values_digest"] for f in actual.flow.finalized] == [
        f["values_digest"] for f in expected["flows"]
    ]
    assert actual.accepted == len(packets) and actual.queue_peak <= 32 and not actual.queue
    assert actual.flow.finalized[-1]["close_reason"] == "CAPTURE_STOP"
    assert not actual.flow.finalized[-1]["eligible"]
    h.stop()
    assert not h.ended  # Same app scope; no additional mock authentication.
    final = h.close()
    assert final["cleanup_status"] == "FIXTURE_VERIFIED"
    assert final["data_plane"]["state"] == "CLOSED"
    assert h.child.poll() == 0 and final["native_gate"] == "BLOCKED"
    assert actual.store.verify_audit() and h.application.store.verify_audit()
    from soc_agent.security_ai.ebpf.collector import EBPFCollector

    restored = EBPFCollector(actual.directory, actual.plan)
    recovered = asyncio.run(restored.recover())
    assert not recovered["collection_live"] and not recovered["research"]["records"]
    assert recovered["state"] == "RESTORED_NO_REATTACH"
    if os.getenv("SOC_TCX_DATA_EVIDENCE"):
        out = Path(os.environ["SOC_TCX_DATA_EVIDENCE"])
        out.mkdir(exist_ok=True)
        (out / f"{scenario}-{tcp}-{ipv6}.json").write_text(
            json.dumps(
                dict(
                    scope="ORDINARY_UID_C_SOCKET_HOST_PARSER_NOT_KERNEL",
                    pcap_sha256=sha,
                    data=final["data_plane"],
                    control_sequence=h.sequence,
                    audit=h.application.store.verify_audit(),
                    restored=recovered["state"],
                ),
                indent=2,
            )
        )


@pytest.mark.parametrize("failure", ["late", "cpu_reuse"])
def test_processing_failure_keeps_authenticated_terminal_reader_until_closed(
    session, tmp_path, failure
):
    import time

    h, _ = session
    execute = parser(tmp_path)
    from tests.zeek_producer_support import valid_wire

    packets = tuple(
        execute(valid_wire(), 1_000_000_000 + ns, sequence)[1]
        for ns, sequence in (
            ((0, 1), (20_000_000, 2), (1_000_000, 3), (21_000_000, 4))
            if failure == "late"
            else ((0, 1), (20_000_000, 2), (21_000_000, 2), (22_000_000, 3))
        )
    )
    h.approve(h.approval)
    h.authenticate_fixture(AuthenticationFixture(), packets=packets)
    h.data.prepare_adapter(7)
    try:
        h.command(Command(command="PREPARE", plan_digest=h.plan.approval, sequence=1))
        # A completed control reply can race the processing error. Neither case
        # authorizes another run; close the same authenticated producer once.
        deadline = time.monotonic() + 2
        while not h.data.error and time.monotonic() < deadline:
            time.sleep(0.01)
    except ValueError:
        pass
    final = h.close()
    assert final["data_plane"]["error"] == (
        "EBPF_REORDER_LATE_CAPTURE_GAP" if failure == "late" else "EBPF_CPU_SEQUENCE_GAP_OR_REUSE"
    )
    assert final["data_plane"]["terminal_closed_observed"]
    assert not final["data_plane"]["transport_failed"]
    assert h.child.poll() == 0
    assert h.data.adapter.accepted == 1
    assert h.data.adapter.received == (4 if failure == "late" else 3)
    assert h.data.adapter.post_error_discarded == 1
    assert h.data.adapter.store.verify_audit()


def test_counter_and_closed_frames_drain_after_processing_failure(session, tmp_path, monkeypatch):
    import socket
    import struct

    from tests.zeek_producer_support import valid_wire

    from soc_agent.security_ai.ebpf_native.contracts import process_identity
    from soc_agent.security_ai.ebpf_tc import data_plane

    h, _ = session
    channel = data_plane.PacketChannel(h.plan, h.envelope[-32:].hex(), tmp_path / "drain")
    channel.source = 2
    channel.identity = process_identity(os.getpid())
    channel.prepare_adapter(7)
    execute = parser(tmp_path)
    raw = execute(valid_wire(), 1_000_000_000, 1)[1]
    counter = struct.pack("<QQ7QII", 7, 1_000_000_001, 4, 2, 0, 2, 0, 0, 0, 1, 2)
    rows = []
    for sequence, kind, payload in ((1, 2, raw), (2, 2, raw), (3, 5, counter), (4, 3, bytes(80))):
        rows.append(
            data_plane.HEADER.pack(
                data_plane.MAGIC,
                1,
                kind,
                2,
                sequence,
                0,
                h.plan.broker.application.application_session.bytes,
                bytes.fromhex(channel.approval),
                bytes.fromhex(h.plan.program_sha256),
            )
            + payload
        )

    class Frames:
        def recvmsg(self, *_args):
            credentials = struct.pack("3i", os.getpid(), os.getuid(), os.getgid())
            return rows.pop(0), [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, credentials)], 0, None

        def close(self):
            pass

    channel.channel = Frames()
    monkeypatch.setattr(
        data_plane.select, "select", lambda *_args: ([channel.channel] if rows else [], [], [])
    )
    with pytest.raises(ValueError, match="CPU_SEQUENCE_GAP_OR_REUSE"):
        channel.pump()
    channel.pump()
    final = channel.snapshot()
    assert final["error"] == "EBPF_CPU_SEQUENCE_GAP_OR_REUSE"
    assert final["terminal_closed_observed"] and not final["transport_failed"]
    assert final["counter_evidence"]["totals"]["unsupported"] == 2
    assert final["counter_evidence"]["source"] == "FIXTURE_COUNTER_NEVER_NATIVE"
    assert final["ring_loss"] == 0 and final["kernel_drops"] is None
    assert channel.adapter.accepted == 0 and channel.adapter.store.verify_audit()
    channel.close()


def test_recvmsg_errno_does_not_overwrite_first_processing_failure(session, tmp_path, monkeypatch):
    import errno

    from soc_agent.security_ai.ebpf_tc import data_plane

    h, _ = session
    channel = data_plane.PacketChannel(h.plan, h.envelope[-32:].hex(), tmp_path)
    channel.identity = h.plan.broker.application.controller
    channel.error = "EBPF_CPU_SEQUENCE_GAP_OR_REUSE"

    class FailedReceive:
        def recvmsg(self, *_args):
            raise OSError(errno.ENOBUFS, "fixture recvmsg failure")

    channel.channel = FailedReceive()
    monkeypatch.setattr(data_plane.select, "select", lambda *_args: ([channel.channel], [], []))
    with pytest.raises(OSError) as error:
        channel.pump()
    assert error.value.errno == errno.ENOBUFS
    assert channel.error == "EBPF_CPU_SEQUENCE_GAP_OR_REUSE"
    assert channel.snapshot()["io_failure"] == {
        "api": "recvmsg",
        "errno": errno.ENOBUFS,
        "source": "ACTUAL_OSERROR",
    }
    assert channel.transport_failed
