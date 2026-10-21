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


def test_processing_failure_keeps_authenticated_terminal_reader_until_closed(session, tmp_path):
    import time

    h, _ = session
    execute = parser(tmp_path)
    from tests.zeek_producer_support import valid_wire

    packets = tuple(
        execute(valid_wire(), 1_000_000_000 + ns, i)[1]
        for i, ns in enumerate((0, 20_000_000, 1_000_000, 21_000_000), 1)
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
    assert final["data_plane"]["error"] == "EBPF_REORDER_LATE_CAPTURE_GAP"
    assert final["data_plane"]["terminal_closed_observed"]
    assert not final["data_plane"]["transport_failed"]
    assert h.child.poll() == 0
    assert h.data.adapter.accepted == 1
    assert h.data.adapter.received == 4
    assert h.data.adapter.post_error_discarded == 1
    assert h.data.adapter.store.verify_audit()
