"""Real unprivileged Unix channel; only raw socket/peer attestation is mocked."""

import asyncio
import socket

import pytest
from tests.unit.streaming_network.test_transport import native_shaped

from soc_agent.security_ai.operational.network_capture import direction_transport as transport
from soc_agent.security_ai.operational.network_capture.direction_policy import DirectionPolicy
from soc_agent.security_ai.operational.network_capture.direction_session import prepare


def message(s, kind, *, count=0, seq=1, error=None, **update):
    result = dict(
        kind=kind,
        session_id=s.session_id,
        accounting_contract="soc-direction-accounting:v3",
        counter_status="COUNTER_VERIFIED",
        counter_sequence=seq,
        kernel_packets=1 if count else 0,
        kernel_packets_total=count,
        capture_drops=0,
        capture_drops_total=0,
        received_frames=count,
        accepted_raw_frames=count,
        outbound_frames=count,
        inbound_frames=0,
        unknown_direction_frames=0,
        direction_filtered_frames=0,
        analysis_accepted=count,
        normalized_packets=count,
        observation_tokens=1024 - count,
        analysis_tokens=512 - count,
        sent_packets=count,
        error=error,
    )
    result.update(update)
    return transport.DirectionMessage(**result)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [None, "rate", "counter", "drop", "sequence", "accounting"])
async def test_unix_accounting_closed_drain_rejection(tmp_path, monkeypatch, failure):
    from soc_agent.security_ai.operational.network_capture import direction_session

    monkeypatch.setattr(direction_session, "require_headroom", lambda: None)
    s = prepare(tmp_path / "session", DirectionPolicy())
    cap = transport.DirectionCapture(tmp_path / "session", s)
    monkeypatch.setattr(transport, "validate_peer", lambda *a: None)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.connect(s.socket_address)
    client.sendall(message(s, "READY").model_dump_json().encode())
    await asyncio.to_thread(cap.handshake)
    cap.start_reader()
    try:
        client.sendall(
            message(s, "HEARTBEAT", count=1, seq=2, sent_packets=0).model_dump_json().encode()
        )
        client.sendall(
            message(s, "PACKET", count=1, seq=2, sequence=1, packet=native_shaped(s, 1))
            .model_dump_json()
            .encode()
        )
        for _ in range(100):
            p = await asyncio.to_thread(cap.receive)
            if p is not None:
                break
            await asyncio.sleep(0.005)
        assert p is not None and cap.delivered == 1
        kwargs = {"kernel_packets": 0}
        if failure == "rate":
            kwargs.update(
                error="V3_OBSERVATION_BUDGET_EXCEEDED",
                budget_failure=dict(
                    budget_type="OBSERVATION",
                    token_balance=0,
                    monotonic_seconds=1,
                    since_last_consume_seconds=0,
                    frame_sequence=1,
                    consumed=1,
                    integrity_scope="CAPTURE_WIDE",
                    abort_reason="V3_OBSERVATION_BUDGET_EXCEEDED",
                    elapsed_monotonic_seconds=1,
                    average_observed_rate=1,
                    counter_sequence=3,
                    kernel_packets_total=1,
                ),
            )
        if failure == "counter":
            kwargs.update(
                counter_status="COUNTER_UNAVAILABLE", kernel_packets=None, capture_drops=None
            )
        if failure == "drop":
            kwargs.update(
                counter_status="CAPTURE_DROPS_DETECTED", capture_drops=1, capture_drops_total=1
            )
        if failure == "sequence":
            kwargs.update(counter_sequence=5)
        if failure == "accounting":
            kwargs.update(outbound_frames=0)
        client.sendall(
            message(s, "CLOSED", count=1, seq=3, elapsed_seconds=1, **kwargs)
            .model_dump_json()
            .encode()
        )
        for _ in range(100):
            if cap.terminal is not None or cap.reader_failed():
                break
            await asyncio.sleep(0.005)
        if failure:
            assert cap.reader_failed() and not cap.completion_verified()
            assert not (tmp_path / "session/verified-closed.json").exists()
            assert (tmp_path / "session/rejected-closed.json").exists()
        else:
            assert cap.completion_verified()
            m = cap.extra_metrics()
            assert m["accepted_raw_frames"] == m["normalized_packets"] == m["sent_packets"] == 1
            assert m["received_frames"] == 1
            assert (tmp_path / "session/verified-closed.json").exists()
    finally:
        client.close()
        cap.close()
    assert cap.reader_thread is None or not cap.reader_thread.is_alive()
    assert not cap.listener_ready()


def test_accounting_projection_does_not_invent_v2_fields():
    from soc_agent.gui.visual_metrics import VisualHistory
    from soc_agent.security_ai.research.packet_accounting import packet_accounting

    assert packet_accounting({}, origin="NATIVE_AF_PACKET")["accepted_raw_frames"] is None
    m = dict(
        accounting_contract="soc-direction-accounting:v3",
        accepted_raw_frames=2,
        direction_filtered_frames=1,
        approved_analysis_packets_per_second=256,
    )
    assert packet_accounting(m, origin="NATIVE_AF_PACKET")["filtered_raw_frames"] == 1
    h = VisualHistory()
    assert h.observe(
        dict(session_id="v3", input_origin="FIXTURE", state="LIVE_COLLECTION", network=m), at=1
    )
    assert h.samples[-1].values["raw"] is None
    assert h.samples[-1].values["analysis_limit"] == 256
    assert not h.observe(
        dict(session_id="v3", input_origin="FIXTURE", state="ERROR", network=m), at=2
    )


def test_v3_normalized_and_sent_are_not_conflated():
    from soc_agent.gui.visual_metrics import VisualHistory

    h = VisualHistory()
    for n in range(2):
        h.observe(
            dict(
                session_id="real-counter-fixture",
                input_origin="FIXTURE",
                state="LIVE_COLLECTION",
                network=dict(
                    accounting_contract="soc-direction-accounting:v3",
                    received_frames=4 * n,
                    normalized_packets=2 * n,
                    sent_packets=n,
                    transport_delivered_packets=0,
                ),
            ),
            at=n + 1,
        )
    values = h.samples[-1].values
    assert (values["raw"], values["normalized"], values["delivered"]) == (4, 2, 0)
