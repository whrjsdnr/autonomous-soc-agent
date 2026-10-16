"""Unix metadata fixtures with mocked peer attestation; no native capture/inference."""

import asyncio
import json
import threading
from datetime import UTC, datetime

import pytest
from tests.integration.streaming_network.test_shutdown import connected, send_closed
from tests.unit.streaming_network.test_transport import native_shaped, stat

from soc_agent.security_ai.operational.network_capture.models import PacketObservation
from soc_agent.security_ai.operational.network_capture.stream_transport import StreamMessage


def at_ns(session, ns):
    value = native_shaped(session, 1).model_dump()
    seconds, nanos = divmod(ns, 10**9)
    value.update(
        capture_timestamp_ns=ns,
        timestamp=datetime.fromtimestamp(seconds, UTC).replace(microsecond=nanos // 1000),
    )
    return PacketObservation.model_validate(value)


def send(owner, client, number, ns):
    client.sendall(stat(owner.session, number + 1, number).model_dump_json().encode())
    client.sendall(
        StreamMessage(
            kind="PACKET",
            session_id=owner.session.session_id,
            sequence=number,
            counter_sequence=number + 1,
            packet=at_ns(owner.session, ns),
        )
        .model_dump_json()
        .encode()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("regression", [1, 1_000_000, 500_000_000, 1_500_000_000])
async def test_regression_has_complete_non_sensitive_context_and_never_infers(
    tmp_path, monkeypatch, regression
):
    owner, client = await connected(tmp_path, monkeypatch)
    first = 1_800_000_002_000_000_999
    try:
        send(owner, client, 1, first)
        send(owner, client, 2, first - regression)
        await asyncio.wait_for(owner.task, 5)
        assert owner.state == "ERROR" and owner.last_error == "STREAM_TIME_REVERSED"
        metrics = owner.store.runtime.state()["network"]
        assert metrics["timestamp_integrity"] == "FAILED_EVENT_TIME_ORDER"
        assert metrics["packet_sequence"] == 2
        context = metrics["time_context"]
        assert context["previous_event_ns"] == first
        assert context["rejected_event_ns"] == first - regression
        assert context["regression_ns"] == regression
        assert context["helper_packet_sequence"] == context["packet_sequence"] == 2
        assert context["counter_sequence"] == 3
        assert context["ordering_scope"] == "GLOBAL" and context["root_cause"] == "UNKNOWN"
        assert context["direction"] == "OUTBOUND"
        assert len(context["flow_key_digest"]) == 64
        assert "192.0.2." not in json.dumps(context)
        assert "source_address" not in context and "packet" not in context
        assert owner.metrics["gap_count"] == 1
        assert owner.metrics["inference_count"] == 0
        assert not list(owner.demo.directory.glob("receipt-*.json"))
        assert owner.store.runtime.verify_audit()
    finally:
        client.close()
        await owner.stop(abort=True)


@pytest.mark.asyncio
async def test_wire_sequence_reordering_is_not_misclassified_as_event_time(tmp_path, monkeypatch):
    owner, client = await connected(tmp_path, monkeypatch)
    try:
        client.sendall(
            StreamMessage(
                kind="PACKET",
                session_id=owner.session.session_id,
                sequence=2,
                counter_sequence=1,
                packet=native_shaped(owner.session, 1),
            )
            .model_dump_json()
            .encode()
        )
        await asyncio.wait_for(owner.task, 5)
        assert owner.last_error == "HELPER_PACKET_BINDING_MISMATCH"
        assert owner.metrics["timestamp_integrity"] == "UNKNOWN"
        assert owner.metrics["packets_collected"] == owner.metrics["inference_count"] == 0
    finally:
        client.close()
        await owner.stop(abort=True)


@pytest.mark.asyncio
async def test_injected_reader_queue_and_seal_reordering_fails_closed(tmp_path, monkeypatch):
    owner, client = await connected(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    original = owner.capture.receive

    def paused():
        if not entered.is_set():
            entered.set()
            assert release.wait(3)
        return original()

    monkeypatch.setattr(owner.capture, "receive", paused)
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        send(owner, client, 1, 1_800_000_000_000_000_001)
        send(owner, client, 2, 1_800_000_000_000_000_002)
        for _ in range(200):
            if owner.capture.packets.qsize() == 2:
                break
            await asyncio.sleep(0.005)
        with owner.capture.reader_lock:
            left, right = owner.capture.packets.get_nowait(), owner.capture.packets.get_nowait()
            owner.capture.packets.put_nowait(right)
            owner.capture.packets.put_nowait(left)
            owner.capture.seals.reverse()  # Deliberate in-memory fixture corruption only.
        release.set()
        await asyncio.wait_for(owner.task, 5)
        assert owner.last_error == "STREAM_PACKET_SEQUENCE_MISMATCH"
        assert owner.metrics["inference_count"] == 0
        assert owner.metrics["finalization"] == "BLOCKED"
    finally:
        release.set()
        client.close()
        await owner.stop(abort=True)


@pytest.mark.asyncio
async def test_reader_preserves_ns_with_equal_datetime_and_normal_closed(tmp_path, monkeypatch):
    owner, client = await connected(tmp_path, monkeypatch)
    try:
        for n in range(1, 4):
            send(owner, client, n, 1_800_000_000_000_000_100 + n)
        send_closed(owner, client, 3)
        await asyncio.wait_for(owner.task, 5)
        assert owner.state == "STOPPED", owner.last_error
        assert owner.metrics["packet_sequence"] == 3
        assert owner.metrics["timestamp_integrity"] == "ORDERED_PREFIX_ONLY"
        assert owner.capture.delivered == 3 and owner.capture.completion_verified()
        assert owner.metrics["inference_count"] == 0  # SHUTDOWN, no timeout eligibility.
    finally:
        client.close()
        await owner.stop()
