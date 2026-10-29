"""Actual local transport and delayed durability; no Kernel/Root/network traffic."""

import asyncio
import json
import socket
import time
from types import SimpleNamespace

import pytest
from tests.unit.continuous.test_runtime import config

from soc_agent.continuous.service import ContinuousRuntime
from soc_agent.continuous.store import Store
from soc_agent.continuous.tcx_producer import TCXProducer

NS = "net:[4026532232]"
POLICY = dict(namespace=NS, files={"continuous.bpf.o": "a" * 64})


def packet(sequence):
    return json.dumps(
        dict(
            contract="soc-continuous-tcx:v1",
            namespace=NS,
            ifindex=1,
            program_sha256="a" * 64,
            sequence=sequence,
        )
    ).encode()


@pytest.mark.asyncio
async def test_slow_projection_keeps_receiving_real_local_transport_heartbeats():
    owner, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    owner.setblocking(False)
    peer.setblocking(False)
    source = TCXProducer(SimpleNamespace(queue_capacity=32, input_sha256="b" * 64))
    source.socket = owner
    loop = asyncio.get_running_loop()
    messages = source.messages(loop, POLICY)

    async def send():
        for i in range(17):
            await loop.sock_sendall(peer, packet(i))
            await asyncio.sleep(0.4)
        await loop.sock_sendall(
            peer,
            json.dumps(
                dict(contract="soc-continuous-tcx-stop:v1", namespace=NS, policy_sha256="b" * 64)
            ).encode(),
        )

    sender = asyncio.create_task(send())
    try:
        first = await anext(messages)
        assert first["sequence"] == 0
        original = source.last_message_unix
        # Reproduce persistence taking longer than the unchanged five-second
        # receive deadline. The receiver must continue independently.
        await asyncio.to_thread(time.sleep, 6.1)
        assert source.last_message_unix > original + 5
        assert time.time() - source.last_message_unix < 1
        assert source.receiver_queue_depth >= 12
        rest = [r async for r in messages]
        assert [r["sequence"] for r in rest[:-1]] == list(range(1, 17))
        assert source.failure is None and source.receiver_dropped_batches == 0
    finally:
        await messages.aclose()
        await sender
        await source.close()
        peer.close()


@pytest.mark.asyncio
async def test_receiver_overflow_fails_closed_and_accounts_for_drop():
    source = TCXProducer(SimpleNamespace(queue_capacity=1))
    source.receive_message = None
    counter = 0

    async def receive(_):
        nonlocal counter
        counter += 1
        return packet(counter)

    source.receive_message = receive
    with pytest.raises(ValueError, match="CONTINUOUS_PRODUCER_RECEIVER_QUEUE_FULL"):
        _ = [r async for r in source.messages(asyncio.get_running_loop(), POLICY)]
    assert source.receiver_dropped_batches == 1
    assert source.failure["capacity"] == 1
    assert source.failure["capture_restarted"] is False


@pytest.mark.asyncio
async def test_missing_transport_still_times_out_at_five_seconds():
    owner, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    owner.setblocking(False)
    source = TCXProducer(SimpleNamespace(queue_capacity=32))
    source.socket = owner
    at = time.monotonic()
    try:
        with pytest.raises(ValueError, match="CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT"):
            await source.receive_message(asyncio.get_running_loop())
        assert 4.9 <= time.monotonic() - at < 6.5
        assert source.failure["timeout_seconds"] == 5
    finally:
        await source.close()
        peer.close()


@pytest.mark.asyncio
async def test_native_storage_yields_and_joins_cancelled_durable_write(tmp_path):
    cfg = config(tmp_path).model_copy(update={"source": "NATIVE_SERVICE"})
    directory = tmp_path / "runtime"
    Store.create(directory, cfg)
    runtime = ContinuousRuntime(directory)
    completed = []

    def durable():
        time.sleep(0.2)
        completed.append(True)

    pending = asyncio.create_task(runtime.storage(durable))
    await asyncio.sleep(0.02)
    assert not pending.done() and not completed
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert completed == [True]  # No unjoined writer at cleanup.
