import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from soc_agent.continuous.tcx_producer import TCXProducer


@pytest.mark.asyncio
async def test_receiver_timeout_preserves_stage_and_does_not_claim_cleanup():
    producer = TCXProducer(SimpleNamespace())
    loop = SimpleNamespace(sock_recv=AsyncMock(side_effect=TimeoutError))
    with pytest.raises(ValueError, match="CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT") as caught:
        await producer.receive_message(loop)
    assert isinstance(caught.value.__cause__, TimeoutError)
    assert producer.failure["timeout_seconds"] == 5
    assert producer.failure["stage"] == "AUTHENTICATED_ROOT_RECEIVE"
    assert producer.failure["last_message_age_seconds"] is None
    await producer.close()
    assert producer.snapshot["state"] == "STOPPED"
    assert producer.snapshot["failure"] == producer.failure
    assert producer.snapshot["cleanup"] == "UNKNOWN"


@pytest.mark.asyncio
async def test_wall_clock_change_cannot_relabel_monotonic_liveness(monkeypatch):
    producer = TCXProducer(SimpleNamespace())
    producer.last_message_unix = time.time()
    producer.last_message_monotonic = time.monotonic() - 6
    monotonic, wall = time.monotonic, time.time()
    monkeypatch.setattr(
        "soc_agent.continuous.tcx_producer.time",
        SimpleNamespace(time=lambda: wall - 1000, monotonic=monotonic),
    )
    with pytest.raises(ValueError, match="CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT"):
        await producer.receive_message(
            SimpleNamespace(sock_recv=AsyncMock(side_effect=TimeoutError))
        )
    assert producer.failure["last_message_age_seconds"] < 0
    assert producer.failure["last_message_age_monotonic_seconds"] >= 6
    assert producer.failure["timeout_seconds"] == 5


@pytest.mark.asyncio
async def test_stop_intent_is_visible_before_immediate_ack_and_send_is_not_replayed():
    producer = TCXProducer(SimpleNamespace(input_sha256="a" * 64))
    producer.socket = object()
    producer.epoch = 7
    observed = []

    async def immediate(*_):
        observed.append(producer.cleanup_evidence["stop_requested_monotonic"])
        producer.stop_ack.set()

    loop = SimpleNamespace(sock_sendall=immediate)
    await producer.send_stop(loop)
    await producer.send_stop(loop)
    assert len(observed) == 1
    assert observed[0] <= producer.cleanup_evidence["stop_send_completed_monotonic"]
    producer.socket = None


@pytest.mark.asyncio
async def test_uncertain_cancelled_stop_send_never_automatically_sends_again():
    import asyncio

    producer = TCXProducer(SimpleNamespace(input_sha256="a" * 64))
    producer.socket = object()
    producer.epoch = 7
    attempted = []

    async def cancelled(*_):
        attempted.append(1)
        raise asyncio.CancelledError

    loop = SimpleNamespace(sock_sendall=cancelled)
    with pytest.raises(asyncio.CancelledError):
        await producer.send_stop(loop)
    assert producer.cleanup_evidence["stop_send_error"] == "CancelledError"
    with pytest.raises(ValueError, match="STOP_SEND_OUTCOME_UNVERIFIED"):
        await producer.send_stop(loop)
    assert len(attempted) == 1 and not producer._stop_sent
    producer.socket = None
