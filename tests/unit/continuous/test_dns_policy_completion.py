"""Finite DNS lifecycle with no AF_PACKET, target entry or DNS traffic."""

import asyncio
from types import SimpleNamespace

import pytest
from tests.unit.continuous.test_dns_source import prepared
from tests.unit.continuous.test_runtime import make

from soc_agent.continuous.dns_source import DNSProducer
from soc_agent.continuous.service import ContinuousRuntime


def completed(tmp_path, monkeypatch):
    from soc_agent.continuous import dns_source

    path, session, pin = prepared(tmp_path)
    monkeypatch.setattr(dns_source, "load", lambda _: session)
    producer = DNSProducer(path, pin)
    producer.capture.terminal = SimpleNamespace(elapsed_seconds=59.2, error=None)
    producer.capture.completion_verified = lambda: True
    producer.state = "STOPPED"
    producer.cleanup = producer.helper_cleanup = "VERIFIED"
    producer.cleanup_evidence_sha256 = "a" * 64
    return producer


@pytest.mark.parametrize(
    "change",
    [
        "early",
        "no_duration",
        "overrun",
        "helper_error",
        "counter",
        "cleanup",
        "receipt",
        "state",
        "error",
    ],
)
def test_only_full_policy_and_cleanup_allow_finite_completion(tmp_path, monkeypatch, change):
    producer = completed(tmp_path, monkeypatch)
    try:
        assert producer.policy_duration_completed
        if change == "early":
            producer.capture.terminal.elapsed_seconds = 58.9
        elif change == "no_duration":
            producer.capture.terminal.elapsed_seconds = None
        elif change == "overrun":
            producer.capture.terminal.elapsed_seconds = 63
        elif change == "helper_error":
            producer.capture.terminal.error = "HELPER_WATCHDOG_EXPIRED"
        elif change == "counter":
            producer.capture.completion_verified = lambda: False
        elif change == "cleanup":
            producer.helper_cleanup = "UNVERIFIED"
        elif change == "receipt":
            producer.cleanup_evidence_sha256 = None
        elif change == "state":
            producer.state = "FAILED"
        else:
            producer.last_error = "FAILED"
        assert not producer.policy_duration_completed
    finally:
        producer.capture.listener.close()


@pytest.mark.asyncio
async def test_runtime_remains_running_after_verified_finite_dns(tmp_path):
    path, store = make(tmp_path)

    class Idle:
        async def events(self):
            while True:
                await asyncio.sleep(0.02)
                if False:
                    yield None

        async def close(self):
            pass

    class FinishedDNS:
        policy_duration_completed = True
        snapshot = dict(state="STOPPED", cleanup="VERIFIED", policy_duration_completed=True)

        async def events(self):
            if False:
                yield None

        async def request_stop(self):
            pass

        async def close(self):
            pass

    runtime = ContinuousRuntime(path, source=Idle(), dns_source=FinishedDNS())
    worker = asyncio.create_task(runtime.run())
    try:
        await asyncio.sleep(0.3)
        assert not worker.done()
        assert runtime.last_error is None
        assert runtime.snapshot()["dns_transport"]["state"] == "STOPPED"
    finally:
        store.control(stop=True)
        await asyncio.wait_for(worker, 5)


@pytest.mark.asyncio
async def test_unverified_finite_dns_still_fails(tmp_path):
    path, _ = make(tmp_path)

    class FailedDNS:
        policy_duration_completed = False

        async def events(self):
            if False:
                yield None

    runtime = ContinuousRuntime(path, dns_source=FailedDNS())
    try:
        with pytest.raises(ValueError, match="SOURCE_EARLY_EXIT"):
            await runtime.collect_dns()
        assert "SOURCE_EARLY_EXIT" in runtime.last_error
    finally:
        await runtime.analysis.close()
