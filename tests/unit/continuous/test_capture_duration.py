"""Conservative enabled time; fixtures never prove real Kernel duration."""

from types import SimpleNamespace

import pytest
from tests.unit.continuous.test_capture_admission import NS, raw_event, reseal, transcript

from soc_agent.continuous.capture import CaptureWindows
from soc_agent.continuous.native import service


def test_duration_recomputed_after_recovery_and_never_double_counted():
    seal, events = transcript()
    start = seal.cpu_windows[0]["after_ns"] + 10
    end = seal.cpu_windows[-1]["before_ns"] - 10
    value = reseal(seal.model_dump(mode="json") | dict(capture_interval_ns=[start, end]))
    raw = dict(kind="native_seal", seal=value.model_dump(mode="json"))
    first, restored = CaptureWindows(NS, "b" * 64), CaptureWindows(NS, "b" * 64)
    for target in (first, restored):
        for event in events:
            target.accept(raw_event(event))
        _, capture = target.accept(raw)
        assert capture["status"] == "VERIFIED"
        assert target.verified_capture_ns == end - start
        with pytest.raises(ValueError, match="REPLAY"):
            target.accept(raw)
        assert target.verified_capture_ns == end - start


def test_legacy_seal_has_no_enabled_time_claim():
    seal, events = transcript()
    seal.check()
    assert "capture_interval_ns" not in seal.model_dump(mode="json")
    target = CaptureWindows(NS, "b" * 64)
    for event in events:
        target.accept(raw_event(event))
    target.accept(dict(kind="native_seal", seal=seal.model_dump(mode="json")))
    assert target.verified_capture_ns == 0


@pytest.mark.parametrize("interval", [[0, 1], [10, 10], [10, 10**15], [1.5, 2]])
def test_invalid_duration_rejected(interval):
    seal, _ = transcript()
    with pytest.raises(ValueError):
        reseal(seal.model_dump(mode="json") | dict(capture_interval_ns=interval)).check()


@pytest.mark.parametrize("gap", [False, True])
def test_provider_excludes_enable_setup_and_expired_lease(monkeypatch, gap):
    provider = service.Provider.__new__(service.Provider)
    provider.capture_started_ns = provider.lease_until_ns = None
    provider.capture_interval_ns = None
    provider.coverage_gap = False
    provider.handle = provider.generation = provider.index = 1
    provider.lib = SimpleNamespace(continuous_renew=lambda *args: 0)
    before = 1_000_000_000
    stamps = iter([before, before + 5, before + (6 if gap else 1) * 10**9, before + 12 * 10**9])
    monkeypatch.setattr(service.time, "monotonic_ns", lambda: next(stamps))
    provider.renew()
    provider.renew()
    provider.boundary = lambda *args: []
    provider.close = lambda: None
    provider.samples = []
    provider.initial = []
    monkeypatch.setattr(service, "clock_samples", lambda *args: [])
    provider.finish()
    if gap:
        assert provider.capture_interval_ns is None
    else:
        assert provider.capture_interval_ns == [before + 5, before + 6 * 10**9]
