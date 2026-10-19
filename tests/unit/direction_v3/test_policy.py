"""No capture: unit-specific admission, fixed resources, immutable legacy approval."""

import hashlib
import math
from pathlib import Path

import pytest
from pydantic import ValidationError

from soc_agent.security_ai.operational.network_capture import direction_session as session
from soc_agent.security_ai.operational.network_capture.calibrated_session import verify_bundle
from soc_agent.security_ai.operational.network_capture.direction_policy import (
    Accounting,
    Budget,
    DirectionPolicy,
)
from soc_agent.security_ai.research.models import digest


def test_fixed_policy_and_legacy_identity():
    p = DirectionPolicy()
    assert (p.frame_budget, p.analysis_budget) == (154624, 77312)
    assert (p.frames_per_second, p.analysis_per_second) == (512, 256)
    assert (
        verify_bundle()["calibrated_helper.py"]
        == "375c06dbeb4e14c881fa496459182677b4efaa293845ecfac0dab0da663c4703"
    )
    for key, value in [
        ("seconds", 301),
        ("interface", "eth0"),
        ("frames_per_second", 513),
        ("analysis_per_second", 257),
        ("transport_capacity", 16),
    ]:
        with pytest.raises((ValueError, ValidationError)):
            DirectionPolicy.model_validate({key: value})


@pytest.mark.parametrize("kind,rate,burst", [("OBSERVATION", 512, 1024), ("ANALYSIS", 256, 512)])
def test_exact_boundary_and_refill(kind, rate, burst):
    b = Budget(kind, rate, burst, 0)
    for i in range(burst):
        b.consume(0, i + 1)
    with pytest.raises(ValueError, match=kind + "_BUDGET_EXCEEDED"):
        b.consume(0, burst + 1)
    assert b.diagnostic["token_balance"] == 0 and b.consumed == burst
    b.consume(1 / rate, burst + 1)
    assert b.tokens == 0 and b.consumed == burst + 1
    for t in [-1, math.inf, math.nan]:
        with pytest.raises(ValueError):
            b.consume(t, burst + 2)


def test_direction_selection_is_not_physical_deduplication():
    a = Accounting(DirectionPolicy(), 0)
    for _ in range(512):
        assert a.admit("OUTBOUND", 0)
        a.normalized += 1
        assert not a.admit("INBOUND", 0)
    s = a.snapshot()
    assert s["received_frames"] == s["accepted_raw_frames"] == 1024
    assert (
        s["direction_filtered_frames"] == s["analysis_accepted"] == s["normalized_packets"] == 512
    )
    with pytest.raises(ValueError, match="OBSERVATION_BUDGET"):
        a.admit("INBOUND", 0)
    assert a.failure["frame_sequence"] == 1025 and a.failure["budget_type"] == "OBSERVATION"


def test_analysis_can_exceed_independently_of_raw():
    a = Accounting(DirectionPolicy(), 0)
    for _ in range(512):
        a.admit("OUTBOUND", 0)
    with pytest.raises(ValueError, match="ANALYSIS_BUDGET"):
        a.admit("OUTBOUND", 0)
    assert a.observation.tokens == 511 and a.analysis.tokens == 0
    assert a.failure["integrity_scope"] == "CAPTURE_WIDE"
    b = Accounting(DirectionPolicy(), 0)
    with pytest.raises(ValueError, match="DIRECTION_UNKNOWN"):
        b.admit("UNKNOWN", 0)
    assert b.unknown == 1 and b.filtered == 0


def test_session_digest_new_approval_and_pins(tmp_path, monkeypatch):
    monkeypatch.setattr(session, "require_headroom", lambda: None)
    s = session.prepare(tmp_path / "new", DirectionPolicy())
    assert session.load(tmp_path / "new") == s
    info = session.instructions(tmp_path / "new", s)
    assert session.MODULE in info["command"] and "--approval-digest" in info["command"]
    assert info["approval_state"] == "APPROVAL_REQUIRED" and s.max_packets == 154624
    assert digest(s.code_sha256) == info["bundle_digest"]
    assert session.approval_digest(s) != digest(s.model_dump(mode="json"))
    assert (tmp_path / "new").stat().st_mode & 0o777 == 0o700
    assert (
        hashlib.sha256(
            Path(session.__file__).with_name("direction_helper.py").read_bytes()
        ).hexdigest()
        == info["helper_sha256"]
    )
