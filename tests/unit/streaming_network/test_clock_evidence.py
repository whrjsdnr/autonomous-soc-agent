"""Portable committed evidence verifies hashes, scope and fail-closed limitations."""

import hashlib
import json
from pathlib import Path

from soc_agent.security_ai.operational.network_capture.total_session import verify_bundle


def test_clock_evidence_bindings_and_limits():
    root = Path(__file__).resolve().parents[3]
    data = json.loads(
        (root / "docs/linux-soc-v1/streaming-clock-checkpoint-evidence.json").read_text()
    )
    assert data["contract"] == "soc-streaming-clock-checkpoint-evidence:v1"
    for name, expected in data["source_sha256"].items():
        # Preserve this historical proof as the live service gains domain hooks.
        # The exact source at 0ee341b is frozen as non-executable test data;
        # current clock behavior is still exercised by the clock regressions.
        path = (
            root / "tests/fixtures/streaming-clock/research-service-0ee341b.txt"
            if name == "src/soc_agent/security_ai/research/service.py"
            else root / name
        )
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
    helper = root / "src/soc_agent/security_ai/operational/network_capture/stream_helper.py"
    # This immutable evidence belongs to the prior helper, not the new DNS scope.
    assert data["helper"]["sha256"] == (
        "1cc1c1f39007d1e8f53207dcd5f79f2128b12ea8077d5d09fcb6a72c5d037c84"
    )
    current = hashlib.sha256(helper.read_bytes()).hexdigest()
    assert current == verify_bundle()["stream_helper.py"]
    assert current != data["helper"]["sha256"]  # Old approval is explicitly invalidated.
    assert data["clock_observation"]["backward_steps"] == []
    assert data["historical_failure_causality"] == "UNKNOWN"
    assert data["limited_fixture_soak"]["source"] == "FIXTURE"
    assert data["limited_fixture_soak"]["new_capture"] is False
    assert data["limited_fixture_soak"]["metrics"]["capture_drops"] is None
    assert data["limited_fixture_soak"]["actual_inferences"] == 2
    assert data["limited_fixture_soak"]["read_only_investigations"] == 2
    assert data["helper"]["proposed_native_seconds"] == 300
    assert data["helper"]["schema_max_seconds"] == 1800
    assert data["native_validation"] == "PENDING_SEPARATE_USER_APPROVAL"
    assert data["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
