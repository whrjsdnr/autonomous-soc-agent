"""Committed evidence is integrity checked and cannot authorize Native inference."""

import hashlib
import json
from pathlib import Path

from soc_agent.security_ai.research.models import SPECS, digest


def test_rate_evidence_integrity_scope_and_approved_helpers():
    root = Path(__file__).resolve().parents[3]
    doc = json.loads((root / "docs/linux-soc-v1/total-rate-backpressure-evidence.json").read_text())
    e = doc["evidence"]
    assert digest(e) == doc["evidence_digest"]
    assert e["contract"] == "soc-total-rate-backpressure-evidence:v1"
    assert not e["native_capture_executed"] and not e["automatic_rate_increase"]
    n = e["native"]
    assert n["actual_burst"] == n["rate_root_cause"] == "UNKNOWN"
    assert n["rejected_closed"]["received_frames"] == 384
    assert n["rejected_closed"]["completion_verified"] is False
    assert n["naive_cumulative_bound"] > 384 and n["verified_closed"] == "MISSING"
    assert n["transport_delivered"] == 192 and n["inference_receipts"] == 0
    assert n["transport_queue_peak"] < n["transport_capacity"]
    for name, sha in e["helper_sha256"].items():
        path = root / "src/soc_agent/security_ai/operational/network_capture" / name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == sha
    profile = e["profile"]
    assert digest(profile["result"]) == profile["result_digest"]
    assert profile["result"]["actual_model_calls"] == 4
    assert profile["result"]["investigations"] == 4
    for model in profile["result"]["models"]:
        assert model["source_origin"] == "FIXTURE"
        assert model["artifact"] == SPECS[model["profile"]]["sha256"]
        assert model["feature_contract_digest"] == (
            "84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e"
        )
    comparison = e["congestion_comparison"]
    assert comparison["baseline"]["packets_processed"] == 27
    assert comparison["candidate"]["packets_processed"] == 38
    assert comparison["candidate"]["inference_excluded"] == 4
    assert comparison["candidate"]["actual_model_inferences"] == 0
    soak = e["soak"]
    assert digest(soak["result"]) == soak["result_digest"]
    assert soak["result"]["elapsed_monotonic_seconds"] >= 60
    assert soak["result"]["retained_packet_metadata_bytes"] == 0
    assert e["dns9"] == e["operational_promotion"] == "BLOCKED"
