"""Evidence pins the current foundation without claiming Native verification."""

import hashlib
import json
from pathlib import Path

from soc_agent.security_ai.ebpf.build import source_digest
from soc_agent.security_ai.research.models import digest

ROOT = Path(__file__).resolve().parents[3]


def evidence():
    return json.loads(
        (ROOT / "docs/linux-soc-v1/ebpf-collector-foundation-evidence.json").read_text()
    )


def test_current_sources_and_explicit_native_blockers():
    v = evidence()
    amendment = json.loads(
        (ROOT / "docs/linux-soc-v1/tcx-packet-data-plane-amendment.json").read_text()
    )
    assert set(amendment["historical_sources"]) == {
        "src/soc_agent/security_ai/ebpf/collector.py",
        "src/soc_agent/security_ai/ebpf/models.py",
        "src/soc_agent/security_ai/ebpf/ring.py",
        "src/soc_agent/security_ai/collectors/packet_producer.py",
    }
    successor = json.loads(
        (ROOT / "docs/linux-soc-v1/phase-d-063-rca-source-amendment.json").read_text()
    )
    assert (
        successor["previous_amendment_sha256"]
        == hashlib.sha256(
            (ROOT / "docs/linux-soc-v1/tcx-packet-data-plane-amendment.json").read_bytes()
        ).hexdigest()
    )
    assert successor["native_approval_required"] and successor["native_release"] == "BLOCKED"
    batch_path = ROOT / "docs/linux-soc-v1/native-stabilization-batch1-source-amendment.json"
    batch = json.loads(batch_path.read_text())
    assert (
        batch["previous_amendment_sha256"]
        == hashlib.sha256(
            (ROOT / "docs/linux-soc-v1/phase-d-063-rca-source-amendment.json").read_bytes()
        ).hexdigest()
    )
    assert batch["native_approval_required"] and batch["native_release"] == "BLOCKED"
    for name, expected in v["source_sha256"].items():
        record = amendment["historical_sources"].get(name)
        historical = ROOT / record["snapshot"] if record else ROOT / name
        assert hashlib.sha256(historical.read_bytes()).hexdigest() == expected
        if record:
            assert record["previous_sha256"] == expected
            current = successor["historical_source_successors"][name]
            assert current["previous_sha256"] == record["current_sha256"]
            latest = batch["historical_source_successors"][name]
            assert latest["previous_sha256"] == current["current_sha256"]
            assert (
                hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == latest["current_sha256"]
            )
    assert amendment["native_approval_required"] and amendment["native_release"] == "BLOCKED"
    assert digest(v["source_sha256"]) == v["foundation_bundle_digest"]
    assert v["build"]["source_digest"] == source_digest()
    assert v["ebpf_verifier"] == v["tc_hook_native"] == "PENDING"
    assert v["native_capture_integrity"] == "UNVERIFIED"
    assert v["native_ai"] == v["dns9"] == v["operational_gate"] == "BLOCKED"
    assert not any(
        v[k]
        for k in (
            "native_hook_attached",
            "bpf_program_loaded",
            "privileged_commands_executed",
            "test_traffic_generated",
            "model_artifacts_modified",
        )
    )
    assert v["preservation"]["errors"] == []


def test_golden_is_numeric_fixture_parity_not_native_model_receipt():
    v = evidence()
    assert len(v["golden_parity"]) == 5
    for row in v["golden_parity"].values():
        assert (
            row["scope"]
            == "HOST_C_PARSER_AND_OFFLINE_ML_FIXTURE_NOT_KERNEL_VERIFIER_OR_NATIVE_PARITY"
        )
        assert row["native_ai"] == "BLOCKED"
        assert len(row["comparisons"][0]["values"]) == 14
    assert v["model_regression"]["evidence"]["input_origin"] == "ZEEK_OFFLINE_PCAP"
    assert v["model_regression"]["scope"].endswith("NOT_EBPF_INFERENCE")
    assert all(run["exit_code"] == 0 for run in v["verified_runs"].values())
    assert v["zeek_counter_correlation"] == "UNKNOWN_NOT_SAME_CAPTURE_HANDLE"
    for shot in v["screenshots"]:
        assert hashlib.sha256((ROOT / shot["file"]).read_bytes()).hexdigest() == shot["sha256"]
