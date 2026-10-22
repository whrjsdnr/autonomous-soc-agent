"""Published evidence binds current code without upgrading fixture proof to Native."""

import hashlib
import json
from pathlib import Path

from soc_agent.security_ai.collectors.live_contract import bundle
from soc_agent.security_ai.research.models import digest, parse_receipt

ROOT = Path(__file__).resolve().parents[3]


def evidence():
    return json.loads(
        (
            ROOT / "docs/linux-soc-v1/zeek-native-attestation-dns-visibility-evidence.json"
        ).read_text()
    )


def test_current_bundle_and_native_boundaries():
    v = evidence()
    # Historical proof remains immutable; admit only the reviewed B-1 Launcher delta.
    amendment = json.loads(
        (ROOT / ("docs/linux-soc-v1/ebpf-privileged-broker-tc-ownership-evidence.json")).read_text()
    )["zeek_launcher_update"]
    assert amendment["previous_bundle"] == v["bundle"]
    assert amendment["previous_bundle_digest"] == v["bundle_digest"]
    c1 = json.loads((ROOT / "docs/linux-soc-v1/tcx-packet-data-plane-amendment.json").read_text())
    assert amendment["current_bundle"] == c1["previous_zeek_bundle"]
    assert amendment["current_bundle_digest"] == c1["previous_zeek_bundle_digest"]
    historical = c1["current_zeek_bundle"]
    assert c1["current_zeek_bundle_digest"] == digest(historical)
    assert {k for k in historical if historical[k] != v["bundle"][k]} == {
        "live_process.py",
        "packet_producer.py",
    }
    assert c1["zeek_changed_files"] == ["packet_producer.py"]
    assert c1["native_approval_required"] is True
    assert amendment["changed_files"] == ["live_process.py"]
    assert amendment["native_approval_required"] is True
    successor = json.loads(
        (ROOT / "docs/linux-soc-v1/phase-d-063-rca-source-amendment.json").read_text()
    )
    assert (
        successor["previous_amendment_sha256"]
        == hashlib.sha256(
            (ROOT / "docs/linux-soc-v1/tcx-packet-data-plane-amendment.json").read_bytes()
        ).hexdigest()
    )
    assert successor["previous_zeek_bundle"] == historical
    assert successor["current_zeek_bundle"] == bundle()
    assert successor["current_zeek_bundle_digest"] == digest(bundle())
    assert successor["zeek_changed_sources"] == sorted(
        k for k in set(bundle()) | set(historical) if bundle().get(k) != historical.get(k)
    )
    assert successor["native_approval_required"] and successor["native_release"] == "BLOCKED"
    for name, sha in v["source_sha256"].items():
        if name == "src/soc_agent/gui/operator_view.py":
            # Immutable f020f71 presentation evidence; later views may add collectors.
            assert sha == "eb208b3276762b64bdcfd0775ae85ca184917a29314ec9debf00ffb2d722d87e"
            continue
        # Old Native evidence records its old source bundle, not current code.
        # The immutable successor amendment separately pins every current file.
        key = Path(name).name
        assert sha == v["bundle"][key]
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == bundle()[key]
    assert v["verdict"] == "PARTIAL"
    assert v["same_handle_native_proof"] == "BLOCKED_NO_REVIEWED_NATIVE_PROVIDER"
    assert v["native_counter_retrieval"] == "UNKNOWN"
    assert v["native_ai"] == v["dns9"] == v["operational_gate"] == "BLOCKED"
    assert not any(
        v[k]
        for k in (
            "native_capture_executed",
            "privileged_commands_executed",
            "test_traffic_generated",
            "model_artifacts_modified",
        )
    )
    assert v["preservation"]["errors"] == []


def test_offline_proof_does_not_attest_historical_capture():
    v = evidence()
    probe = v["offline_counter_probe"]
    assert probe["retrieval"] == "UNSUPPORTED" and probe["dropped"] is None
    assert probe["scope"] == "OWNED_OFFLINE_HANDLE_NOT_ZEEK_NATIVE_HANDLE"
    n = v["native_projection"]
    assert n["eligible_windows"] == 0 and n["port53_metadata"] == 68
    assert n["progress"]["finalization_reasons"] == {"PACKET_LIMIT": 51}
    assert v["dns_historical_cause"] == "DNS_VISIBILITY_UNKNOWN"
    m = v["offline_models"]
    assert m["stream_plan"]["bundle_digest"] == v["bundle_digest"]
    assert m["audit_digest"] == m["recovered_audit_digest"]
    assert m["queue_final"] == m["inference_queue_final"] == m["restored_new_inferences"] == 0
    for row in m["records"]:
        receipt = parse_receipt(row["receipt"])
        assert receipt.origin == "ZEEK_OFFLINE_PCAP" and receipt.write_policy == "WRITE_DENIED"
        assert row["investigation"]["status"] == "ASSESSED_READ_ONLY"
    assert all(run["exit_code"] == 0 for run in v["verified_runs"].values())
    for shot in v["screenshots"]:
        assert hashlib.sha256((ROOT / shot["file"]).read_bytes()).hexdigest() == shot["sha256"]
