import hashlib
import json
import struct
from pathlib import Path

DOCS = Path(__file__).resolve().parents[3] / "docs/linux-soc-v1"


def test_actual_engine_and_model_evidence_not_native_or_dns9_promotion():
    doc = json.loads((DOCS / "zeek-network14-dns9-evidence.json").read_text())
    assert doc["verdict"] == "PARTIAL"
    assert not doc["native_capture_executed"] and not doc["privileged_commands_executed"]
    assert not doc["test_network_traffic_generated"]
    assert len(doc["golden_runs"]) == 5
    assert doc["dns9"]["status"] == "BLOCKED" and doc["dns9"]["feature_values"] is None
    assert doc["summary_only_baseline"]["inference_count"] == 0
    records = doc["zeek_research_records"]
    assert len(records) == 2
    assert {r["profile"] for r in records} == {"quality", "edge"}
    for row in records:
        receipt = row["receipt"]
        assert (
            receipt["origin"] == "ZEEK_OFFLINE_PCAP"
            and receipt["producer_origin"] == "OFFLINE_PCAP"
        )
        assert (
            receipt["status"] == "RESEARCH_ONLY" and receipt["operational_inference"] == "BLOCKED"
        )
        assert receipt["script_sha256"] == doc["script_sha256"]
        assert receipt["capture_session"] == doc["zeek_model_run"]["session_id"]
        assert row["investigation"]["status"] == "ASSESSED_READ_ONLY"
        assert row["investigation"]["checkpoint_restored"]
        assert row["investigation"]["provider_calls"] == 0
        assert row["investigation"]["action_policy"] == "WRITE_DENIED"
        encoded = json.dumps(
            receipt, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        assert hashlib.sha256(encoded).hexdigest() == row["receipt_digest"]
    assert doc["zeek_model_run"]["recovered_new_inferences"] == 0
    assert (
        doc["zeek_model_run"]["process_cleanup"] and doc["zeek_model_run"]["model_worker_stopped"]
    )
    assert not doc["preservation"]["errors"]


def test_gui_source_and_public_screenshot_hashes():
    doc = json.loads((DOCS / "zeek-network14-dns9-evidence.json").read_text())
    assert len(doc["screenshots"]) == 8
    for record in doc["screenshots"]:
        p = DOCS / record["filename"]
        assert p.parent == DOCS / "zeek-network14-screenshots"
        data = p.read_bytes()
        assert hashlib.sha256(data).hexdigest() == record["sha256"]
        assert data[:8] == b"\x89PNG\r\n\x1a\n"
        assert struct.unpack("!II", data[16:24]) in {(1920, 1080), (1366, 768)}
        assert record["source_origin"] == "ZEEK_OFFLINE_PCAP" and not record["native_capture"]
    assert doc["gui_run"]["separate_run_from_model_receipts"]
    assert doc["gui_run"]["collector_metrics"]["inference_count"] == 2
    assert doc["gui_run"]["producer"]["inference_queue"]["depth"] == 0
