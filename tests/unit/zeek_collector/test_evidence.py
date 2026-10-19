"""Public offline/GUI evidence must not claim parity or Native capture."""

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DOCS = ROOT / "docs/linux-soc-v1"


def test_public_evidence_offline_origin_and_blocked_model_gates():
    evidence = json.loads((DOCS / "zeek-collector-evidence.json").read_text())
    assert evidence["native_capture_executed"] is False
    assert evidence["privilege_command_executed"] is False
    actual = evidence["actual_offline"]
    snapshot = actual["snapshot"]
    assert snapshot["input_origin"] == "ZEEK_OFFLINE_PCAP" and not snapshot["collection_live"]
    assert actual["container_removed"] and actual["recovered_new_rows"] == 0
    assert snapshot["collector"]["metrics"]["network_events"] == 2
    assert snapshot["collector"]["metrics"]["dns_events"] == 1
    assert snapshot["research"]["records"] == []
    assert snapshot["collector"]["metrics"]["inference_count"] == 0
    assert snapshot["collector"]["parity"]["network14"] == "BLOCKED"
    assert snapshot["collector"]["parity"]["dns9"] == "BLOCKED"
    assert snapshot["runtime_audit_integrity"] == "VERIFIED"
    assert snapshot["write_policy"] == "WRITE_DENIED"
    assert evidence["verdict"] == "PARTIAL"


def test_public_wslg_screenshot_digests_resolution_and_origin():
    evidence = json.loads((DOCS / "zeek-collector-evidence.json").read_text())
    assert len(evidence["screenshots"]) == 12
    counts = {"ZEEK_OFFLINE_PCAP": 0, "SYNTHETIC_ZEEK_JSON": 0}
    for record in evidence["screenshots"]:
        path = DOCS / record["filename"]
        assert path.parent == DOCS / "zeek-collector-screenshots"
        body = path.read_bytes()
        assert body[:8] == b"\x89PNG\r\n\x1a\n"
        assert struct.unpack("!II", body[16:24]) in {(1920, 1080), (1366, 768)}
        assert hashlib.sha256(body).hexdigest() == record["sha256"]
        assert record["actual_wslg"] and not record["native_capture"]
        counts[record["origin"]] += 1
    assert counts == {"ZEEK_OFFLINE_PCAP": 4, "SYNTHETIC_ZEEK_JSON": 8}
