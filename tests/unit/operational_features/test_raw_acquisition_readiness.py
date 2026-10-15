"""Download-ready public listings cannot grant runtime model authority."""

import hashlib
import json
from pathlib import Path

import pytest

from soc_agent.security_ai.operational.network_capture.models import model_gates

CATALOG = Path(__file__).resolve().parents[3] / "docs/linux-soc-v1/raw-dataset-manifests.json"


def test_catalog_and_pending_manifests_are_integrity_bound():
    document = json.loads(CATALOG.read_text())
    for item in [document, *document["manifests"]]:
        field = "catalog_digest" if item is document else "manifest_digest"
        content = {k: v for k, v in item.items() if k != field}
        expected = hashlib.sha256(
            json.dumps(content, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        assert item[field] == expected
    assert len(document["fallback_shortlist"]) == 3


def test_remote_metadata_is_not_acquired_raw_or_training_permission():
    document = json.loads(CATALOG.read_text())
    assert document["new_raw_downloads"] == document["new_training_runs"] == 0
    for entry in document["manifests"]:
        assert entry["admission"] == "NOT_ADMITTED" and entry["readiness"] == "BLOCKED"
        assert entry["raw_sha256"] == entry["label_sha256"] == entry["sample_count"] == "UNKNOWN"
        assert entry["actual_training_authority"] == "NONE"
        assert entry["write_disposition"] == "WRITE_DENIED"


@pytest.mark.parametrize("model", ["network-quality", "network-edge", "dns"])
def test_acquisition_ready_does_not_unlock_independent_runtime_gate(model):
    gate = model_gates()[model]
    assert gate["operational_input"] == "NOT_INFERABLE"
    assert gate["inference"] == gate["finding_promotion"] == "BLOCKED"


def test_network_offline_origin_requires_reviewed_new_producer_version():
    document = json.loads(CATALOG.read_text())
    assert document["producer_change"] == "NOT_AUTHORIZED_NOT_PERFORMED"
    assert "1.1.0 proposal only" in document["proposed_network_version"]
    for entry in document["manifests"]:
        assert entry["producer_version"] == "1.0.0"
