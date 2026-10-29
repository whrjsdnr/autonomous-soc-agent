import json

import pytest

from soc_agent.security_ai.dns9_contract import TrainingExtractionReview, inspect_training


def test_contract_retains_nine_ordered_features_and_never_grants_inference():
    report = inspect_training()
    assert len(report["feature_names"]) == 9
    assert report["feature_names"][0] == "FQDN_count"
    assert report["status"] == "INCOMPLETE"
    assert report["operational_inference"] == "BLOCKED"
    assert report["model_action_granted"] is False
    assert "INDEPENDENT_RAW_DNS_TO_NINE_FEATURE_GOLDEN_PAIRS" in report["missing"]


def test_changed_training_source_is_rejected(tmp_path):
    from pathlib import Path

    from soc_agent.security_ai import dns9_contract

    body = json.loads(
        Path(dns9_contract.__file__).with_name("dns9_training_contract.json").read_text()
    )
    for name in body["source_files"]:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("changed")
    with pytest.raises(ValueError, match="SOURCE_CHANGED"):
        inspect_training(tmp_path)
    body["status"] = "ELIGIBLE"
    with pytest.raises(ValueError):
        TrainingExtractionReview.model_validate(body)
