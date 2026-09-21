"""Rebuild the exact Phase 3-5 selections without consulting holdout scores."""

import json
from pathlib import Path

from soc_agent.security_ai.evaluation import (
    calibration_partition,
    partitions,
    select_anomaly,
    select_classifier,
)
from tests.evaluation_support import auth_rows, network_rows


def selected_models(directory: Path):
    rows, _ = network_rows(directory / "development.csv")
    train, val, _, _ = partitions(
        rows, dataset_name="synthetic-network-development", dataset_version="1"
    )
    select, cal = calibration_partition(val)
    network = select_anomaly(train, val, domain="network")
    classifier = select_classifier(train, select, calibration=cal)
    auth = auth_rows()
    train, val, _, _ = partitions(
        auth, dataset_name="synthetic-auth-development", dataset_version="1"
    )
    authentication = select_anomaly(train, val, domain="authentication")
    result = {
        "network_classifier": (classifier, rows),
        "network_anomaly": (network, rows),
        "authentication_anomaly": (authentication, auth),
    }
    report = json.loads(
        (Path(__file__).parents[1] / "docs/evaluation/synthetic-phase3-5.json").read_text()
    )
    for name, (selection, _) in result.items():
        assert (
            selection.freeze_digest == report["experiments"][name]["final_test"]["selection_digest"]
        )
    return result
