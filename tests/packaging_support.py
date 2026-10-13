"""Separate native development selections from exact historical-release reproduction."""

import json
from pathlib import Path

from soc_agent.security_ai.evaluation import (
    calibration_partition,
    partitions,
    select_anomaly,
    select_classifier,
)
from tests.evaluation_support import auth_rows, network_rows


def development_models(directory: Path, *, probability_transform="native"):
    rows, _ = network_rows(directory / "development.csv")
    train, val, _, _ = partitions(
        rows, dataset_name="synthetic-network-development", dataset_version="1"
    )
    select, cal = calibration_partition(val)
    network = select_anomaly(train, val, domain="network")
    classifier = select_classifier(
        train, select, calibration=cal, probability_transform=probability_transform
    )
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
    return result


def selected_models(directory: Path):
    """Release reproduction remains exact, including recorded runtime/library versions."""
    result = development_models(directory)
    report = json.loads(
        (Path(__file__).parents[1] / "docs/evaluation/synthetic-phase3-5.json").read_text(
            encoding="utf-8"
        )
    )
    for name, (selection, _) in result.items():
        assert (
            selection.freeze_digest == report["experiments"][name]["final_test"]["selection_digest"]
        )
    return result
