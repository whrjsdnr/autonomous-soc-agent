"""Reproducible synthetic-only experiment. Candidate sets and generators are fixed in code."""

import argparse
import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from soc_agent.security_ai.anomaly_common import AnomalyTrainingConfig
from soc_agent.security_ai.authentication import train_authentication
from soc_agent.security_ai.evaluation import (
    EvaluationRow,
    Partition,
    calibration_partition,
    evaluate_test,
    partitions,
    select_anomaly,
    select_classifier,
)
from soc_agent.security_ai.evaluation.experiments import score_diagnostics
from soc_agent.security_ai.network.anomaly_training import train_anomaly
from soc_agent.security_ai.network.dataset import CICIDS2017Adapter
from soc_agent.security_ai.network.schema import COLUMNS
from soc_agent.security_ai.network.training import TrainingConfig, train
from tests.authentication_support import fixture_examples
from tests.evaluation_support import auth_rows, holdout, network_rows


def previously_observed(directory: Path) -> dict:
    path = directory / "previously-observed.csv"
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([c for c, _ in COLUMNS] + ["Label", "Flow ID"])
        for index, label in enumerate(("BENIGN", "DoS", "PortScan", "BruteForce")):
            for sample in range(30):
                n = (index + 1) * 1000 + sample
                writer.writerow([n, n + 10, n + 20, n * 10, n * 20, label, f"{index}-{sample}"])
    dataset = CICIDS2017Adapter(dataset_name="previously-observed-synthetic").load(
        (path,), observed_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    anomaly = train_anomaly(dataset, config=AnomalyTrainingConfig(n_estimators=16))
    classifier = train(dataset, config=TrainingConfig(n_estimators=5, max_depth=2))
    auth = train_authentication(fixture_examples(), config=AnomalyTrainingConfig(n_estimators=16))

    def diagnostic(indices, role):
        rows = tuple(
            EvaluationRow(
                features=dataset.examples[i].features,
                label=dataset.examples[i].label,
                group_id=dataset.examples[i].group_id,
                row_id=dataset.examples[i].row_id,
            )
            for i in indices
        )
        part = Partition(
            role=role, rows=rows, dataset_name="previously-observed", dataset_version="1"
        )
        pred = tuple(anomaly.detector.predict(r.features) for r in rows)
        return [
            d.model_dump(mode="json")
            for d in score_diagnostics(
                part,
                tuple(p.raw_anomaly_measure for p in pred),
                tuple(p.anomaly_score for p in pred),
            )
        ]

    return {
        "purpose": "diagnosis/regression only; previously observed test, NOT blind",
        "classifier": classifier.metadata.test.model_dump(mode="json"),
        "network_anomaly": anomaly.metadata.test.model_dump(mode="json"),
        "authentication": auth.metadata.test.model_dump(mode="json"),
        "network_validation_diagnostics": diagnostic(
            anomaly.metadata.split.validation, "selection"
        ),
        "network_observed_test_diagnostics": diagnostic(anomaly.metadata.split.test, "test"),
    }


def run_experiment(directory: Path) -> dict:
    rows, dataset = network_rows(directory / "development.csv")
    train_part, val, reserved, _ = partitions(
        rows, dataset_name="synthetic-network-development", dataset_version="1"
    )
    select, cal = calibration_partition(val)
    # Freeze ALL selections before constructing independent holdout records or reading labels.
    network = select_anomaly(train_part, val, domain="network")
    classifier = select_classifier(train_part, select, calibration=cal)
    auth_train, auth_val, auth_reserved, _ = partitions(
        auth_rows(), dataset_name="synthetic-auth-development", dataset_version="1"
    )
    authentication = select_anomaly(auth_train, auth_val, domain="authentication")
    frozen_digests = [m.freeze_digest for m in (network, classifier, authentication)]
    network_test_rows, _ = network_rows(
        directory / "independent-holdout.csv", seed=3591, count=40, namespace="holdout"
    )
    network_test = holdout(network_test_rows, "synthetic-network-independent-holdout")
    auth_test = holdout(
        auth_rows(count=20, namespace="holdout", seed=3592), "synthetic-auth-independent-holdout"
    )
    output = {}
    for name, frozen, test in (
        ("network_anomaly", network, network_test),
        ("network_classifier", classifier, network_test),
        ("authentication_anomaly", authentication, auth_test),
    ):
        report = evaluate_test(frozen, test)
        output[name] = {
            "selection": frozen.report.model_dump(mode="json"),
            "final_test": report.model_dump(mode="json"),
        }
    assert frozen_digests == [m.freeze_digest for m in (network, classifier, authentication)]
    return {
        "data_status": "SYNTHETIC ONLY; real security generalization NOT MEASURED",
        "generator_version": "1",
        "development_seeds": [3501, 3502],
        "independent_holdout_seeds": [3591, 3592],
        "selection_order": "all candidates frozen before holdout generation; no post-test retuning",
        "reserved_outer_test_rows_not_used": [len(reserved.rows), len(auth_reserved.rows)],
        "network_ingestion_audit": dataset.inspection.model_dump(mode="json"),
        "experiments": output,
        "previously_observed": previously_observed(directory),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="soc-evaluation-") as directory:
        report = run_experiment(Path(directory))
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Synthetic evaluation report: {args.output}")


if __name__ == "__main__":
    main()
