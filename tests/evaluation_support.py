"""Versioned synthetic generators, fixed before test evaluation; never real SOC data."""

import csv
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np

from soc_agent.security_ai.authentication import (
    AuthenticationEvent,
    AuthenticationWindowExtractor,
    authentication_record,
)
from soc_agent.security_ai.evaluation import EvaluationRow, Partition
from soc_agent.security_ai.features import SourceReference
from soc_agent.security_ai.network.dataset import CICIDS2017Adapter
from soc_agent.security_ai.network.schema import COLUMNS


def network_rows(path: Path, *, seed: int = 3501, count: int = 100, namespace: str = "development"):
    rng = np.random.default_rng(seed)
    means = (
        (1e6, 30, 25, 3000, 2500),
        (5e5, 100, 10, 5000, 500),
        (1e5, 300, 3, 20000, 120),
        (2e5, 80, 2, 1500, 40),
    )
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([c for c, _ in COLUMNS] + ["Label", "Flow ID"])
        for label, mean in zip(("BENIGN", "BruteForce", "DoS", "PortScan"), means, strict=True):
            for i in range(count):
                v = np.asarray(mean) * rng.lognormal(0, 0.65, 5)
                writer.writerow(
                    [
                        float(v[0]),
                        *(max(0, int(x)) for x in v[1:]),
                        label,
                        f"{namespace}-{label}-{i}",
                    ]
                )
    dataset = CICIDS2017Adapter(dataset_name=f"synthetic-evaluation-{namespace}").load(
        (path,), observed_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    return tuple(
        EvaluationRow(features=e.features, label=e.label, group_id=e.group_id, row_id=e.row_id)
        for e in dataset.examples
    ), dataset


def auth_rows(*, count: int = 50, namespace: str = "development", seed: int = 3502):
    rng = np.random.default_rng(seed)
    records = []
    labels = {}
    seen = set()
    # Distinct finite windows, with overlapping class behavior; never change rules after test.
    for account in range(count):
        for window, label in enumerate(("normal", "anomalous")):
            while True:
                failed = int(rng.integers(0, 8) if label == "normal" else rng.integers(8, 55))
                success = int(rng.integers(5, 90) if label == "normal" else rng.integers(1, 25))
                success = 2 * success + int(namespace == "holdout")
                if (failed, success) not in seen:
                    break
            seen.add((failed, success))
            name = f"{namespace}-account-{account}"
            labels[(name, window * 5)] = label
            for j in range(failed + success):
                event = AuthenticationEvent(
                    event_id=f"{name}-{window}-{j}",
                    account_id=name,
                    event_time=datetime(2026, 1, 1, tzinfo=UTC)
                    + timedelta(seconds=window * 300 + j),
                    authentication_result="failure" if j < failed else "success",
                    source_identifier="fixture-source",
                )
                records.append(
                    authentication_record(
                        event,
                        source=SourceReference(
                            source_type="dataset",
                            source_name=f"synthetic-auth-evaluation-{namespace}",
                            source_version="1",
                            record_id=event.event_id,
                        ),
                    )
                )
    windows = AuthenticationWindowExtractor().extract(tuple(records))
    return tuple(
        EvaluationRow(
            features=w.features,
            label=labels[(w.account_id, w.started_at.minute)],
            group_id=w.account_id,
            row_id=f"{w.account_id}:{w.started_at.isoformat()}",
            event_ids=w.event_ids,
        )
        for w in windows
    )


def holdout(rows, name):
    return Partition(role="test", rows=rows, dataset_name=name, dataset_version="1")
