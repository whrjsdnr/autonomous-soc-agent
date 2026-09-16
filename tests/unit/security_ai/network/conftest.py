import csv
from datetime import UTC, datetime
from pathlib import Path

import pytest

from soc_agent.security_ai.network.dataset import CICIDS2017Adapter, PreparedDataset
from soc_agent.security_ai.network.schema import COLUMNS


@pytest.fixture
def csv_path(tmp_path: Path) -> Path:
    path = tmp_path / "synthetic.csv"
    with path.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [" " + column for column, _ in COLUMNS] + [" Label", "Flow ID", "Timestamp", "Target"]
        )
        for class_index, label in enumerate(("BENIGN", "DoS", "PortScan", "BruteForce")):
            for i in range(30):
                base = (class_index + 1) * 1000
                writer.writerow(
                    [
                        base + i,
                        base + i + 10,
                        base + i + 20,
                        base * 10 + i,
                        base * 20 + i,
                        label,
                        f"flow-{class_index}-{i}",
                        "IDENTIFIER_TIME",
                        label,
                    ]
                )
    return path


@pytest.fixture
def dataset(csv_path: Path) -> PreparedDataset:
    return CICIDS2017Adapter(dataset_name="synthetic-network-fixture").load(
        (csv_path,), observed_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
