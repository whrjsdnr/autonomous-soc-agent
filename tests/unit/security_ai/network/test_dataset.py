import csv
from datetime import UTC, datetime
from pathlib import Path

import pytest

from soc_agent.security_ai.features import SecurityRecord, SourceReference
from soc_agent.security_ai.network.dataset import CICIDS2017Adapter, PreparedDataset
from soc_agent.security_ai.network.schema import NetworkFeatureExtractor, network_feature_schema

WHEN = datetime(2026, 1, 1, tzinfo=UTC)


def test_inspection_and_projection(csv_path: Path, dataset: PreparedDataset) -> None:
    report = CICIDS2017Adapter().inspect((csv_path,))
    assert report.rows == 120
    assert dict(report.files[0].label_counts) == {
        "BENIGN": 30,
        "BruteForce": 30,
        "DoS": 30,
        "PortScan": 30,
    }
    assert report.files[0].duplicate_rows == 0
    assert set(report.files[0].excluded_columns) == {"Label", "Flow ID", "Timestamp", "Target"}
    assert next(c for c in report.files[0].columns if c.name == "Timestamp").constant
    example = dataset.examples[0]
    assert example.features.feature_schema == network_feature_schema()
    assert example.features.feature_names == (
        "duration_us",
        "fwd_packets",
        "bwd_packets",
        "fwd_bytes",
        "bwd_bytes",
    )
    assert "Label" not in example.features.values and "Target" not in example.features.values
    source = example.features.provenance.sources[0]
    assert source.source_reference.source_name == "synthetic-network-fixture"
    assert source.source_reference.record_id == "synthetic.csv:2"
    assert source.dataset_reference.dataset.label_field == "Label"


@pytest.mark.parametrize("value", ["", "NaN", "Infinity", "-Infinity", "many", "-1"])
def test_invalid_numeric_policy(csv_path: Path, value: str) -> None:
    with csv_path.open() as stream:
        rows = list(csv.reader(stream))
    rows[1][0] = value
    with csv_path.open("w", newline="") as stream:
        csv.writer(stream).writerows(rows)
    adapter = CICIDS2017Adapter(dataset_name="fixture")
    with pytest.raises(ValueError, match="row 2"):
        adapter.load((csv_path,), observed_at=WHEN)
    prepared = adapter.load((csv_path,), observed_at=WHEN, invalid_policy="drop")
    assert len(prepared.examples) == 119
    assert prepared.rejected_rows == ("synthetic.csv:2",)
    column = prepared.inspection.files[0].columns[0]
    assert column.missing == int(value == "")
    assert column.nan == int(value == "NaN")
    assert column.infinity == int(value in {"Infinity", "-Infinity"})


@pytest.mark.parametrize("kind", ["label", "duplicate", "width", "empty_label"])
def test_bad_csv_contract(csv_path: Path, kind: str) -> None:
    with csv_path.open() as stream:
        rows = list(csv.reader(stream))
    if kind == "label":
        rows[0][5] = "MissingLabel"
    elif kind == "duplicate":
        rows[0][-1] = "Flow Duration"
    elif kind == "width":
        rows[1].pop()
    else:
        rows[1][5] = ""
    with csv_path.open("w", newline="") as stream:
        csv.writer(stream).writerows(rows)
    with pytest.raises(ValueError):
        CICIDS2017Adapter().load((csv_path,), observed_at=WHEN)


def test_duplicate_inspection(csv_path: Path) -> None:
    with csv_path.open() as stream:
        rows = list(csv.reader(stream))
    with csv_path.open("a", newline="") as stream:
        csv.writer(stream).writerow(rows[1])
    report = CICIDS2017Adapter().inspect((csv_path,))
    assert report.files[0].duplicate_rows == 1


def test_dataset_stream_bridge(dataset: PreparedDataset) -> None:
    first = dataset.examples[0].features
    record = SecurityRecord(
        record_type="network_flow",
        record_schema_version="1.0.0",
        source="userspace_fixture",
        observed_at=WHEN,
        fields=first.input_payload(),
        source_reference=SourceReference(
            source_type="stream",
            source_name="network_flow_events",
            source_version="1",
            record_id="event-42",
        ),
    )
    other = NetworkFeatureExtractor().extract(record)
    assert first.input_fingerprint == other.input_fingerprint
    assert first.provenance != other.provenance


def test_no_dataset_and_unknown_policy(tmp_path: Path) -> None:
    adapter = CICIDS2017Adapter()
    with pytest.raises(ValueError):
        adapter.inspect(())
    with pytest.raises(ValueError):
        adapter.load((), observed_at=WHEN, invalid_policy="guess")


def test_grouping_direction_and_file_fallback() -> None:
    from soc_agent.security_ai.network.dataset import _group

    first = {
        "Source IP": "192.0.2.1",
        "Source Port": "80",
        "Destination IP": "192.0.2.2",
        "Destination Port": "5000",
        "Protocol": "6",
    }
    second = {
        "Source IP": "192.0.2.2",
        "Source Port": "5000",
        "Destination IP": "192.0.2.1",
        "Destination Port": "80",
        "Protocol": "6",
    }
    assert _group(first, "a.csv") == _group(second, "b.csv")
    assert _group({}, "a.csv") != _group({}, "b.csv")


def test_dataset_digest_uses_actual_file_bytes(csv_path: Path) -> None:
    import hashlib

    adapter = CICIDS2017Adapter()
    first = adapter.inspect((csv_path,)).files[0].sha256
    assert first == hashlib.sha256(csv_path.read_bytes()).hexdigest()
    assert first == adapter.inspect((csv_path,)).files[0].sha256
    # Whitespace normalization leaves semantics unchanged but exact source bytes differ.
    original = csv_path.read_bytes()
    csv_path.write_bytes(original.replace(b"Flow Duration", b"Flow Duration ", 1))
    second = adapter.inspect((csv_path,)).files[0].sha256
    assert second != first
    assert second == hashlib.sha256(csv_path.read_bytes()).hexdigest()
