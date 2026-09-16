"""CSV inspection and explicit projection; no training, downloads or inference."""

import csv
import hashlib
import io
import math
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Literal

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.features import (
    DatasetRecordReference,
    DatasetSchema,
    FeatureSet,
    SecurityRecord,
    SourceReference,
)
from soc_agent.security_ai.features.models import Snapshot
from soc_agent.security_ai.network.schema import COLUMNS, NetworkFeatureExtractor
from soc_agent.state.evidence import NonEmptyText


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class ColumnInspection(Snapshot):
    name: str
    inferred_type: Literal["numeric", "text"]
    missing: int
    nan: int
    infinity: int
    constant: bool


class FileInspection(Snapshot):
    name: str
    sha256: str
    rows: int
    columns: tuple[ColumnInspection, ...]
    label_counts: tuple[tuple[str, int], ...]
    duplicate_rows: int
    excluded_columns: tuple[str, ...]


class DatasetInspection(Snapshot):
    files: tuple[FileInspection, ...]

    @property
    def rows(self) -> int:
        return sum(file.rows for file in self.files)


class NetworkExample(Snapshot):
    features: FeatureSet
    label: NonEmptyText
    group_id: str
    row_id: str


class PreparedDataset(Snapshot):
    dataset: DatasetSchema
    inspection: DatasetInspection
    examples: tuple[NetworkExample, ...]
    rejected_rows: tuple[str, ...] = ()
    invalid_policy: Literal["reject", "drop"] = "reject"
    grouping: str = "bidirectional_endpoints_or_flow_id_or_file"


def _read(path: Path) -> tuple[list[str], list[dict[str, str]], str]:
    try:
        content = path.read_bytes()
        with io.StringIO(content.decode("utf-8-sig"), newline="") as stream:
            reader = csv.reader(stream)
            header = [name.strip() for name in next(reader)]
            if len(set(header)) != len(header) or not all(header):
                raise ValueError("Duplicate or empty normalized columns")
            if not {"Label", *(column for column, _ in COLUMNS)} <= set(header):
                raise ValueError("Missing required CSV columns")
            rows = []
            for row in reader:
                if len(row) != len(header):
                    raise ValueError("CSV row width differs from header")
                rows.append(dict(zip(header, (value.strip() for value in row), strict=True)))
            return header, rows, hashlib.sha256(content).hexdigest()
    except (OSError, UnicodeError, csv.Error, StopIteration, ValueError):
        raise ValueError("Invalid or unreadable network CSV contract") from None


def _inspect(
    path: Path, header: list[str], rows: list[dict[str, str]], file_digest: str
) -> FileInspection:
    columns = []
    for name in header:
        missing = nan = infinity = 0
        numeric = True
        for row in rows:
            value = row[name]
            if not value:
                missing += 1
                continue
            try:
                number = float(value)
                nan += math.isnan(number)
                infinity += math.isinf(number)
            except ValueError:
                numeric = False
        columns.append(
            ColumnInspection(
                name=name,
                inferred_type="numeric" if numeric else "text",
                missing=missing,
                nan=nan,
                infinity=infinity,
                constant=len({row[name] for row in rows}) <= 1,
            )
        )
    hashes = [digest(canonical_json_object(row)) for row in rows]
    return FileInspection(
        name=path.name,
        sha256=file_digest,
        rows=len(rows),
        columns=tuple(columns),
        label_counts=tuple(sorted(Counter(row["Label"] for row in rows).items())),
        duplicate_rows=len(hashes) - len(set(hashes)),
        excluded_columns=tuple(name for name in header if name not in {c for c, _ in COLUMNS}),
    )


def _group(row: dict[str, str], filename: str) -> str:
    keys = ("Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol")
    if all(row.get(key) for key in keys):
        endpoints = sorted(
            [
                [row["Source IP"], row["Source Port"]],
                [row["Destination IP"], row["Destination Port"]],
            ]
        )
        return digest(canonical_json_object({"endpoints": endpoints, "protocol": row["Protocol"]}))
    if row.get("Flow ID"):
        return digest("flow:" + row["Flow ID"])
    return digest("file:" + filename)


class CICIDS2017Adapter:
    def __init__(self, *, dataset_name: str = "CIC-IDS2017", dataset_version: str = "1") -> None:
        self.dataset = DatasetSchema(
            dataset_name=dataset_name,
            dataset_version=dataset_version,
            record_schema_version="1.0.0",
            label_field="Label",
        )

    def inspect(self, paths: tuple[Path, ...]) -> DatasetInspection:
        return DatasetInspection(
            files=tuple(_inspect(path, *_read(path)) for path in self._paths(paths))
        )

    @staticmethod
    def _paths(paths: tuple[Path, ...]) -> tuple[Path, ...]:
        if not paths or len({path.name for path in paths}) != len(paths):
            raise ValueError("Provide CSV files with unique basenames")
        return tuple(sorted(paths))

    def load(
        self,
        paths: tuple[Path, ...],
        *,
        observed_at: datetime,
        invalid_policy: Literal["reject", "drop"] = "reject",
    ) -> PreparedDataset:
        if invalid_policy not in {"reject", "drop"}:
            raise ValueError("Unknown invalid numeric policy")
        examples, rejected, reports = [], [], []
        for path in self._paths(paths):
            header, rows, file_digest = _read(path)
            reports.append(_inspect(path, header, rows, file_digest))
            for index, row in enumerate(rows, start=2):
                row_id = f"{path.name}:{index}"
                try:
                    if not row["Label"]:
                        raise ValueError("Missing label")
                    payload = {}
                    for column, name in COLUMNS:
                        value = float(row[column])
                        if not math.isfinite(value):
                            raise ValueError("Nonfinite number")
                        if name != "duration_us":
                            if not value.is_integer():
                                raise ValueError("Nonintegral count")
                            value = int(value)
                        payload[name] = value
                    record = SecurityRecord(
                        record_type="network_flow",
                        record_schema_version="1.0.0",
                        source=path.name,
                        observed_at=observed_at,
                        source_reference=SourceReference(
                            source_type="dataset",
                            source_name=self.dataset.dataset_name,
                            source_version=self.dataset.dataset_version,
                            record_id=row_id,
                        ),
                        dataset_reference=DatasetRecordReference(
                            dataset=self.dataset, record_id=row_id
                        ),
                        fields=payload | {"Label": row["Label"]},
                    )
                    features = NetworkFeatureExtractor().extract(record)
                    examples.append(
                        NetworkExample(
                            features=features,
                            label=row["Label"],
                            row_id=row_id,
                            group_id=_group(row, path.name),
                        )
                    )
                except (ValueError, TypeError, OverflowError):
                    if invalid_policy == "reject":
                        raise ValueError(f"Invalid network CSV record at row {index}") from None
                    rejected.append(row_id)
        return PreparedDataset(
            dataset=self.dataset,
            inspection=DatasetInspection(files=tuple(reports)),
            examples=tuple(examples),
            rejected_rows=tuple(rejected),
            invalid_policy=invalid_policy,
        )
