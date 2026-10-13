"""Strict offline CSV comparison. Never attests a producer or authorizes inference."""

import argparse
import csv
import hashlib
import json
import re
from decimal import Decimal, localcontext
from io import StringIO
from pathlib import Path
from typing import Literal

import numpy as np
from pydantic import Field

from soc_agent.external_runtime import CODE_PIN, CONTRACT
from soc_agent.security_ai.external.metadata import reviewed_binding
from soc_agent.security_ai.external.models import Hash, Snapshot, Text, content_digest_payload

MAX_BYTES = 8 * 1024 * 1024
MAX_ROWS = 1024
_NUMBER = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z")


class ExportRejected(ValueError):
    """Sanitized diagnostics: no flow identity, raw CSV field or source path."""


class ExportRow(Snapshot):
    key_digest: Hash
    numbers: tuple[str, ...] = Field(min_length=40, max_length=40)


class ExportTable(Snapshot):
    csv_digest: Hash
    feature_names: tuple[Text, ...] = Field(min_length=40, max_length=40)
    key_columns: tuple[Text, ...] = Field(min_length=1, max_length=10)
    rows: tuple[ExportRow, ...] = Field(min_length=1, max_length=MAX_ROWS)


class FeatureDifference(Snapshot):
    name: Text
    absolute_error: str
    relative_error: str | None  # undefined when reference is zero and values differ
    numeric_equal: bool
    float32_equal: bool
    reference_float32_loss: bool
    candidate_float32_loss: bool


class RowComparison(Snapshot):
    key_digest: Hash
    reference_float32_matrix_digest: Hash
    candidate_float32_matrix_digest: Hash
    features: tuple[FeatureDifference, ...] = Field(min_length=40, max_length=40)


class ExportComparison(Snapshot):
    contract_version: Literal["soc-top40-export-comparison:v1"] = "soc-top40-export-comparison:v1"
    policy: Literal["EXACT_DECIMAL_EXPORTS_V1"] = "EXACT_DECIMAL_EXPORTS_V1"
    reference_csv_digest: Hash
    candidate_csv_digest: Hash
    feature_names_digest: Hash
    reference_rows: int
    candidate_rows: int
    compared_rows: int
    missing_key_digests: tuple[Hash, ...]
    extra_key_digests: tuple[Hash, ...]
    mismatched_features: tuple[Text, ...]
    row_comparisons: tuple[RowComparison, ...]
    numerical_status: Literal["PASS", "FAIL"]
    training_parity_status: Literal["INCONCLUSIVE"] = "INCONCLUSIVE"
    inference_status: Literal["NOT_INFERABLE"] = "NOT_INFERABLE"
    write_disposition: Literal["WRITE_DENIED"] = "WRITE_DENIED"
    blockers: tuple[str, ...] = (
        "TRAINING_PRODUCER_COMMIT_AND_CONFIGURATION_UNVERIFIED",
        "PCAP_TO_CSV_GOLDEN_LINK_UNVERIFIED",
        "FEATURE_UNITS_AND_CALCULATION_PARITY_UNVERIFIED",
    )


def official_names() -> tuple[str, ...]:
    return reviewed_binding(
        "detection_quality", expected_code_identity=CODE_PIN, runtime_contract_digest=CONTRACT
    ).feature_identity.ordered_names


def _number(token: str) -> Decimal:
    # No whitespace repairs, blanks, nonfinite imputation or giant exponent allocation.
    if len(token) > 128 or _NUMBER.fullmatch(token) is None:
        raise ExportRejected("INVALID_FEATURE_NUMBER")
    value = Decimal(token)
    if not value.is_finite() or value.copy_abs() > Decimal.from_float(
        float(np.finfo(np.float32).max)
    ):
        raise ExportRejected("FLOAT32_OVERFLOW_OR_NONFINITE")
    if abs(value.as_tuple().exponent) > 400:
        raise ExportRejected("DECIMAL_EXPONENT_LIMIT")
    return value


def parse_export(data: bytes, *, key_columns: tuple[str, ...]) -> ExportTable:
    """Project official names from an export, preserving exact numeric tokens and keys.

    Other bounded CSV columns are not emitted. Explicit keys must distinguish flow
    segments; matching only a reversible 5-tuple or fuzzy timestamps is not performed.
    """
    if type(data) is not bytes or not 0 < len(data) <= MAX_BYTES:
        raise ExportRejected("EXPORT_SIZE_REJECTED")
    names = official_names()
    if (
        not key_columns
        or len(key_columns) > 10
        or len(set(key_columns)) != len(key_columns)
        or any(not k or len(k) > 256 or k in names for k in key_columns)
    ):
        raise ExportRejected("EXPLICIT_UNIQUE_FLOW_KEY_REQUIRED")
    try:
        reader = csv.reader(StringIO(data.decode("utf-8"), newline=""), strict=True)
        header = next(reader)
        if len(header) > 256 or len(set(header)) != len(header):
            raise ExportRejected("DUPLICATE_OR_EXCESS_COLUMNS")
        if not set((*names, *key_columns)).issubset(header):
            raise ExportRejected("OFFICIAL_FEATURE_OR_FLOW_KEY_MISSING")
        indexes = tuple(header.index(n) for n in names)
        key_indexes = tuple(header.index(k) for k in key_columns)
        rows = []
        seen = set()
        for values in reader:
            if len(values) != len(header) or any(len(v) > 4096 for v in values):
                raise ExportRejected("MALFORMED_EXPORT_ROW")
            key = tuple(values[i] for i in key_indexes)
            if any(not k or not k.strip() for k in key):
                raise ExportRejected("EMPTY_FLOW_KEY")
            digest = content_digest_payload({"columns": list(key_columns), "values": list(key)})
            if digest in seen:
                raise ExportRejected("AMBIGUOUS_DUPLICATE_FLOW_KEY")
            seen.add(digest)
            numbers = tuple(values[i] for i in indexes)
            for n in numbers:
                _number(n)
            rows.append(ExportRow(key_digest=digest, numbers=numbers))
            if len(rows) > MAX_ROWS:
                raise ExportRejected("EXPORT_ROW_LIMIT")
        if not rows:
            raise ExportRejected("EMPTY_EXPORT")
    except (UnicodeError, csv.Error, StopIteration) as error:
        raise ExportRejected("INVALID_CSV_SERIALIZATION") from error
    return ExportTable(
        csv_digest=hashlib.sha256(data).hexdigest(),
        feature_names=names,
        key_columns=key_columns,
        rows=tuple(rows),
    )


def _difference(name: str, reference: str, candidate: str) -> FeatureDifference:
    a, b = _number(reference), _number(candidate)
    with localcontext() as context:
        context.prec = 600  # exceeds bounded token significant digits; no acceptance tolerance
        error = abs(a - b)
        relative = Decimal(0) if error == 0 else error / abs(a) if a != 0 else None
    a32, b32 = np.float32(float(a)), np.float32(float(b))
    # Numeric signed-zero equality and float32 bit equality are separate contracts.
    return FeatureDifference(
        name=name,
        absolute_error=str(error),
        relative_error=str(relative) if relative is not None else None,
        numeric_equal=a == b,
        float32_equal=a32.astype("<f4").tobytes() == b32.astype("<f4").tobytes(),
        reference_float32_loss=Decimal.from_float(float(a32)) != a,
        candidate_float32_loss=Decimal.from_float(float(b32)) != b,
    )


def _matrix_digest(row: ExportRow) -> str:
    matrix = np.array([float(_number(n)) for n in row.numbers], dtype="<f4")
    return hashlib.sha256(matrix.tobytes()).hexdigest()


def compare_exports(
    reference: bytes, candidate: bytes, *, key_columns: tuple[str, ...]
) -> ExportComparison:
    """Exact numeric comparison only; no user-controlled tolerance or verified flag."""
    ref, other = (parse_export(data, key_columns=key_columns) for data in (reference, candidate))
    left, right = ({r.key_digest: r for r in table.rows} for table in (ref, other))
    shared = sorted(left.keys() & right.keys())
    comparisons = tuple(
        RowComparison(
            key_digest=key,
            reference_float32_matrix_digest=_matrix_digest(left[key]),
            candidate_float32_matrix_digest=_matrix_digest(right[key]),
            features=tuple(
                _difference(name, a, b)
                for name, a, b in zip(
                    ref.feature_names, left[key].numbers, right[key].numbers, strict=True
                )
            ),
        )
        for key in shared
    )
    mismatches = tuple(
        name
        for i, name in enumerate(ref.feature_names)
        if any(
            not row.features[i].numeric_equal or not row.features[i].float32_equal
            for row in comparisons
        )
    )
    missing, extra = (
        tuple(sorted(left.keys() - right.keys())),
        tuple(sorted(right.keys() - left.keys())),
    )
    return ExportComparison(
        reference_csv_digest=ref.csv_digest,
        candidate_csv_digest=other.csv_digest,
        feature_names_digest=hashlib.sha256("\n".join(ref.feature_names).encode()).hexdigest(),
        reference_rows=len(left),
        candidate_rows=len(right),
        compared_rows=len(shared),
        missing_key_digests=missing,
        extra_key_digests=extra,
        mismatched_features=mismatches,
        row_comparisons=comparisons,
        numerical_status="FAIL" if missing or extra or mismatches else "PASS",
    )


def _read_bounded(path: Path, expected_digest: str) -> bytes:
    if re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
        raise ExportRejected("INVALID_EXPECTED_DIGEST")
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ExportRejected("EXPORT_SIZE_REJECTED")
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ExportRejected("SOURCE_FILE_DIGEST_MISMATCH")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--reference-sha256", required=True)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--key", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = compare_exports(
            _read_bounded(args.reference, args.reference_sha256),
            _read_bounded(args.candidate, args.candidate_sha256),
            key_columns=tuple(args.key),
        )
        # Exclusive creation: never replaces a prior report or source file.
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result.model_dump(mode="json"), stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except (ExportRejected, OSError):
        parser.exit(2, "EXPORT_COMPARISON_REJECTED\n")
    # Even exact numeric agreement cannot produce an operational success exit code.
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
