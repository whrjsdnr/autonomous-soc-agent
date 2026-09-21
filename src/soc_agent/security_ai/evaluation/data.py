"""Validated evaluation partitions, privacy-conscious audit, and leakage rejection."""

import hashlib
from collections import Counter
from typing import Literal, Self

from pydantic import Field, model_validator
from sklearn.model_selection import GroupShuffleSplit

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.features import FeatureSet
from soc_agent.security_ai.features.models import Snapshot
from soc_agent.security_ai.splitting import SplitMetadata, split_examples

Role = Literal["train", "selection", "calibration", "test"]


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json_object({"value": value}).encode()).hexdigest()


class EvaluationRow(Snapshot):
    features: FeatureSet
    label: str = Field(min_length=1)
    group_id: str = Field(min_length=1)
    row_id: str = Field(min_length=1)
    event_ids: tuple[str, ...] = ()


class Partition(Snapshot):
    role: Role
    rows: tuple[EvaluationRow, ...] = Field(min_length=1)
    dataset_name: str = Field(min_length=1)
    dataset_version: str = Field(min_length=1)
    split_strategy: str = "caller-supplied independent partition"
    split_seed: int | None = None

    @model_validator(mode="after")
    def validate_rows(self) -> Self:
        if len({r.row_id for r in self.rows}) != len(self.rows):
            raise ValueError("Duplicate evaluation row identities")
        if (
            len(
                {
                    (
                        r.features.feature_schema.model_dump_json(),
                        r.features.provenance.extractor_name,
                        r.features.provenance.extractor_version,
                    )
                    for r in self.rows
                }
            )
            != 1
        ):
            raise ValueError("Mixed feature contracts")
        events = [e for r in self.rows for e in r.event_ids]
        if len(events) != len(set(events)):
            raise ValueError("Duplicate source events")
        return self

    @property
    def content_digest(self) -> str:
        # Stable across newly allocated feature IDs/timestamps; source identity remains bound.
        return digest(
            [
                {
                    "row": r.row_id,
                    "group": r.group_id,
                    "label": r.label,
                    "fingerprint": r.features.input_fingerprint,
                    "events": list(r.event_ids),
                    "sources": [
                        s.model_dump(mode="json", exclude={"record_id"})
                        for s in r.features.provenance.sources
                    ],
                }
                for r in self.rows
            ]
        )


def checked(partition: Partition, role: Role) -> Partition:
    partition = Partition.model_validate(partition.model_dump())
    if partition.role != role:
        raise ValueError(f"Expected {role} partition; test data cannot select configurations")
    return partition


def identities(partition: Partition) -> dict[str, set[str]]:
    return {
        "groups": {digest(r.group_id) for r in partition.rows},
        "inputs": {r.features.input_fingerprint for r in partition.rows},
        "events": {digest(e) for r in partition.rows for e in r.event_ids},
        "sources": {
            digest(s.source_reference.model_dump(mode="json"))
            for r in partition.rows
            for s in r.features.provenance.sources
        },
    }


def require_disjoint(*partitions: Partition) -> None:
    ids = [identities(p) for p in partitions]
    for i, left in enumerate(ids):
        for right in ids[i + 1 :]:
            if any(left[k] & right[k] for k in left):
                raise ValueError("Group, input, event or source leakage across partitions")


class PartitionAudit(Snapshot):
    split_strategy: str
    split_seed: int | None
    role: Role
    dataset_name: str
    dataset_version: str
    digest: str
    rows: int
    groups: int
    class_counts: tuple[tuple[str, int], ...]
    class_group_counts: tuple[tuple[str, int], ...]
    normal_rows: int
    missing_values: int
    nonfinite_values: int
    duplicate_input_rows: int
    duplicate_inputs_across_groups: int
    group_digests: tuple[str, ...]
    group_class_counts: tuple[tuple[str, tuple[tuple[str, int], ...]], ...]
    feature_schema: str
    extractor: str


def audit(partition: Partition, normal_label: str) -> PartitionAudit:
    import math

    partition = Partition.model_validate(partition.model_dump())
    rows = partition.rows
    fps = Counter(r.features.input_fingerprint for r in rows)
    groups: dict[str, set[str]] = {}
    for r in rows:
        groups.setdefault(r.features.input_fingerprint, set()).add(r.group_id)
    feature = rows[0].features
    return PartitionAudit(
        split_strategy=partition.split_strategy,
        split_seed=partition.split_seed,
        role=partition.role,
        dataset_name=partition.dataset_name,
        dataset_version=partition.dataset_version,
        digest=partition.content_digest,
        rows=len(rows),
        groups=len({r.group_id for r in rows}),
        class_counts=tuple(sorted(Counter(r.label for r in rows).items())),
        class_group_counts=tuple(
            (label, len({r.group_id for r in rows if r.label == label}))
            for label in sorted({r.label for r in rows})
        ),
        normal_rows=sum(r.label == normal_label for r in rows),
        missing_values=sum(v is None for r in rows for v in r.features.feature_values),
        nonfinite_values=sum(
            isinstance(v, float) and not math.isfinite(v)
            for r in rows
            for v in r.features.feature_values
        ),
        duplicate_input_rows=sum(n - 1 for n in fps.values()),
        duplicate_inputs_across_groups=sum(len(g) > 1 for g in groups.values()),
        group_digests=tuple(sorted(digest(g) for g in {r.group_id for r in rows})),
        group_class_counts=tuple(
            sorted(
                (
                    digest(g),
                    tuple(sorted(Counter(r.label for r in rows if r.group_id == g).items())),
                )
                for g in {r.group_id for r in rows}
            )
        ),
        feature_schema=f"{feature.feature_schema.schema_name}@{feature.feature_schema.schema_version}",
        extractor=f"{feature.provenance.extractor_name}@{feature.provenance.extractor_version}",
    )


def partitions(
    rows: tuple[EvaluationRow, ...],
    *,
    dataset_name: str,
    dataset_version: str,
    seed: int = 42,
) -> tuple[Partition, Partition, Partition, SplitMetadata]:
    split = split_examples(rows, seed)
    values = tuple(
        Partition(
            role=role,
            rows=tuple(rows[i] for i in indices),
            dataset_name=dataset_name,
            dataset_version=dataset_version,
            split_strategy=split.strategy,
            split_seed=seed,
        )
        for role, indices in (
            ("train", split.train),
            ("selection", split.validation),
            ("test", split.test),
        )
    )
    require_disjoint(*values)
    return (*values, split)


def calibration_partition(selection: Partition, *, seed: int = 42) -> tuple[Partition, Partition]:
    """Group-held calibration half; fail rather than trying seeds until labels work."""
    selection = checked(selection, "selection")
    rows = selection.rows
    # Connected groups already kept intact by the outer split; merge identical inputs here too.
    parent = list(range(len(rows)))

    def root(i: int) -> int:
        while parent[i] != i:
            i = parent[i]
        return i

    seen_group, seen_input = {}, {}
    for i, r in enumerate(rows):
        for key, seen in ((r.group_id, seen_group), (r.features.input_fingerprint, seen_input)):
            if key in seen:
                parent[root(i)] = root(seen[key])
            else:
                seen[key] = i
    groups = [root(i) for i in range(len(rows))]
    if len(set(groups)) < 4:
        raise ValueError("Insufficient independent validation groups for calibration")
    a, b = next(
        GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=seed).split(rows, groups=groups)
    )
    if any({rows[i].label for i in part} != {r.label for r in rows} for part in (a, b)):
        raise ValueError("Calibration split omitted a class; no fallback")
    left = Partition(
        role="selection",
        rows=tuple(rows[i] for i in a),
        dataset_name=selection.dataset_name,
        dataset_version=selection.dataset_version,
        split_strategy=selection.split_strategy + ";validation-GroupShuffleSplit-0.5",
        split_seed=seed,
    )
    right = Partition(
        role="calibration",
        rows=tuple(rows[i] for i in b),
        dataset_name=selection.dataset_name,
        dataset_version=selection.dataset_version,
        split_strategy=selection.split_strategy + ";validation-GroupShuffleSplit-0.5",
        split_seed=seed,
    )
    require_disjoint(left, right)
    return left, right
