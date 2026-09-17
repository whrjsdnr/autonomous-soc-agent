"""Grouped partitions shared by labeled evaluation pipelines, never random fallback."""

from typing import Protocol, Self

import numpy as np
from pydantic import model_validator
from sklearn.model_selection import StratifiedGroupKFold

from soc_agent.security_ai.features import FeatureSet
from soc_agent.security_ai.features.models import Snapshot


class SplitExample(Protocol):
    features: FeatureSet
    label: str
    group_id: str
    row_id: str


class SplitMetadata(Snapshot):
    train: tuple[int, ...]
    validation: tuple[int, ...]
    test: tuple[int, ...]
    groups: tuple[str, ...]
    row_ids: tuple[str, ...]
    fingerprints: tuple[str, ...]
    strategy: str = "StratifiedGroupKFold-5;fold0-test;fold1-validation;fold2-4-train"

    @model_validator(mode="after")
    def validate_partition(self) -> Self:
        partitions = (self.train, self.validation, self.test)
        flat = [i for part in partitions for i in part]
        if not all(partitions) or sorted(flat) != list(range(len(self.groups))):
            raise ValueError("Invalid split partition")
        if len(self.groups) != len(self.row_ids) or len(self.groups) != len(self.fingerprints):
            raise ValueError("Split provenance lengths differ")
        for values in (self.groups, self.fingerprints):
            sets = [{values[i] for i in part} for part in partitions]
            if any(sets[i] & sets[j] for i, j in ((0, 1), (0, 2), (1, 2))):
                raise ValueError("Group or duplicate feature leakage across partitions")
        return self


def split_examples(examples: tuple[SplitExample, ...], seed: int = 42) -> SplitMetadata:
    if len({e.row_id for e in examples}) != len(examples):
        raise ValueError("Duplicate row identities")
    # Union groups connected by identical input fingerprints, including across CSV files.
    parent = list(range(len(examples)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen_groups, seen_inputs, labels = {}, {}, {}
    for i, example in enumerate(examples):
        fp = example.features.input_fingerprint
        if fp in labels and labels[fp] != example.label:
            raise ValueError("Identical model inputs have conflicting labels")
        labels[fp] = example.label
        for key, seen in ((example.group_id, seen_groups), (fp, seen_inputs)):
            if key in seen:
                parent[root(i)] = root(seen[key])
            else:
                seen[key] = i
    groups = tuple(str(root(i)) for i in range(len(examples)))
    classes = sorted({e.label for e in examples})
    if len(classes) < 2 or any(
        len({groups[i] for i, e in enumerate(examples) if e.label == label}) < 5
        for label in classes
    ):
        raise ValueError(
            "Each class requires at least five independent groups for the baseline split"
        )
    y = np.asarray([e.label for e in examples])
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    folds = [tuple(int(i) for i in test) for _, test in splitter.split(np.zeros(len(y)), y, groups)]
    parts = (tuple(sorted(i for fold in folds[2:] for i in fold)), folds[1], folds[0])
    if any({examples[i].label for i in part} != set(classes) for part in parts):
        raise ValueError("Grouped stratification omitted a class; provide independent groups")
    return SplitMetadata(
        train=parts[0],
        validation=parts[1],
        test=parts[2],
        groups=groups,
        row_ids=tuple(e.row_id for e in examples),
        fingerprints=tuple(e.features.input_fingerprint for e in examples),
    )
