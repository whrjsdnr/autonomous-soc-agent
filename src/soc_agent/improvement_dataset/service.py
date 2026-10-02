"""Explicit select/validate/build/version. No runtime integration or side-effect authority."""

from collections.abc import Iterable

from soc_agent.improvement_dataset.models import (
    DatasetManifest,
    ImprovementDataset,
    SourceSnapshotIdentity,
)
from soc_agent.improvement_dataset.selection import load_sources, select
from soc_agent.improvement_dataset.store import ImprovementDatasetStore
from soc_agent.review.identity import content_digest


class ImprovementDatasetBuilder:
    def __init__(self, store: ImprovementDatasetStore) -> None:
        self.store = store

    def build(self, evaluation_ids: Iterable[str]) -> ImprovementDataset:
        # Explicit candidate selection. Duplicates/order do not alter the logical dataset.
        identities = tuple(sorted(set(evaluation_ids)))
        with self.store.database.transaction() as connection:
            selections, samples = [], []
            for identity in identities:
                selection, sample = select(*load_sources(connection, self.store.feedback, identity))
                selections.append(selection)
                if sample is not None:
                    samples.append(sample)
            manifest = DatasetManifest(
                source_snapshot_id=content_digest(
                    SourceSnapshotIdentity(sources=tuple(s.sources for s in selections))
                ),
                selection=tuple(selections),
                samples=tuple(
                    sorted((s.sample for s in selections if s.sample), key=lambda r: r.identity)
                ),
                sample_count=len(samples),
                excluded_count=len(selections) - len(samples),
            )
            digest = content_digest(manifest)
            value = ImprovementDataset(
                dataset_id=digest, dataset_version=digest, manifest_digest=digest, manifest=manifest
            )
            return self.store._insert(connection, value, tuple(samples))
