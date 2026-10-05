"""Stable content partition with source-support and incident leakage guards."""

from soc_agent.improvement_candidates.models import DatasetBinding, SampleFacts
from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.offline_evaluation.models import (
    DatasetPartition,
    IncidentGroup,
    PartitionContent,
    SplitConfig,
)
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError


def partition(
    dataset: DatasetBinding,
    facts: tuple[SampleFacts, ...],
    support: tuple[ArtifactReference, ...],
    config: SplitConfig,
) -> DatasetPartition:
    members = {f.sample.identity: f.sample for f in facts}
    if len(members) != len(facts) or any(members.get(r.identity) != r for r in support):
        raise StoredDataError("Split support is not in the source dataset")
    incident_ids = sorted({f.sources.incident_id for f in facts}, key=str)
    groups = tuple(
        IncidentGroup(
            incident_id=incident,
            samples=tuple(
                sorted(
                    (f.sample for f in facts if f.sources.incident_id == incident),
                    key=lambda r: r.identity,
                )
            ),
        )
        for incident in incident_ids
    )
    supporting_ids = {r.identity for r in support}
    development, holdout = [], []
    for group in groups:
        # Membership is content-addressed; no random seed or mutable iteration state.
        bucket = int(content_digest(group), 16) % config.bucket_count
        if supporting_ids & {r.identity for r in group.samples} or (
            bucket >= config.holdout_buckets
        ):
            development.extend(group.samples)
        else:
            holdout.extend(group.samples)
    content = PartitionContent(
        dataset=dataset,
        config=config,
        source_support_refs=support,
        incident_groups=groups,
        development=tuple(sorted(development, key=lambda r: r.identity)),
        holdout=tuple(sorted(holdout, key=lambda r: r.identity)),
    )
    return DatasetPartition(split_id=content_digest(content), content=content)
