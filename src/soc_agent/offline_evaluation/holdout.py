"""Declared-source leakage validation. Integrity is not proof of operating label truth."""

from collections import Counter
from datetime import timedelta
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.evaluation.authentication import EvaluationDataset, fixture_dataset
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.state.evidence import UTCTimestamp


class HoldoutMember(Snapshot):
    case_id: str = Field(min_length=1, max_length=128)
    split: Literal["TRAINING", "DEVELOPMENT", "HOLDOUT"]
    incident_id: UUID
    source_identity: Hash
    source_digest: Hash
    event_references: tuple[UUID, ...] = Field(min_length=1)
    content_digests: tuple[Hash, ...] = Field(min_length=1)
    window_start: UTCTimestamp
    window_end: UTCTimestamp

    @model_validator(mode="after")
    def window(self) -> Self:
        if (
            self.window_end <= self.window_start
            or self.window_start.timestamp() % 300
            or self.window_end - self.window_start != timedelta(minutes=5)
        ):
            raise ValueError("HOLDOUT_WINDOW_REJECTED")
        if len(set(self.event_references)) != len(self.event_references):
            raise ValueError("DUPLICATE_HOLDOUT_EVENT")
        return self


class HoldoutContract(Snapshot):
    contract_version: Literal["soc-independent-holdout:v1"] = "soc-independent-holdout:v1"
    dataset_id: Hash
    dataset_version: Hash
    dataset_digest: Hash
    ground_truth_digest: Hash
    source_identity: Hash
    source_digest: Hash
    source_assurance: Literal["PREAUTHORED_FIXTURE", "EXTERNAL_REPORTED", "UNKNOWN"]
    label_provenance: Hash
    labels_from_detection_output: Literal[False] = False
    collection_start: UTCTimestamp
    collection_end: UTCTimestamp
    split_identity: Hash
    split_method: Literal["EXPLICIT_GROUP_AND_TIME_DISJOINT"] = "EXPLICIT_GROUP_AND_TIME_DISJOINT"
    evaluation_unit: Literal["INCIDENT_UTC_FIVE_MINUTE_WINDOW_RULE"] = (
        "INCIDENT_UTC_FIVE_MINUTE_WINDOW_RULE"
    )
    dataset_size: int = Field(ge=1, strict=True)
    positive_count: int = Field(ge=0, strict=True)
    negative_count: int = Field(ge=0, strict=True)
    members: tuple[HoldoutMember, ...] = Field(min_length=3, max_length=1024)
    contract_digest: Hash

    @model_validator(mode="after")
    def integrity(self) -> Self:
        if self.dataset_id != self.dataset_version or self.dataset_version != self.dataset_digest:
            raise ValueError("HOLDOUT_DATASET_IDENTITY_REJECTED")
        if (
            self.collection_end <= self.collection_start
            or self.positive_count + self.negative_count != self.dataset_size
        ):
            raise ValueError("HOLDOUT_COUNTS_PERIOD_REJECTED")
        if {m.split for m in self.members} != {"TRAINING", "DEVELOPMENT", "HOLDOUT"}:
            raise ValueError("THREE_DISJOINT_SPLITS_REQUIRED")
        if any(
            not self.collection_start <= m.window_start < m.window_end <= self.collection_end
            for m in self.members
        ):
            raise ValueError("HOLDOUT_COLLECTION_PERIOD_REJECTED")
        if self.split_identity != content_digest_payload(
            {"members": [m.model_dump(mode="json") for m in self.members]}
        ):
            raise ValueError("HOLDOUT_SPLIT_DIGEST_REJECTED")
        for i, left in enumerate(self.members):
            for right in self.members[i + 1 :]:
                overlap = (
                    left.window_start < right.window_end and right.window_start < left.window_end
                )
                same_source = left.source_identity == right.source_identity
                same_incident = left.incident_id == right.incident_id
                repeated = (
                    bool(set(left.event_references) & set(right.event_references))
                    or bool(set(left.content_digests) & set(right.content_digests))
                    or left.source_digest == right.source_digest
                )
                if left.case_id == right.case_id or repeated:
                    raise ValueError("DUPLICATE_HOLDOUT_SOURCE")
                if left.split != right.split and (
                    same_source or same_incident or (overlap and same_source)
                ):
                    raise ValueError("HOLDOUT_SPLIT_LEAKAGE")
                if overlap and same_source:
                    raise ValueError("HOLDOUT_TIME_OVERLAP")
        if self.contract_digest != content_digest_payload(
            self.model_dump(mode="json", exclude={"contract_digest"})
        ):
            raise ValueError("HOLDOUT_CONTRACT_DIGEST_REJECTED")
        return self

    def validate_dataset(self, dataset: EvaluationDataset) -> EvaluationDataset:
        dataset = EvaluationDataset.model_validate_json(dataset.model_dump_json())
        if (
            self.dataset_digest != content_digest_payload(dataset.model_dump(mode="json"))
            or self.ground_truth_digest != dataset.ground_truth_digest
        ):
            raise ValueError("HOLDOUT_DATA_OR_LABEL_TAMPERING")
        if self.source_assurance == "PREAUTHORED_FIXTURE":
            authored = fixture_dataset()
            trusted = {case.case_id: case for case in authored.cases}
            if dataset.dataset_id != authored.dataset_id or any(
                trusted.get(case.case_id) != case for case in dataset.cases
            ):
                raise ValueError("UNVERIFIED_FIXTURE_LABEL_PROVENANCE")
        cases = {c.case_id: c for c in dataset.cases}
        if set(cases) != {m.case_id for m in self.members}:
            raise ValueError("HOLDOUT_CASE_COVERAGE_REJECTED")
        if self.label_provenance != content_digest_payload(
            {"labels": [label.label_provenance for case in dataset.cases for label in case.labels]}
        ):
            raise ValueError("HOLDOUT_LABEL_PROVENANCE_REJECTED")
        if self.source_identity != content_digest_payload(
            {"sources": sorted({member.source_identity for member in self.members})}
        ):
            raise ValueError("HOLDOUT_SOURCE_IDENTITY_REJECTED")
        holdout_cases = []
        for member in self.members:
            case = cases[member.case_id]
            sources = tuple(sorted({e.source.namespace for e in case.events}))
            if member.source_identity != content_digest_payload({"namespaces": list(sources)}):
                raise ValueError("HOLDOUT_SOURCE_IDENTITY_REJECTED")
            if member.source_digest != content_digest_payload(
                {"events": [e.model_dump(mode="json") for e in case.events]}
            ):
                raise ValueError("HOLDOUT_SOURCE_DIGEST_REJECTED")
            if (
                case.incident_id != member.incident_id
                or set(member.event_references) != {e.event_id for e in case.events}
                or set(member.content_digests) != {e.source_digest for e in case.events}
            ):
                raise ValueError("HOLDOUT_EVENT_BINDING_REJECTED")
            if any(
                not member.window_start <= e.event_timestamp < member.window_end
                for e in case.events
            ):
                raise ValueError("HOLDOUT_WINDOW_BINDING_REJECTED")
            if member.split == "HOLDOUT":
                holdout_cases.append(case)
        counts = Counter(label.ground_truth_label for c in holdout_cases for label in c.labels)
        if (self.dataset_size, self.positive_count, self.negative_count) != (
            sum(counts.values()),
            counts["EXPECTED_ADVISORY"],
            counts["NO_ADVISORY_EXPECTED"],
        ):
            raise ValueError("HOLDOUT_LABEL_COUNTS_REJECTED")
        if self.source_digest != content_digest_payload(
            {"members": [m.source_digest for m in self.members]}
        ):
            raise ValueError("HOLDOUT_RAW_SOURCE_DIGEST_REJECTED")
        if self.source_assurance == "PREAUTHORED_FIXTURE" and any(
            label.source_origin != "FIXTURE" for c in dataset.cases for label in c.labels
        ):
            raise ValueError("FIXTURE_NATIVE_HOLDOUT_CONFUSION")
        body = {
            "dataset_id": dataset.dataset_id,
            "cases": holdout_cases,
            "label_semantics": dataset.label_semantics,
            "ground_truth_digest": content_digest_payload(
                {"cases": [c.model_dump(mode="json") for c in holdout_cases]}
            ),
        }
        return EvaluationDataset.model_validate(body)
