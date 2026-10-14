"""Declared fixture splits only; not an independent operating holdout."""

from datetime import timedelta

import pytest

from soc_agent.evaluation.authentication import EvaluationDataset, fixture_dataset
from soc_agent.offline_evaluation.holdout import HoldoutContract, HoldoutMember
from soc_agent.security_ai.external.models import content_digest_payload as digest


def contracts():
    all_cases = fixture_dataset().cases
    cases = tuple(
        c for c in all_cases if c.case_id in ("normal", "single", "repeated", "transition")
    )
    dataset = EvaluationDataset(
        cases=cases,
        ground_truth_digest=digest({"cases": [c.model_dump(mode="json") for c in cases]}),
    )
    members = []
    for case in cases:
        split = (
            "TRAINING"
            if case.case_id == "normal"
            else "DEVELOPMENT"
            if case.case_id == "transition"
            else "HOLDOUT"
        )
        start = case.labels[0].window_start
        members.append(
            HoldoutMember(
                case_id=case.case_id,
                split=split,
                incident_id=case.incident_id,
                source_identity=digest(
                    {"namespaces": sorted({e.source.namespace for e in case.events})}
                ),
                source_digest=digest({"events": [e.model_dump(mode="json") for e in case.events]}),
                event_references=tuple(e.event_id for e in case.events),
                content_digests=tuple(e.source_digest for e in case.events),
                window_start=start,
                window_end=start + timedelta(minutes=5),
            )
        )
    ds = digest(dataset.model_dump(mode="json"))
    body = {
        "contract_version": "soc-independent-holdout:v1",
        "dataset_id": ds,
        "dataset_version": ds,
        "dataset_digest": ds,
        "ground_truth_digest": dataset.ground_truth_digest,
        "source_identity": digest({"sources": sorted({m.source_identity for m in members})}),
        "source_digest": digest({"members": [m.source_digest for m in members]}),
        "source_assurance": "PREAUTHORED_FIXTURE",
        "label_provenance": digest(
            {"labels": [label.label_provenance for c in cases for label in c.labels]}
        ),
        "labels_from_detection_output": False,
        "collection_start": members[0].window_start,
        "collection_end": members[0].window_end,
        "split_identity": digest({"members": [m.model_dump(mode="json") for m in members]}),
        "split_method": "EXPLICIT_GROUP_AND_TIME_DISJOINT",
        "evaluation_unit": "INCIDENT_UTC_FIVE_MINUTE_WINDOW_RULE",
        "dataset_size": 10,
        "positive_count": 2,
        "negative_count": 8,
        "members": tuple(members),
    }
    # Hash canonical JSON timestamps, not Python datetime rendering.
    provisional = HoldoutContract.model_construct(**body, contract_digest="0" * 64)
    normalized = provisional.model_dump(mode="json", exclude={"contract_digest"})
    contract = HoldoutContract.model_validate(body | {"contract_digest": digest(normalized)})
    return dataset, contract


def reseal(body):
    body["split_identity"] = digest({"members": body["members"]})
    body["contract_digest"] = digest({k: v for k, v in body.items() if k != "contract_digest"})
    return HoldoutContract.model_validate_json(__import__("json").dumps(body))


def test_fixture_membership_counts_and_determinism():
    dataset, contract = contracts()
    held = contract.validate_dataset(dataset)
    assert {c.case_id for c in held.cases} == {"single", "repeated"}
    assert contracts()[1] == contract


@pytest.mark.parametrize("attack", ["source", "incident", "event", "digest", "case", "overlap"])
def test_split_leakage_rejected_even_when_rehashed(attack):
    _, contract = contracts()
    body = contract.model_dump(mode="json")
    left, right = body["members"][:2]
    if attack == "source":
        right["source_identity"] = left["source_identity"]
    elif attack == "incident":
        right["incident_id"] = left["incident_id"]
    elif attack == "event":
        right["event_references"] = left["event_references"]
    elif attack == "digest":
        right["content_digests"] = left["content_digests"]
    elif attack == "case":
        right["case_id"] = left["case_id"]
    else:
        right["split"] = left["split"]
        right["source_identity"] = left["source_identity"]
    with pytest.raises(ValueError):
        reseal(body)


@pytest.mark.parametrize(
    "attack", ["labels", "raw", "counts", "timestamp", "truth", "member_source", "version"]
)
def test_contract_and_data_tampering(attack):
    dataset, contract = contracts()
    body = contract.model_dump(mode="json")
    if attack == "labels":
        body["ground_truth_digest"] = "0" * 64
    elif attack == "raw":
        body["source_digest"] = "0" * 64
    elif attack == "counts":
        body.update(positive_count=3, negative_count=7)
    elif attack == "timestamp":
        body["members"][0]["window_end"] = body["members"][0]["window_start"]
    elif attack == "truth":
        body["labels_from_detection_output"] = True
    elif attack == "member_source":
        body["members"][0]["source_identity"] = "0" * 64
    else:
        body["dataset_version"] = "0" * 64
    with pytest.raises(ValueError):
        reseal(body).validate_dataset(dataset)


def test_rehashed_detector_label_cannot_impersonate_authored_fixture_truth():
    dataset, contract = contracts()
    body = dataset.model_dump(mode="json")
    case = next(c for c in body["cases"] if c["case_id"] == "single")
    case["labels"][0]["ground_truth_label"] = "EXPECTED_ADVISORY"
    body["ground_truth_digest"] = digest({"cases": body["cases"]})
    changed = EvaluationDataset.model_validate_json(__import__("json").dumps(body))
    bound = contract.model_dump(mode="json")
    identity = digest(changed.model_dump(mode="json"))
    bound.update(
        dataset_id=identity,
        dataset_version=identity,
        dataset_digest=identity,
        ground_truth_digest=changed.ground_truth_digest,
        positive_count=3,
        negative_count=7,
    )
    with pytest.raises(ValueError, match="UNVERIFIED_FIXTURE_LABEL_PROVENANCE"):
        reseal(bound).validate_dataset(changed)
