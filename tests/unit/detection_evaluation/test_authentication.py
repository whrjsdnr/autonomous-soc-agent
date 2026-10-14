"""Independent fixture labels, real correlation engine, no native or LLM accuracy claim."""

import json

import pytest
from pydantic import ValidationError

from soc_agent.evaluation.authentication import (
    EvaluationDataset,
    evaluate,
    fixture_dataset,
    metrics,
)


def test_labels_are_deterministic_complete_and_not_attack_truth():
    first = fixture_dataset()
    second = fixture_dataset()
    assert first == second
    assert len(first.cases) == 11
    assert sum(len(case.labels) for case in first.cases) == 60
    assert all(label.source_origin == "FIXTURE" for case in first.cases for label in case.labels)
    assert first.label_semantics == "INDEPENDENT_ADVISORY_UTILITY_NOT_ATTACK_TRUTH"
    assert not any(case.case_id in ("S07", "S08", "S09", "S10", "S12") for case in first.cases)


@pytest.mark.parametrize(
    "change", ["LABEL", "DIGEST", "INCIDENT", "EVENT_ID", "ORIGIN", "TIME", "DUPLICATE"]
)
def test_ground_truth_tampering_rejected(change):
    value = json.loads(fixture_dataset().model_dump_json())
    label = value["cases"][0]["labels"][0]
    if change == "LABEL":
        label["ground_truth_label"] = "EXPECTED_ADVISORY"
    elif change == "DIGEST":
        label["evidence_references"][0] = "0" * 64
    elif change == "INCIDENT":
        label["incident_id"] = "00000000-0000-0000-0000-000000000001"
    elif change == "EVENT_ID":
        label["event_ids"][0] = "00000000-0000-0000-0000-000000000001"
    elif change == "ORIGIN":
        label["source_origin"] = "NATIVE_OS"
    elif change == "TIME":
        label["window_end"] = label["window_start"]
    else:
        value["cases"][0]["labels"].append(label)
    with pytest.raises(ValidationError):
        EvaluationDataset.model_validate(value)


def test_metrics_zero_denominators_are_unknown_and_negative_counts_rejected():
    assert all(value is None for value in metrics({}).values())
    result = metrics({"TP": 2, "FP": 1, "TN": 3, "FN": 1})
    assert result["precision"] == result["recall"] == result["f1"] == 2 / 3
    assert result["false_positive_rate"] == 1 / 4
    assert result["false_negative_rate"] == 1 / 3
    with pytest.raises(ValueError):
        metrics({"TP": -1})


def test_real_engine_metrics_replay_and_fp_fn_cases():
    first = evaluate(fixture_dataset())
    second = evaluate(fixture_dataset())
    assert first["evaluation_digest"] == second["evaluation_digest"]
    assert first["confusion_matrix"] == {"TP": 7, "FP": 2, "TN": 49, "FN": 2}
    assert first["metrics"]["precision"] == first["metrics"]["recall"] == 7 / 9
    assert {case["case_id"] for case in first["false_positives"]} == {"benign-burst"}
    assert {case["case_id"] for case in first["false_negatives"]} == {"late"}
    cases = {case["case_id"]: case for case in first["cases"]}
    assert cases["duplicate"]["duplicate_events"] == 5
    assert cases["duplicate"]["finding_count"] == 2
    assert cases["boundary"]["finding_count"] == cases["unsupported"]["finding_count"] == 0
    assert first["source_origin"] == ["FIXTURE"]
    assert first["latency_assurance"] == "SIMULATED_FIXTURE_CLOCK_NOT_PRODUCTION_LATENCY"


def test_multiple_account_findings_collapse_to_one_rule_window_unit():
    from datetime import timedelta
    from uuid import NAMESPACE_URL, uuid5

    from soc_agent.demo.scenario_models import START, Scenario, ssh
    from soc_agent.demo.scenario_pipeline import fixture_event
    from soc_agent.evaluation.authentication import DATASET, RULES, EvaluationCase, GroundTruth
    from soc_agent.realtime.models import CommonEvent
    from soc_agent.security_ai.external.models import content_digest_payload

    identity = uuid5(NAMESPACE_URL, "evaluation-multiple-scope-fixture")
    scenario = Scenario(
        scenario_id="scopes",
        messages=tuple(
            ssh("Failed", f"fixture-{account}") for account in range(3) for _ in range(5)
        ),
    )
    events = tuple(
        CommonEvent.model_validate(
            fixture_event(scenario, i, identity).model_dump()
            | {"ingestion_timestamp": START + timedelta(seconds=30)}
        )
        for i in range(15)
    )
    labels = tuple(
        GroundTruth(
            dataset_id=DATASET,
            scenario_id="scopes",
            incident_id=identity,
            event_ids=tuple(e.event_id for e in events),
            ground_truth_label="EXPECTED_ADVISORY" if rule in RULES[:3] else "NO_ADVISORY_EXPECTED",
            expected_rule_id=rule,
            event_timestamp=events[-1].event_timestamp,
            window_start=START,
            window_end=START + timedelta(seconds=300),
            source_origin="FIXTURE",
            evidence_references=tuple(e.source_digest for e in events),
            label_provenance="independent-test-spec-multiple-account-scopes:v1",
        )
        for rule in RULES
    )
    case = EvaluationCase(
        case_id="scopes",
        description="Independent multi-scope test",
        incident_id=identity,
        events=events,
        arrival_order=tuple(range(15)),
        labels=labels,
    )
    dataset = EvaluationDataset(
        cases=(case,),
        ground_truth_digest=content_digest_payload({"cases": [case.model_dump(mode="json")]}),
    )
    result = evaluate(dataset)
    assert result["confusion_matrix"] == {"TP": 3, "FP": 0, "TN": 2, "FN": 0}
    assert result["cases"][0]["finding_count"] == 5
    assert result["cases"][0]["unique_rule_window_detections"] == 3
