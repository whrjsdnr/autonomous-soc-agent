"""Explicit human facts, completeness, and selected-path counting contracts."""

from uuid import UUID

import pytest
from pydantic import ValidationError
from tests.unit.offline_comparison.test_coverage import inputs

from soc_agent.feedback import (
    CoverageExpectation,
    FeedbackRequest,
    InvestigationPathAdjudication,
    ReviewCompleteness,
    Verdict,
)
from soc_agent.feedback.models import DiagnosticLabel, adjudications_conflict
from soc_agent.offline_comparison.adapter import measure, replay, safety
from soc_agent.offline_comparison.coverage_models import (
    CoverageConfiguration,
    CoverageGroundTruth,
    PinnedPathAdjudication,
)
from soc_agent.offline_comparison.evaluation import criterion_result, reference
from soc_agent.offline_comparison.execution import execute_pair
from soc_agent.offline_comparison.models import (
    CONTRACT_EVALUATOR_VERSION,
    CaseOutcome,
    EvaluationCase,
    ValueState,
    VerdictState,
)
from soc_agent.offline_evaluation.models import AcceptanceCriterion, MetricName
from soc_agent.review.identity import content_digest
from soc_agent.tools.enums import ToolPermission as P


def adjudication(unnecessary=(), completeness="COMPLETE"):
    return InvestigationPathAdjudication(
        unnecessary_permissions=unnecessary, review_completeness=completeness
    )


@pytest.mark.parametrize(
    "completeness,unnecessary",
    [("COMPLETE", (P.FILE_READ,)), ("COMPLETE", ()), ("PARTIAL", (P.FILE_READ,))],
)
def test_valid_explicit_human_contract(completeness, unnecessary):
    value = CoverageExpectation(
        required_permissions=(P.NETWORK_READ,),
        path_adjudication=adjudication(unnecessary, completeness),
    )
    assert value.path_adjudication.unnecessary_permissions == unnecessary
    assert value.path_adjudication.review_completeness.value == completeness


@pytest.mark.parametrize("invalid", [P.NETWORK_WRITE, "invented_permission"])
def test_adjudication_rejects_non_read_only_permission(invalid):
    with pytest.raises(ValidationError):
        adjudication((invalid,))


@pytest.mark.parametrize("permissions", [(P.FILE_READ, P.FILE_READ), (P.SYSTEM_READ, P.FILE_READ)])
def test_noncanonical_adjudication_rejected(permissions):
    with pytest.raises(ValidationError):
        adjudication(permissions)


def test_overlap_extra_fields_and_mutation_rejected():
    with pytest.raises(ValidationError):
        CoverageExpectation(
            required_permissions=(P.FILE_READ,), path_adjudication=adjudication((P.FILE_READ,))
        )
    value = adjudication((P.FILE_READ, P.SYSTEM_READ))
    with pytest.raises(ValidationError):
        value.review_completeness = ReviewCompleteness.PARTIAL
    with pytest.raises(ValidationError):
        InvestigationPathAdjudication.model_validate({**value.model_dump(), "execute": "anything"})


def test_legacy_feedback_identity_and_no_label_backfill():
    request = FeedbackRequest(
        submission_id=UUID(int=1),
        incident_id=UUID(int=2),
        experience_id="1" * 64,
        experience_digest="2" * 64,
        evaluation_id="3" * 64,
        evaluation_digest="4" * 64,
        verdict=Verdict.INCORRECT,
        labels=(DiagnosticLabel.UNNECESSARY_INVESTIGATION,),
        coverage_expectation=CoverageExpectation(required_permissions=(P.NETWORK_READ,)),
    )
    dumped = request.model_dump(mode="json")
    assert "path_adjudication" not in dumped["coverage_expectation"]
    assert FeedbackRequest.model_validate(dumped).digest == request.digest
    assert request.coverage_expectation.path_adjudication is None


def test_human_disagreement_not_merged_and_partial_never_infers_complete():
    assert adjudications_conflict(set(), (adjudication(()), adjudication((P.FILE_READ,))))
    assert adjudications_conflict({P.SYSTEM_READ}, (adjudication((P.SYSTEM_READ,), "PARTIAL"),))
    assert adjudications_conflict(
        set(), (adjudication(()), adjudication((P.FILE_READ,), "PARTIAL"))
    )
    assert not adjudications_conflict(
        set(), (adjudication((P.FILE_READ,)), adjudication((P.FILE_READ,), "PARTIAL"))
    )


def test_confirmation_binding_digest_includes_completeness_and_unnecessary_set():
    request = FeedbackRequest(
        submission_id=UUID(int=1),
        incident_id=UUID(int=2),
        experience_id="1" * 64,
        experience_digest="2" * 64,
        evaluation_id="3" * 64,
        evaluation_digest="4" * 64,
        verdict=Verdict.CORRECT,
    )
    variants = tuple(
        request.model_copy(
            update={
                "coverage_expectation": CoverageExpectation(
                    required_permissions=(P.NETWORK_READ,), path_adjudication=value
                )
            }
        )
        for value in (
            None,
            adjudication(()),
            adjudication((), "PARTIAL"),
            adjudication((P.FILE_READ,)),
        )
    )
    assert len({value.digest for value in variants}) == len(variants)


def frozen_case(value):
    source, facts, spec, plan, baseline, truths = inputs()
    artifacts = execute_pair(
        source, spec, plan, facts, baseline, truths, evaluator_version=CONTRACT_EVALUATOR_VERSION
    )
    original = artifacts.baseline_result.content.cases[0]
    truth = original.content.coverage
    if value is not None:
        truth = CoverageGroundTruth(
            required_permissions=truth.required_permissions,
            status=truth.status,
            feedback_refs=truth.feedback_refs,
            path_adjudications=(
                PinnedPathAdjudication(feedback=truth.feedback_refs[0], adjudication=value),
            ),
        )
    content = original.content.model_copy(update={"coverage": truth})
    return EvaluationCase(case_id=content_digest(content), content=content), spec


@pytest.mark.parametrize(
    "value,baseline_paths,candidate_paths,expected",
    [
        (
            adjudication((P.SYSTEM_READ,)),
            (P.NETWORK_READ, P.SYSTEM_READ),
            (P.NETWORK_READ,),
            (1, 0, VerdictState.PASS),
        ),
        (
            adjudication((P.FILE_READ, P.SYSTEM_READ)),
            (P.SYSTEM_READ,),
            (P.SYSTEM_READ,),
            (1, 1, VerdictState.PASS),
        ),
        (
            adjudication((P.SYSTEM_READ,)),
            (P.NETWORK_READ,),
            (P.NETWORK_READ, P.SYSTEM_READ),
            (0, 1, VerdictState.FAIL),
        ),
        (adjudication(()), (P.SYSTEM_READ,), (P.NETWORK_READ,), (0, 0, VerdictState.PASS)),
        (
            adjudication((), "PARTIAL"),
            (P.SYSTEM_READ,),
            (P.NETWORK_READ,),
            (None, None, VerdictState.UNKNOWN),
        ),
        (None, (P.SYSTEM_READ,), (P.NETWORK_READ,), (None, None, VerdictState.UNKNOWN)),
    ],
)
def test_metric_and_existing_criterion_use_same_frozen_human_facts(
    value, baseline_paths, candidate_paths, expected
):
    # This tests measurement of two sandbox observations, not a remove-path candidate operation.
    case, spec = frozen_case(value)
    results = []
    for paths in (baseline_paths, candidate_paths):
        config = CoverageConfiguration(covered_permissions=paths)
        trace = replay(case, config)
        outcome = CaseOutcome(case=reference(case.case_id, case), status="EXECUTED", trace=trace)
        metric = next(
            m
            for m in measure(spec.content.metrics, (outcome,), safety((case,), (outcome,)))
            if m.metric == MetricName.UNNECESSARY_PATHS
        )
        assert metric.value == expected[len(results)]
        assert metric.state == (
            ValueState.MEASURED if metric.value is not None else ValueState.NOT_MEASURABLE
        )
        assert replay(case, config) == trace
        results.append(metric)
    criterion = AcceptanceCriterion(
        metric=MetricName.UNNECESSARY_PATHS, operator="NOT_GREATER_THAN_BASELINE"
    )
    assert criterion_result(criterion, *results, 1).status == expected[2]


def test_adjudication_requires_pinned_contributing_feedback():
    case, _ = frozen_case(adjudication(()))
    truth = case.content.coverage
    invalid = PinnedPathAdjudication(
        feedback=reference("9" * 64, adjudication(())), adjudication=adjudication(())
    )
    with pytest.raises(ValidationError):
        CoverageGroundTruth.model_validate({**truth.model_dump(), "path_adjudications": (invalid,)})
