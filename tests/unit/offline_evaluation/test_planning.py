import pytest
from pydantic import ValidationError
from tests.unit.improvement_candidates.test_analysis import BINDING, fact

from soc_agent.experience.models import HistoricalOutcome
from soc_agent.feedback import DiagnosticLabel as Label
from soc_agent.improvement_candidates import AnalysisConfig, CandidateType
from soc_agent.improvement_candidates.analysis import analyze
from soc_agent.improvement_candidates.generation import generate
from soc_agent.improvement_dataset.models import (
    ArtifactReference,
    ImprovementSample,
    SampleContent,
)
from soc_agent.offline_evaluation import (
    HardInvariant,
    MeasurementState,
    SplitConfig,
)
from soc_agent.offline_evaluation.models import (
    EvaluationSpecification,
    MetricName,
    PlanningBlocker,
    RequiredEvidence,
    VariantKind,
)
from soc_agent.offline_evaluation.planning import make_test_plan, specify
from soc_agent.offline_evaluation.split import partition
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError


def candidate_for(kind):
    options = {
        CandidateType.PROMPT: {"labels": (Label.FALSE_POSITIVE,)},
        CandidateType.INVESTIGATION_STRATEGY: {"labels": (Label.MISSED_INVESTIGATION,)},
        CandidateType.TOOL_SELECTION_STRATEGY: {"labels": (Label.FALSE_NEGATIVE,)},
        CandidateType.RULE: {"outcome": HistoricalOutcome.FAILED},
    }[kind]
    facts = tuple(fact(n, **options) for n in (1, 2))
    candidates = tuple(c for p in analyze(BINDING, facts, AnalysisConfig()) for c in generate(p))
    candidate = next(c for c in candidates if c.content.candidate_type == kind)
    return candidate, facts


@pytest.mark.parametrize(
    "kind,metric,variant_kind",
    [
        (CandidateType.PROMPT, MetricName.UNSUPPORTED_ASSERTIONS, VariantKind.PROMPT),
        (
            CandidateType.INVESTIGATION_STRATEGY,
            MetricName.INVESTIGATION_STEPS,
            VariantKind.STRATEGY,
        ),
        (
            CandidateType.TOOL_SELECTION_STRATEGY,
            MetricName.SELECTED_READ_ONLY,
            VariantKind.SELECTOR,
        ),
        (CandidateType.RULE, MetricName.RULE_DECISION_MISMATCH, VariantKind.RULE),
    ],
)
def test_type_specific_contracts_binding_safety_and_unknowns(kind, metric, variant_kind):
    candidate, facts = candidate_for(kind)
    specification = specify(candidate, facts, SplitConfig())
    c = specification.content
    plan = make_test_plan(specification)
    assert c.binding.candidate.identity == candidate.candidate_id
    assert c.binding.candidate.digest == content_digest(candidate.content)
    assert c.binding.candidate_type == kind
    assert c.binding.dataset == candidate.content.dataset
    assert c.binding.supporting_pattern_refs == candidate.content.failure_pattern_refs
    assert c.binding.supporting_sample_refs == candidate.content.supporting_sample_refs
    assert c.baseline.target_locator == candidate.content.proposal.target_reference
    assert c.baseline.target_version is None and c.baseline.baseline_reference == "UNKNOWN"
    assert c.variant.kind == variant_kind and c.variant.artifact_reference == "UNKNOWN"
    assert c.variant.requires_candidate_variant and not c.variant.generated_by_planner
    metrics = {m.name: m for m in c.metrics}
    assert metric in metrics
    assert all(
        m.current_state in {MeasurementState.UNKNOWN, MeasurementState.NOT_MEASURABLE}
        for m in metrics.values()
    )
    assert all("value" not in m.model_dump() for m in metrics.values())
    if kind == CandidateType.INVESTIGATION_STRATEGY:
        assert metrics[metric].current_state == MeasurementState.NOT_MEASURABLE
    assert c.governance_invariants == c.regression_invariants == tuple(sorted(HardInvariant))
    assert HardInvariant.NO_UNCERTAIN_AUTO_RETRY in c.governance_invariants
    assert c.requires_all_hard_invariants and c.hard_invariants_precede_performance
    assert c.require_nonempty_complete_holdout
    assert c.environment.no_real_account_or_network_modification
    assert c.environment.mock_or_sandbox_external_tools and c.environment.no_live_response_execution
    assert c.authority == "OFFLINE_ADVISORY" and c.readiness == "BLOCKED"
    assert PlanningBlocker.NO_HOLDOUT in c.blockers
    assert c.partition.content.holdout == ()
    assert RequiredEvidence.UNSEEN_PROVENANCE in c.required_evidence
    assert all(criterion.unknown_handling == "BLOCK" for criterion in c.acceptance_criteria)
    assert any(
        criterion.operator == "NOT_GREATER_THAN_BASELINE" for criterion in c.acceptance_criteria
    )
    assert any(criterion.operator == "COVERS_BOUND_HOLDOUT" for criterion in c.acceptance_criteria)
    assert plan.content.specification.digest == content_digest(c)
    assert plan.content.binding == c.binding
    assert (
        plan.content.execution_mode == "OFFLINE" and plan.content.status == "PLANNED_NOT_EXECUTED"
    )
    assert plan.content.requires_candidate_variant
    assert plan.content.ordered_test_cases[3].input_subset == "HOLDOUT"
    assert plan.content.safety_assertions == c.governance_invariants
    assert all(
        test.safety_assertions == c.governance_invariants
        for test in plan.content.ordered_test_cases
    )
    assert all(
        name not in specification.model_dump_json()
        for name in (
            "quality_score",
            "success_probability",
            "priority_score",
            "accuracy",
        )
    )
    with pytest.raises(ValidationError):
        specification.content.baseline.baseline_reference = "assumed-v1"


def test_deterministic_partition_guards_support_and_same_incident():
    candidate, source = candidate_for(CandidateType.PROMPT)
    other = fact(3)
    # Rebind this historical sample to a supporting incident.
    sources = other.sources.model_copy(update={"incident_id": source[0].sources.incident_id})
    content = SampleContent(
        sources=sources,
        verdict=other.verdict,
        labels=other.labels,
        objective=other.objective,
    )
    sample = ImprovementSample(sample_id=content_digest(content), content=content)
    other = other.model_copy(
        update={
            "sources": sources,
            "sample": ArtifactReference(identity=sample.sample_id, digest=content_digest(sample)),
        }
    )
    facts = source + (other,) + tuple(fact(n) for n in range(4, 24))
    config = SplitConfig(bucket_count=2)
    a = partition(BINDING, facts, candidate.content.supporting_sample_refs, config)
    b = partition(BINDING, tuple(reversed(facts)), candidate.content.supporting_sample_refs, config)
    assert a == b and a.content.holdout
    development = {r.identity for r in a.content.development}
    holdout = {r.identity for r in a.content.holdout}
    assert not development & holdout
    assert development | holdout == {f.sample.identity for f in facts}
    assert other.sample.identity in development
    assert {r.identity for r in candidate.content.supporting_sample_refs} <= development
    assert a.content.leakage_status == "RETROSPECTIVE_ONLY"
    assert a.content.requires_unseen_evaluation_evidence
    with pytest.raises(StoredDataError):
        partition(BINDING, source[:1], candidate.content.supporting_sample_refs, config)
    with pytest.raises(ValidationError):
        type(a).model_validate(
            a.model_dump()
            | {
                "content": a.content.model_dump() | {"holdout": a.content.development},
            }
        )


def test_specification_plan_identity_time_config_and_snapshot():
    candidate, facts = candidate_for(CandidateType.PROMPT)
    a = specify(candidate, facts, SplitConfig())
    b = specify(candidate, tuple(reversed(facts)), SplitConfig())
    assert a.specification_id == b.specification_id and a.content == b.content
    assert make_test_plan(a).content == make_test_plan(b).content
    changed_time = a.model_copy(update={"created_at": a.created_at.replace(year=2000)})
    assert make_test_plan(changed_time).plan_id == make_test_plan(a).plan_id
    config_changed = specify(candidate, facts, SplitConfig(bucket_count=7))
    assert config_changed.specification_id != a.specification_id
    assert config_changed.content.partition.split_id != a.content.partition.split_id
    newer_binding = BINDING.model_copy(
        update=dict.fromkeys(
            ("dataset_id", "dataset_version", "manifest_digest"),
            "a" * 64,
        )
    )
    assert (
        partition(
            newer_binding,
            facts,
            candidate.content.supporting_sample_refs,
            SplitConfig(),
        ).split_id
        != a.content.partition.split_id
    )
    content = a.content.model_copy(update={"planner_version": "soc-offline-evaluation-planner:v2"})
    assert content_digest(content) != a.specification_id


@pytest.mark.parametrize(
    "data",
    [
        {"bucket_count": 1},
        {"bucket_count": True},
        {"bucket_count": 2.5},
        {"holdout_buckets": 0},
        {"bucket_count": 2, "holdout_buckets": 2},
    ],
)
def test_split_config_validation(data):
    with pytest.raises(ValidationError):
        SplitConfig(**data)


def test_no_active_authority_or_weakened_invariants():
    candidate, facts = candidate_for(CandidateType.PROMPT)
    specification = specify(candidate, facts, SplitConfig())
    for change in (
        {"authority": "APPROVAL"},
        {"evaluation_mode": "PRODUCTION"},
        {"requires_all_hard_invariants": False},
        {"governance_invariants": ()},
        {"regression_invariants": ()},
        {"require_nonempty_complete_holdout": False},
    ):
        data = specification.model_dump()
        data["content"].update(change)
        with pytest.raises(ValidationError):
            EvaluationSpecification.model_validate(data)


def test_metrics_are_definitions_not_new_correctness_judgments():
    candidate, facts = candidate_for(CandidateType.PROMPT)
    original = tuple(f.model_dump_json() for f in facts)
    specification = specify(candidate, facts, SplitConfig())
    assert original == tuple(f.model_dump_json() for f in facts)
    assert any("adjudicat" in m.counting_rule for m in specification.content.metrics)
    assert any("rubric" in m.required_observation.value for m in specification.content.metrics)
    assert all(
        not any(char.isdigit() for char in m.counting_rule) for m in specification.content.metrics
    )
    assert all(
        "threshold" not in criterion.model_dump()
        for criterion in specification.content.acceptance_criteria
    )
