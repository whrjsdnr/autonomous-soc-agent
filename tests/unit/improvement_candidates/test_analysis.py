import hashlib
from uuid import UUID

import pytest
from pydantic import ValidationError

from soc_agent.experience.models import GovernanceOutcome, HistoricalOutcome
from soc_agent.feedback.models import DiagnosticLabel as Label
from soc_agent.feedback.models import Verdict
from soc_agent.improvement_candidates import (
    AnalysisConfig,
    CandidateType,
    PatternType,
)
from soc_agent.improvement_candidates.analysis import analyze
from soc_agent.improvement_candidates.generation import generate
from soc_agent.improvement_candidates.models import (
    DatasetBinding,
    ImprovementCandidate,
    SampleFacts,
)
from soc_agent.improvement_dataset.models import (
    ArtifactReference,
    ImprovementSample,
    ObjectiveContext,
    SampleContent,
    SourceSnapshot,
)
from soc_agent.investigation.runtime.models import WorkflowStep
from soc_agent.review.persistence.models import StoredDataError


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


BINDING = DatasetBinding(
    **dict.fromkeys(
        ("dataset_id", "dataset_version", "manifest_digest"),
        digest("dataset"),
    )
)


def fact(
    number,
    labels=(),
    verdict=Verdict.INCORRECT,
    outcome=HistoricalOutcome.NOT_EXECUTED,
    recovery=False,
    uncertain=False,
):
    def ref(kind):
        identity = digest(f"{kind}-{number}")
        return ArtifactReference(identity=identity, digest=identity)

    sources = SourceSnapshot(
        incident_id=UUID(int=number),
        experience=ref("experience"),
        evaluation=ref("evaluation"),
        feedback=(ref("feedback"),),
    )
    objective = ObjectiveContext(
        current_step=WorkflowStep.DECIDE,
        next_step=WorkflowStep.GOVERN,
        terminal=False,
        waiting_for_human=True,
        workflow_failure=None,
        governance_outcome=GovernanceOutcome.WAITING,
        execution_outcome=outcome,
        orchestration_step_count=5,
        analysis_observed=True,
        fusion_observed=False,
    )
    content = SampleContent(sources=sources, verdict=verdict, labels=labels, objective=objective)
    from soc_agent.review.identity import content_digest

    sample = ImprovementSample(sample_id=content_digest(content), content=content)
    return SampleFacts(
        sample=ArtifactReference(identity=sample.sample_id, digest=content_digest(sample)),
        sources=sources,
        objective=objective,
        verdict=verdict,
        labels=labels,
        recovery_observed=recovery,
        uncertain_observed=uncertain,
        reconciliation_observed=False,
    )


@pytest.mark.parametrize(
    "kind,options,expected_types",
    [
        (PatternType.FALSE_POSITIVE, {"labels": (Label.FALSE_POSITIVE,)}, {CandidateType.PROMPT}),
        (
            PatternType.FALSE_NEGATIVE,
            {"labels": (Label.FALSE_NEGATIVE,)},
            {CandidateType.PROMPT, CandidateType.TOOL_SELECTION_STRATEGY},
        ),
        (
            PatternType.UNNECESSARY_INVESTIGATION,
            {"labels": (Label.UNNECESSARY_INVESTIGATION,)},
            {CandidateType.INVESTIGATION_STRATEGY},
        ),
        (
            PatternType.MISSED_INVESTIGATION,
            {"labels": (Label.MISSED_INVESTIGATION,)},
            {CandidateType.INVESTIGATION_STRATEGY, CandidateType.TOOL_SELECTION_STRATEGY},
        ),
        (
            PatternType.EXECUTION_FAILURE,
            {"outcome": HistoricalOutcome.FAILED},
            {CandidateType.RULE},
        ),
        (
            PatternType.EXECUTION_UNCERTAINTY,
            {"outcome": HistoricalOutcome.UNCERTAIN},
            {CandidateType.RULE},
        ),
        (PatternType.RECOVERY, {"recovery": True}, {CandidateType.RULE}),
        (PatternType.INCORRECT, {}, {CandidateType.PROMPT}),
    ],
)
def test_grounded_support_and_structured_reviews(kind, options, expected_types):
    facts = (fact(2, **options), fact(1, **options), fact(3, verdict=Verdict.CORRECT))
    patterns = analyze(BINDING, facts, AnalysisConfig())
    (pattern,) = (p for p in patterns if p.content.pattern_type == kind)
    assert pattern.content.occurrence_count == 2
    assert pattern.content.root_cause_status == "UNKNOWN"
    expected_support = tuple(sorted((facts[0].sample, facts[1].sample), key=lambda r: r.identity))
    assert pattern.content.supporting_sample_refs == expected_support
    assert pattern.content.supporting_feedback_refs == tuple(
        sorted(
            (facts[0].sources.feedback[0], facts[1].sources.feedback[0]),
            key=lambda r: r.identity,
        )
    )
    assert pattern.content.observed_facts == tuple(
        sorted(facts[:2], key=lambda f: f.sample.identity)
    )
    candidates = generate(pattern)
    assert {c.content.candidate_type for c in candidates} == expected_types
    for candidate in candidates:
        c = candidate.content
        assert c.dataset == BINDING
        assert c.failure_pattern_refs[0].identity == pattern.pattern_id
        assert c.supporting_sample_refs == expected_support
        assert c.authority == "ADVISORY" and c.status == "PROPOSED"
        assert c.requires_offline_evaluation and c.requires_human_approval
        assert c.proposal.operation == "REVIEW" and c.proposal.target_version is None
        assert "unverified" in c.expected_effect
        assert not any(char.isdigit() for char in c.expected_effect)
        assert not any(char.isdigit() for char in str(c.proposal.model_dump()))
        assert "UNKNOWN" in c.rationale
        assert candidate.candidate_id == candidate.candidate_version
        with pytest.raises(ValidationError):
            candidate.content.authority = "EXECUTE"


def test_minimum_support_config_binding_and_determinism():
    facts = (fact(1, labels=(Label.FALSE_POSITIVE,)), fact(2, labels=(Label.FALSE_POSITIVE,)))
    assert analyze(BINDING, facts[:1], AnalysisConfig()) == ()
    assert analyze(BINDING, facts, AnalysisConfig(minimum_pattern_support=3)) == ()
    a = analyze(BINDING, facts, AnalysisConfig())
    b = analyze(BINDING, tuple(reversed(facts)), AnalysisConfig())
    assert tuple(p.content for p in a) == tuple(p.content for p in b)
    assert tuple(p.pattern_id for p in a) == tuple(p.pattern_id for p in b)
    for first, second in zip(a, b, strict=True):
        assert tuple(c.content for c in generate(first)) == tuple(
            c.content for c in generate(second)
        )
    three = facts + (fact(3, labels=(Label.FALSE_POSITIVE,)),)
    low = analyze(BINDING, three, AnalysisConfig())
    high = analyze(BINDING, three, AnalysisConfig(minimum_pattern_support=3))
    assert {p.pattern_id for p in low}.isdisjoint({p.pattern_id for p in high})
    assert all(f.verdict == Verdict.INCORRECT for f in facts)
    with pytest.raises(StoredDataError):
        analyze(BINDING, facts + facts, AnalysisConfig())


@pytest.mark.parametrize("value", [0, 1, True, 2.5])
def test_support_config_validation(value):
    with pytest.raises(ValidationError):
        AnalysisConfig(minimum_pattern_support=value)


def test_operational_facts_do_not_infer_incorrectness_or_human_rejection_failure():
    facts = tuple(
        fact(i, verdict=Verdict.CORRECT, outcome=HistoricalOutcome.FAILED) for i in (1, 2)
    )
    patterns = analyze(BINDING, facts, AnalysisConfig())
    assert {p.content.pattern_type for p in patterns} == {PatternType.EXECUTION_FAILURE}
    assert all(f.verdict == Verdict.CORRECT for f in patterns[0].content.observed_facts)
    rejected = tuple(fact(i, verdict=Verdict.CORRECT) for i in (1, 2))
    from soc_agent.improvement_dataset.models import ImprovementSample, SampleContent
    from soc_agent.review.identity import content_digest

    updated = []
    for f in rejected:
        objective = f.objective.model_copy(
            update={
                "governance_outcome": GovernanceOutcome.HUMAN_REJECTED,
            }
        )
        content = SampleContent(
            sources=f.sources, verdict=f.verdict, labels=f.labels, objective=objective
        )
        sample = ImprovementSample(sample_id=content_digest(content), content=content)
        updated.append(
            SampleFacts.model_validate(
                f.model_dump()
                | {
                    "objective": objective,
                    "sample": ArtifactReference(
                        identity=sample.sample_id, digest=content_digest(sample)
                    ),
                }
            )
        )
    rejected = tuple(updated)
    assert analyze(BINDING, rejected, AnalysisConfig()) == ()


def test_historical_uncertainty_is_distinct_from_current_execution_failure():
    facts = tuple(
        fact(
            i,
            verdict=Verdict.CORRECT,
            outcome=HistoricalOutcome.SUCCEEDED,
            recovery=True,
            uncertain=True,
        )
        for i in (1, 2)
    )
    patterns = analyze(BINDING, facts, AnalysisConfig())
    assert {p.content.pattern_type for p in patterns} == {
        PatternType.EXECUTION_UNCERTAINTY,
        PatternType.RECOVERY,
    }
    assert all(p.content.root_cause_status == "UNKNOWN" for p in patterns)


def test_candidate_rejects_active_authority_and_unsupported_types():
    pattern = analyze(BINDING, (fact(1), fact(2)), AnalysisConfig())[0]
    candidate = generate(pattern)[0]
    for update in (
        {"authority": "POLICY"},
        {"status": "APPROVED"},
        {"status": "PROMOTED"},
        {"requires_offline_evaluation": False},
        {"requires_human_approval": False},
        {"candidate_type": "model_retrain"},
        {"candidate_type": "code_patch"},
        {"proposal": candidate.content.proposal.model_dump() | {"threshold": 0.43}},
    ):
        data = candidate.model_dump()
        data["content"].update(update)
        with pytest.raises(ValidationError):
            ImprovementCandidate.model_validate(data)
