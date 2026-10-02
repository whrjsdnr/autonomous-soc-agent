"""Fixed advisory review rules. No configuration patch or causal inference."""

from soc_agent.improvement_candidates.models import (
    CandidateContent,
    FailurePattern,
    ImprovementCandidate,
    InvestigationProposal,
    PatternType,
    PromptProposal,
    ReviewFocus,
    RuleProposal,
    ToolSelectionProposal,
)
from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.review.identity import content_digest


def generate(pattern: FailurePattern) -> tuple[ImprovementCandidate, ...]:
    c = pattern.content
    focus = (
        ReviewFocus(c.pattern_type.value.removesuffix("_pattern") + "_label_review")
        if (
            c.pattern_type
            in {
                PatternType.FALSE_POSITIVE,
                PatternType.FALSE_NEGATIVE,
                PatternType.UNNECESSARY_INVESTIGATION,
                PatternType.MISSED_INVESTIGATION,
            }
        )
        else {
            PatternType.INCORRECT: ReviewFocus.HUMAN_INCORRECT,
            PatternType.EXECUTION_FAILURE: ReviewFocus.EXECUTION_FAILURE,
            PatternType.EXECUTION_UNCERTAINTY: ReviewFocus.EXECUTION_UNCERTAINTY,
            PatternType.RECOVERY: ReviewFocus.RECOVERY,
        }[c.pattern_type]
    )
    proposals = []
    if c.pattern_type in {
        PatternType.INCORRECT,
        PatternType.FALSE_POSITIVE,
        PatternType.FALSE_NEGATIVE,
    }:
        proposals.append(PromptProposal(focus=focus))
    if c.pattern_type in {PatternType.UNNECESSARY_INVESTIGATION, PatternType.MISSED_INVESTIGATION}:
        proposals.append(InvestigationProposal(focus=focus))
    if c.pattern_type in {PatternType.FALSE_NEGATIVE, PatternType.MISSED_INVESTIGATION}:
        proposals.append(ToolSelectionProposal(focus=focus))
    if c.pattern_type in {
        PatternType.EXECUTION_FAILURE,
        PatternType.EXECUTION_UNCERTAINTY,
        PatternType.RECOVERY,
    }:
        proposals.append(RuleProposal(focus=focus))
    candidates = []
    for proposal in proposals:
        content = CandidateContent(
            dataset=c.dataset,
            candidate_type=proposal.candidate_type,
            # Bind logical pattern content, excluding metadata creation time.
            failure_pattern_refs=(
                ArtifactReference(
                    identity=pattern.pattern_id,
                    digest=content_digest(c),
                ),
            ),
            supporting_sample_refs=c.supporting_sample_refs,
            proposal=proposal,
            rationale=(
                f"{c.occurrence_count} samples support {c.pattern_type.value}. "
                "This is a review opportunity; root cause remains UNKNOWN."
            ),
            expected_effect=(
                "Aim to improve the reviewed category after offline evaluation; "
                "benefit and causal attribution remain unverified."
            ),
        )
        digest = content_digest(content)
        candidates.append(
            ImprovementCandidate(
                candidate_id=digest,
                candidate_version=digest,
                content=content,
            )
        )
    return tuple(sorted(candidates, key=lambda candidate: candidate.candidate_id))
