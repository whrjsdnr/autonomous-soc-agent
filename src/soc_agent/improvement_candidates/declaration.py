"""Explicit advisory proposal declaration. The analyst-pattern generator is unchanged."""

from soc_agent.improvement_candidates.models import (
    DECLARATION_VERSION,
    CoverageProposal,
    ImprovementCandidate,
    InvestigationProposal,
    ReviewFocus,
)
from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.tools.models import ReadOnlyPermission


def declare_coverage(
    review: ImprovementCandidate, required_permission: ReadOnlyPermission
) -> ImprovementCandidate:
    review = ImprovementCandidate.model_validate(review.model_dump())
    if not isinstance(review.content.proposal, InvestigationProposal) or (
        review.content.proposal.focus != ReviewFocus.MISSED_INVESTIGATION
    ):
        raise StoredDataError("Coverage declaration requires MISSED_INVESTIGATION strategy review")
    proposal = CoverageProposal(
        required_permission=required_permission,
        review_candidate=ArtifactReference(
            identity=review.candidate_id, digest=content_digest(review.content)
        ),
    )
    content = type(review.content).model_validate(
        review.content.model_dump()
        | {
            "schema_version": "improvement-candidate:v2",
            "generator_version": DECLARATION_VERSION,
            "proposal": proposal.model_dump(),
        }
    )
    digest = content_digest(content)
    return ImprovementCandidate(candidate_id=digest, candidate_version=digest, content=content)
