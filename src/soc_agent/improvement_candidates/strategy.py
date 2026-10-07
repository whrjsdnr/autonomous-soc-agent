"""Compile explicit structured fields only; never interpret advisory prose."""

from soc_agent.improvement_candidates.models import CoverageProposal, ImprovementCandidate
from soc_agent.planning.strategy import InvestigationStrategy


class UnsupportedStrategyProposal(ValueError):
    """This candidate has no supported declarative strategy semantics."""


def compile_candidate_strategy(candidate: ImprovementCandidate) -> InvestigationStrategy:
    candidate = ImprovementCandidate.model_validate(candidate.model_dump())
    proposal = candidate.content.proposal
    if not isinstance(proposal, CoverageProposal):
        raise UnsupportedStrategyProposal(
            "Only explicit read-only coverage proposals are supported"
        )
    return InvestigationStrategy(required_permissions=(proposal.required_permission,))
