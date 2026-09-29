"""Fail closed without automatic retry, replan or reapproval."""

from soc_agent.review.errors import ReviewError


class PromotionError(ReviewError):
    pass


class InvalidPromotionArtifact(PromotionError):
    pass


class ResponseReviewRejected(PromotionError):
    pass


class ResponseChangesRequested(PromotionError):
    pass


class IncidentClosed(PromotionError):
    pass


class PromotionToolMissing(PromotionError):
    pass


class ToolMetadataChanged(PromotionError):
    pass


class InputSchemaChanged(PromotionError):
    pass


class PromotionInputInvalid(PromotionError):
    pass


class PromotionPolicyDenied(PromotionError):
    pass


class PromotionPolicyChanged(PromotionError):
    pass
