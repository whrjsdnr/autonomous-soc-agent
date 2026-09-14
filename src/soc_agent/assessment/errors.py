"""Analysis failures, distinct from LLM boundary failures."""


class AssessmentError(Exception):
    """Root of deterministic assessment failures."""


class NoEvidenceError(AssessmentError):
    """An assessment requires incident evidence."""


class InvalidEvidenceReferenceError(AssessmentError):
    """Analysis references evidence outside the supplied incident."""


class InvalidAnalysisReferenceError(AssessmentError):
    """Assessment references an unknown local observation or hypothesis."""


class InvalidAssessmentDraftError(AssessmentError):
    """The analysis draft is structurally invalid."""


class AssessmentContextTooLargeError(AssessmentError):
    """Projected context exceeds the bounded request size."""
