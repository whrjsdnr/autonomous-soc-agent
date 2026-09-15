"""Response planning and lifecycle failures; lower boundary errors retain meaning."""


class ResponseError(Exception):
    """Root response boundary failure."""


class ResponsePlanningError(ResponseError):
    """Invalid draft, catalog, tool input, or oversized context."""


class ResponsePlanMismatchError(ResponseError):
    """Incident provenance does not match."""


class InvalidResponseReferenceError(ResponsePlanningError):
    """Assessment references are absent from the incident."""


class ResponseStepNotFoundError(ResponseError):
    """Unknown response step."""


class ResponseStepStateError(ResponseError):
    """Invalid response lifecycle transition."""
