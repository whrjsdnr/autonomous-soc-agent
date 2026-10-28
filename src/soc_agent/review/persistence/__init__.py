"""Persistent governance exports without loading AI inference during Controller startup."""

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from soc_agent.review.persistence.models import CommitOutcomeUnknown as CommitOutcomeUnknown
    from soc_agent.review.persistence.models import (
        FailureAuditUnavailable as FailureAuditUnavailable,
    )
    from soc_agent.review.persistence.models import StorageError as StorageError
    from soc_agent.review.persistence.models import StoredDataError as StoredDataError
    from soc_agent.review.persistence.models import UnsupportedSchemaError as UnsupportedSchemaError
    from soc_agent.review.persistence.service import (
        PersistentHumanReviewService as PersistentHumanReviewService,
    )
    from soc_agent.review.persistence.store import SQLiteGovernanceStore as SQLiteGovernanceStore

_EXPORTS = {
    "CommitOutcomeUnknown": "soc_agent.review.persistence.models",
    "FailureAuditUnavailable": "soc_agent.review.persistence.models",
    "PersistentHumanReviewService": "soc_agent.review.persistence.service",
    "SQLiteGovernanceStore": "soc_agent.review.persistence.store",
    "StorageError": "soc_agent.review.persistence.models",
    "StoredDataError": "soc_agent.review.persistence.models",
    "UnsupportedSchemaError": "soc_agent.review.persistence.models",
}
__all__ = list(_EXPORTS)


def __getattr__(name: str):
    try:
        module = _EXPORTS[name]
    except KeyError:
        raise AttributeError(name) from None
    return getattr(import_module(module), name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_EXPORTS))
