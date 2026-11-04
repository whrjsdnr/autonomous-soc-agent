"""Source contracts without composing investigation/inference during import."""

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from soc_agent.ingestion.models import SOCEvent as SOCEvent
    from soc_agent.ingestion.store import EventIngestor as EventIngestor
    from soc_agent.ingestion.store import migrate_ingestion as migrate_ingestion

_EXPORTS = {
    "SOCEvent": "soc_agent.ingestion.models",
    "EventIngestor": "soc_agent.ingestion.store",
    "migrate_ingestion": "soc_agent.ingestion.store",
}
__all__ = list(_EXPORTS)


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(name)
    value = getattr(import_module(_EXPORTS[name]), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_EXPORTS))
