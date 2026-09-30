"""Explicit source ingestion; does not infer attacks or grant workflow authority."""

from soc_agent.ingestion.models import SOCEvent
from soc_agent.ingestion.store import EventIngestor, migrate_ingestion

__all__ = ["SOCEvent", "EventIngestor", "migrate_ingestion"]
