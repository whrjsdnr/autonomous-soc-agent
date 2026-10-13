"""Retained flow reports become source records, never model-derived Evidence."""

from uuid import NAMESPACE_URL, uuid5

from soc_agent.ingestion.models import IngestionReceipt
from soc_agent.security_ai.features import SecurityRecord, SourceReference, SourceType


def network_record(receipt: IngestionReceipt) -> SecurityRecord:
    event = receipt.event
    if event.event_type != "network":
        raise ValueError("Network record requires a network source report")
    return SecurityRecord(
        record_id=uuid5(NAMESPACE_URL, f"soc-network:{event.event_id}"),
        incident_id=receipt.incident_id,
        record_type="network_flow",
        record_schema_version="1.0.0",
        source=event.source,
        source_reference=SourceReference(
            source_type=SourceType.STREAM, source_name=event.source, record_id=str(event.event_id)
        ),
        observed_at=event.occurred_at,
        fields=event.attributes.model_dump(),
    )
