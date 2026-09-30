"""Reuse the existing authentication source/feature contract without inventing attempts."""

from uuid import NAMESPACE_URL, uuid5

from soc_agent.ingestion.models import IngestionReceipt
from soc_agent.security_ai.authentication.aggregation import authentication_record
from soc_agent.security_ai.features import SecurityRecord, SourceReference, SourceType


def authentication_records(receipt: IngestionReceipt) -> tuple[SecurityRecord, ...]:
    records = []
    for attempt in receipt.event.attributes.attempts:
        record = authentication_record(
            attempt,
            source=SourceReference(
                source_type=SourceType.STREAM,
                source_name=receipt.event.source,
                record_id=f"{receipt.event.event_id}:{attempt.event_id}",
            ),
        )
        records.append(
            SecurityRecord.model_validate(
                {
                    **record.model_dump(),
                    "incident_id": receipt.incident_id,
                    "record_id": uuid5(
                        NAMESPACE_URL, f"soc-auth:{receipt.event.event_id}:{attempt.event_id}"
                    ),
                }
            )
        )
    return tuple(records)
