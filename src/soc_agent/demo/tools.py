"""Synthetic read/report and simulated WRITE adapters. No OS/network action implementation."""

from typing import Literal
from uuid import UUID

from soc_agent.ingestion.store import EventIngestor
from soc_agent.review.models import Frozen
from soc_agent.tools import Tool, ToolMetadata, ToolPermission, ToolRiskLevel


class DemoIdentityInput(Frozen):
    account_id: Literal["demo-alice", "demo-bob"]


class DemoIdentityOutput(DemoIdentityInput):
    simulated: Literal[True] = True
    real_system_modified: Literal[False] = False
    outcome: Literal["would_disable_demo_identity"] = "would_disable_demo_identity"


async def simulate_disable(value: DemoIdentityInput) -> DemoIdentityOutput:
    return DemoIdentityOutput(account_id=value.account_id)


def demo_response_tool():
    return Tool(
        ToolMetadata(
            name="disable_demo_account",
            description="Simulation only; modifies no real account",
            permission=ToolPermission.SYSTEM_WRITE,
            risk_level=ToolRiskLevel.HIGH,
        ),
        DemoIdentityInput,
        DemoIdentityOutput,
        simulate_disable,
    )


class DemoReadInput(Frozen):
    incident_id: UUID


class DemoReport(Frozen):
    event_id: UUID
    source: str
    occurred_at: str
    canonical_digest: str
    ingestion_version: str
    subject: Literal["demo-alice", "demo-bob"]
    reported_failures: int
    reported_successes: int
    meaning: Literal["synthetic_source_report_not_verified_login_activity"] = (
        "synthetic_source_report_not_verified_login_activity"
    )


def demo_read_tool(ingestor: EventIngestor):
    async def read(value: DemoReadInput):
        receipt = ingestor.load(value.incident_id)
        event = receipt.event
        if not event.synthetic or event.source != "synthetic-demo":
            raise ValueError("Demo reader only handles synthetic demo reports")
        failures = sum(a.authentication_result == "failure" for a in event.attributes.attempts)
        return DemoReport(
            event_id=event.event_id,
            source=event.source,
            occurred_at=event.occurred_at.isoformat(),
            canonical_digest=receipt.canonical_digest,
            ingestion_version=receipt.ingestion_version,
            subject=event.subject,
            reported_failures=failures,
            reported_successes=len(event.attributes.attempts) - failures,
        )

    return Tool(
        ToolMetadata(
            name="read_demo_authentication",
            description="Read bounded synthetic source reports only",
            permission=ToolPermission.SYSTEM_READ,
            risk_level=ToolRiskLevel.READ_ONLY,
        ),
        DemoReadInput,
        DemoReport,
        read,
    )
