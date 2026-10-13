"""Offline external Security AI replay through the shared Desktop/Headless SOC runtime."""

import argparse
import asyncio
import json
import os
import stat
from pathlib import Path
from uuid import UUID

from soc_agent._json import canonical_json_object
from soc_agent.application import compose_application
from soc_agent.deployment import DeploymentDescriptor
from soc_agent.desktop import OfflineDesktopClient, initialize, source_report_tool, writer_lock
from soc_agent.ingestion import EventIngestor
from soc_agent.local_events import InputIssue, LocalJSONLSource
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StorageError
from soc_agent.security_ai.external.metadata import reviewed_binding
from soc_agent.security_ai.external.models import (
    IncidentAssociation,
    Profile,
    Snapshot,
    SourceEvidenceReference,
    SourceFeatureObservation,
    content_digest_payload,
)
from soc_agent.security_ai.external.read_only_backend import CapabilityDenied
from soc_agent.security_ai.external.runtime_store import RuntimeGovernanceStore
from soc_agent.security_ai.external.service import ModelInput
from soc_agent.state import Evidence
from soc_agent.tools import ToolRegistry

CODE_PIN = "56293972d069dffaf564a390ab7a4c4554c2a2a5b2ab6be6f6f758b5ea3cce44"
CONTRACT = content_digest_payload(
    {"runtime": "soc-external-runtime:v1", "schema": 16, "disposition": "READ_ONLY"}
)


class FeatureRow(Snapshot):
    event_id: UUID
    profiles: tuple[Profile, ...]
    observation: SourceFeatureObservation


def read_features(path: Path) -> dict[UUID, list[FeatureRow]]:
    # Reuse the bounded regular-file/symlink/UTF-8 validation at the local input boundary.
    from soc_agent.local_events import explicit_path

    path = explicit_path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > 4 * 1024 * 1024:
        raise ValueError("Bounded regular feature file required")
    for component in (path, *path.parents):
        if getattr(component.stat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("Reparse feature paths rejected")
    result = {}
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("Feature source changed during open")
        consumed = 0
        for count in range(1001):
            line = stream.readline(256 * 1024 + 1)
            if not line:
                break
            consumed += len(line)
            if count == 1000 or len(line) > 256 * 1024 or consumed > before.st_size:
                raise ValueError("Feature replay limit exceeded")
            row = FeatureRow.model_validate_json(line)
            if row.observation.association is not None:
                raise ValueError("Input cannot assign a repository or incident association")
            if not row.profiles or len(set(row.profiles)) != len(row.profiles):
                raise ValueError("Explicit unique model profiles required")
            result.setdefault(row.event_id, []).append(row)
    return result


def bind_features(store, incident_id: UUID, rows: list[FeatureRow]) -> tuple[ModelInput, ...]:
    # Source Evidence describes the supplied feature file, never a model prediction.
    current = store.load(incident_id)
    seen = {}
    pending = []
    for row in rows:
        observation = row.observation
        if observation.source_event_id != str(row.event_id):
            raise ValueError("Feature source event identity mismatch")
        if observation.event_time_end is None:
            raise ValueError("Explicit source timestamp required")
        if observation.observation_key not in seen:
            evidence = Evidence(
                incident_id=incident_id,
                source=observation.source_namespace,
                summary="Synthetic precomputed feature input; extraction assurance unverified",
                raw_data=canonical_json_object(observation.source_payload()),
                observed_at=observation.event_time_end,
            )
            current = store.append_evidence(current.anchor, evidence)
            seen[observation.observation_key] = evidence
        pending.append((row, seen[observation.observation_key]))
    inputs = []
    for row, evidence in pending:
        observation = row.observation.model_copy(
            update={
                "association": IncidentAssociation(
                    incident_id=incident_id,
                    snapshot=current.anchor,
                    source_evidence_references=(
                        SourceEvidenceReference(
                            evidence_id=evidence.evidence_id,
                            content_digest=content_digest(evidence),
                        ),
                    ),
                )
            }
        )
        for profile in row.profiles:
            binding = reviewed_binding(
                profile, expected_code_identity=CODE_PIN, runtime_contract_digest=CONTRACT
            )
            inputs.append(ModelInput(binding=binding, observation=observation))
    return tuple(inputs)


async def replay(application, events: Path, features: dict[UUID, list[FeatureRow]]) -> int:
    service = application.service
    for event in LocalJSONLSource(events).events():
        if isinstance(event, InputIssue):
            raise ValueError("Invalid event source schema")
        incident = service.ingest(event).incident_id
        if event.event_id in features:
            # Existing context is resumed without rerunning inference or replacing source data.
            if service.store.boundary.binding(incident) is None:
                inputs = bind_features(service.store, incident, features[event.event_id])
                service.analyze_external(incident, inputs)
        runtime = service.runtime_factory()
        with service.store.database.transaction(write=False) as connection:
            exists = connection.execute(
                "SELECT 1 FROM workflow_checkpoints WHERE incident_id=?", (str(incident),)
            ).fetchone()
        if exists:
            runtime.restore(incident)
        else:
            runtime.start(incident)
        for _ in range(32):
            result = await runtime.advance(incident)
            if result.waiting_for_human or result.terminal:
                break
        else:
            raise ValueError("Explicit runtime budget exceeded")
        print(
            json.dumps(
                {
                    "incident_id": str(incident),
                    "workflow": result.next_step.value,
                    "human_boundary": result.waiting_for_human,
                    "context_available": service.store.boundary.binding(incident) is not None,
                },
                ensure_ascii=True,
            )
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--external-features", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--native-python", type=Path)
    parser.add_argument("--profile", choices=("DESKTOP", "SERVER"), default="DESKTOP")
    args = parser.parse_args()
    if os.name == "nt" and args.profile != "DESKTOP":
        parser.error("Windows Server deployment is not supported")
    try:
        features = read_features(args.external_features)
        if args.profile == "DESKTOP":
            application = initialize(
                args.directory,
                external_artifacts=args.artifacts,
                external_interpreter=args.native_python,
            )
            directory = args.directory
        else:
            path = args.directory / "external-validation.sqlite"
            store = (
                RuntimeGovernanceStore(path)
                if path.exists()
                else RuntimeGovernanceStore.create_isolated(args.directory)
            )
            ingestion = EventIngestor(store)
            registry = ToolRegistry()
            registry.register(source_report_tool(ingestion))
            application = compose_application(
                store,
                deployment=DeploymentDescriptor(profile="SERVER"),
                registry=registry,
                ingestion=ingestion,
                llm_client=OfflineDesktopClient(),
                external_artifacts=args.artifacts,
                external_interpreter=args.native_python,
            )
            directory = args.directory
        with writer_lock(directory):
            return asyncio.run(replay(application, args.input, features))
    except (ValueError, OSError, ImportError, StorageError, CapabilityDenied):
        print("External runtime configuration/input/inference unavailable; no fallback")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
