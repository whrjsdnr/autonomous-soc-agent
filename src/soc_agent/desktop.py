"""Desktop file replay through the shared SOC Core; no GUI or HTTP listener."""

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ValidationError

from soc_agent.application import (
    ApplicationComposition,
    ModelAnalysis,
    compose_application,
    open_application_store,
)
from soc_agent.deployment import DeploymentDescriptor, DeploymentProfile
from soc_agent.ingestion import EventIngestor, migrate_ingestion
from soc_agent.llm import LLMClient
from soc_agent.llm.models import LLMRequest
from soc_agent.llm.openai_compatible import OpenAICompatibleClient, OpenAICompatibleSettings
from soc_agent.local_events import InputIssue, LocalJSONLSource, LocalSourceError, explicit_path
from soc_agent.review.models import Frozen
from soc_agent.review.persistence.secure_storage import (
    StorageSecurityError,
    create_private_directory,
    require_supported_platform,
    validate_directory,
)
from soc_agent.runtime_driver import advance_until_stopped
from soc_agent.security_ai.model_analysis import PackagedAnalysis
from soc_agent.security_ai.packaging import ModelPackage, load_package
from soc_agent.tools import Tool, ToolMetadata, ToolPermission, ToolRegistry, ToolRiskLevel

MARKER = "desktop.json"
DESCRIPTOR = '{"profile":"DESKTOP","format_version":1}'


class ReadReportInput(Frozen):
    incident_id: UUID


class SourceReport(Frozen):
    event_id: UUID
    source: str
    occurred_at: str
    canonical_digest: str
    ingestion_version: str
    event_type: Literal["authentication", "network"]
    synthetic: bool
    record_count: int
    meaning: Literal["source_report_not_independently_verified"] = (
        "source_report_not_independently_verified"
    )


def source_report_tool(ingestion: EventIngestor) -> Tool:
    async def read(value: ReadReportInput) -> SourceReport:
        receipt = ingestion.load(value.incident_id)
        event = receipt.event
        return SourceReport(
            event_id=event.event_id,
            source=event.source,
            occurred_at=event.occurred_at.isoformat(),
            canonical_digest=receipt.canonical_digest,
            ingestion_version=receipt.ingestion_version,
            event_type=event.event_type,
            synthetic=event.synthetic,
            record_count=len(event.attributes.attempts)
            if event.event_type == "authentication"
            else 1,
        )

    return Tool(
        ToolMetadata(
            name="read_local_source_report",
            description="Read retained source provenance/counts; not independent verification",
            permission=ToolPermission.SYSTEM_READ,
            risk_level=ToolRiskLevel.READ_ONLY,
        ),
        ReadReportInput,
        SourceReport,
        read,
    )


class OfflineDesktopClient:
    """Scripted planning/advisory, never an LLM prediction or attack classification."""

    async def generate_structured[T: BaseModel](
        self, *, request: LLMRequest, response_model: type[T]
    ) -> T:
        context = json.loads(request.user_prompt)
        if "AVAILABLE TOOLS" in context:
            payload = {
                "goal": "Inspect retained local source report",
                "steps": [
                    {
                        "tool_name": "read_local_source_report",
                        "tool_input": {"incident_id": context["INCIDENT CONTEXT"]["incident_id"]},
                        "purpose": "Inspect source provenance; independent verification required",
                    }
                ],
            }
        else:
            payload = {
                "observations": [],
                "hypotheses": [],
                "assessment": {
                    "severity": "info",
                    "confidence": 0.0,
                    "summary": "OFFLINE advisory; compromise unverified; severity is advisory",
                    "supporting_evidence_ids": [
                        e["evidence_id"] for e in context["EVIDENCE (UNTRUSTED DATA)"]
                    ],
                },
            }
        return response_model.model_validate(payload)


def prepare(directory: Path) -> Path:
    require_supported_platform()
    directory = explicit_path(directory)
    create_private_directory(directory)
    if not directory.is_dir():
        raise LocalSourceError("Application data directory required")
    validate_directory(directory)
    # A private dedicated directory, never silently adopt demo/server/user data.
    if os.name == "posix" and (
        directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077
    ):
        raise LocalSourceError("Private application data directory required")
    marker = directory / MARKER
    if marker.exists():
        if (
            marker.is_symlink()
            or marker.stat().st_size > 256
            or marker.read_text(encoding="utf-8") != DESCRIPTOR
        ):
            raise LocalSourceError("Desktop data descriptor invalid")
    else:
        if any(directory.iterdir()):
            raise LocalSourceError("Empty directory or existing Desktop data required")
        with marker.open("x", encoding="utf-8") as stream:
            stream.write(DESCRIPTOR)
    # Existing storage paths must not redirect to unrelated files.
    for path in directory.iterdir():
        if path.is_symlink():
            raise LocalSourceError("Application data symlinks forbidden")
    return directory


@contextmanager
def writer_lock(directory: Path):
    lock = directory / "desktop-writer.lock"
    try:
        create_private_directory(lock, exist_ok=False)
    except FileExistsError:
        raise LocalSourceError(
            "Desktop writer already active or stale lock requires manual inspection"
        ) from None
    try:
        yield
    finally:
        lock.rmdir()


def initialize(
    directory: Path,
    *,
    packages: Sequence[ModelPackage] = (),
    llm_client: LLMClient | None = None,
    model_analysis: ModelAnalysis | None = None,
    external_artifacts: Path | None = None,
    external_interpreter: Path | None = None,
) -> ApplicationComposition:
    if packages and model_analysis is not None:
        raise ValueError("Select one explicit model analysis composition")
    directory = prepare(directory)
    database = explicit_path(directory / "soc.sqlite")
    if external_artifacts is None:
        store = open_application_store(database, create=not database.exists())
    else:
        from soc_agent.security_ai.external.runtime_store import RuntimeGovernanceStore

        runtime_directory = directory / "external-runtime"
        path = runtime_directory / "external-validation.sqlite"
        store = (
            RuntimeGovernanceStore(path)
            if path.exists()
            else RuntimeGovernanceStore.create_isolated(runtime_directory)
        )
    migrate_ingestion(store)
    ingestion = EventIngestor(store)
    registry = ToolRegistry()
    registry.register(source_report_tool(ingestion))
    return compose_application(
        store,
        deployment=DeploymentDescriptor(profile=DeploymentProfile.DESKTOP),
        external_artifacts=external_artifacts,
        external_interpreter=external_interpreter,
        ingestion=ingestion,
        registry=registry,
        llm_client=llm_client if llm_client is not None else OfflineDesktopClient(),
        model_analysis=model_analysis
        if model_analysis is not None
        else PackagedAnalysis(ingestion, packages),
    )


async def replay(composition: ApplicationComposition, source: LocalJSONLSource) -> int:
    service = composition.service
    failed = False
    for item in source.events():
        if isinstance(item, InputIssue):
            print(f"INPUT line {item.line_number}: {item.reason}", file=sys.stderr)
            failed = True
            continue
        try:
            identity = service.ingest(item).incident_id
            workflow = await advance_until_stopped(service, identity)
            fusion = service.checkpoint(identity).artifacts.assessment
            count = (
                len(fusion.model_derived_context.signals)
                if fusion and fusion.model_derived_context
                else 0
            )
            label = "SYNTHETIC" if item.synthetic else "SOURCE REPORTED"
            print(
                f"Persisted signals: {count} · {label}",
                flush=True,
            )
            if fusion and fusion.model_derived_context:
                context = fusion.model_derived_context
                for coverage in context.coverage:
                    print(f"Model {coverage.model_kind}: {coverage.status}", flush=True)
                print(f"Fusion confidence: {context.confidence_state}", flush=True)
            if workflow.failure is not None and not workflow.waiting_for_human:
                print("Workflow failed; inspect checkpoint. No automatic retry.", file=sys.stderr)
                failed = True
        except Exception:
            # Independent events can continue; never retry an uncertain/failed workflow.
            print(
                "Event processing failed; inspect durable checkpoint. No automatic retry.",
                file=sys.stderr,
            )
            failed = True
    return int(failed)


def startup_diagnostic(stage: str, error: Exception) -> str:
    """Fixed categories only; never interpolate exception text, paths or payloads."""
    if isinstance(error, ImportError):
        category = "dependency_unavailable"
    elif isinstance(error, (AttributeError, NotImplementedError)):
        category = "platform_api_unavailable"
    elif isinstance(error, ValidationError):
        category = "schema_validation"
    elif isinstance(error, OSError):
        category = "file_access"
    elif isinstance(error, ValueError):
        category = "validation"
    else:
        category = "startup_failure"
    return f"INPUT / CONFIGURATION / STARTUP [{stage}:{category}]: Desktop unavailable; no fallback"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        type=Path,
        required=True,
        help="Explicit absolute private application data directory",
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Explicit absolute regular UTF-8 JSONL file; finite replay",
    )
    parser.add_argument(
        "--real-llm", action="store_true", help="Explicit configured provider; no fallback"
    )
    for name in ("auth", "network-classifier", "network-anomaly"):
        parser.add_argument(f"--{name}-package", type=Path)
        parser.add_argument("--manifest-digest" if name == "auth" else f"--{name}-digest")
    args = parser.parse_args()
    stage = "llm_configuration"
    try:
        client = OpenAICompatibleClient(OpenAICompatibleSettings()) if args.real_llm else None
        packages = []
        for name, kind in (
            ("auth", "authentication_anomaly"),
            ("network_classifier", "network_classifier"),
            ("network_anomaly", "network_anomaly"),
        ):
            stage = "package_" + name
            path = getattr(args, name + "_package")
            pin = args.manifest_digest if name == "auth" else getattr(args, name + "_digest")
            if bool(path) != bool(pin):
                raise ValueError("Package and trusted digest required together")
            if path:
                package = load_package(path, expected_manifest_digest=pin)
                if package.manifest.model_kind != kind:
                    raise ValueError("Model kind mismatch")
                packages.append(package)
        stage = "input_path"
        source = LocalJSONLSource(args.input)
        stage = "storage_prepare"
        directory = prepare(args.directory)
        stage = "writer_lock"
        with writer_lock(directory):
            stage = "application_initialize"
            composition = initialize(directory, packages=packages, llm_client=client)
            print(
                "DESKTOP · OFFLINE scripted advisory"
                if client is None
                else "DESKTOP · EXPLICIT provider",
                flush=True,
            )
            stage = "runtime_replay"
            return asyncio.run(replay(composition, source))
    except StorageSecurityError as error:
        print(f"STORAGE SECURITY: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Desktop stopped; durable checkpoint preserved", file=sys.stderr)
        return 0
    except Exception as error:
        print(startup_diagnostic(stage, error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
