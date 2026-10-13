"""Bounded local input coordinator for the existing durable SOC runtime."""

import argparse
import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from soc_agent.demo.command_center import MARKER, DemoManifest, manifest, open_demo, prepare
from soc_agent.ingestion.models import Event
from soc_agent.llm.openai_compatible import OpenAICompatibleClient, OpenAICompatibleSettings
from soc_agent.runtime_driver import advance_until_stopped
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.packaging import ModelPackage, load_package

MAX_LINE = 128 * 1024


def publish(directory: Path, value: DemoManifest) -> None:
    """Atomic observation allowlist publication, never incident state mutation."""
    temporary = directory / (MARKER + ".pending")
    temporary.write_text(value.model_dump_json(), encoding="utf-8")
    temporary.replace(directory / MARKER)


def initialize(
    directory: Path,
    *,
    real_llm: bool = False,
    model_analysis=None,
    packages: Sequence[ModelPackage] = (),
):
    # Validate requested provider before touching any directory. No .env loading/fallback.
    client = None
    if real_llm:
        try:
            client = OpenAICompatibleClient(OpenAICompatibleSettings())
        except ValidationError:
            raise ValueError(
                "CONFIGURATION: required SOC_LLM settings unavailable or invalid"
            ) from None
    existed = (directory / MARKER).exists()
    prepare(directory)
    value = manifest(directory)
    if existed and value.mode != "live-local":
        raise ValueError("Snapshot directory cannot be converted into live runtime data")
    if not existed:
        publish(directory, value.model_copy(update={"mode": "live-local"}))
    return open_demo(directory, llm_client=client, model_analysis=model_analysis, packages=packages)


async def process_event(service, directory: Path, event: Event, *, notify=print):
    """Reuse ingestion/start/step with pinned revisions; never submit execution authority."""
    if (
        not event.synthetic
        or event.source != "synthetic-demo"
        or event.subject not in ("demo-alice", "demo-bob", "demo-network-host")
    ):
        raise ValueError("INPUT: only explicit synthetic authentication/network reports supported")
    value = manifest(directory)
    if value.mode != "live-local":
        raise ValueError("Explicit live local directory required")
    if len(value.incidents) >= 1000 and event.event_id not in {
        service.ingestion.load(identity).event.event_id for identity in value.incidents
    }:
        raise ValueError("Local incident limit reached")
    result = service.ingest(event)
    identity = result.incident_id
    publish(
        directory,
        value.model_copy(update={"incidents": tuple(sorted(set(value.incidents) | {identity}))}),
    )
    return await advance_until_stopped(service, identity, notify=notify)


async def consume(service, directory, stream):
    failed = False
    while True:
        line = stream.readline(MAX_LINE + 1)
        if not line:
            break
        if len(line) > MAX_LINE:
            print("INPUT: line limit exceeded; stopped", file=sys.stderr)
            return 1
        if not line.strip():
            continue
        try:
            event = TypeAdapter(Event).validate_json(line)
            result = await process_event(service, directory, event)
            if result.failure is not None and not result.waiting_for_human:
                print(f"Workflow failure: {result.failure}; no retry", file=sys.stderr)
                failed = True
        except Exception:
            # Do not echo input, provider body, configuration or sensitive exception values.
            # No retry; a subsequent independent event may still be processed.
            print("Event failed; inspect durable checkpoint. No automatic retry.", file=sys.stderr)
            failed = True
    return int(failed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--input", type=Path, help="Synthetic JSONL; omitted reads stdin")
    parser.add_argument(
        "--real-llm", action="store_true", help="Explicit provider opt-in; no fallback"
    )
    for name in ("auth", "network-classifier", "network-anomaly"):
        parser.add_argument(f"--{name}-package", type=Path)
        parser.add_argument("--manifest-digest" if name == "auth" else f"--{name}-digest")
    args = parser.parse_args()
    try:
        packages = []
        for name, kind in (
            ("auth", "authentication_anomaly"),
            ("network_classifier", "network_classifier"),
            ("network_anomaly", "network_anomaly"),
        ):
            path = getattr(args, name + "_package")
            pin = args.manifest_digest if name == "auth" else getattr(args, name + "_digest")
            if bool(path) != bool(pin):
                raise ValueError(
                    "Explicit package path and trusted manifest digest required together"
                )
            if path:
                package = load_package(path, expected_manifest_digest=pin)
                if package.manifest.model_kind != kind:
                    raise ValueError("Configured model kind differs from package")
                packages.append(package)
        service = initialize(args.directory, real_llm=args.real_llm, packages=packages)
        with exclusive_runtime_lock(args.directory / "runtime.lock"):
            print("LIVE LOCAL RUNTIME · SYNTHETIC inputs · no privileged execution", flush=True)
            if args.input:
                with args.input.open(encoding="utf-8") as stream:
                    return asyncio.run(consume(service, args.directory, stream))
            return asyncio.run(consume(service, args.directory, sys.stdin))
    except KeyboardInterrupt:
        return 0
    except Exception:
        print("CONFIGURATION / STARTUP: local runtime unavailable; no fallback", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
