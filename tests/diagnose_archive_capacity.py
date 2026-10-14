"""Five-minute isolated native capacity observation, no archive executor or model/LLM."""

import argparse
import asyncio
import json
import time
from pathlib import Path

from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.archive import ArchiveRequest, archive_manifest
from soc_agent.security_ai.operational.authentication_investigation import read_authentication_view
from soc_agent.security_ai.operational.capacity import capacity_observation, record_capacity
from soc_agent.security_ai.operational.journal_health import collect_with_health
from soc_agent.security_ai.operational.native_authentication import LinuxAuthenticationCollector
from soc_agent.security_ai.operational.retention import MaintenanceLog
from tests.authentication_crash_harness import open_pipeline, security_check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=300)
    args = parser.parse_args()
    if not args.directory.is_absolute() or args.directory.exists() or not 1 <= args.seconds <= 7200:
        parser.error("New private path/bounded duration required")
    create_private_directory(args.directory, exist_ok=False)
    collector = LinuxAuthenticationCollector(include_pam_failures=True)
    p = open_pipeline(args.directory / "native", collector.identity, create=True)
    log = MaintenanceLog.create(args.directory / "native" / "maintenance.sqlite", p)
    output = args.directory / "samples.jsonl"
    create_private_file(output)
    started = time.monotonic()
    last = None
    count = 0
    with exclusive_runtime_lock(args.directory / "native" / "writer.lock"):
        while True:
            health = collect_with_health(p, collector, audit=log, limit=128 if count == 0 else 16)
            if not health.continuation_allowed:
                raise ValueError("NATIVE_CONTINUATION_BLOCKED")
            for _ in range(384):
                if p.step() == "IDLE":
                    break
            else:
                raise ValueError("DRAIN_LIMIT")
            current = capacity_observation(p, previous=last)
            record_capacity(log, current)
            with output.open("a") as stream:
                stream.write(
                    json.dumps(
                        {
                            "elapsed_seconds": time.monotonic() - started,
                            "observation": current.model_dump(mode="json"),
                        },
                        allow_nan=False,
                    )
                    + "\n"
                )
            last = current
            count += 1
            if time.monotonic() - started >= args.seconds:
                break
            time.sleep(min(10, max(0, args.seconds - (time.monotonic() - started))))
        view = read_authentication_view(p)
        manifests = []
        with p.store.database.transaction(write=False) as c:
            sources = [p.store._decode(r) for r in c.execute("SELECT * FROM operational_sources")]
        for source in sources:
            request = ArchiveRequest(
                incident_id=p.incident_id,
                source_event_ids=(source.event.event_id,),
                expected_source_digests=(source.content_digest,),
            )
            manifest = archive_manifest(p, request)
            assert (
                not manifest.archive_execution_allowed and manifest.readiness_status == "PROTECTED"
            )
            manifests.append(manifest.model_dump(mode="json"))
        result = {
            "elapsed_seconds": time.monotonic() - started,
            "sample_count": count,
            "data_kind": "REAL_OS",
            "queue_records": view.queue_records_persisted,
            "authentication_events": view.authentication_events_verified,
            "manifest_count": len(manifests),
            "manifests": manifests,
            "last_observation": last.model_dump(mode="json"),
            "security": asyncio.run(security_check(p)),
            "audit_entry_count": len(log.entries()),
        }
        create_private_file(args.directory / "results.json")
        (args.directory / "results.json").write_text(json.dumps(result, indent=2, allow_nan=False))
    print(
        json.dumps(
            {
                "elapsed_seconds": result["elapsed_seconds"],
                "sample_count": count,
                "native_authentication_events": view.authentication_events_verified,
                "status": last.status,
            }
        )
    )


if __name__ == "__main__":
    main()
