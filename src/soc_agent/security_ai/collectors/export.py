"""Explicit local diagnostic export. Never emits an inference receipt or security finding."""

import json
from pathlib import Path

from soc_agent.review.persistence.secure_storage import create_private_file


def export(collector, path: Path, format: str) -> dict:
    if format not in {"json", "markdown"}:
        raise ValueError("ZEEK_EXPORT_FORMAT_REJECTED")
    collector.store.verify()
    snapshot = collector.snapshot()
    value = dict(
        contract="soc-zeek-diagnostic-export:v1",
        source=collector.store.source.model_dump(mode="json"),
        events=snapshot["collector"]["events"],
        parity=snapshot["collector"]["parity"],
        audit_digest=collector.store.runtime.verify_audit(),
        inference_receipts=[],
        investigation="BLOCKED_NO_VERIFIED_AI_RECEIPT",
        research_only=True,
        operational_gate="BLOCKED",
        write_policy="WRITE_DENIED",
    )
    body = json.dumps(value, indent=2, sort_keys=True)
    if format == "markdown":
        body = (
            "# Zeek offline diagnostics\n\nNot an AI finding. "
            "Network14 / DNS9 parity BLOCKED.\n\n```json\n" + body + "\n```\n"
        )
    # Existing secure helper enforces private parent, no replacement or symlink writes.
    create_private_file(path)
    path.write_text(body)
    return dict(status="EXPORTED_DIAGNOSTICS_ONLY", events=len(value["events"]), format=format)
