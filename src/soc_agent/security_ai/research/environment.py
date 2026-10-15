"""Read-only verification of explicit existing project-local research dependencies."""

import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from soc_agent.gui.environment import verified_paths
from soc_agent.local_events import explicit_path
from soc_agent.security_ai.research.models import SPECS, digest

CATALOGUE = "be717132a184f76d3821087f088f735faf6c4a8b6759863919c81a6411994848"


@dataclass(frozen=True)
class Paths:
    ml: Path
    python: Path
    soc_source: Path
    producer_source: Path | None = None


def defaults() -> Paths:
    python, _ = verified_paths()  # Fixed existing isolated interpreter, no installation.
    root = Path(__file__).resolve().parents[4]
    return Paths(root.parent / "ML", python, root / "src")


def read_local(path: Path, limit: int) -> bytes:
    explicit_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o022
            or info.st_size > limit
        ):
            raise ValueError("UNSAFE_RESEARCH_FILE")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            body = stream.read(limit + 1)
        if len(body) > limit:
            raise ValueError("RESEARCH_FILE_LIMIT")
        return body
    finally:
        os.close(fd)


def catalogue() -> dict:
    doc = json.loads(read_local(Path(__file__).with_name("replay.json"), 32 * 1024))
    if doc.pop("manifest_digest") != CATALOGUE or digest(doc) != CATALOGUE:
        raise ValueError("REPLAY_CATALOGUE_TAMPERED")
    return doc


def verify(paths: Paths) -> dict:
    doc = catalogue()
    explicit_path(paths.ml)
    if (
        not paths.python.is_file()
        or paths.python
        != paths.ml.parent / "autonomous-soc-agent/.security-ai-demo/inference/bin/python"
        or paths.python.resolve() != Path(sys.executable).resolve()
    ):
        raise ValueError("RESEARCH_BACKEND_UNAVAILABLE")
    # Paths come from fixed project composition, never GUI fields/request bodies.
    for rel, expected in doc["source_code_sha256"].items():
        body = read_local((paths.producer_source or paths.ml) / rel, 128 * 1024)
        if hashlib.sha256(body).hexdigest() not in [
            expected,
            *doc.get("reviewed_local_source_variants", {}).get(rel, []),
        ]:
            raise ValueError("RESEARCH_PRODUCER_SOURCE_CHANGED")
    for kind in ("raw", "label"):
        body = read_local(paths.ml / doc[kind + "_relative_path"], doc[kind + "_bytes"])
        if (
            len(body) != doc[kind + "_bytes"]
            or hashlib.sha256(body).hexdigest() != doc[kind + "_sha256"]
        ):
            raise ValueError("RESEARCH_SOURCE_DIGEST_MISMATCH")
    models = []
    for profile, spec in SPECS.items():
        root = paths.ml / "models/network-research-v1-final" / spec["directory"]
        if root.is_symlink() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
            raise ValueError("UNSAFE_RESEARCH_ARTIFACT_ROOT")
        manifest = json.loads(read_local(root / "artifact.json", 128 * 1024))
        claimed = manifest.pop("manifest_digest")
        if (
            claimed != spec["manifest"]
            or digest(manifest) != spec["manifest"]
            or manifest["model_id"] != spec["model_id"]
            or manifest["threshold"] != spec["threshold"]
            or manifest["status"] != "RESEARCH_ONLY"
            or manifest["operational_promotion"] is not False
        ):
            raise ValueError("RESEARCH_MANIFEST_MISMATCH")
        if (
            manifest["producer"]["semantic_version"] != "1.1.0"
            or manifest["feature_contract"]["names"] != doc["feature_names"]
            or manifest["sklearn_version"] != "1.9.1"
            or manifest["python_version"] != "3.12.14"
        ):
            raise ValueError("RESEARCH_FEATURE_OR_BACKEND_MISMATCH")
        data = read_local(root / "model.joblib", 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != spec["sha256"]:
            raise ValueError("RESEARCH_ARTIFACT_DIGEST_MISMATCH")
        models.append(
            {
                "profile": profile,
                "artifact": "VERIFIED",
                "model_id": spec["model_id"],
                "threshold": spec["threshold"],
                "status": "RESEARCH_ONLY",
                "operational": "BLOCKED",
            }
        )
    return {
        "status": "READY",
        "meaning": "PREFLIGHT_ONLY_NO_INFERENCE",
        "models": models,
        "producer": "1.1.0 / Network14 / OFFLINE_PCAP",
        "operational_inference": "BLOCKED",
        "write_policy": "WRITE_DENIED",
    }
