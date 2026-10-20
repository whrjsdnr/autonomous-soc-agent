"""Bounded execution manifest and session-bound approval, with no Native authority.

The root-owned execution schema is compiled from a strict JSON release. C consumes
this closed format rather than loading Python or a custom JSON DSO before PAM.
"""

import hashlib
import os
import stat
import struct
from pathlib import Path

from soc_agent.review.models import Hash
from soc_agent.security_ai.ebpf_tc.contracts import NativePlan
from soc_agent.security_ai.ebpf_tc.dependencies import read_held

HEADER = struct.Struct("<8sIIII32s160s16s")
RECORD = struct.Struct("<256s32sQII")
ENVELOPE_SIZE = 352
CONFIGURATION = ("/etc/ld.so.cache", "/etc/nsswitch.conf")


def configuration() -> tuple[dict[str, object], ...]:
    """Static configuration snapshots; dynamic NSS/PAM closure remains UNKNOWN."""
    if Path("/etc/ld.so.preload").exists() or Path("/etc/ld.so.preload").is_symlink():
        raise ValueError("RELEASE_SYSTEM_PRELOAD_DENIED")
    result = []
    for name in CONFIGURATION:
        path = Path(name)
        body = read_held(path, owner=0)
        result.append(
            {
                "path": name,
                "sha256": hashlib.sha256(body).hexdigest(),
                "size": len(body),
                "mode": stat.S_IMODE(path.stat().st_mode),
            }
        )
    return tuple(result)


def execution_manifest(manifest) -> bytes:
    """Compile only validated models; no root execution, authentication or installation."""
    from soc_agent.security_ai.ebpf_tc.installation import ReleaseManifest

    manifest = ReleaseManifest.model_validate(manifest.model_dump(mode="json"))
    records = {d.path: (d.sha256, d.size, d.mode) for d in manifest.dependencies}
    records.update({d.path: (d.sha256, d.size, d.mode) for d in manifest.system_configuration})
    policy = manifest.payloads["pam-policy.conf"]
    entry = manifest.payloads["entry"]
    records["/usr/libexec/soc-agent-ebpf/entry"] = (entry.sha256, entry.size, entry.mode)
    records[manifest.pam_destination] = (policy.sha256, policy.size, 0o644)
    if not 3 <= len(records) <= 72 or sum(r[1] for r in records.values()) > 64 * 1024**2:
        raise ValueError("RELEASE_EXECUTION_BUDGET")
    hashes = b"".join(
        bytes.fromhex(manifest.payloads[n].sha256)
        for n in ("bootstrap", "broker", "libnative-tc.so", "tc.bpf.o")
    )
    body = HEADER.pack(
        b"SOCRC001",
        1,
        len(records),
        0,
        0,
        bytes.fromhex(manifest.identity),
        hashes + bytes.fromhex(manifest.bundle_digest),
        manifest.version.encode().ljust(16, b"\0"),
    )
    for name, (sha, size, mode) in sorted(records.items()):
        if len(name.encode()) >= 256 or (
            mode != 0o555 if name == "/usr/libexec/soc-agent-ebpf/entry" else bool(mode & 0o7022)
        ):
            raise ValueError("RELEASE_EXECUTION_RECORD")
        body += RECORD.pack(name.encode().ljust(256, b"\0"), bytes.fromhex(sha), size, mode, 0)
    return body


def release_approval(plan: NativePlan, manifest) -> bytes:
    """Approval bytes only. A sealed *root-created* copy requires future fresh PAM.

    This cannot start a process, create an authenticated broker or open either gate.
    The legacy request ABI remains subordinate to this outer approved envelope.
    """
    from soc_agent.security_ai.ebpf_tc.installation import ReleaseManifest

    manifest = ReleaseManifest.model_validate(manifest.model_dump(mode="json"))
    plan = NativePlan.model_validate(plan.model_dump(mode="json"))
    if plan.mode != "B2D_TCX_BLOCKED":
        raise ValueError("RELEASE_TCX_PLAN_REQUIRED")
    expected = (
        plan.bootstrap_sha256,
        plan.native_broker_sha256,
        plan.loader_sha256,
        plan.program_sha256,
        plan.bundle_digest,
    )
    actual = tuple(
        manifest.payloads[n].sha256 for n in ("bootstrap", "broker", "libnative-tc.so", "tc.bpf.o")
    ) + (manifest.bundle_digest,)
    if expected != actual:
        raise ValueError("RELEASE_APPROVAL_SCOPE_MISMATCH")
    body = (
        plan.wire() + bytes.fromhex(manifest.identity) + manifest.version.encode().ljust(16, b"\0")
    )
    return body + hashlib.sha256(body + bytes(32)).digest()


def verify_execution_manifest(directory: Path, manifest) -> None:
    body = read_held((directory / "release.trust").absolute(), owner=os.getuid(), limit=32768)
    if body != execution_manifest(manifest):
        raise ValueError("RELEASE_EXECUTION_MANIFEST_MISMATCH")


def candidate_snapshot(manifest_sha: Hash | None = None) -> dict[str, object]:
    return {
        "release_candidate": "B2F_BLOCKED_NATIVE_QUALIFICATION",
        "manifest_digest": manifest_sha,
        "installation_integrity": "NOT_OBSERVED",
        "pam_nss_trust": "STATIC_SNAPSHOTS_DYNAMIC_CLOSURE_UNKNOWN",
        "native_release": "BLOCKED",
        "authentication_restored": False,
        "automatic_attach": False,
    }
