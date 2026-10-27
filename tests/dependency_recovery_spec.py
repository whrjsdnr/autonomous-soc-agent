"""Unapproved, pure fixture specification; not an installer or approval verifier.

No filesystem, process, network or production-policy access. The independent
results describe supplied fixture observations only. Even perfect observations
and a synthetic receipt cannot authorize a production replacement or execution.
"""

from typing import Literal

from pydantic import Field

from tests.r1r2_draft_spec import FrozenSpec, Hash

FILES = (
    "bootstrap",
    "broker",
    "entry",
    "libnative-tc.so",
    "manifest.bin",
    "pam-policy.conf",
    "release.json",
    "release.trust",
    "tc.bpf.o",
)
DESTINATION = "/usr/libexec/soc-agent-ebpf"


class FileObservation(FrozenSpec):
    name: str
    sha256: Hash
    uid: int = Field(ge=0)
    gid: int = Field(ge=0)
    mode: int = Field(ge=0, le=0o7777)
    nlink: int = Field(ge=0)
    regular: bool


class Inventory(FrozenSpec):
    directory: str
    directory_trusted: bool
    files: tuple[FileObservation, ...]
    trust_binding_verified: bool


class Dependency(FrozenSpec):
    path: str
    package_version: str
    sha256: Hash


class RuntimePin(FrozenSpec):
    root_manifest: Hash
    bundle: Hash
    dependencies: tuple[Dependency, ...] = Field(min_length=1, max_length=64)


class RuntimeObservation(FrozenSpec):
    pin: RuntimePin
    package_verified: bool
    dynamic_closure_verified: bool
    abi: Literal["OBSERVED_COMPATIBLE_LIMITED", "INCOMPATIBLE", "UNKNOWN"]


class StageResult(FrozenSpec):
    status: Literal["VERIFIED_FIXTURE_ONLY", "INVALID", "UNKNOWN"]
    reasons: tuple[str, ...] = ()
    authorizes_runtime: Literal[False] = False


def compare_inventory(pin: Inventory, observed: Inventory, directory: str) -> StageResult:
    """Compare complete retained-file observations without evaluating old runtime."""
    reasons = []
    for label, inventory in (("PIN", pin), ("OBSERVED", observed)):
        names = [item.name for item in inventory.files]
        if len(names) != len(FILES) or set(names) != set(FILES):
            reasons.append(label + "_FILE_SET")
        if inventory.directory != directory or not inventory.directory_trusted:
            reasons.append(label + "_DIRECTORY")
        if not inventory.trust_binding_verified:
            reasons.append(label + "_TRUST_BINDING")
        for item in inventory.files:
            mode = 0o555 if item.name in {"bootstrap", "broker", "entry"} else 0o444
            if (
                item.uid != 0
                or item.gid != 0
                or item.mode != mode
                or item.nlink != 1
                or not item.regular
            ):
                reasons.append(label + "_FILE_METADATA")
    expected = {item.name: item.sha256 for item in pin.files}
    actual = {item.name: item.sha256 for item in observed.files}
    if expected != actual:
        reasons.append("FILE_SHA_MISMATCH")
    return StageResult(
        status="INVALID" if reasons else "VERIFIED_FIXTURE_ONLY", reasons=tuple(reasons)
    )


def compare_runtime(pin: RuntimePin, observed: RuntimeObservation) -> StageResult:
    """New runtime uses its own pins; ABI success never replaces exact hashes."""
    reasons = []
    for label, dependencies in (
        ("PIN", pin.dependencies),
        ("OBSERVED", observed.pin.dependencies),
    ):
        if len({item.path for item in dependencies}) != len(dependencies):
            reasons.append(label + "_DUPLICATE_DEPENDENCY")
    if pin != observed.pin:
        reasons.append("RUNTIME_IDENTITY_MISMATCH")
    if not observed.package_verified:
        reasons.append("PACKAGE_UNVERIFIED")
    if not observed.dynamic_closure_verified:
        reasons.append("DYNAMIC_CLOSURE_UNVERIFIED")
    if observed.abi == "INCOMPATIBLE":
        reasons.append("ABI_INCOMPATIBLE")
    if reasons:
        return StageResult(status="INVALID", reasons=tuple(reasons))
    if observed.abi == "UNKNOWN":
        return StageResult(status="UNKNOWN", reasons=("ABI_UNKNOWN",))
    return StageResult(status="VERIFIED_FIXTURE_ONLY")


class Binding(FrozenSpec):
    old_manifest: Hash
    new_runtime: RuntimePin
    session: str = Field(min_length=1, max_length=128)
    scope_sha: Hash
    evidence_sha: Hash


class DraftReceipt(FrozenSpec):
    contract: Literal["RECOVERY_DRAFT_NOT_A_PRODUCTION_RECEIPT"] = (
        "RECOVERY_DRAFT_NOT_A_PRODUCTION_RECEIPT"
    )
    identity: Hash
    binding: Binding
    reviewer: str = Field(min_length=1, max_length=128)
    ledger_tip: Hash
    expires_at: int = Field(gt=0)


def blocked_admission_reasons(
    expected: Binding,
    receipt: DraftReceipt | None,
    *,
    ledger_tip: Hash,
    used_receipts: frozenset[str],
    now: int,
    preservation: StageResult,
    rollback: StageResult,
    runtime: StageResult,
) -> tuple[str, ...]:
    """Diagnostic reasons only. Always blocked: never emits an allow or receipt."""
    reasons = ["UNAPPROVED_DRAFT_NOT_ACTIVE"]
    if receipt is None:
        reasons.append("APPROVAL_MISSING")
    else:
        if receipt.binding != expected:
            reasons.append("APPROVAL_BINDING_MISMATCH")
        if receipt.ledger_tip != ledger_tip:
            reasons.append("STALE_LEDGER")
        if receipt.identity in used_receipts:
            reasons.append("REPLAY")
        if receipt.expires_at <= now:
            reasons.append("APPROVAL_EXPIRED")
    for name, result in (
        ("PRESERVATION", preservation),
        ("ROLLBACK", rollback),
        ("RUNTIME", runtime),
    ):
        if result.status != "VERIFIED_FIXTURE_ONLY":
            reasons.append(name + "_UNVERIFIED")
    return tuple(reasons)
