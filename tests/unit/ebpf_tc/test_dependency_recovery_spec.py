"""Synthetic draft contract tests; no Root, filesystem mutation or Native run."""

import pytest
from pydantic import ValidationError
from tests.dependency_recovery_spec import (
    DESTINATION,
    FILES,
    Binding,
    Dependency,
    DraftReceipt,
    FileObservation,
    Inventory,
    RuntimeObservation,
    RuntimePin,
    StageResult,
    blocked_admission_reasons,
    compare_inventory,
    compare_runtime,
)


def inventory(directory=DESTINATION):
    return Inventory(
        directory=directory,
        directory_trusted=True,
        trust_binding_verified=True,
        files=tuple(
            FileObservation(
                name=name,
                sha256=f"{index:064x}",
                uid=0,
                gid=0,
                mode=0o555 if name in {"entry", "broker", "bootstrap"} else 0o444,
                nlink=1,
                regular=True,
            )
            for index, name in enumerate(FILES, 1)
        ),
    )


def runtime(version="ubuntu2.3", sha="3" * 64):
    return RuntimePin(
        root_manifest="1" * 64,
        bundle="2" * 64,
        dependencies=(
            Dependency(path="/usr/lib/libz.so.1.3", package_version=version, sha256=sha),
        ),
    )


def observation(pin):
    return RuntimeObservation(
        pin=pin,
        package_verified=True,
        dynamic_closure_verified=True,
        abi="OBSERVED_COMPATIBLE_LIMITED",
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("sha256", "f" * 64),
        ("uid", 1000),
        ("gid", 1000),
        ("mode", 0o777),
        ("nlink", 2),
        ("regular", False),
    ],
)
def test_old_file_tampering_is_independent_of_valid_new_runtime(field, value):
    pin = inventory()
    changed = pin.files[0].model_copy(update={field: value})
    altered = pin.model_copy(update=dict(files=(changed, *pin.files[1:])))
    assert compare_inventory(pin, altered, DESTINATION).status == "INVALID"
    assert compare_runtime(runtime(), observation(runtime())).status == "VERIFIED_FIXTURE_ONLY"


@pytest.mark.parametrize(
    "mutation", ["missing", "extra", "duplicate", "path", "trust", "directory"]
)
def test_preservation_requires_complete_exact_inventory(mutation):
    pin = inventory()
    changes = {
        "missing": dict(files=pin.files[:-1]),
        "extra": dict(files=(*pin.files, pin.files[0].model_copy(update=dict(name="extra")))),
        "duplicate": dict(files=(*pin.files[:-1], pin.files[0])),
        "path": dict(directory="/tmp/untrusted"),
        "trust": dict(trust_binding_verified=False),
        "directory": dict(directory_trusted=False),
    }
    result = compare_inventory(pin, pin.model_copy(update=changes[mutation]), DESTINATION)
    assert result.status == "INVALID"
    assert result.authorizes_runtime is False


def test_rollback_has_its_own_exact_file_pins_and_path():
    path = "/usr/libexec/.soc-agent-ebpf.rollback-" + "a" * 64
    pin = inventory(path)
    assert compare_inventory(pin, pin, path).status == "VERIFIED_FIXTURE_ONLY"
    assert compare_inventory(pin, inventory(), path).status == "INVALID"
    bad = pin.model_copy(update=dict(files=pin.files[:-1]))
    assert compare_inventory(pin, bad, path).status == "INVALID"


@pytest.mark.parametrize("changed", [runtime(sha="f" * 64), runtime(version="ubuntu2.2")])
def test_new_runtime_drift_rejected_despite_abi_success_and_preserved_old_files(changed):
    pin = inventory()
    assert compare_inventory(pin, pin, DESTINATION).status == "VERIFIED_FIXTURE_ONLY"
    assert compare_runtime(runtime(), observation(changed)).status == "INVALID"


def test_version_upgrade_requires_its_own_new_pins_not_overwriting_old_identity():
    old = runtime("ubuntu2.2", "8" * 64)
    new = runtime()
    old_serialized = old.model_dump_json()
    assert compare_runtime(old, observation(new)).status == "INVALID"
    assert compare_runtime(new, observation(new)).status == "VERIFIED_FIXTURE_ONLY"
    assert old.model_dump_json() == old_serialized


@pytest.mark.parametrize(
    "changes,status",
    [
        (dict(abi="INCOMPATIBLE"), "INVALID"),
        (dict(abi="UNKNOWN"), "UNKNOWN"),
        (dict(package_verified=False), "INVALID"),
        (dict(dynamic_closure_verified=False), "INVALID"),
        (dict(pin=runtime().model_copy(update=dict(root_manifest="f" * 64))), "INVALID"),
        (dict(pin=runtime().model_copy(update=dict(bundle="f" * 64))), "INVALID"),
    ],
)
def test_runtime_proof_failures(changes, status):
    result = compare_runtime(runtime(), observation(runtime()).model_copy(update=changes))
    assert result.status == status
    assert result.authorizes_runtime is False


def test_duplicate_dependency_paths_rejected():
    pin = runtime()
    bad = pin.model_copy(update=dict(dependencies=pin.dependencies * 2))
    assert compare_runtime(bad, observation(bad)).status == "INVALID"


def binding():
    return Binding(
        old_manifest="a" * 64,
        new_runtime=runtime(),
        session="synthetic-only-session",
        scope_sha="b" * 64,
        evidence_sha="c" * 64,
    )


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ("none", "APPROVAL_MISSING"),
        ("ledger", "STALE_LEDGER"),
        ("replay", "REPLAY"),
        ("expired", "APPROVAL_EXPIRED"),
        ("session", "APPROVAL_BINDING_MISMATCH"),
        ("old_manifest", "APPROVAL_BINDING_MISMATCH"),
        ("scope_sha", "APPROVAL_BINDING_MISMATCH"),
        ("evidence_sha", "APPROVAL_BINDING_MISMATCH"),
        ("runtime", "APPROVAL_BINDING_MISMATCH"),
        ("valid_fixture", "UNAPPROVED_DRAFT_NOT_ACTIVE"),
    ],
)
def test_draft_never_authorizes_and_reports_receipt_failures(mutation, reason):
    expected = binding()
    receipt = DraftReceipt(
        identity="d" * 64,
        binding=expected,
        reviewer="synthetic-reviewer-not-an-actual-approval",
        ledger_tip="e" * 64,
        expires_at=20,
    )
    if mutation in {"session", "old_manifest", "scope_sha", "evidence_sha", "runtime"}:
        value = (
            "other-session"
            if mutation == "session"
            else runtime(sha="f" * 64)
            if mutation == "runtime"
            else "f" * 64
        )
        field = "new_runtime" if mutation == "runtime" else mutation
        receipt = receipt.model_copy(
            update=dict(binding=expected.model_copy(update={field: value}))
        )
    good = StageResult(status="VERIFIED_FIXTURE_ONLY")
    reasons = blocked_admission_reasons(
        expected,
        None if mutation == "none" else receipt,
        ledger_tip="0" * 64 if mutation == "ledger" else "e" * 64,
        used_receipts=frozenset({receipt.identity}) if mutation == "replay" else frozenset(),
        now=20 if mutation == "expired" else 10,
        preservation=good,
        rollback=good,
        runtime=good,
    )
    assert reason in reasons
    assert "UNAPPROVED_DRAFT_NOT_ACTIVE" in reasons


def test_draft_result_and_receipt_cannot_claim_production_authority():
    with pytest.raises(ValidationError):
        StageResult(status="VERIFIED_FIXTURE_ONLY", authorizes_runtime=True)
    with pytest.raises(ValidationError):
        StageResult(status="ELIGIBLE")


@pytest.mark.parametrize("stage", ["preservation", "rollback", "runtime"])
def test_independent_failed_stage_remains_visible(stage):
    good = StageResult(status="VERIFIED_FIXTURE_ONLY")
    inputs = dict(preservation=good, rollback=good, runtime=good)
    inputs[stage] = StageResult(status="UNKNOWN")
    reasons = blocked_admission_reasons(
        binding(), None, ledger_tip="e" * 64, used_receipts=frozenset(), now=10, **inputs
    )
    assert stage.upper() + "_UNVERIFIED" in reasons
