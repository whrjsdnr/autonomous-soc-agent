"""Qualification-only fixtures; no sudo/Kernel/authentication or real campaign writes."""

import json
from pathlib import Path

import pytest
from tests.unit.ebpf_tc.test_native_campaign import IDENTITY
from tests.unit.ebpf_tc.test_native_campaign import fixture as fixture

from soc_agent.security_ai import native_campaign as legacy
from soc_agent.security_ai import stabilization_campaign as module
from soc_agent.security_ai.ebpf_tc.installation import canonical


@pytest.fixture
def stable(fixture):
    root, receipt, scope, dns = fixture
    b = json.loads((root / "budget.json").read_text())
    b.update(
        campaign=module.CAMPAIGN,
        native_max=10,
        root_installations_max=10,
        native_per_batch_max=2,
        root_per_batch_max=2,
        execution_contract="EXACT_SHA_SINGLE_ATTEMPT_V1",
        controller_sha256=legacy.sha(Path(module.__file__).read_bytes()),
    )
    (root / "budget.json").write_bytes(canonical(b))
    ledger = json.loads((root / "execution-ledger.jsonl").read_text())
    ledger.update(campaign=module.CAMPAIGN, budget_sha256=legacy.sha(canonical(b)))
    (root / "execution-ledger.jsonl").write_bytes(canonical(ledger))
    return root, receipt, scope, dns


def approved(stable, batch="BATCH1", n=1):
    root, path, scope, dns = stable
    body = canonical(
        dict(
            campaign=module.CAMPAIGN,
            decision="APPROVED",
            batch=batch,
            release=IDENTITY,
            scope=scope,
            dns_scope=dns,
            native_attempts=1,
            root_installations=1,
            budget_sha256=legacy.sha((root / "budget.json").read_bytes()),
            controller_sha256=legacy.sha(Path(module.__file__).read_bytes()),
            reference=f"FIXTURE_NO_NATIVE_{n}",
        )
    )
    path.write_bytes(body)
    return legacy.sha(body)


def finish_review(ledger, attempt, safe=True):
    ledger.finish(attempt, outcome="RETURNED_PENDING_EVIDENCE_REVIEW", evidence={})
    ledger._locked(
        lambda rows: dict(
            event="DIAGNOSTIC_E2E_EVIDENCE_REVIEW_COMPLETED",
            attempt_id=attempt,
            safe_for_next_attempt=safe,
        )
    )


def reserve(stable, batch="BATCH1", n=1):
    root, path, scope, dns = stable
    return module.StabilizationCampaign(root, batch).reserve(
        IDENTITY, scope, dns, path, approved(stable, batch, n), root_cost=1
    )


def test_legacy_campaign_still_rejects_new_campaign(stable):
    with pytest.raises(ValueError, match="NATIVE_CAMPAIGN_IDENTITY"):
        legacy.NativeCampaign(stable[0])


def test_batch_and_global_limits_and_no_refunds(stable):
    root = stable[0]
    for batch in range(1, 6):
        ledger = module.StabilizationCampaign(root, f"BATCH{batch}")
        for n in range(2):
            a = reserve(stable, f"BATCH{batch}", batch * 10 + n)
            assert a["native_used"] == a["root_installations_used"] == (batch - 1) * 2 + n + 1
            finish_review(ledger, a["attempt_id"])
        with pytest.raises(ValueError, match="BATCH_BUDGET_EXHAUSTED|BUDGET_EXHAUSTED"):
            reserve(stable, f"BATCH{batch}", batch * 10 + 2)
    rows = [json.loads(x) for x in (root / "execution-ledger.jsonl").read_text().splitlines()]
    assert len([r for r in rows if r["event"] == "NATIVE_ATTEMPT_RESERVED"]) == 10


@pytest.mark.parametrize("finish,safe", [(False, False), (True, False)])
def test_unreviewed_or_unsafe_previous_attempt_blocks_new_execution(stable, finish, safe):
    ledger = module.StabilizationCampaign(stable[0], "BATCH1")
    a = reserve(stable)
    if finish:
        finish_review(ledger, a["attempt_id"], safe)
    before = (stable[0] / "execution-ledger.jsonl").read_bytes()
    with pytest.raises(ValueError, match="PREVIOUS_ATTEMPT_UNREVIEWED"):
        reserve(stable, n=2)
    assert (stable[0] / "execution-ledger.jsonl").read_bytes() == before


@pytest.mark.parametrize("field", ["batch", "budget_sha256", "controller_sha256", "release"])
def test_receipt_binding_and_exact_sha_cannot_be_bypassed(stable, field):
    root, path, scope, dns = stable
    approved(stable)
    a = json.loads(path.read_text())
    a[field] = "bad"
    path.write_bytes(canonical(a))
    before = (root / "execution-ledger.jsonl").read_bytes()
    with pytest.raises(ValueError):
        module.StabilizationCampaign(root, "BATCH1").reserve(
            IDENTITY, scope, dns, path, legacy.sha(path.read_bytes()), root_cost=1
        )
    assert (root / "execution-ledger.jsonl").read_bytes() == before


def test_malformed_budget_missing_root_authority_is_rejected(stable):
    root = stable[0]
    b = json.loads((root / "budget.json").read_text())
    b["root_installations_max"] = None
    (root / "budget.json").write_bytes(canonical(b))
    with pytest.raises(ValueError, match="BUDGET_CONTRACT"):
        module.StabilizationCampaign(root, "BATCH1")


def test_executor_failure_is_after_durable_reservation_and_never_retries(
    stable, tmp_path, monkeypatch
):
    from types import SimpleNamespace

    from soc_agent.security_ai.ebpf_tc import phase_d, unified_image

    root, path, scope, dns = stable
    approved_sha = approved(stable)
    (tmp_path / "dns-sidecar").mkdir()
    (tmp_path / "dns-sidecar/release.json").write_bytes(canonical(dict(scope=dns)))
    monkeypatch.setattr(
        phase_d,
        "validate",
        lambda *args: dict(
            scope=scope, bundle=IDENTITY["bundle"], tcx_manifest=IDENTITY["tcx_manifest"]
        ),
    )
    monkeypatch.setattr(unified_image, "installed_release", lambda: SimpleNamespace(identity="old"))
    calls = []

    def fail(*args, **kwargs):
        rows = [
            json.loads(row) for row in (root / "execution-ledger.jsonl").read_text().splitlines()
        ]
        assert rows[-1]["event"] == "NATIVE_ATTEMPT_RESERVED"
        assert rows[-1]["native_used"] == rows[-1]["root_installations_used"] == 1
        calls.append("FIXTURE_NO_NATIVE")
        raise OSError(13, "FIXTURE_PRIVATE_TEXT_NOT_PERSISTED")

    monkeypatch.setattr(phase_d, "execute", fail)
    with pytest.raises(OSError):
        module.execute(
            tmp_path,
            IDENTITY["manifest"],
            IDENTITY["image"],
            campaign=root,
            batch="BATCH1",
            approval_file=path,
            approval_sha=approved_sha,
        )
    assert calls == ["FIXTURE_NO_NATIVE"]
    raw = (root / "execution-ledger.jsonl").read_bytes()
    assert b"FIXTURE_PRIVATE_TEXT_NOT_PERSISTED" not in raw
    assert json.loads(raw.splitlines()[-1])["evidence"]["errno"] == 13
    with pytest.raises(ValueError, match="ALREADY_CONSUMED"):
        module.execute(
            tmp_path,
            IDENTITY["manifest"],
            IDENTITY["image"],
            campaign=root,
            batch="BATCH1",
            approval_file=path,
            approval_sha=approved_sha,
        )
    assert calls == ["FIXTURE_NO_NATIVE"]
