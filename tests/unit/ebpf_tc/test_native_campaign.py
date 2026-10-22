"""Temporary qualification ledgers only; no real campaign record or Native execution."""

import copy
import json
from types import SimpleNamespace

import pytest

from soc_agent.security_ai import native_campaign as campaign
from soc_agent.security_ai.ebpf_tc import phase_d
from soc_agent.security_ai.ebpf_tc.installation import canonical

IDENTITY = dict(manifest="a" * 64, bundle="b" * 64, image="c" * 64, tcx_manifest="d" * 64)


@pytest.fixture
def fixture(tmp_path):
    root = tmp_path / "campaign"
    root.mkdir(mode=0o700)
    scope = copy.deepcopy(phase_d.SCOPE)
    baseline = canonical(dict(source="ORDINARY_FIXTURE_NO_NATIVE_EVIDENCE"))
    budget = canonical(
        dict(
            campaign="NATIVE_SOC_PHASE_D",
            native_used=0,
            native_max=5,
            root_installations_used=0,
            root_installations_max=5,
            scope=dict(
                namespace=scope["namespace"],
                interface="lo",
                tcx_hook="INGRESS",
                max_duration_seconds=300,
                tcx_metadata_events=4096,
                queue_capacity=32,
                privileged_address_space_mib=256,
                privileged_cpu_seconds=20,
                dns=dict(
                    max_capture_seconds=7,
                    max_active_seconds=10,
                    max_packets=32,
                    snaplen_bytes=512,
                    endpoint="127.0.0.53:53",
                    qname="native-0516.localhost.",
                    qtype="A",
                    udp_queries=1,
                    tcp_queries=1,
                ),
            ),
        )
    )
    (root / "baseline.json").write_bytes(baseline)
    (root / "budget.json").write_bytes(budget)
    (root / "execution-ledger.jsonl").write_bytes(
        canonical(
            dict(
                event="CAMPAIGN_CREATED_DEVELOPMENT_ONLY",
                campaign="NATIVE_SOC_PHASE_D",
                budget_sha256=campaign.sha(budget),
                baseline_sha256=campaign.sha(baseline),
            )
        )
    )
    return (
        root,
        root / "approval.json",
        copy.deepcopy(phase_d.SCOPE),
        copy.deepcopy(phase_d.DNS_SCOPE),
    )


def approval(fixture, sequence=1, identity=None):
    root, path, scope, dns = fixture
    body = canonical(
        dict(
            campaign="NATIVE_SOC_PHASE_D",
            decision="APPROVED",
            release=identity or IDENTITY,
            scope=scope,
            dns_scope=dns,
            native_attempts=1,
            root_installations=1,
            approval_reference=f"ORDINARY_FIXTURE_NOT_NATIVE:{sequence}",
        )
    )
    path.write_bytes(body)
    return campaign.sha(body)


def test_reserve_fsyncs_before_callback_and_failed_attempt_is_consumed(
    fixture, tmp_path, monkeypatch
):
    from soc_agent.security_ai.ebpf_tc import unified_image

    root, path, scope, dns = fixture
    approved = approval(fixture)
    original = (root / "execution-ledger.jsonl").read_bytes()
    calls = []
    monkeypatch.setattr(
        phase_d,
        "validate",
        lambda *a: dict(
            bundle=IDENTITY["bundle"], tcx_manifest=IDENTITY["tcx_manifest"], scope=scope
        ),
    )
    (tmp_path / "dns-sidecar").mkdir()
    (tmp_path / "dns-sidecar/release.json").write_bytes(canonical(dict(scope=dns)))
    monkeypatch.setattr(unified_image, "installed_release", lambda: SimpleNamespace(identity="old"))

    def failed(*args, **kwargs):
        calls.append("fixture_callback_not_native")
        rows = [json.loads(x) for x in (root / "execution-ledger.jsonl").read_text().splitlines()]
        assert rows[-1]["event"] == "NATIVE_ATTEMPT_RESERVED"
        assert rows[-1]["native_used"] == rows[-1]["root_installations_used"] == 1
        raise OSError(13, "fixture secret diagnostic must not enter ledger")

    monkeypatch.setattr(phase_d, "execute", failed)
    with pytest.raises(OSError) as caught:
        campaign.execute_phase_d(
            tmp_path,
            IDENTITY["manifest"],
            IDENTITY["image"],
            campaign=root,
            approval_file=path,
            approval_sha=approved,
        )
    assert caught.value.errno == 13 and calls == ["fixture_callback_not_native"]
    body = (root / "execution-ledger.jsonl").read_bytes()
    assert body.startswith(original) and b"fixture secret" not in body
    final = json.loads(body.splitlines()[-1])
    assert final["outcome"] == "FAILED" and final["evidence"]["errno"] == 13
    assert final["native_verified"] is False
    with pytest.raises(ValueError, match="ALREADY_CONSUMED"):
        campaign.NativeCampaign(root).reserve(IDENTITY, scope, dns, path, approved, root_cost=1)
    assert (root / "execution-ledger.jsonl").read_bytes() == body


@pytest.mark.parametrize("limit", ["native_max", "root_installations_max"])
def test_independent_budget_exhaustion_and_failure_does_not_refund(fixture, limit):
    root, path, scope, dns = fixture
    budget = json.loads((root / "budget.json").read_bytes())
    budget[limit] = 1
    (root / "budget.json").write_bytes(canonical(budget))
    first = json.loads((root / "execution-ledger.jsonl").read_bytes())
    first["budget_sha256"] = campaign.sha(canonical(budget))
    (root / "execution-ledger.jsonl").write_bytes(canonical(first))
    ledger = campaign.NativeCampaign(root)
    reserved = ledger.reserve(IDENTITY, scope, dns, path, approval(fixture), root_cost=1)
    ledger.finish(reserved["attempt_id"], outcome="FAILED", evidence={"source": "FIXTURE"})
    before = (root / "execution-ledger.jsonl").read_bytes()
    with pytest.raises(ValueError, match="BUDGET_EXHAUSTED"):
        ledger.reserve(IDENTITY, scope, dns, path, approval(fixture, 2), root_cost=1)
    assert (root / "execution-ledger.jsonl").read_bytes() == before


@pytest.mark.parametrize("mismatch", ["missing", "image", "scope", "digest"])
def test_unapproved_artifact_or_scope_never_reserves_or_executes(fixture, mismatch):
    root, path, scope, dns = fixture
    before = (root / "execution-ledger.jsonl").read_bytes()
    approved = approval(fixture)
    identity = dict(IDENTITY)
    if mismatch == "missing":
        path.unlink()
    elif mismatch == "image":
        identity["image"] = "e" * 64
    elif mismatch == "scope":
        scope["interface"] = "eth0"
    else:
        approved = "0" * 64
    with pytest.raises((ValueError, FileNotFoundError)):
        campaign.NativeCampaign(root).reserve(identity, scope, dns, path, approved, root_cost=1)
    assert (root / "execution-ledger.jsonl").read_bytes() == before


def test_ledger_corruption_or_duplicate_finish_cannot_be_rewritten_as_verified(fixture):
    root, path, scope, dns = fixture
    ledger = campaign.NativeCampaign(root)
    reserved = ledger.reserve(IDENTITY, scope, dns, path, approval(fixture), root_cost=1)
    with pytest.raises(ValueError, match="OUTCOME"):
        ledger.finish(reserved["attempt_id"], outcome="VERIFIED", evidence={})
    ledger.finish(reserved["attempt_id"], outcome="FAILED", evidence={})
    with pytest.raises(ValueError, match="ATTEMPT_STATE"):
        ledger.finish(reserved["attempt_id"], outcome="FAILED", evidence={})
    body = (
        (root / "execution-ledger.jsonl")
        .read_bytes()
        .replace(b'"root_cost":1', b'"root_cost":0', 1)
    )
    (root / "execution-ledger.jsonl").write_bytes(body)
    with pytest.raises(ValueError, match="LEDGER_CHAIN"):
        ledger.reserve(IDENTITY, scope, dns, path, approval(fixture, 2), root_cost=1)


def test_cli_requires_campaign_and_exact_approval_receipt_before_execution(monkeypatch):
    monkeypatch.setattr(
        "sys.argv", ["phase_d", "unused", "--execute", "--manifest", "a" * 64, "--image", "b" * 64]
    )
    monkeypatch.setattr(campaign, "execute_phase_d", lambda *a, **k: pytest.fail("Native"))
    with pytest.raises(SystemExit) as caught:
        phase_d.main()
    assert caught.value.code == 2


def test_simultaneous_requests_cannot_consume_one_approval_twice(fixture):
    from concurrent.futures import ThreadPoolExecutor

    root, path, scope, dns = fixture
    approved = approval(fixture)

    def reserve():
        try:
            return campaign.NativeCampaign(root).reserve(
                IDENTITY, scope, dns, path, approved, root_cost=1
            )["event"]
        except ValueError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: reserve(), range(2)))
    assert sorted(results) == sorted(
        ["NATIVE_ATTEMPT_RESERVED", "NATIVE_CAMPAIGN_APPROVAL_ALREADY_CONSUMED"]
    )
    assert len((root / "execution-ledger.jsonl").read_text().splitlines()) == 2


@pytest.mark.parametrize("invalid", [-1, True, 6])
def test_invalid_initial_usage_cannot_expand_effective_budget(fixture, invalid):
    root = fixture[0]
    budget = json.loads((root / "budget.json").read_bytes())
    budget["native_used"] = invalid
    (root / "budget.json").write_bytes(canonical(budget))
    with pytest.raises(ValueError, match="BUDGET_RANGE"):
        campaign.NativeCampaign(root)
