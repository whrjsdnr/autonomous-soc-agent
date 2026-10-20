"""Public B-1 proof binds exact reviewed code; Native claims cannot be promoted."""

import json
from pathlib import Path

from soc_agent.security_ai.ebpf_broker.identity import broker_sha, bundle
from soc_agent.security_ai.research.models import digest

ROOT = Path(__file__).resolve().parents[3]


def test_broker_evidence_binds_source_bundle_and_explicit_zeek_amendment():
    value = json.loads(
        (ROOT / ("docs/linux-soc-v1/ebpf-privileged-broker-tc-ownership-evidence.json")).read_text()
    )
    assert value["bundle"] == bundle() and value["bundle_digest"] == digest(bundle())
    assert value["broker_entry_sha256"] == broker_sha()
    change = value["zeek_launcher_update"]
    assert change["native_approval_required"]
    assert {
        k
        for k in change["current_bundle"]
        if (change["current_bundle"][k] != change["previous_bundle"][k])
    } == {"live_process.py"}
    assert value["deterministic_old_baseline_race"]["expected_failure"]


def test_broker_evidence_never_admits_fixture_authority_as_native():
    value = json.loads(
        (ROOT / ("docs/linux-soc-v1/ebpf-privileged-broker-tc-ownership-evidence.json")).read_text()
    )
    assert not any(value["native_actions"].values())
    assert not any(value["authority"].values())
    assert value["native_approval"]["command"] is None
    assert value["verdicts"]["NATIVE_AUTH"] == value["verdicts"]["NATIVE_TC_ATTACH"] == "PENDING"
    assert all(
        value["verdicts"][k] == "BLOCKED" for k in ("NATIVE_AI", "DNS9", "OPERATIONAL_PROMOTION")
    )
    assert all(v["exit_code"] == 0 for v in value["results"].values())
