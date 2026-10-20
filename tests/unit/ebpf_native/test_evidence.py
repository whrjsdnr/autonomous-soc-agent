"""Bind the published Phase A inspection evidence to its reviewed source files."""

import hashlib
import json
from pathlib import Path

from soc_agent.security_ai.ebpf_native.loader import bundle
from soc_agent.security_ai.research.models import digest

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/linux-soc-v1/ebpf-native-loader-supervisor-evidence.json"


def test_published_inspector_bundle_and_fixture_screenshots_match_sources():
    evidence = json.loads(EVIDENCE.read_text())
    implementation = evidence["implementation"]
    assert implementation["bundle"] == bundle()
    assert implementation["bundle_digest"] == digest(bundle())
    for name, expected in evidence["screenshots"]["sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected


def test_published_mock_results_never_admit_native_authentication_or_capture():
    evidence = json.loads(EVIDENCE.read_text())
    assert not any(evidence["native_actions"].values())
    assert evidence["native_execution_command"] is None
    assert evidence["policy_fixture"]["authentication_per_application"] == 1
    assert not evidence["policy_fixture"]["authority_restored"]
    assert evidence["implementation"]["inspection"]["kernel_load"] is False
    assert evidence["implementation"]["inspection"]["tc_attach"] is False
    assert all(v["exit_code"] == 0 for v in evidence["regressions"].values())
    assert evidence["final_implementation_export_tests"]["final-loader-contract"]["exit_code"] == 0
    assert evidence["verdicts"]["FRESH_TERMINAL_AUTH_NATIVE"] == "PENDING"
    assert evidence["verdicts"]["TC_HOOK_NATIVE"] == "PENDING"
    for gate in ("NATIVE_AI", "DNS9", "OPERATIONAL_PROMOTION"):
        assert evidence["verdicts"][gate] == "BLOCKED"
