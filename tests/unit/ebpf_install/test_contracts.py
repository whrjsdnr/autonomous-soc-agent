"""Mock observations never grant Native authority or change the host."""

import os

import pytest
from pydantic import ValidationError

from soc_agent.security_ai.ebpf_tc.auth_qualification import PamFixture
from soc_agent.security_ai.ebpf_tc.qualification import REQUIRED_CAPS, CapabilityFacts, KernelFacts


@pytest.mark.parametrize(
    "changes",
    [
        {"tty_uid": 1001},
        {"tty_foreground": False},
        {"challenges": 0},
        {"challenges": 2},
        {"authentication": "DENIED"},
        {"authentication": "CANCELLED"},
        {"authentication": "TIMEOUT"},
        {"account": "DENIED"},
        {"account": "EXPIRED"},
        {"cached_only": True},
        {"password_policy_guaranteed": False},
    ],
)
def test_pam_failure_cancellation_cache_account_and_terminal_cases(changes):
    result = (
        PamFixture(uid=1000, tty_uid=1000, **changes).verdict()
        if "tty_uid" not in changes
        else PamFixture(uid=1000, **changes).verdict()
    )
    assert result["contract"] == "BLOCKED" and result["authority_created"] == "NONE"
    assert result["native_authentication"] == "PENDING"


def test_mock_success_is_not_native_or_password_storage():
    fixture = PamFixture(uid=1000, tty_uid=1000)
    assert fixture.verdict()["contract"] == "FIXTURE_VERIFIED"
    assert fixture.verdict()["authority_created"] == "NONE"
    with pytest.raises(ValidationError):
        PamFixture(uid=1000, tty_uid=1000, password="forbidden")
    with pytest.raises(ValidationError):
        PamFixture(uid=1000, tty_uid=1000, service="sudo")


@pytest.mark.parametrize(
    "caps",
    [
        frozenset(),
        frozenset({"CAP_BPF"}),
        REQUIRED_CAPS | {"CAP_SYS_ADMIN"},
        REQUIRED_CAPS | {"CAP_PERFMON"},
    ],
)
def test_missing_or_excess_capabilities_are_blocked(caps):
    value = CapabilityFacts(
        source="FIXTURE", uid=1000, effective=caps, permitted=caps, ambient=caps
    ).verdict()
    assert value["scope"] == "MISSING_OR_EXCESS_CAPABILITY"
    assert value["native_transfer"] == "UNKNOWN" and value["native_release"] == "BLOCKED"


def test_candidate_profile_is_not_native_capability_qualification():
    value = CapabilityFacts(
        source="FIXTURE",
        uid=1000,
        effective=REQUIRED_CAPS,
        permitted=REQUIRED_CAPS,
        ambient=REQUIRED_CAPS,
    ).verdict()
    assert value["scope"] == "MATCHES_CANDIDATE" and value["native_transfer"] == "UNKNOWN"


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({}, "UNKNOWN_NATIVE_PROBE_REQUIRED"),
        ({"btf_present": False}, "UNKNOWN_NATIVE_PROBE_REQUIRED"),
        ({"bpf_syscall_config": False}, "BLOCKED"),
        ({"net_xgress_config": False}, "BLOCKED"),
        ({"net_cls_bpf_config": None}, "UNKNOWN_NATIVE_PROBE_REQUIRED"),
    ],
)
def test_kernel_config_is_not_runtime_tcx_support(changes, expected):
    fields = (
        dict(
            kernel="6.18.33.2",
            bpf_syscall_config=True,
            net_cls_bpf_config=True,
            net_xgress_config=True,
            btf_present=True,
            bpffs_mounted=False,
            namespace="net:[44]",
            ifindex=1,
            libbpf="1.3.0",
        )
        | changes
    )
    facts = KernelFacts(**fields)
    assert facts.verdict("net:[44]", 1)["preflight"] == expected
    assert facts.verdict("net:[45]", 1)["preflight"] == "BLOCKED"
    assert facts.verdict("net:[44]", 2)["preflight"] == "BLOCKED"
    assert facts.tcx_native == "NOT_PROBED"


def test_observe_host_does_not_claim_kernel_probe():
    from soc_agent.security_ai.ebpf_tc.qualification import observe_kernel

    facts = observe_kernel()
    assert facts.ifindex == int(open("/sys/class/net/lo/ifindex").read())
    assert facts.namespace == os.readlink("/proc/self/ns/net")
    assert facts.verdict(facts.namespace, facts.ifindex)["native_release"] == "BLOCKED"


def test_root_execution_of_development_verifier_is_rejected_before_file_io(monkeypatch):
    from soc_agent.security_ai.ebpf_tc.installation import validate_root_release

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(ValueError, match="NON_ROOT_REQUIRED"):
        validate_root_release(None)
