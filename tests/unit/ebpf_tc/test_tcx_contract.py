"""TCX fixture state cannot be promoted to Native or persistent authority."""

import pytest
from pydantic import ValidationError

from soc_agent.security_ai.ebpf_tc.tcx import LinkFixtureResult, unobserved


def test_unobserved_is_unknown_not_zero_or_live():
    value = unobserved()
    assert value["link_id"] is None and value["ownership"] == "NOT_OBSERVED"
    assert value["kernel_support"] == "UNKNOWN_NOT_PROBED"
    assert value["program_semantics"] == "BLOCKED_TCX_PASS_SKIPS_CHAIN"
    assert value["native_release"] == "BLOCKED"


@pytest.mark.parametrize(
    "change", [{"native": True}, {"phase": 99}, {"source": "NATIVE"}, {"link_fd": 71}]
)
def test_fake_identity_or_fd_cannot_become_native(change):
    base = dict(
        source="TCX_FAKE_RESOURCE_TABLE_NOT_KERNEL",
        native=False,
        replay=-1,
        link_id=501,
        attach=0,
        detach=0,
        phase=4,
        active=0,
        references=0,
        foreign=1,
        deletes=1,
        closed=1,
        trace="",
        owner=dict(
            origin="C_FAKE_NOT_KERNEL",
            link_id=501,
            program_id=101,
            attach_type=46,
            ifindex=1,
            namespace_inode=44,
            generation=1,
            broker_pid=9,
            broker_ticks=77,
            pinned=0,
            program_sha="02" * 32,
            program_tag="03" * 8,
            application="01" * 16,
        ),
    )
    with pytest.raises(ValidationError):
        LinkFixtureResult.model_validate(base | change)
