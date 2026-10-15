"""Explicit checks for this approved WSL run; never grants privileges or sends traffic."""

import grp
import hashlib
import os
import pwd
from pathlib import Path

from soc_agent.security_ai.operational.network_capture import native_probe
from soc_agent.security_ai.operational.network_capture.capture import interface_identity
from soc_agent.security_ai.operational.network_capture.permissions import (
    capture_permission,
    privileges,
)


def test_approved_probe_source_is_exactly_the_reviewed_version():
    expected = "59b67d8a7654eebbb7f05e3810b3d3e2da0aea5029872a09ca01ed1e9a12a50d"
    assert hashlib.sha256(Path(native_probe.__file__).read_bytes()).hexdigest() == expected


def test_os_identity_matches_the_approved_uid_and_gid():
    assert os.getuid() == os.geteuid() == pwd.getpwuid(os.geteuid()).pw_uid == 1000
    assert os.getgid() == os.getegid() == grp.getgrgid(os.getegid()).gr_gid == 1000
    assert all(privileges()[field] == 0 for field in ("CapEff", "CapPrm", "CapInh", "CapAmb"))


def test_real_permission_denial_is_not_capture_or_producer_success():
    before = privileges()
    identity = interface_identity("lo")
    result = capture_permission("lo")
    assert result["capture"] == "PERMISSION_DENIED"
    assert result["privileges_unchanged"] and privileges() == before
    assert interface_identity("lo") == identity
    assert result["actual_packets_verified"] is False
    assert result["capture_drops"] is None
    assert result["automatic_privilege_escalation"] is False
    assert all(
        gate["operational_input"] == "NOT_INFERABLE" and gate["finding_promotion"] == "BLOCKED"
        for gate in result["operational_models"].values()
    )
