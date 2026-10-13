"""Verify the actual host storage fixture, not a mocked Windows security policy."""

import os

from soc_agent.review.persistence.secure_storage import validate_directory


def test_common_temp_storage_satisfies_host_private_policy(tmp_path):
    validate_directory(tmp_path)
    if os.name == "nt":
        from soc_agent.review.persistence.windows_storage import (
            ADMINISTRATORS,
            FULL_ACCESS,
            SYSTEM,
            NativeWin32,
        )

        assert tmp_path.name == "SOC private tests"
        api = NativeWin32()
        with api.hold(str(tmp_path)) as handle:
            snapshot = api.snapshot(handle)
        assert snapshot.owner == api.user and snapshot.protected and not snapshot.reparse
        assert {a.sid for a in snapshot.aces} == {api.user, SYSTEM, ADMINISTRATORS}
        assert all(a.kind == 0 and a.flags == 3 and a.mask == FULL_ACCESS for a in snapshot.aces)
    else:
        assert tmp_path.stat().st_mode & 0o777 == 0o700
