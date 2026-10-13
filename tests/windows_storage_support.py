"""Read-only, redacted ACL diagnostics for actual Windows test fixtures."""

from pathlib import Path

from soc_agent.review.persistence.secure_storage import StorageSecurityError


def acl_diagnostics(path: Path, *, target_alias: str) -> str:
    from soc_agent.review.persistence.windows_storage import INHERITED, NativeWin32

    api = NativeWin32()
    known = {
        api.user: "CURRENT_USER (SID redacted)",
        "S-1-5-18": "SYSTEM",
        "S-1-5-32-544": "ADMINISTRATORS",
        "S-1-3-4": "OWNER_RIGHTS",
        "S-1-1-0": "EVERYONE",
        "S-1-5-32-545": "USERS",
        "S-1-5-11": "AUTHENTICATED_USERS",
        api.volume_root_owner(): "TRUSTEDINSTALLER (OS resolved)",
    }
    lines = []
    for index, component in enumerate((path, *path.parents)):
        alias = target_alias if index == 0 else f"{target_alias}/ancestor[{index}]"
        try:
            with api.hold(str(component)) as handle:
                value = api.snapshot(handle)
        except StorageSecurityError:
            lines.append(f"{alias}: descriptor unavailable; no fallback")
            continue
        lines.append(
            f"{alias}: owner={known.get(value.owner, 'OTHER (SID redacted)')} "
            f"protected={value.protected} reparse={value.reparse} "
            f"filesystem={value.filesystem} persistent_acls={value.persistent_acls}"
        )
        for ace in value.aces[:64]:
            lines.append(
                f"  ACE principal={known.get(ace.sid, 'OTHER (SID redacted)')} "
                f"kind={ace.kind} mask=0x{ace.mask:08x} flags=0x{ace.flags:02x} "
                f"inherited={bool(ace.flags & INHERITED)} inherit_only={bool(ace.flags & 8)}"
            )
    return "\n".join(lines)
