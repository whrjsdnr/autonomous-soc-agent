"""Embedded Namespace checks. No entry, mounts, grants, Docker or traffic."""

import hashlib
import json
import os
import time
from pathlib import Path


def namespace_runtime_root_check(packet):
    policy = packet.get("policy")
    binding = packet["binding"]
    body = packet.get("policy_body")
    if (
        any((os.getuid(), os.geteuid(), os.getgid(), os.getegid()))
        or (os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID"))
        != (str(binding["uid"]), str(binding["gid"]))
        or not isinstance(body, str)
        or hashlib.sha256(body.encode()).hexdigest() != packet.get("policy_sha")
        or json.loads(body) != policy
        or policy.get("contract") != "SOC_NAMESPACE_SUPERVISOR_BUILD_POLICY_V1"
        or policy.get("decision") != "APPROVED"
        or policy.get("binding") != binding
        or policy.get("activate_namespace_supervisor") is not True
        or any(
            policy.get(k) is not False
            for k in ("authorize_root", "authorize_native", "authorize_traffic")
        )
        or not policy["issued_at"] <= time.time() < policy["expires_at"]
        or not 0 < policy["expires_at"] - policy["issued_at"] <= 86400
        or any(v in policy["approver"].upper() for v in ("MOCK", "FIXTURE", "SCRIPTED"))
        or os.readlink("/proc/self/ns/net") != binding["namespace"]
        or Path("/proc/sys/kernel/random/boot_id").read_text().strip() != binding["boot_id"]
    ):
        raise ValueError("NAMESPACE_RUNTIME_POLICY_REQUIRED")
    fd = os.open("/run/netns/soc-native-b3", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino, st.st_uid) != (
            binding["namespace_device"],
            binding["namespace_inode"],
            0,
        ):
            raise ValueError("NAMESPACE_RUNTIME_LEASE_CHANGED")
    finally:
        os.close(fd)
