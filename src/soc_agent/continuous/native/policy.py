"""Read an administrator-installed service contract; never issue or activate authority.

No diagnostic or development receipt is accepted as a service installation grant.
The fixed file must be installed only after the existing human review process.
"""

import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

POLICY = Path("/etc/soc-agent/continuous-installation.json")
INSTALL = Path("/usr/lib/soc-agent/continuous")
RUNTIME_FILES = {
    "python": Path("/usr/bin/python3").resolve(),
    "libbpf": Path("/usr/lib/x86_64-linux-gnu/libbpf.so.1").resolve(),
    "libelf": Path("/usr/lib/x86_64-linux-gnu/libelf.so.1").resolve(),
    "libz": Path("/usr/lib/x86_64-linux-gnu/libz.so.1").resolve(),
    "libc": Path("/usr/lib/x86_64-linux-gnu/libc.so.6").resolve(),
}


def root_file(path: Path, limit=65536) -> bytes:
    for parent in (path, *path.parents):
        info = parent.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError("CONTINUOUS_UNTRUSTED_INSTALLATION")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("CONTINUOUS_INSTALLATION_BOUND")
        return os.read(fd, limit + 1)
    finally:
        os.close(fd)


def validate(body: bytes, *, now=None) -> dict:
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("CONTINUOUS_INSTALLATION_SCHEMA")
    required = {
        "contract",
        "purpose",
        "namespace",
        "interface",
        "uid",
        "expires_at",
        "human_review_sha256",
        "risk_review_sha256",
        "files",
        "network_effect",
        "native_model_inference",
        "runtime",
    }
    if (
        set(value) != required
        or value["contract"] != "soc-continuous-installation:v1"
        or (
            value["purpose"] != "CONTINUOUS_COLLECTOR_SERVICE"
            or value["interface"] != "lo"
            or value["network_effect"] != "PASSIVE_INGRESS_ONLY"
            or value["native_model_inference"] is not False
            or type(value["uid"]) is not int
            or value["uid"] < 1000
        )
    ):
        raise ValueError("CONTINUOUS_INSTALLATION_SCOPE")
    import re

    if not re.fullmatch(r"net:\[[1-9][0-9]*\]", value["namespace"]):
        raise ValueError("CONTINUOUS_INSTALLATION_NAMESPACE")
    if not isinstance(value["files"], dict):
        raise ValueError("CONTINUOUS_INSTALLATION_FILES_SCHEMA")
    if set(value["files"]) != {"continuous.bpf.o", "provider.so", "service.py", "policy.py"} or any(
        not isinstance(pin, str) or not re.fullmatch("[a-f0-9]{64}", pin)
        for pin in [
            *value["files"].values(),
            value["human_review_sha256"],
            value["risk_review_sha256"],
        ]
    ):
        raise ValueError("CONTINUOUS_INSTALLATION_BINDING")
    if not isinstance(value["runtime"], dict):
        raise ValueError("CONTINUOUS_RUNTIME_SCHEMA")
    if set(value["runtime"]) != set(RUNTIME_FILES) or any(
        not isinstance(pin, str) or not re.fullmatch("[a-f0-9]{64}", pin)
        for pin in value["runtime"].values()
    ):
        raise ValueError("CONTINUOUS_RUNTIME_BINDING")
    expiry = datetime.fromisoformat(value["expires_at"])
    current = now or datetime.now(UTC)
    if expiry.tzinfo is None or not current < expiry or (expiry - current).total_seconds() > 86400:
        raise ValueError("CONTINUOUS_INSTALLATION_EXPIRED_OR_UNBOUNDED")
    return value


def installed() -> dict:
    value = validate(root_file(POLICY))
    for name, path in RUNTIME_FILES.items():
        if hashlib.sha256(root_file(path, 16 * 1024**2)).hexdigest() != value["runtime"][name]:
            raise ValueError("CONTINUOUS_RUNTIME_CHANGED")
    for name, pin in value["files"].items():
        if hashlib.sha256(root_file(INSTALL / name, 4 * 1024**2)).hexdigest() != pin:
            raise ValueError("CONTINUOUS_INSTALLED_EXECUTABLE_CHANGED")
    return value
