"""Read-only host facts and deterministic qualification; no capability or BPF syscalls."""

import gzip
import os
import platform
from pathlib import Path
from typing import Literal

from pydantic import Field

from soc_agent.security_ai.research.models import Frozen

REQUIRED_CAPS = frozenset({"CAP_BPF", "CAP_NET_ADMIN"})


class CapabilityFacts(Frozen):
    source: Literal["FIXTURE", "READ_ONLY_PROC"]
    effective: frozenset[str]
    permitted: frozenset[str]
    ambient: frozenset[str]
    uid: int = Field(ge=0)

    def verdict(self) -> dict[str, str]:
        scope = (
            "MATCHES_CANDIDATE"
            if self.uid != 0 and self.effective == self.permitted == self.ambient == REQUIRED_CAPS
            else "MISSING_OR_EXCESS_CAPABILITY"
        )
        return {
            "scope": scope,
            "source": self.source,
            "native_transfer": "UNKNOWN",
            "native_release": "BLOCKED",
        }


class KernelFacts(Frozen):
    kernel: str = Field(max_length=128)
    bpf_syscall_config: bool | None
    net_cls_bpf_config: bool | None
    net_xgress_config: bool | None
    btf_present: bool
    bpffs_mounted: bool
    namespace: str = Field(pattern=r"^net:\[[0-9]+\]$")
    ifindex: int = Field(gt=0)
    libbpf: str = Field(max_length=64)
    tcx_native: Literal["NOT_PROBED"] = "NOT_PROBED"

    def verdict(self, namespace: str, ifindex: int) -> dict[str, str]:
        mismatch = namespace != self.namespace or ifindex != self.ifindex
        missing = False in (
            self.bpf_syscall_config,
            self.net_cls_bpf_config,
            self.net_xgress_config,
        )
        return {
            "preflight": "BLOCKED" if mismatch or missing else "UNKNOWN_NATIVE_PROBE_REQUIRED",
            "btf": "OBSERVED"
            if self.btf_present
            else "MISSING_NOT_ALWAYS_REQUIRED_NON_CORE_PROGRAM",
            "tcx": self.tcx_native,
            "native_release": "BLOCKED",
        }


def observe_kernel() -> KernelFacts:
    release = platform.release()
    config = ""
    try:
        if Path("/proc/config.gz").exists():
            with gzip.open("/proc/config.gz", "rt") as stream:
                config = stream.read(1024**2)
        elif (path := Path("/boot/config-" + release)).is_file():
            config = path.read_text()[: 1024**2]
    except (OSError, EOFError):
        config = ""

    def option(name):
        if not config:
            return None
        return name + "=y" in config or name + "=m" in config

    import subprocess

    result = subprocess.run(
        ["/usr/bin/pkg-config", "--modversion", "libbpf"],
        capture_output=True,
        text=True,
        timeout=5,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
    )
    return KernelFacts(
        kernel=release,
        bpf_syscall_config=option("CONFIG_BPF_SYSCALL"),
        net_cls_bpf_config=option("CONFIG_NET_CLS_BPF"),
        net_xgress_config=option("CONFIG_NET_XGRESS"),
        btf_present=Path("/sys/kernel/btf/vmlinux").is_file(),
        bpffs_mounted=any(
            " - bpf " in line for line in Path("/proc/self/mountinfo").read_text().splitlines()
        ),
        namespace=os.readlink("/proc/self/ns/net"),
        ifindex=int(Path("/sys/class/net/lo/ifindex").read_text()),
        libbpf=result.stdout.strip() if result.returncode == 0 else "UNKNOWN",
    )


def unobserved() -> dict[str, str | None]:
    return {
        "installed_release": None,
        "installation_integrity": "NOT_OBSERVED",
        "authentication": "NATIVE_PENDING",
        "capability_state": "UNKNOWN_NATIVE_TRANSFER",
        "kernel_compatibility": "UNKNOWN_NOT_PROBED",
        "cleanup": "NOT_OBSERVED",
        "native_release": "BLOCKED",
    }
