"""Compile only. Never loads BPF, installs a service or assigns capabilities."""

import hashlib
import subprocess
from pathlib import Path


def verify_object(path: Path) -> None:
    """Parse BTF map definitions in userspace; never load or attach a BPF program."""
    import ctypes

    from soc_agent.continuous.native.policy import RUNTIME_FILES

    lib = ctypes.CDLL(str(RUNTIME_FILES["libbpf"]), use_errno=True)
    lib.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    lib.bpf_object__open_file.restype = ctypes.c_void_p
    lib.libbpf_get_error.argtypes = [ctypes.c_void_p]
    lib.libbpf_get_error.restype = ctypes.c_long
    lib.bpf_object__close.argtypes = [ctypes.c_void_p]
    lib.bpf_object__close.restype = None
    obj = lib.bpf_object__open_file(bytes(path), None)
    if not obj or lib.libbpf_get_error(obj):
        raise ValueError("CONTINUOUS_BPF_OBJECT_PARSE_FAILED")
    # bpf_object__load is intentionally absent: parsing requires no Kernel authority.
    lib.bpf_object__close(obj)


def build(directory: Path) -> dict[str, str]:
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = Path(__file__).parent
    headers = root.parents[1] / "security_ai/ebpf"
    commands = [
        [
            "clang-18",
            "-O2",
            "-g",
            "-ffile-prefix-map=" + str(root.parents[3]) + "=/soc-agent-source",
            "-fdebug-compilation-dir=/soc-agent-build",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-I/usr/include/x86_64-linux-gnu",
            "-I" + str(headers),
            "-c",
            str(root / "continuous.bpf.c"),
            "-o",
            str(directory / "continuous.bpf.o"),
        ],
        [
            "cc",
            "-O2",
            "-g0",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-misleading-indentation",
            "-shared",
            "-fPIC",
            "-Wl,-z,relro,-z,now,-z,noexecstack,--build-id=none",
            "-I" + str(headers),
            str(root / "provider.c"),
            "-lbpf",
            "-o",
            str(directory / "provider.so"),
        ],
    ]
    for command in commands:
        subprocess.run(command, check=True, capture_output=True, timeout=60)
    verify_object(directory / "continuous.bpf.o")
    import json
    import shutil

    from soc_agent.continuous.native.policy import RUNTIME_FILES

    (directory / "runtime-identity.json").write_text(
        json.dumps(
            {
                name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in RUNTIME_FILES.items()
            },
            sort_keys=True,
        )
    )

    for name in ("service.py", "policy.py"):
        shutil.copyfile(root / name, directory / name)
    (directory / "soc-continuous-collector.service").write_text(
        "[Unit]\nDescription=SOC policy-bound passive TCX collector\n"
        "[Service]\nType=simple\nUser=root\n"
        "ExecStart=/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/python3 -I "
        "/usr/lib/soc-agent/continuous/service.py\n"
        "NetworkNamespacePath=/run/netns/soc-native-b3\n"
        "RuntimeDirectory=soc-agent-continuous\nRuntimeDirectoryMode=0755\n"
        "CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_CHOWN\n"
        "NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n"
        "ReadWritePaths=/run/soc-agent-continuous /var/lib/soc-agent/continuous\n"
        "RestrictAddressFamilies=AF_UNIX AF_NETLINK\n"
        "MemoryMax=128M\nCPUQuota=25%\nTasksMax=4\nLimitMEMLOCK=8388608\n"
        "Restart=no\nTimeoutStopSec=10\nKillMode=control-group\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.iterdir())}


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(json.dumps(build(parser.parse_args().directory.absolute()), sort_keys=True))
