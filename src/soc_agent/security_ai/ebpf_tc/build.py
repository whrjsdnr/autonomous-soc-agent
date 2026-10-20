"""Compile/link only; no installation, setuid, file-capability or Kernel invocation."""

import hashlib
import subprocess
from pathlib import Path

from soc_agent.security_ai.ebpf_broker.identity import bundle as broker_bundle
from soc_agent.security_ai.research.models import digest

ROOT = Path(__file__).parent
FLAGS = ["-O2", "-g0", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation"]


def bundle() -> dict[str, str]:
    result = {"b1/" + k: v for k, v in broker_bundle().items()}
    result.update(
        {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(ROOT.iterdir())
            if p.suffix in {".py", ".c", ".h", ".conf"}
        }
    )
    return result


def compile_native(destination: Path) -> dict[str, str]:
    destination.mkdir(parents=True, exist_ok=True)
    commands = [
        [
            "cc",
            *FLAGS,
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-pie",
            "-no-pie",
            "-nostdlib",
            "-static",
            "-Wl,-z,noexecstack,--build-id=none",
            str(ROOT / "entry.c"),
            "-o",
            str(destination / "entry"),
        ],
        [
            "cc",
            *FLAGS,
            "-fPIC",
            "-shared",
            "-Wl,-z,relro,-z,now,-z,noexecstack",
            *[
                str(ROOT / n)
                for n in (
                    "core.c",
                    "os.c",
                    "trust.c",
                    "netlink.c",
                    "loader.c",
                    "tcx.c",
                    "tcx_dispatch.c",
                )
            ],
            "-lbpf",
            "-lcrypto",
            "-o",
            str(destination / "libnative-tc.so"),
        ],
    ]
    # Retained, gated PAM migration reference; no custom SUID installation remains.
    # It cannot acquire privilege or bypass the removed Entry proof creation path.
    commands.append(
        [
            "cc",
            *FLAGS,
            *[str(ROOT / n) for n in ("bootstrap.c", "core.c", "os.c", "trust.c")],
            "-lcrypto",
            "-l:libpam.so.0",
            "-l:libpam_misc.so.0",
            "-Wl,-z,relro,-z,now,-z,noexecstack",
            "-o",
            str(destination / "bootstrap"),
        ]
    )
    # Broker embeds our reviewed loader code, rather than resolving a custom DSO
    # after privilege transfer. Only the unprivileged fake driver uses $ORIGIN.
    commands.append(
        [
            "cc",
            *FLAGS,
            *[
                str(ROOT / n)
                for n in (
                    "broker.c",
                    "core.c",
                    "os.c",
                    "trust.c",
                    "netlink.c",
                    "loader.c",
                    "tcx.c",
                    "tcx_dispatch.c",
                )
            ],
            "-lbpf",
            "-lcrypto",
            "-Wl,-z,relro,-z,now,-z,noexecstack",
            "-o",
            str(destination / "broker"),
        ]
    )
    for name in ("fixture",):
        commands.append(
            [
                "cc",
                *FLAGS,
                str(ROOT / (name + ".c")),
                str(ROOT / "tcx_fixture.c"),
                "-L" + str(destination),
                "-lnative-tc",
                "-Wl,-rpath,$ORIGIN",
                "-Wl,-z,relro,-z,now,-z,noexecstack",
                "-o",
                str(destination / ("tc-" + name if name == "fixture" else name)),
            ]
        )
    commands.append(
        [
            "cc",
            *FLAGS,
            str(ROOT / "dispatch_fixture.c"),
            "-L" + str(destination),
            "-lnative-tc",
            "-Wl,-rpath,$ORIGIN",
            "-o",
            str(destination / "tcx-dispatch-fixture"),
        ]
    )
    for command in commands:
        subprocess.run(command, capture_output=True, check=True, timeout=30)
    tcx = compile_tcx(destination)
    return (
        {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (
                destination / "entry",
                destination / "bootstrap",
                destination / "broker",
                destination / "libnative-tc.so",
                destination / "tc-fixture",
                destination / "tcx-dispatch-fixture",
            )
        }
        | tcx
        | {"source_bundle_digest": digest(bundle())}
    )


def compile_tcx(destination: Path) -> dict[str, str]:
    """Compile a distinct TCX_NEXT object; never load or attach it."""
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / "tcx.bpf.o"
    subprocess.run(
        [
            "clang",
            "-target",
            "bpfel",
            "-O2",
            "-g",
            "-Wall",
            "-Werror",
            "-fdebug-compilation-dir=/soc-ebpf",
            "-fdebug-prefix-map=" + str(ROOT.parent) + "=/soc-ebpf",
            "-I/usr/include/x86_64-linux-gnu",
            "-c",
            str(ROOT / "tcx.bpf.c"),
            "-o",
            str(output),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return {output.name: hashlib.sha256(output.read_bytes()).hexdigest()}
