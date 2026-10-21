"""Compile/link only; no installation, setuid, file-capability or Kernel invocation."""

import hashlib
import subprocess
from pathlib import Path

from soc_agent.security_ai.ebpf_broker.identity import bundle as broker_bundle
from soc_agent.security_ai.research.models import digest

ROOT = Path(__file__).parent
AUTH_POLICY = {
    "SOC_AUTH_PAM_SHA": Path("/etc/pam.d/sudo"),
    "SOC_AUTH_COMMON_SHA": Path("/etc/pam.d/common-auth"),
    "SOC_AUTH_ACCOUNT_SHA": Path("/etc/pam.d/common-account"),
}

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
    # Bind the unprivileged metadata/feature contract as well as privileged code.
    for name in ("clock.py", "collector.py", "models.py", "ring.py", "event.h", "parser.h"):
        p = ROOT.parent / "ebpf" / name
        result["data_adapter/" + name] = hashlib.sha256(p.read_bytes()).hexdigest()
    p = ROOT.parent / "collectors" / "packet_producer.py"
    result["data_adapter/packet_producer.py"] = hashlib.sha256(p.read_bytes()).hexdigest()
    return result


def compile_native(destination: Path) -> dict[str, str]:
    from soc_agent.security_ai.ebpf_tc.password_policy import validate_pam_inputs

    validate_pam_inputs({key: path.read_text() for key, path in AUTH_POLICY.items()})
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
                    "handoff.c",
                    "netlink.c",
                    "loader.c",
                    "data.c",
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
    # OS-authenticated entry; no custom PAM/SUID or inherited sudo FD assumptions.
    commands.append(
        [
            "cc",
            *FLAGS,
            *[
                f'-D{key}="{hashlib.sha256(path.read_bytes()).hexdigest()}"'
                for key, path in AUTH_POLICY.items()
            ],
            *[
                str(ROOT / n)
                for n in (
                    "os_bootstrap.c",
                    "auth_qualification.c",
                    "unified_proof.c",
                    "handoff.c",
                    "core.c",
                    "os.c",
                    "trust.c",
                )
            ],
            "-lcrypto",
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
                    "handoff.c",
                    "netlink.c",
                    "loader.c",
                    "data.c",
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
    commands.append(
        [
            "cc",
            *FLAGS,
            *[
                str(ROOT / n)
                for n in ("handoff_fixture.c", "handoff.c", "data.c", "core.c", "os.c", "trust.c")
            ],
            "-lcrypto",
            "-Wl,-z,relro,-z,now,-z,noexecstack",
            "-o",
            str(destination / "os-handoff-fixture"),
        ]
    )
    # Ordinary-UID packet replay peer; never installed or selected by Native argv.
    commands.append(
        [
            "cc",
            *FLAGS,
            "-DSOC_PACKET_FIXTURE=1",
            *[
                str(ROOT / n)
                for n in ("handoff_fixture.c", "handoff.c", "data.c", "core.c", "os.c", "trust.c")
            ],
            "-lcrypto",
            "-Wl,-z,relro,-z,now,-z,noexecstack",
            "-o",
            str(destination / "packet-handoff-fixture"),
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
