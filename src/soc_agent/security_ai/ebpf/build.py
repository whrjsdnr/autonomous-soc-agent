"""Compile-only fixed commands. No bpftool, BPF syscall, TC or privileged invocation."""

import hashlib
import subprocess
from pathlib import Path


def compile_program(destination: Path) -> dict:
    root = Path(__file__).parent
    destination.mkdir(parents=True, exist_ok=True)
    commands = [
        [
            "clang",
            "-target",
            "bpfel",
            "-O2",
            "-g",
            "-Wall",
            "-Werror",
            "-fdebug-compilation-dir=/soc-ebpf",
            "-I/usr/include/x86_64-linux-gnu",
            "-fdebug-prefix-map=" + str(root) + "=/soc-ebpf",
            "-c",
            str(root / "tc.bpf.c"),
            "-o",
            str(destination / "tc.bpf.o"),
        ],
        [
            "cc",
            "-O2",
            "-Wall",
            "-Werror",
            str(root / "consumer.c"),
            "-lbpf",
            "-o",
            str(destination / "ring-consumer"),
        ],
    ]
    for argv in commands:
        subprocess.run(argv, check=True, capture_output=True, timeout=30)
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (destination / "tc.bpf.o", destination / "ring-consumer")
    }


def source_digest() -> str:
    from soc_agent.security_ai.research.models import digest

    root = Path(__file__).parent
    return digest(
        {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.iterdir())
            if p.suffix in {".c", ".h"}
        }
    )
