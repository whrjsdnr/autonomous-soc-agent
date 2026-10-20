"""Unprivileged compiled libbpf ELF inspection; Native load/attach remain unreachable."""

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


def file_sha(path: Path) -> str:
    if (
        path.is_symlink()
        or not path.is_file()
        or not 64 <= path.stat().st_size <= 1024**2
        or path.stat().st_mode & 0o6000
    ):
        raise ValueError("EBPF_LOADER_FILE_REJECTED")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bundle() -> dict[str, str]:
    root = Path(__file__).parent
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.iterdir())
        if p.suffix in {".py", ".c"}
    }


def compile_loader(directory: Path) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).with_name("loader.c")
    output = directory / "phase-a-loader"
    subprocess.run(
        ["cc", "-O2", "-Wall", "-Werror", str(source), "-lbpf", "-lcrypto", "-o", str(output)],
        capture_output=True,
        check=True,
        timeout=30,
    )
    return file_sha(output)


class Inspector:
    """Accept only a binary reproduced from this package's fixed phase-A C source."""

    def __init__(self, loader: Path, loader_sha: str):
        with tempfile.TemporaryDirectory(prefix="soc-loader-reference-") as directory:
            reference = compile_loader(Path(directory))
        if reference != loader_sha or file_sha(loader) != reference:
            raise ValueError("EBPF_LOADER_REFERENCE_MISMATCH")
        try:
            capabilities = os.getxattr(loader, "security.capability")
        except OSError as exc:
            import errno

            if exc.errno not in {errno.ENODATA, errno.ENOTSUP}:
                raise ValueError("EBPF_LOADER_CAPABILITY_INSPECTION_FAILED") from exc
        else:
            if capabilities:
                raise ValueError("EBPF_LOADER_PRIVILEGED_FILE_DENIED")
        self.loader, self.sha = loader, reference

    def inspect(self, program: Path, expected: str) -> dict:
        return _inspect(program, expected, self.loader, self.sha)


def inspect(program: Path, expected: str, loader: Path, loader_sha: str) -> dict:
    return Inspector(loader, loader_sha).inspect(program, expected)


def _inspect(program: Path, expected: str, loader: Path, loader_sha: str) -> dict:
    if os.geteuid() == 0 or file_sha(program) != expected or file_sha(loader) != loader_sha:
        raise ValueError("EBPF_LOADER_IDENTITY_MISMATCH")
    try:
        p = subprocess.run(
            [str(loader.absolute()), "--inspect", str(program.absolute()), expected],
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("EBPF_LOADER_PREPARATION_REJECTED") from exc
    if p.returncode or len(p.stdout) > 4096:
        raise ValueError("EBPF_LOADER_PREPARATION_REJECTED")
    value = json.loads(p.stdout)
    if value.get("kernel_load") is not False or value.get("tc_attach") is not False:
        raise ValueError("EBPF_PHASE_A_NATIVE_EXECUTION_DISABLED")
    if file_sha(program) != expected or file_sha(loader) != loader_sha:
        raise ValueError("EBPF_LOADER_IDENTITY_MISMATCH")
    return value


def native_load_or_attach() -> None:
    raise ValueError("EBPF_PHASE_A_NATIVE_EXECUTION_DISABLED")


def capability_preflight() -> dict:
    """Read-only candidate requirements, never grants or Native admission proof."""
    text = Path("/proc/self/status").read_text()
    bits = int(
        next(line.split()[1] for line in text.splitlines() if line.startswith("CapEff:")), 16
    )
    required = {"CAP_BPF": 39, "CAP_NET_ADMIN": 12}
    return dict(
        effective={name: bool(bits & (1 << bit)) for name, bit in required.items()},
        required=list(required),
        cap_perfmon_required_for_this_tc_contract=False,
        privilege_granted=False,
        native_execution="PHASE_A_DISABLED",
    )
