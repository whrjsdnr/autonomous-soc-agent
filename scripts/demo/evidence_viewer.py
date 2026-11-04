"""Frozen, read-only presentation of retained results through the existing GUI.

This is an evidence viewer, never a replacement for `soc-agent start --gui`.
Its manifest records separate historical experiments, not a new combined E2E.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(release: Path) -> dict:
    manifest = json.loads((release / "manifest.json").read_text())
    if manifest["purpose"] != "PRESERVED_EVIDENCE_VIEW_ONLY":
        raise ValueError("DEMO_MANIFEST_PURPOSE")
    for name, expected in manifest["files"].items():
        path = Path(name) if Path(name).is_absolute() else release / name
        if not path.is_file() or sha256(path) != expected:
            raise ValueError(f"DEMO_INTEGRITY_MISMATCH: {name}")
    return manifest


def install_read_only_guard(protected: list[Path]) -> list[str]:
    """Deny new execution and protect retained evidence, including SQLite writes.

    This restricts the presentation process only; no production policy is changed.
    It is not a sandbox for malicious code or a substitute for live admission.
    """
    roots = tuple(path.resolve() for path in protected)
    violations: list[str] = []

    def is_protected(value) -> bool:
        if not isinstance(value, (str, bytes, os.PathLike)):
            return False
        path = Path(os.fsdecode(value)).resolve()
        return any(path == root or root in path.parents for root in roots)

    def deny(reason: str):
        violations.append(reason)
        print(f"PRESERVED_DEMO_READ_ONLY: {reason}", file=sys.stderr, flush=True)
        raise PermissionError(f"PRESERVED_DEMO_READ_ONLY: {reason}")

    connect = sqlite3.connect

    def read_only_connect(database, *args, **kwargs):
        raw = os.fsdecode(database)
        path = Path(unquote(urlsplit(raw).path)) if raw.startswith("file:") else Path(raw)
        if is_protected(path):
            database = path.resolve().as_uri() + "?mode=ro"
            kwargs["uri"] = True
        return connect(database, *args, **kwargs)

    sqlite3.connect = read_only_connect

    def audit(event, args):
        # ctypes locates the existing GUI's Cairo/Pango libraries through this
        # read-only cache query. No compiler, service or arbitrary child is allowed.
        if event == "subprocess.Popen" and args[1] == ["/sbin/ldconfig", "-p"]:
            return
        if event in {"subprocess.Popen", "os.system", "os.posix_spawn", "os.exec", "os.fork"}:
            deny("NEW_PROCESS_FORBIDDEN")
        if event in {"os.kill", "os.killpg"}:
            deny("PROCESS_CONTROL_FORBIDDEN")
        if event in {"socket.connect", "socket.sendto", "socket.bind"}:
            deny("NETWORK_OR_IPC_EXECUTION_FORBIDDEN")
        if event == "pickle.find_class" and str(args[0]).startswith(("sklearn", "xgboost")):
            deny("NEW_MODEL_LOAD_FORBIDDEN")
        if (
            event == "ctypes.dlopen"
            and args[0]
            and any(name in str(args[0]) for name in ("provider.so", "libnative-tc"))
        ):
            deny("NATIVE_PROVIDER_FORBIDDEN")
        if event == "open" and is_protected(args[0]):
            mode, flags = args[1:3]
            if (mode and any(char in mode for char in "wax+")) or (
                flags and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
            ):
                deny("EVIDENCE_WRITE_FORBIDDEN")
        if event in {"os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.utime", "os.truncate"}:
            if is_protected(args[0]):
                deny("EVIDENCE_MUTATION_FORBIDDEN")
        if event in {"os.rename", "os.link", "os.symlink"}:
            if any(is_protected(value) for value in args[:2]):
                deny("EVIDENCE_RELOCATION_FORBIDDEN")

    sys.addaudithook(audit)
    return violations


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "view", nargs="?", default="native", choices=("native", "replay", "api", "authentication")
    )
    parser.add_argument(
        "--check", action="store_true", help="Verify frozen files without starting GUI"
    )
    args = parser.parse_args(argv)
    release = Path(__file__).resolve().parent
    manifest = verify(release)
    view = manifest["views"][args.view]
    print("PRESERVED EVIDENCE — NOT LIVE / NO NEW MODEL OR API CALLS", flush=True)
    print(view["description"], flush=True)
    print("Integrity PASS. Close window or Ctrl+C to stop this viewer.", flush=True)
    if args.check:
        return 0
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(release / "python"))
    protected = [Path(path) for path in manifest["protected"]]
    protected.extend((release / "python", release / "manifest.json", Path(__file__).resolve()))
    violations = install_read_only_guard(protected)
    from soc_agent.gui import __main__ as entry
    from soc_agent.gui import production

    original = production.Desktop

    class EvidenceDesktop(original):
        def __init__(self, root, config, **kwargs):
            super().__init__(root, config, **kwargs)
            root.title(f"Autonomous SOC Agent — {args.view}")

    production.Desktop = EvidenceDesktop
    try:
        return entry.main(
            ["--data-directory", str(release / "view-state" / args.view), *view["gui_args"]]
        )
    finally:
        production.Desktop = original
        print(
            f"Viewer stopped. Blocked operations: {len(violations)}. Historical evidence retained.",
            flush=True,
        )


if __name__ == "__main__":
    raise SystemExit(main())
