"""One terminal command; passwords belong exclusively to the operating system."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

from soc_agent.security_ai.operational.network_capture.total_session import verify_bundle
from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.total_auth import sudo_binary


def terminal_authenticate(*, run=None):
    # Inherit terminal stdin/stderr. Never PIPE, capture_output, password API or sudo -S.
    if not sys.stdin.isatty():
        raise ValueError("TOTAL_INTERACTIVE_TERMINAL_REQUIRED")
    runner = run or subprocess.run
    result = runner([sudo_binary(), "-v"], timeout=60, check=False)
    if result.returncode != 0:
        raise ValueError("TOTAL_AUTH_DENIED_OR_CANCELLED")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start")
    start.add_argument("--gui", required=True, action="store_true")
    start.add_argument("--monitor", required=True, choices=("total",))
    start.add_argument("--data-directory", type=Path)
    args = parser.parse_args(argv)
    try:
        from soc_agent.security_ai.operational.network_capture.live_session import unprivileged

        unprivileged()
        hashes = verify_bundle()
        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            raise ValueError("TOTAL_WSLG_DISPLAY_REQUIRED")
        import tkinter  # noqa: F401

        data = (
            args.data_directory
            or Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
            / "autonomous-soc-agent/gui"
        )
        if ResearchAdapter(data, live_metadata=True).status().get("status") != "READY":
            raise ValueError("TOTAL_RESEARCH_ARTIFACT_OR_ENVIRONMENT_BLOCKED")
        print("NEW TOTAL HELPER APPROVAL: lo / 300s / 128 raw frames/s / burst 256 / max 38656.")
        print("Temporary CAP_NET_RAW; drops after socket open; DNS metadata digests only.")
        print("RESEARCH_ONLY; DNS9 and operational AI BLOCKED; no security WRITE.")
        print("Total Helper SHA256: " + hashes["total_helper.py"])
        from soc_agent.security_ai.research.models import digest

        print("Helper bundle digest: " + digest(hashes))
        if not sys.stdin.isatty() or input("Approve this new scope? [yes/NO] ").strip() != "yes":
            raise ValueError("TOTAL_SCOPE_APPROVAL_CANCELLED")
        terminal_authenticate()
        from soc_agent.gui.__main__ import main as gui_main

        return gui_main(
            ["--data-directory", str(data), "--total-approved-sha", hashes["total_helper.py"]]
        )
    except (
        ValueError,
        OSError,
        ImportError,
        EOFError,
        KeyboardInterrupt,
        subprocess.TimeoutExpired,
    ) as error:
        code = str(error) if isinstance(error, ValueError) else type(error).__name__
        if not code.replace("_", "").isalnum():
            code = "TOTAL_STARTUP_FAILED"
        print("Total monitoring BLOCKED: " + code, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
