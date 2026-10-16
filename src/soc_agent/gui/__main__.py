"""Launch the local Linux desktop; no listener, credentials or automatic runtime start."""

import argparse
import os
import signal
import sys
from pathlib import Path

from soc_agent.gui.backend import GUIConfig
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-directory",
        type=Path,
        default=Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
        / "autonomous-soc-agent/gui",
    )
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--native-python", type=Path)
    parser.add_argument(
        "--source-label",
        choices=("UNVERIFIED", "LIVE_WSL", "FIXTURE"),
        default="UNVERIFIED",
        help="Display label only; never source attestation or inference authority",
    )
    args = parser.parse_args()
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("SOC_GUI_REQUIRES_UNPRIVILEGED_USER", file=sys.stderr)
        return 1
    try:
        import tkinter as tk
    except ImportError:
        print("SOC GUI BLOCKED: Tkinter unavailable", file=sys.stderr)
        return 1
    try:
        from soc_agent.gui.app import Desktop

        config = GUIConfig(
            data_directory=args.data_directory.absolute(),
            runtime_directory=args.runtime,
            artifacts=args.artifacts,
            native_python=args.native_python,
            source_label=args.source_label,
        )
        create_private_directory(config.data_directory)
        lock = config.data_directory / "desktop.lock"
        if not lock.exists():
            create_private_file(lock)
        with exclusive_runtime_lock(lock):
            root = tk.Tk()
            desktop = Desktop(root, config)
            previous = {}
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous[signum] = signal.signal(signum, lambda *_: root.after(0, desktop.close))
            try:
                root.mainloop()
            finally:
                for signum, handler in previous.items():
                    signal.signal(signum, handler)
        return 0
    except (
        ImportError,
        tk.TclError,
        OSError,
        ValueError,
    ) as error:
        # Never echo configuration, provider exceptions, credentials or raw journal content.
        print(
            "SOC GUI BLOCKED: "
            + type(error).__name__
            + " — check WSLg, system Pango/Cairo, private directory and duplicate GUI.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
