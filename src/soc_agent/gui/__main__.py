"""Launch the local Linux desktop; no listener, credentials or automatic runtime start."""

import argparse
import os
import signal
import sys
from contextlib import nullcontext
from pathlib import Path

from soc_agent.gui.backend import GUIConfig
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock


def main(argv=None, *, prepared=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-directory",
        type=Path,
        default=Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
        / "autonomous-soc-agent/gui",
    )
    parser.add_argument(
        "--analysis-result",
        type=Path,
        help="Verify and display an existing audited analysis report",
    )
    parser.add_argument(
        "--analysis-ml-root", type=Path, help="Existing pinned ML workspace for offline replay"
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
    parser.add_argument("--total-approved-sha", help=argparse.SUPPRESS)
    parser.add_argument(
        "--total-rate-policy",
        default="legacy",
        choices=("legacy", "conservative-v2", "balanced-v2", "performance-v2", "direction-v3"),
    )
    parser.add_argument("--calibrated-approved-bundle", help=argparse.SUPPRESS)
    parser.add_argument(
        "--collector",
        choices=("existing-capture", "zeek-offline", "zeek-network14-offline", "zeek-live"),
        default="existing-capture",
    )
    parser.add_argument("--zeek-pcap", type=Path)
    parser.add_argument("--zeek-pcap-sha256")
    parser.add_argument("--developer", action="store_true", help="Open research/replay tools")
    args = parser.parse_args(argv)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("SOC_GUI_REQUIRES_UNPRIVILEGED_USER", file=sys.stderr)
        return 1
    try:
        import tkinter as tk
    except ImportError:
        print("SOC GUI BLOCKED: Tkinter unavailable", file=sys.stderr)
        return 1
    try:
        if args.developer:
            from soc_agent.gui.app import Desktop
        else:
            from soc_agent.gui.production import Desktop

        config = GUIConfig(
            analysis_result=args.analysis_result,
            analysis_ml_root=args.analysis_ml_root,
            collector_type=args.collector,
            zeek_pcap=args.zeek_pcap,
            zeek_pcap_sha256=args.zeek_pcap_sha256,
            total_approved_sha=args.total_approved_sha,
            total_rate_policy=args.total_rate_policy,
            calibrated_approved_bundle=args.calibrated_approved_bundle,
            data_directory=args.data_directory.absolute(),
            runtime_directory=args.runtime,
            artifacts=args.artifacts,
            native_python=args.native_python,
            source_label=args.source_label,
        )
        if prepared is not None and (args.developer or config != prepared.config):
            raise ValueError("ZEEK_GUI_CONFIGURATION_MISMATCH")
        create_private_directory(config.data_directory)
        lock = config.data_directory / "desktop.lock"
        if not lock.exists():
            create_private_file(lock)
        with nullcontext() if prepared is not None else exclusive_runtime_lock(lock):
            root = tk.Tk()
            desktop = (
                Desktop(root, config, worker=prepared.worker, on_ready=prepared.gui_ready)
                if prepared is not None
                else Desktop(root, config)
            )
            desktop.terminal_managed = prepared is not None
            previous = {}

            def requested_exit(signum, *_):
                callback = (
                    desktop.close
                    if args.developer
                    else lambda: desktop.close(
                        reason="USER_STOP" if signum == signal.SIGINT else "CONTROLLER_EXIT"
                    )
                )
                root.after(0, callback)

            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                previous[signum] = signal.signal(signum, requested_exit)
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
