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
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "continuous":
        from soc_agent.continuous.cli import main as continuous_main

        return continuous_main(arguments[1:])
    if arguments and arguments[0] == "analyze-offline":
        from soc_agent.security_ai.offline_analysis_cli import main as analysis_main

        return analysis_main(arguments[1:])
    if arguments and arguments[0] == "native-recovery":
        from soc_agent.security_ai.ebpf_tc.operational_recovery import main as recovery_main

        return recovery_main(arguments[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "analyze-offline", help="Pinned offline AI, read-only response and scripted investigation"
    )
    sub.add_parser(
        "native-recovery", help="Governed recovery prepare/check/execute; separate grants"
    )
    start = sub.add_parser("start")
    start.add_argument("--gui", required=True, action="store_true")
    start.add_argument("--monitor", required=True, choices=("total",))
    start.add_argument("--data-directory", type=Path)
    start.add_argument(
        "--rate-policy",
        default="legacy",
        choices=("legacy", "conservative-v2", "balanced-v2", "performance-v2", "direction-v3"),
    )
    start.add_argument("--approve-calibrated-sha")
    start.add_argument("--approve-direction-sha")
    start.add_argument(
        "--collector",
        choices=(
            "existing-capture",
            "zeek-offline",
            "zeek-network14-offline",
            "zeek-live",
            "ebpf-tcx",
        ),
        default="existing-capture",
    )
    start.add_argument("--pcap", type=Path)
    start.add_argument("--pcap-sha256")
    args = parser.parse_args(argv)
    try:
        from soc_agent.security_ai.operational.network_capture.live_session import unprivileged

        unprivileged()
        if args.collector == "ebpf-tcx":
            from soc_agent.security_ai.ebpf_tc.unified_startup import start

            if (
                args.pcap is not None
                or args.pcap_sha256 is not None
                or args.rate_policy != "legacy"
                or args.approve_calibrated_sha
                or args.approve_direction_sha
            ):
                raise ValueError("TCX_UNIFIED_SCOPE_OPTIONS_DENIED")
            return start(args.data_directory)
        if args.collector == "zeek-live":
            from soc_agent.security_ai.collectors.startup import start

            if (
                args.pcap is not None
                or args.pcap_sha256 is not None
                or args.rate_policy != "legacy"
            ):
                raise ValueError("ZEEK_LIVE_SCOPE_OPTIONS_DENIED")
            return start(args.data_directory)
        if args.collector.startswith("zeek-"):
            from soc_agent.gui.__main__ import main as gui_main
            from soc_agent.security_ai.collectors.offline import OfflineZeek, pcap_digest

            if (
                args.pcap is None
                or args.pcap_sha256 is None
                or pcap_digest(args.pcap) != args.pcap_sha256
            ):
                raise ValueError("ZEEK_EXPLICIT_PCAP_DIGEST_REQUIRED")
            OfflineZeek().environment()
            gui_args = [
                "--collector",
                args.collector,
                "--zeek-pcap",
                str(args.pcap.absolute()),
                "--zeek-pcap-sha256",
                args.pcap_sha256,
            ]
            if args.data_directory:
                gui_args += ["--data-directory", str(args.data_directory)]
            print("ZEEK OFFLINE ONLY / NETWORK14 + DNS9 BLOCKED / NO AUTHENTICATION OR CAPTURE")
            return gui_main(gui_args)
        hashes = verify_bundle()
        helper = "total_helper.py"
        selected = None
        if args.rate_policy != "legacy":
            from soc_agent.security_ai.operational.network_capture import calibrated_session
            from soc_agent.security_ai.operational.network_capture.calibrated_policy import (
                policy,
                require_headroom,
            )

            if args.rate_policy == "direction-v3":
                from soc_agent.security_ai.operational.network_capture import direction_session
                from soc_agent.security_ai.operational.network_capture.direction_policy import (
                    DirectionPolicy,
                )

                selected = DirectionPolicy()
                hashes = direction_session.verify_bundle()
                helper = "direction_helper.py"
            else:
                selected = policy(args.rate_policy)
                hashes = calibrated_session.verify_bundle()
                helper = "calibrated_helper.py"
            print("FIXTURE_CALIBRATED / NATIVE_CALIBRATION_PENDING / APPROVAL_REQUIRED")
            print("Policy: " + selected.model_dump_json())
            print("New Helper SHA256: " + hashes[helper])
            from soc_agent.security_ai.research.models import digest

            print("New Bundle Digest: " + digest(hashes))
            approved = (
                args.approve_direction_sha
                if args.rate_policy == "direction-v3"
                else args.approve_calibrated_sha
            )
            if approved != hashes[helper]:
                raise ValueError(
                    "V3_NEW_SHA_APPROVAL_REQUIRED"
                    if args.rate_policy == "direction-v3"
                    else "CALIBRATED_NEW_SHA_APPROVAL_REQUIRED"
                )
            require_headroom()
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
        if selected is None:
            print(
                "NEW TOTAL HELPER APPROVAL: lo / 300s / 128 raw frames/s / burst 256 / max 38656."
            )
        print("Temporary CAP_NET_RAW; drops after socket open; DNS metadata digests only.")
        print("RESEARCH_ONLY; DNS9 and operational AI BLOCKED; no security WRITE.")
        print("Total Helper SHA256: " + hashes[helper])
        from soc_agent.security_ai.research.models import digest

        print("Helper bundle digest: " + digest(hashes))
        if not sys.stdin.isatty() or input("Approve this new scope? [yes/NO] ").strip() != "yes":
            raise ValueError("TOTAL_SCOPE_APPROVAL_CANCELLED")
        terminal_authenticate()
        from soc_agent.gui.__main__ import main as gui_main

        gui_args = ["--data-directory", str(data), "--total-approved-sha", hashes[helper]]
        if selected is not None:
            gui_args += [
                "--total-rate-policy",
                args.rate_policy,
                "--calibrated-approved-bundle",
                digest(hashes),
            ]
        return gui_main(gui_args)
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
