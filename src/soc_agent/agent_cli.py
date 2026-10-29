"""One-command application facade over existing service and desktop entry points."""

import argparse
import json
import os
import re
import sys
from pathlib import Path

from soc_agent import agent_runtime as runtime
from soc_agent.review.persistence.models import StorageError


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("setup", "start", "status", "stop", "gui", "doctor"):
        item = commands.add_parser(command)
        item.add_argument("--home", type=Path, help="Private application profile directory")
        if command == "setup":
            source = item.add_mutually_exclusive_group()
            source.add_argument("--replay", type=Path)
            source.add_argument("--config", type=Path)
            source.add_argument("--native-review", type=Path)
            source.add_argument(
                "--recover-from", type=Path, help="Create an isolated Replay recovery copy"
            )
            item.add_argument("--runtime", type=Path, help="Attach an existing initialized service")
            item.add_argument("--ml-root", type=Path)
            item.add_argument("--authentication-runtime", type=Path)
        if command == "start":
            item.add_argument("--gui", action="store_true")
            item.add_argument(
                "--preview", action="store_true", help="Non-consuming preflight; never execute"
            )
    args = parser.parse_args(argv)
    try:
        if os.geteuid() == 0:
            raise ValueError("SOC_APPLICATION_REQUIRES_ORDINARY_USER")
        home = runtime.home_path(args.home)
        if args.command == "setup":
            result = runtime.setup(
                home,
                replay=args.replay,
                config=args.config,
                runtime=args.runtime,
                review=args.native_review,
                ml_root=args.ml_root,
                authentication_runtime=args.authentication_runtime,
                recover_from=args.recover_from,
            )
        elif args.command == "gui":
            return runtime.gui(home)
        elif args.command == "start":
            result = runtime.start(home, preview=args.preview, gui=args.gui)
        else:
            result = getattr(runtime, args.command)(home)
        print(json.dumps(result, indent=2, default=str))
        if (
            args.command == "start"
            and args.gui
            and not args.preview
            and runtime.profile(home).configuration.source != "NATIVE_SERVICE"
        ):
            return runtime.gui(home)
        return int(result.get("returncode", 0) != 0)
    except (ValueError, OSError, StorageError) as error:
        # Never echo malformed input documents, environment values or raw log payloads.
        message = str(error)
        code = message if re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", message) else type(error).__name__
        print(
            json.dumps(dict(status="BLOCKED", error=code, automatic_retry=False)), file=sys.stderr
        )
        return 2
