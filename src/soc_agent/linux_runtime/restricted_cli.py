"""Explicit test-resource preparation and authenticated requests to a running monitor."""

import argparse
import asyncio
import json
import os
import socket
from pathlib import Path

from soc_agent.linux_runtime.operator import operator_request
from soc_agent.linux_runtime.restricted_response import RestrictedResponseExecutor
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.review.persistence.secure_storage import validate_directory
from soc_agent.runtime_lock import exclusive_runtime_lock


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--test-mode", action="store_true", required=True)
    sub.add_parser("list")
    request = sub.add_parser("request")
    request.add_argument("finding_id")
    rollback = sub.add_parser("rollback-request")
    rollback.add_argument("finding_id")
    rollback.add_argument("candidate_id")
    for operation in ("approve", "reject", "execute"):
        command = sub.add_parser(operation)
        command.add_argument("candidate_id")
        command.add_argument("--expected-digest", required=True)
    args = parser.parse_args()
    if os.name != "posix" or not hasattr(socket, "SO_PEERCRED"):
        print(json.dumps({"ok": False, "status": "BLOCKED", "error": "LINUX_REQUIRED"}))
        raise SystemExit(1)
    if args.command == "prepare":
        validate_directory(args.directory)
        with exclusive_runtime_lock(args.directory / "writer.lock"):
            registration = RestrictedResponseExecutor(
                LinuxMonitor(args.directory)
            ).enable_test_mode(test_mode=args.test_mode)
        print(
            json.dumps(
                {
                    "test_mode": True,
                    "resource_id": registration.resource_id,
                    "registration_digest": registration.digest,
                    "restricted_executor_enabled": True,
                    "automatic_approval": False,
                    "os_security_execution": "DISABLED",
                }
            )
        )
        return
    result = asyncio.run(
        operator_request(
            args.directory,
            "restricted-" + args.command,
            **{
                key: getattr(args, key)
                for key in ("candidate_id", "finding_id", "expected_digest")
                if hasattr(args, key)
            },
        )
    )
    print(json.dumps(result))
    if not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
