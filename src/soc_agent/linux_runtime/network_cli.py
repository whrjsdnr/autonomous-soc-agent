"""Explicit Linux capture configuration/diagnostics; never elevates privileges."""

import argparse
import json
from pathlib import Path

from soc_agent.linux_runtime.network_monitor import configure, network_status
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig, model_gates
from soc_agent.security_ai.operational.network_capture.permissions import capture_permission


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("diagnose")
    check.add_argument("--interface", required=True)
    init = sub.add_parser("configure")
    init.add_argument("--directory", type=Path, required=True)
    init.add_argument("--interface", required=True)
    init.add_argument("--retain-query-names", action="store_true")
    query = sub.add_parser("status")
    query.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "diagnose":
        result = capture_permission(args.interface)
    elif args.command == "configure":
        configure(
            args.directory,
            CaptureConfig(interface=args.interface, retain_query_names=args.retain_query_names),
        )
        result = {
            "status": "CONFIGURED",
            "automatic_privilege_escalation": False,
            "operational_models": model_gates(),
        }
    else:
        result = network_status(args.directory, RuntimeStore(args.directory))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
