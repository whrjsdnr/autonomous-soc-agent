"""USER EXECUTION ONLY: finite v2 policy over the existing capture engine."""

import argparse
from pathlib import Path

from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.network_capture.calibrated_policy import require_headroom
from soc_agent.security_ai.operational.network_capture.calibrated_session import (
    approval_digest,
    load,
)
from soc_agent.security_ai.operational.network_capture.live_helper import check_privileges
from soc_agent.security_ai.operational.network_capture.stream_helper import run
from soc_agent.security_ai.research.models import digest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--session-digest", required=True)
    parser.add_argument("--approval-digest", required=True)
    args = parser.parse_args(argv)
    session = load(args.directory)
    if args.approval_digest != approval_digest(session) or args.session_digest != digest(
        session.model_dump(mode="json")
    ):
        raise ValueError("CALIBRATED_EXPLICIT_APPROVAL_MISMATCH")
    if any(
        (args.directory / n).exists()
        for n in ("verified-closed.json", "rejected-closed.json", "transport-failure.json")
    ):
        raise ValueError("CALIBRATED_SESSION_REPLAY_DENIED")
    require_headroom()
    check_privileges()
    with exclusive_runtime_lock(args.directory / "helper.lock"):
        run(args.directory, args.session_digest, session_loader=load, dns_metadata=True)


if __name__ == "__main__":
    main()
