"""USER EXECUTION ONLY. New approved scope; one socket for Network + DNS metadata."""

import argparse
from pathlib import Path

from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.network_capture.live_helper import check_privileges
from soc_agent.security_ai.operational.network_capture.stream_helper import run
from soc_agent.security_ai.operational.network_capture.total_session import load


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--session-digest", required=True)
    args = parser.parse_args()
    check_privileges()
    load(args.directory)
    with exclusive_runtime_lock(args.directory / "helper.lock"):
        run(args.directory, args.session_digest, session_loader=load, dns_metadata=True)


if __name__ == "__main__":
    main()
