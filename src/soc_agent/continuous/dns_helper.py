"""Fixed reviewed DNS metadata helper; cannot obtain its own capability/Namespace."""

import argparse
from pathlib import Path

from soc_agent.continuous.dns_source import load
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.network_capture.live_helper import check_privileges
from soc_agent.security_ai.operational.network_capture.stream_helper import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--session-digest", required=True)
    args = parser.parse_args()
    check_privileges()  # No socket, capture, privilege request or bind on failure.
    load(args.directory)
    with exclusive_runtime_lock(args.directory / "helper.lock"):
        run(
            args.directory,
            args.session_digest,
            session_loader=load,
            dns_metadata=True,
            packet_filter=lambda packet: 53 in (packet.source_port, packet.destination_port),
        )


if __name__ == "__main__":
    main()
