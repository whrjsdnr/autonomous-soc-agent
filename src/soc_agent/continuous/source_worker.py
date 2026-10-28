"""Existing pinned PCAP Reader/parser in the isolated research interpreter; no capture."""

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from soc_agent.security_ai.research.environment import Paths, read_local, verify


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ml", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    import os
    import resource

    if os.geteuid() == 0:
        raise ValueError("CONTINUOUS_REPLAY_REQUIRES_ORDINARY_UID")
    resource.setrlimit(resource.RLIMIT_AS, (3 * 1024**3,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    verify(Paths(args.ml, Path(sys.executable), Path(__file__).parents[2]), offline=False)
    import hashlib

    body = read_local(args.input, 64 * 1024**2)
    if hashlib.sha256(body).hexdigest() != args.sha:
        raise ValueError("CONTINUOUS_PCAP_SOURCE_SHA")
    from ml.ctu13.pcap import PcapReader

    from soc_agent.security_ai.operational.network_capture.parsing import (
        PacketRejected,
        parse_packet,
    )

    interface = hashlib.sha256(("PCAP:" + args.sha).encode()).hexdigest()
    reader = PcapReader((body,))
    if reader.format != "PCAP":
        raise ValueError("CONTINUOUS_CLASSIC_PCAP_REQUIRED")
    offset = 24
    for r in reader:
        frame = body[offset + 16 : offset + 16 + r.captured_length]
        offset += 16 + r.captured_length
        identity = str(uuid5(NAMESPACE_URL, args.sha + ":" + str(r.index)))
        try:
            if r.captured_length != r.wire_length or r.timestamp_ns % 1000:
                raise PacketRejected("CONTINUOUS_TRUNCATION_OR_CLOCK_PRECISION")
            seconds, nanos = divmod(r.timestamp_ns, 10**9)
            packet = parse_packet(
                frame,
                interface_id=interface,
                timestamp=datetime.fromtimestamp(seconds, UTC).replace(microsecond=nanos // 1000),
                direction="UNKNOWN",
                native=False,
            )
        except PacketRejected:
            ether = int.from_bytes(r.header[12:14], "big") if len(r.header) >= 14 else 0
            print(
                json.dumps(
                    dict(
                        sequence=r.index,
                        kind="excluded",
                        id=identity,
                        event_ns=r.timestamp_ns,
                        affects_integrity=ether in (0x800, 0x86DD, 0x8100, 0x88A8),
                    )
                ),
                flush=True,
            )
            continue
        print(
            json.dumps(
                dict(
                    sequence=r.index,
                    kind="packet",
                    id=identity,
                    packet=packet.model_dump(mode="json"),
                )
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
