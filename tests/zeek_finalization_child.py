"""Owned no-capture process fixture for stdout, signal and process-exit races."""

import json
import signal
import sys
import time


def main():
    scenario = sys.argv[1]
    count = size = 0
    network = 0

    def emit(kind, data):
        nonlocal count, size
        count += 1
        body = (json.dumps(dict(sequence=count, kind=kind, data=data)) + "\n").encode()
        sys.stdout.buffer.write(body)
        sys.stdout.buffer.flush()
        size += len(body)

    def finish(*_):
        nonlocal network
        if scenario == "stop_flush":
            # More than a pipe buffer; parent must keep reading while stop waits.
            for i in range(1000):
                emit(
                    "network",
                    dict(
                        ts=1800000000,
                        uid="fixture-" + str(i),
                        id=dict(orig_h="192.0.2.1", orig_p=1000, resp_h="192.0.2.2", resp_p=80),
                        proto="tcp",
                    ),
                )
                network += 1
        proof = dict(
            stop_reason="ZEEK_DONE",
            packet_records=0,
            network_events=network,
            dns_events=0,
            messages_before_closed=count,
            bytes_before_closed=size,
            omitted_packet_records=0,
            omitted_events=0,
            pkts_recvd=0,
            pkts_dropped=0,
            pkts_link=0,
            bytes_recvd=0,
        )
        emit("closed", proof)
        if scenario == "closed_hang":
            while True:
                time.sleep(0.01)
        if scenario == "duplicate":
            emit("closed", proof)
        if scenario == "partial":
            sys.stdout.buffer.write(b'{"sequence":3')
            sys.stdout.buffer.flush()
        raise SystemExit(1 if scenario == "exit1" else 124 if scenario == "timeout" else 0)

    emit("ready", {})
    if scenario == "missing":
        return
    if scenario == "stop_flush":
        signal.signal(signal.SIGINT, finish)
        while True:
            time.sleep(0.01)
    finish()


if __name__ == "__main__":
    main()
