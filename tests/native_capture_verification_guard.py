"""Run offline regressions with new packet/IPv4/IPv6 sockets denied, including spawn."""

import errno
import json
import socket
import sys

import pytest

blocked = 0


def deny_network_sockets(event: str, args: tuple[object, ...]) -> None:
    global blocked
    if event == "socket.__new__" and args[1] in (socket.AF_PACKET, socket.AF_INET, socket.AF_INET6):
        blocked += 1
        raise PermissionError(errno.EPERM, "NETWORK_DISABLED_FOR_SAVED_EVIDENCE_REGRESSION")


sys.addaudithook(deny_network_sockets)

if __name__ == "__main__":
    result = pytest.main(sys.argv[1:])
    print(
        json.dumps(
            {
                "network_socket_attempts_blocked_by_test_guard": blocked,
                "new_native_capture_or_test_traffic": False,
            }
        )
    )
    raise SystemExit(result)
