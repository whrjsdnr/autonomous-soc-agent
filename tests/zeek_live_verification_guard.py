"""Forbid privileged commands and Native Docker capture in all verification subprocesses."""

import sys

from tests.native_capture_verification_guard import deny_network_sockets  # noqa:F401


def no_native_process(event, args):
    if event != "subprocess.Popen":
        return
    argv = args[1]
    if not isinstance(argv, (list, tuple)):
        raise PermissionError("UNSTRUCTURED_PROCESS_DENIED")
    values = [str(x) for x in argv]
    if any(x.rsplit("/", 1)[-1] in {"sudo", "pkexec", "setpriv"} for x in values):
        raise PermissionError("PRIVILEGE_EXECUTION_DENIED_IN_VERIFICATION")
    if any(x.startswith("--cap-add") or x in {"--network=host", "--privileged"} for x in values):
        raise PermissionError("NATIVE_DOCKER_CAPTURE_DENIED_IN_VERIFICATION")


sys.addaudithook(no_native_process)

if __name__ == "__main__":
    import pytest

    result = pytest.main(sys.argv[1:])
    print("VERIFICATION_GUARD: NO PRIVILEGE, AF_PACKET OR TEST TRAFFIC EXECUTION")
    raise SystemExit(result)
