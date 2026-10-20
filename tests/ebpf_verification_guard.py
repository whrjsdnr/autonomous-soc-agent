"""Deny hook/load tooling in addition to existing no-capture/no-network guard."""

import sys

from tests.zeek_live_verification_guard import no_native_process  # noqa:F401


def no_bpf_tools(event, args):
    if event == "subprocess.Popen":
        argv = args[1]
        # Compiler output filenames are data, not executed collector commands.
        if (
            isinstance(argv, (list, tuple))
            and argv
            and str(argv[0]).rsplit("/", 1)[-1] not in {"cc", "clang"}
            and any(str(v).rsplit("/", 1)[-1] in {"bpftool", "tc", "ring-consumer"} for v in argv)
        ):
            raise PermissionError("KERNEL_HOOK_AND_RING_FD_EXECUTION_DENIED")


sys.addaudithook(no_bpf_tools)

if __name__ == "__main__":
    import pytest

    rc = pytest.main(sys.argv[1:])
    print("EBPF VERIFICATION: NO LOAD / TC ATTACH / PRIVILEGE / AF_PACKET / TEST TRAFFIC")
    raise SystemExit(rc)
