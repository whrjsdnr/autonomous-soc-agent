"""Actual shared C parser executed on in-memory fixtures, never kernel/BPF load."""

import ctypes
import subprocess
from pathlib import Path
from uuid import UUID

from soc_agent.security_ai.ebpf.build import source_digest
from soc_agent.security_ai.ebpf.models import Plan
from soc_agent.security_ai.ebpf.ring import ABI


def plan(**change):
    values = dict(
        session_id=UUID(int=100),
        generation=7,
        program_sha256="a" * 64,
        source_digest=source_digest(),
        ifindex=1,
        net_namespace="net:[123]",
        hook="INGRESS",
        origin="EBPF_TC_FIXTURE",
        clock="FIXTURE_PCAP_EVENT_NS",
    )
    return Plan.model_validate(values | change)


def parser(directory: Path):
    root = Path(__file__).resolve().parents[1] / "src/soc_agent/security_ai/ebpf"
    source = directory / "fixture.c"
    source.write_text("""#include <string.h>
#include "parser.h"
int fixture(const unsigned char *p, unsigned int n, unsigned int wire,
            unsigned long long ns, unsigned long long seq, int hook, struct soc_event *out) {
    memset(out,0,sizeof(*out));
    int rc=soc_parse(p,n,wire,out);
    out->generation=7;out->timestamp_ns=ns;out->cpu_sequence=seq;
    out->ifindex=1;out->hook=hook;
    return rc;
}
""")
    output = directory / "parser.so"
    subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Werror",
            "-I",
            str(root),
            str(source),
            "-o",
            str(output),
        ],
        check=True,
        capture_output=True,
        timeout=15,
    )
    dll = ctypes.CDLL(str(output))
    dll.fixture.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.c_ulonglong,
        ctypes.c_ulonglong,
        ctypes.c_int,
        ctypes.c_void_p,
    ]
    dll.fixture.restype = ctypes.c_int

    def execute(frame, ns=1800000000000000000, sequence=1, hook=1, wire=None):
        output = ctypes.create_string_buffer(ABI.size)
        rc = dll.fixture(
            frame,
            min(128, len(frame)),
            len(frame) if wire is None else wire,
            ns,
            sequence,
            hook,
            output,
        )
        return rc, output.raw

    return execute
