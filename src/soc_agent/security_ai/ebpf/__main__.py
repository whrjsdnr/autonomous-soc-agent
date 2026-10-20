"""Compile/prepare EBPF_TC only. No Native load, authentication or hook command exists."""

import argparse
import asyncio
import hashlib
import json
import os
import secrets
from pathlib import Path

from soc_agent.security_ai.ebpf.build import compile_program, source_digest
from soc_agent.security_ai.ebpf.collector import EBPFCollector
from soc_agent.security_ai.ebpf.models import Plan


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("compile")
    build.add_argument("--output", type=Path, required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--collector", choices=("ebpf-tc",), default="ebpf-tc")
    prepare.add_argument("--interface", choices=("lo",), default="lo")
    prepare.add_argument("--hook", choices=("INGRESS", "EGRESS"), default="INGRESS")
    prepare.add_argument("--program", type=Path, required=True)
    prepare.add_argument("--data-directory", type=Path, required=True)
    prepare.add_argument("--gui", action="store_true")
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        raise ValueError("EBPF_NO_ROOT_GUI")
    if args.command == "compile":
        print(json.dumps(compile_program(args.output), indent=2))
        return 0
    if args.program.is_symlink() or not 64 <= args.program.stat().st_size <= 1024**2:
        raise ValueError("EBPF_PROGRAM_FILE_BOUND")
    body = args.program.read_bytes()
    if body[:6] != b"\x7fELF\x02\x01" or int.from_bytes(body[18:20], "little") != 247:
        raise ValueError("EBPF_PROGRAM_NOT_BPF_ELF")
    plan = Plan(
        generation=secrets.randbelow(2**63 - 1) + 1,
        program_sha256=hashlib.sha256(body).hexdigest(),
        source_digest=source_digest(),
        ifindex=int(Path("/sys/class/net/lo/ifindex").read_text()),
        net_namespace=os.readlink("/proc/self/ns/net"),
        hook=args.hook,
        origin="EBPF_TC_NATIVE",
        clock="KERNEL_MONOTONIC_NS",
    )
    owner = EBPFCollector(args.data_directory / ("session-" + plan.session_id.hex), plan)
    if args.gui:
        from soc_agent.security_ai.ebpf.gui import launch

        return launch(owner)
    print(json.dumps(asyncio.run(owner.prepare()), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
