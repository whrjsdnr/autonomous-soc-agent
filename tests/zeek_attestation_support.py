"""Actual pinned libpcap offline-only failure experiment; cannot open an interface."""

import json
import os
import subprocess
from pathlib import Path

from soc_agent.security_ai.collectors.offline import IMAGE, pcap_digest

OFFLINE_QUERY = r"""
import ctypes, hashlib, json
lib = ctypes.CDLL('/lib/x86_64-linux-gnu/libpcap.so.0.8')
lib.pcap_lib_version.restype = ctypes.c_char_p
lib.pcap_open_offline.restype = ctypes.c_void_p
lib.pcap_open_offline.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.pcap_stats.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
lib.pcap_close.argtypes = [ctypes.c_void_p]
lib.pcap_geterr.argtypes = [ctypes.c_void_p]
lib.pcap_geterr.restype = ctypes.c_char_p
class Stats(ctypes.Structure):
    _fields_ = [('received',ctypes.c_uint),('dropped',ctypes.c_uint),('ifdrop',ctypes.c_uint)]
error = ctypes.create_string_buffer(256)
handle = lib.pcap_open_offline(b'/input.pcap', error)
if not handle:
    raise RuntimeError('OFFLINE_HANDLE_OPEN_FAILED')
try:
    stats = Stats()
    result = lib.pcap_stats(handle, ctypes.byref(stats))
    unsupported = result < 0 and b'savefile' in lib.pcap_geterr(handle).lower()
    print(json.dumps(dict(
        version=lib.pcap_lib_version().decode(),
        return_code=result,
        retrieval='UNSUPPORTED' if unsupported else 'FAILED' if result < 0 else 'SUCCESS',
        received=stats.received if result == 0 else None,
        dropped=stats.dropped if result == 0 else None,
        handle_identity=hashlib.sha256(str(handle).encode()).hexdigest(),
        scope='OWNED_OFFLINE_HANDLE_NOT_ZEEK_NATIVE_HANDLE',native_attestation='BLOCKED')))
finally:
    lib.pcap_close(handle)
"""


def offline_counter_probe(pcap: Path) -> dict:
    sha = pcap_digest(pcap)
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--cap-drop=ALL",
        "--read-only",
        "--security-opt=no-new-privileges",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--cpus=1",
        "--memory=512m",
        "--pids-limit=64",
        "--mount",
        f"type=bind,source={pcap.absolute()},target=/input.pcap,readonly",
        IMAGE,
        "/usr/bin/timeout",
        "10s",
        "python3",
        "-c",
        OFFLINE_QUERY,
    ]
    p = subprocess.run(cmd, capture_output=True, timeout=20)
    if p.returncode or len(p.stdout) > 4096:
        raise ValueError("OFFLINE_LIBPCAP_EXPERIMENT_FAILED")
    return {**json.loads(p.stdout), "pcap_sha256": sha, "image": IMAGE}
