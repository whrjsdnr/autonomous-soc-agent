"""Official pinned Zeek only, no interface option, no capabilities, no container network."""

import hashlib
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from uuid import uuid4

IMAGE = "zeek/zeek@sha256:3fac39de707be96cb1a8163cab98a11bb2a1aa9e3535247db0f17b9c4670a019"
VERSION = "9.0.0"
# Fixed program, no shell interpolation of paths, user data, or GUI input.
PROGRAM = (
    "set -eu; /usr/bin/timeout -k 2s 55s /usr/local/zeek/bin/zeek "
    "-r /input/input.pcap /policy/privacy.zeek; "
    "printf '%s\\n' SOC_ZEEK_CONN_V1; if [ -f conn.log ]; then cat conn.log; fi; "
    "printf '%s\\n' SOC_ZEEK_DNS_V1; if [ -f dns.log ]; then cat dns.log; fi"
)


def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def pcap_digest(path: Path) -> str:
    path = path.absolute()
    if (
        path.is_symlink()
        or not path.is_file()
        or not 24 <= path.stat().st_size <= 16 * 1024**2
        or any(c in str(path) for c in ",\n\r")
    ):
        raise ValueError("ZEEK_PCAP_PATH_OR_SIZE_REJECTED")
    with path.open("rb") as stream:
        if stream.read(4) not in {
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
            b"\x0a\x0d\x0d\x0a",
        }:
            raise ValueError("ZEEK_PCAP_MAGIC_REJECTED")
    return file_digest(path)


class OfflineZeek:
    def __init__(self):
        self.container = None
        self.process = None
        self.cancelled = threading.Event()
        self.lock = threading.Lock()
        self.peak_output_bytes = 0
        self.elapsed_seconds = None

    def _docker(self) -> str:
        binary = shutil.which("docker")
        if binary is None:
            raise ValueError("ZEEK_OFFICIAL_ENVIRONMENT_UNAVAILABLE")
        return binary

    def environment(self) -> dict:
        p = subprocess.run(
            [self._docker(), "image", "inspect", "--format", "{{.Id}}", IMAGE],
            capture_output=True,
            timeout=10,
            check=False,
        )
        if p.returncode or not re.fullmatch(rb"sha256:[a-f0-9]{64}\n?", p.stdout):
            raise ValueError("ZEEK_PINNED_IMAGE_NOT_INSTALLED")
        return dict(image=IMAGE, version=VERSION, environment="OFFICIAL_CONTAINER_OFFLINE_ONLY")

    def _remove(self):
        with self.lock:
            identity = self.container
            if identity is None:
                return
            p = subprocess.run(
                [self._docker(), "rm", "--force", identity],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            if p.returncode:
                raise ValueError("ZEEK_CONTAINER_CLEANUP_UNCERTAIN")
            self.container = None

    def stop(self):
        self.cancelled.set()
        try:
            self._remove()
        finally:
            if self.process is not None and self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=5)

    def run(self, pcap: Path, approved_sha: str, logs: Path) -> dict:
        if os.geteuid() == 0:
            raise ValueError("ZEEK_REQUIRES_UNPRIVILEGED_USER")
        pcap = pcap.absolute()
        if not re.fullmatch(r"[a-f0-9]{64}", approved_sha) or pcap_digest(pcap) != approved_sha:
            raise ValueError("ZEEK_PCAP_DIGEST_MISMATCH")
        self.environment()
        policy = Path(__file__).with_name("privacy.zeek").absolute()
        policy_digest = file_digest(policy)
        started = time.monotonic()
        argv = [
            self._docker(),
            "create",
            "--pull=never",
            "--log-driver=none",
            "--network=none",
            "--cap-drop=ALL",
            "--read-only",
            "--security-opt=no-new-privileges",
            "--memory=512m",
            "--memory-swap=512m",
            "--cpus=1",
            "--pids-limit=64",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--label",
            "soc.offline.session=" + uuid4().hex,
            "--tmpfs",
            f"/work:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid={os.getuid()},gid={os.getgid()}",
            "--workdir",
            "/work",
            "--ulimit",
            "fsize=16777216:16777216",
            "--mount",
            f"type=bind,source={pcap},target=/input/input.pcap,readonly",
            "--mount",
            f"type=bind,source={policy},target=/policy/privacy.zeek,readonly",
            "--entrypoint",
            "/bin/sh",
            IMAGE,
            "-c",
            PROGRAM,
        ]
        try:
            with self.lock:
                if self.cancelled.is_set():
                    raise ValueError("ZEEK_OFFLINE_CANCELLED")
                created = subprocess.run(argv, capture_output=True, timeout=15, check=False)
                if created.returncode or not re.fullmatch(rb"[a-f0-9]{64}\n?", created.stdout):
                    raise ValueError("ZEEK_CONTAINER_CREATE_FAILED")
                self.container = created.stdout.decode().strip()
            self.process = subprocess.Popen(
                [self._docker(), "start", "--attach", self.container],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )

            def expire():
                try:
                    self.stop()
                except (OSError, ValueError, subprocess.SubprocessError):
                    self.cancelled.set()  # Process cleanup is checked again in finally.

            deadline = threading.Timer(60, expire)
            deadline.start()
            kind = None
            handles = {}
            try:
                for name in ("network", "dns"):
                    path = logs / ("conn.log" if name == "network" else "dns.log")
                    handles[name] = path.open("xb")
                    path.chmod(0o600)
                for line in iter(lambda: self.process.stdout.readline(16385), b""):
                    self.peak_output_bytes += len(line)
                    if len(line) > 16384 or self.peak_output_bytes > 8 * 1024**2:
                        raise ValueError("ZEEK_OUTPUT_BUDGET_EXCEEDED")
                    if line == b"SOC_ZEEK_CONN_V1\n":
                        kind = "network"
                        continue
                    if line == b"SOC_ZEEK_DNS_V1\n":
                        kind = "dns"
                        continue
                    if kind is None:
                        raise ValueError("ZEEK_OUTPUT_FRAMING_REJECTED")
                    # Defense in depth: reject a broken privacy script before persistence.
                    import json

                    row = json.loads(line)
                    allowed = {
                        "ts",
                        "uid",
                        "id.orig_h",
                        "id.orig_p",
                        "id.resp_h",
                        "id.resp_p",
                        "proto",
                        "duration",
                        "orig_pkts",
                        "resp_pkts",
                        "orig_ip_bytes",
                        "resp_ip_bytes",
                        "missed_bytes",
                        "conn_state",
                        "trans_id",
                        "rtt",
                        "qtype",
                        "rcode",
                        "TTLs",
                        "TC",
                    }
                    if not isinstance(row, dict) or not set(row) <= allowed:
                        raise ValueError("ZEEK_PRIVACY_FILTER_FAILED")
                    handles[kind].write(line)
                code = self.process.wait(timeout=5)
                if self.cancelled.is_set():
                    raise ValueError("ZEEK_OFFLINE_CANCELLED_OR_TIMEOUT")
                if code or kind != "dns":
                    raise ValueError("ZEEK_PROCESS_FAILED")
            finally:
                deadline.cancel()
                deadline.join(2)
                for f in handles.values():
                    f.close()
                self.process.stdout.close()
            if file_digest(policy) != policy_digest:
                raise ValueError("ZEEK_PRIVACY_POLICY_CHANGED")
            if file_digest(pcap) != approved_sha:
                raise ValueError("ZEEK_PCAP_CHANGED_DURING_PROCESSING")
            self.elapsed_seconds = time.monotonic() - started
            return dict(
                version=VERSION,
                image=IMAGE,
                policy_sha256=file_digest(policy),
                exit_code=0,
                elapsed_seconds=self.elapsed_seconds,
                output_bytes=self.peak_output_bytes,
                native_capture=False,
                log_sha256={n: file_digest(logs / n) for n in ("conn.log", "dns.log")},
            )
        finally:
            self._remove()
            if self.process is not None and self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=5)
