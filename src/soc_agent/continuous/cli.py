"""Explicit lifecycle for the unprivileged service; never installs or authenticates Root."""

import argparse
import asyncio
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from soc_agent.continuous.models import ContinuousConfig, require_source_authority
from soc_agent.continuous.service import ContinuousRuntime
from soc_agent.continuous.store import Store
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest


def code_identity():
    root = Path(__file__).parents[1]
    return digest(
        {
            str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*.py"))
        }
    )


def status(directory):
    store = Store(directory)
    value = store.state()
    value["queue"] = store.queue.counts()
    value["heartbeat_stale"] = time.time() - value.get("heartbeat_unix", 0) > max(
        10, store.config.heartbeat_seconds * 3
    )
    if value.get("state") in ("RUNNING", "DEGRADED") and value["heartbeat_stale"]:
        value["state"] = "UNKNOWN_STALE_HEARTBEAT"
        value["cleanup"] = "UNVERIFIED_AFTER_SERVICE_LOSS"
        value["collection_live"] = False
        # Preserve the last observation, but do not display it as current liveness.
        value["last_observed_collector"] = value.get("collector", "UNKNOWN")
        value["last_observed_worker"] = value.get("worker", "UNKNOWN")
        value["collector"] = value["worker"] = "UNKNOWN_STALE_HEARTBEAT"
    return value


def start(directory):
    store = Store(directory)
    require_source_authority(store.config)
    if read_local(directory / "code-identity", 128).decode() != code_identity():
        raise ValueError("CONTINUOUS_EXECUTABLE_INTEGRITY_CHANGED")
    from soc_agent.runtime_lock import exclusive_runtime_lock

    with exclusive_runtime_lock(directory / "start.lock"):
        with exclusive_runtime_lock(directory / "service.lock"):
            pass
        if status(directory).get("cleanup", "").startswith("UNVERIFIED"):
            raise ValueError("CONTINUOUS_UNVERIFIED_CLEANUP_REVIEW_REQUIRED")
        log = os.open(
            directory / "service.log", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        try:
            proc = subprocess.Popen(
                [sys.executable, "-m", "soc_agent.cli", "continuous", "run", str(directory)],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                start_new_session=True,
                shell=False,
            )
        finally:
            os.close(log)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise ValueError("CONTINUOUS_SERVICE_START_FAILED")
            current = status(directory)
            if current.get("service_pid") == proc.pid and not current["heartbeat_stale"]:
                return dict(status="SERVICE_HEARTBEAT_VERIFIED", pid=proc.pid, mode="CONTINUOUS")
            time.sleep(0.05)
        raise ValueError("CONTINUOUS_START_HEALTH_TIMEOUT_REVIEW_REQUIRED")


async def run(directory):
    if read_local(directory / "code-identity", 128).decode() != code_identity():
        raise ValueError("CONTINUOUS_EXECUTABLE_INTEGRITY_CHANGED")
    service = ContinuousRuntime(directory)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, service.stop.set)
    await service.run()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=[
            "init",
            "start",
            "run",
            "status",
            "stop",
            "reset-worker",
            "service-unit",
            "archive",
            "restore",
        ],
    )
    parser.add_argument("directory", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--from-archive", type=Path)
    args = parser.parse_args(argv)
    directory = args.directory.absolute()
    try:
        if os.geteuid() == 0:
            raise ValueError("CONTINUOUS_SERVICE_REQUIRES_ORDINARY_UID")
        if args.command == "init":
            if not args.config:
                raise ValueError("CONTINUOUS_CONFIG_REQUIRED")
            config = ContinuousConfig.model_validate_json(read_local(args.config.absolute(), 32768))
            Store.create(directory, config)
            (directory / "code-identity").write_text(code_identity())
            (directory / "code-identity").chmod(0o600)
            result = dict(status="INITIALIZED_NOT_STARTED", mode="CONTINUOUS", source=config.source)
        elif args.command == "restore":
            from soc_agent.continuous.retention import restore

            if not args.from_archive:
                raise ValueError("CONTINUOUS_ARCHIVE_REQUIRED")
            result = restore(args.from_archive.absolute(), directory)
        elif args.command == "archive":
            from soc_agent.continuous.retention import archive

            result = archive(directory)
        elif args.command == "status":
            result = status(directory)
        elif args.command == "start":
            result = start(directory)
        elif args.command == "run":
            asyncio.run(run(directory))
            result = status(directory)
        elif args.command in ("stop", "reset-worker"):
            Store(directory).control(
                stop=args.command == "stop", reset=args.command == "reset-worker"
            )
            result = dict(status="REQUESTED_NOT_COMPLETED", action=args.command)
        else:
            # A real user-service unit for this ordinary runtime, not a Root
            # collector unit or permission activation. Caller installs explicitly.
            if any(
                c in str(directory) + sys.executable + str(Path(__file__).parents[2])
                for c in '\n\r%"'
            ):
                raise ValueError("CONTINUOUS_UNIT_PATH")
            print(
                "[Unit]\nDescription=SOC ordinary Continuous Runtime\n[Service]\nType=simple\n"
                + f'Environment="PYTHONPATH={Path(__file__).parents[2]}"\n'
                + f'ExecStart="{sys.executable}" -m soc_agent.cli continuous run "{directory}"\n'
                + "Restart=no\nKillMode=control-group\nTimeoutStopSec=35\nNoNewPrivileges=yes\n"
                + "MemoryMax=512M\nCPUQuota=50%\nTasksMax=32\n[Install]\nWantedBy=default.target"
            )
            return 0
        print(json.dumps(result, ensure_ascii=False, default=str))
        return 0
    except (ValueError, OSError, RuntimeError) as error:
        print(
            json.dumps(
                dict(
                    status="BLOCKED", error=type(error).__name__ + ":" + str(error), executed=False
                )
            )
        )
        return 2
