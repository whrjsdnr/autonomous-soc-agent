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
    path = directory / "observation.json"
    if path.exists() and "control" in json.loads(read_local(path, 262144)).get("snapshot", {}):
        return observed_status(directory)
    return stored_status(directory)


def stored_status(directory):
    store = Store(directory)
    value = store.state()
    value["queue"] = store.queue.counts()
    return _freshness(value, store.config.heartbeat_seconds)


def observed_status(directory):
    """Atomic health/display view only. Never used for start/admission or approvals."""
    record = observation(directory)
    if record is None:
        return stored_status(directory)
    config = ContinuousConfig.model_validate(record["configuration"])
    return _freshness(record["snapshot"], config.heartbeat_seconds)


def observation(directory):
    """Read one atomic, bound display record, without SQLite or a second read."""
    from uuid import UUID

    from soc_agent.review.persistence.secure_storage import validate_directory

    validate_directory(directory)
    path = directory / "observation.json"
    if not path.exists():
        return None  # Compatibility with prior Runtime versions.
    record = json.loads(read_local(path, 262144))
    if (
        not isinstance(record, dict)
        or set(record) != {"contract", "store_id", "configuration", "snapshot", "digest"}
        or record["contract"] != "soc-continuous-observation:v1"
        or record["digest"] != digest({k: v for k, v in record.items() if k != "digest"})
    ):
        raise ValueError("CONTINUOUS_OBSERVATION_INTEGRITY")
    UUID(record["store_id"])
    config = ContinuousConfig.model_validate(record["configuration"])
    value = record["snapshot"]
    if not isinstance(value, dict) or value.get("source", config.source) != config.source:
        raise ValueError("CONTINUOUS_OBSERVATION_SOURCE")
    return record


def _freshness(value, heartbeat_seconds):
    control = value.get("control")
    if control is not None:
        from soc_agent.continuous.process_identity import same_runtime

        if (
            not isinstance(control, dict)
            or control.get("contract") != "soc-runtime-control:v1"
            or type(control.get("monotonic")) not in (int, float)
            or type(control.get("sequence")) is not int
            or control["sequence"] <= 0
            or control.get("lease_seconds") != 5
            or not isinstance(control.get("identity"), dict)
        ):
            raise ValueError("CONTINUOUS_CONTROL_IDENTITY")
        value["heartbeat_stale"] = not (
            0 <= time.monotonic() - control["monotonic"] < 5 and same_runtime(control["identity"])
        )
    else:
        value["heartbeat_stale"] = time.time() - value.get("heartbeat_unix", 0) > max(
            10, heartbeat_seconds * 3
        )
    terminal_failure = (
        value.get("state") == "DEGRADED"
        and value.get("collector") == value.get("worker") == "STOPPED"
        and value.get("collection_live") is False
        and value.get("final_flush") in {"VERIFIED", "FAILED"}
        and str(value.get("cleanup", "")).startswith("UNVERIFIED")
    )
    if (
        value.get("state") in ("RUNNING", "DEGRADED")
        and value["heartbeat_stale"]
        and not terminal_failure
    ):
        value["state"] = "UNKNOWN_STALE_HEARTBEAT"
        value["cleanup"] = "UNVERIFIED_AFTER_SERVICE_LOSS"
        value["collection_live"] = False
        # Preserve the last observation, but do not display it as current liveness.
        value["last_observed_collector"] = value.get("collector", "UNKNOWN")
        value["last_observed_worker"] = value.get("worker", "UNKNOWN")
        value["collector"] = value["worker"] = "UNKNOWN_STALE_HEARTBEAT"
    return value


def request_stop(directory: Path, *, expected_config=None):
    """Signal only the bound ordinary CLI Runtime; no SQLite wait or Root control.

    pidfd plus start/boot/UID and exact command binding prevent PID reuse. Old
    Runtimes retain their original durable request path, never a guessed PID.
    """
    record = observation(directory)
    control = record["snapshot"].get("control") if record else None
    if control is None:
        store = Store(directory)
        if expected_config is not None and store.config != expected_config:
            raise ValueError("AGENT_AUTHORITATIVE_CONFIG_CHANGED")
        store.control(stop=True)
        return
    from soc_agent.continuous.process_identity import same_runtime

    _freshness(
        record["snapshot"],
        ContinuousConfig.model_validate(record["configuration"]).heartbeat_seconds,
    )
    identity = control["identity"]
    config = ContinuousConfig.model_validate(record["configuration"])
    if expected_config is not None and config != expected_config:
        raise ValueError("AGENT_AUTHORITATIVE_CONFIG_CHANGED")
    fd = os.pidfd_open(identity["pid"])
    try:
        argv = Path(f"/proc/{identity['pid']}/cmdline").read_bytes().split(b"\0")
        wanted = [b"-m", b"soc_agent.cli", b"continuous", b"run", os.fsencode(directory)]
        if not same_runtime(identity) or not any(
            argv[i : i + len(wanted)] == wanted for i in range(len(argv))
        ):
            raise ValueError("CONTINUOUS_STOP_PROCESS_BINDING")
        signal.pidfd_send_signal(fd, signal.SIGTERM)
    finally:
        os.close(fd)


def start(directory):
    store = Store(directory)
    require_source_authority(store.config)
    if read_local(directory / "code-identity", 128).decode() != code_identity():
        raise ValueError("CONTINUOUS_EXECUTABLE_INTEGRITY_CHANGED")
    from soc_agent.runtime_lock import exclusive_runtime_lock

    with exclusive_runtime_lock(directory / "start.lock"):
        with exclusive_runtime_lock(directory / "service.lock"):
            pass
        if stored_status(directory).get("cleanup", "").startswith("UNVERIFIED"):
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
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise ValueError("CONTINUOUS_SERVICE_START_FAILED")
                current = status(directory)
                if current.get("service_pid") == proc.pid and not current["heartbeat_stale"]:
                    return dict(
                        status="SERVICE_HEARTBEAT_VERIFIED", pid=proc.pid, mode="CONTINUOUS"
                    )
                time.sleep(0.05)
            raise ValueError("CONTINUOUS_START_HEALTH_TIMEOUT_REVIEW_REQUIRED")
        except (ValueError, OSError):
            # Only the child created above is owned. Never stop another service
            # or leave this partial start running after reporting failure.
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=store.config.shutdown_seconds + 5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                    store.event("CONTINUOUS_START_FORCED_REAP", {"cleanup": "UNVERIFIED"})
            raise


async def run(directory):
    if read_local(directory / "code-identity", 128).decode() != code_identity():
        raise ValueError("CONTINUOUS_EXECUTABLE_INTEGRITY_CHANGED")
    service = ContinuousRuntime(directory)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):

        def stop():
            service.stop_reason = service.stop_reason or "OPERATOR_REQUEST"
            if service.signal_stop_request is None:
                service.signal_stop_request = dict(
                    received_monotonic=time.monotonic(),
                    received_unix=time.time(),
                    identity=service.control_identity,
                    origin="PROCESS_SIGNAL_NO_SENDER_ATTRIBUTION_OR_AUTHORITY_GRANT",
                    audit="DEFERRED_UNTIL_DURABLE_STORAGE_AVAILABLE",
                )
            service.stop.set()

        loop.add_signal_handler(sig, stop)
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
            "observe",
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
        elif args.command == "observe":
            result = observed_status(directory)
        elif args.command == "start":
            result = start(directory)
        elif args.command == "run":
            asyncio.run(run(directory))
            result = status(directory)
        elif args.command in ("stop", "reset-worker"):
            if args.command == "stop":
                request_stop(directory)
            else:
                Store(directory).control(reset=True)
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
        # A foreground run may fail after real capture and cleanup. Its exit
        # alone cannot establish that nothing executed; retained service/Audit
        # evidence remains authoritative, including when admission itself failed.
        run_failed = args.command == "run"
        print(
            json.dumps(
                dict(
                    status="FAILED_OR_BLOCKED" if run_failed else "BLOCKED",
                    error=type(error).__name__ + ":" + str(error),
                    executed=None if run_failed else False,
                    **({"execution_evidence_directory": str(directory)} if run_failed else {}),
                )
            )
        )
        return 2
