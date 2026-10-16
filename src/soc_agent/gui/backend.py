"""GUI controller: existing commands/read models; live decisions use OS-authenticated socket."""

import asyncio
import json
import os
import sqlite3
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field

from soc_agent.application import compose_application
from soc_agent.demo.scenario import run_scenario
from soc_agent.demo.scenario_models import scenarios
from soc_agent.deployment import DeploymentDescriptor
from soc_agent.desktop import OfflineDesktopClient, source_report_tool
from soc_agent.gui.queries import investigation_rows
from soc_agent.gui.runtime_process import PersistentRuntimeProcess
from soc_agent.ingestion import EventIngestor
from soc_agent.linux_runtime.__main__ import status
from soc_agent.linux_runtime.operator import OperatorRequest, operator_request
from soc_agent.review.persistence.secure_storage import create_private_directory, validate_directory
from soc_agent.security_ai.external.models import Snapshot
from soc_agent.security_ai.external.runtime_store import RuntimeGovernanceStore
from soc_agent.tools import ToolRegistry


class GUIConfig(Snapshot):
    data_directory: Path
    runtime_directory: Path | None = None
    artifacts: Path | None = None
    native_python: Path | None = None
    refresh_seconds: int = Field(default=15, ge=10, le=300)
    source_label: Literal["UNVERIFIED", "LIVE_WSL", "FIXTURE"] = "UNVERIFIED"


def observed_snapshot(reader):
    # Stamp before reading: a slow old poll must never outrank a completed Stop.
    started = time.monotonic_ns()
    return {**reader(), "observation_started_ns": started}


class Backend:
    """One instance belongs to one GUI worker event loop, never the Tk thread."""

    def __init__(self, config: GUIConfig):
        self.config = config
        self.directory = config.data_directory.absolute()
        create_private_directory(self.directory)
        self.runtime = config.runtime_directory.absolute() if config.runtime_directory else None
        self.child: PersistentRuntimeProcess | None = None
        self.process_log = None
        self.model_service = None
        self.model_incident = None
        self.model_paths = (config.native_python, config.artifacts)
        self.busy_probe = False
        from soc_agent.security_ai.research.service import ResearchDemo

        self.research_demo = ResearchDemo(self.directory)
        from soc_agent.security_ai.research.live_service import LiveMonitoring

        self.live_monitoring = LiveMonitoring(self.directory)
        from soc_agent.security_ai.research.stream_auth import OSAuthentication
        from soc_agent.security_ai.research.stream_service import StreamingMonitoring

        self.streaming_monitoring = StreamingMonitoring(self.directory)
        self.streaming_auth = OSAuthentication()
        self.closed = False
        self.busy_scenario = False
        self.scenario_results = []

    async def _cli(self, module: str, args: list[str], *, timeout=30) -> dict:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            module,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, _ = await asyncio.wait_for(process.communicate(), timeout)
        except TimeoutError:
            # Only this owned bounded helper is signalled. Never retry an uncertain write.
            if process.returncode is None:
                process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 5)
            except TimeoutError:
                return {"ok": False, "status": "UNKNOWN", "error": "HELPER_SHUTDOWN_UNCERTAIN"}
            return {"ok": False, "status": "UNKNOWN", "error": "BACKEND_TIMEOUT_NO_RETRY"}
        if process.returncode or len(out) > 1024 * 1024:
            return {"ok": False, "status": "BLOCKED", "error": "BACKEND_COMMAND_FAILED"}
        return {"ok": True, "result": json.loads(out)}

    def attach(self, directory: Path):
        if self.child and self.child.returncode is None:
            raise ValueError("OWNED_RUNTIME_MUST_STOP_BEFORE_ATTACH")
        validate_directory(directory)
        from soc_agent.linux_runtime.store import RuntimeStore

        RuntimeStore(directory)
        self.runtime = directory.absolute()
        return {"status": "ATTACHED", "ownership": "EXTERNAL", "directory": str(self.runtime)}

    async def initialize_runtime(self, directory: Path, repeated: int, accounts: int, mode: str):
        if directory.exists() or mode not in ("READ_ONLY", "SCRIPTED"):
            raise ValueError("FRESH_RUNTIME_AND_EXPLICIT_MODE_REQUIRED")
        if not 2 <= repeated <= 10000 or not 2 <= accounts <= 10000:
            raise ValueError("THRESHOLD_RANGE")
        result = await self._cli(
            "soc_agent.linux_runtime",
            [
                "--directory",
                str(directory),
                "init",
                "--repeated-failures",
                str(repeated),
                "--multiple-accounts",
                str(accounts),
                "--assessment-mode",
                mode,
            ],
        )
        if result["ok"]:
            self.runtime = directory
        return result

    async def start(self):
        if self.runtime is None:
            raise ValueError("RUNTIME_NOT_CONFIGURED")
        current = await self.dashboard()
        if current.get("runtime_state") in ("RUNNING", "STOPPING"):
            raise ValueError("EXISTING_RUNTIME_NOT_ADOPTED")
        if self.child and self.child.returncode is None:
            raise ValueError("RUNTIME_ALREADY_OWNED")
        log = self.directory / ("runtime-" + str(uuid4()) + ".log")
        self.process_log = log.open("xb")
        self.child = await asyncio.to_thread(
            PersistentRuntimeProcess,
            [
                sys.executable,
                "-m",
                "soc_agent.linux_runtime",
                "--directory",
                str(self.runtime),
                "start",
                "--operator-uid",
                str(os.geteuid()),
            ],
            self.process_log,
        )
        await asyncio.sleep(0.15)
        if self.child.returncode is not None:
            self.process_log.close()
            return {"status": "BLOCKED", "error": "RUNTIME_START_FAILED"}
        return {"status": "START_REQUESTED", "ownership": "GUI_CHILD", "pid": self.child.pid}

    async def stop(self):
        if not self.child or self.child.returncode is not None:
            return {"status": "NOT_OWNED", "external_runtime_untouched": True}
        result = await self._cli(
            "soc_agent.linux_runtime", ["--directory", str(self.runtime), "stop"]
        )
        try:
            await asyncio.wait_for(self.child.wait(), 30)
        except TimeoutError:
            self.child.terminate()  # Own runtime SIGTERM uses the existing graceful handler.
            try:
                await asyncio.wait_for(self.child.wait(), 30)
            except TimeoutError:
                return {"status": "UNKNOWN", "error": "OWNED_SHUTDOWN_INCOMPLETE"}
        if self.process_log:
            self.process_log.close()
        return {
            "status": "STOPPED",
            "exit_code": self.child.returncode,
            "stop_request": result["ok"],
        }

    async def close(self):
        # GUI lifetime is not Runtime lifetime. A file-backed log and new session
        # keep this explicitly started Runtime independent; no transport destructor kills it.
        alive = self.child is not None and self.child.returncode is None
        if self.process_log:
            self.process_log.close()
        await self.research_demo.stop()
        await self.live_monitoring.stop()
        await self.streaming_monitoring.stop()
        await self.streaming_auth.cancel()
        self.closed = True
        return {
            "status": "DETACHED",
            "runtime_continues": alive,
            "external_runtime_untouched": True,
        }

    async def dashboard(self):
        research = await asyncio.to_thread(self.research_demo.snapshot)
        live = await asyncio.to_thread(self.live_monitoring.snapshot)
        streaming = await asyncio.to_thread(self.streaming_monitoring.snapshot)
        if self.runtime is None or not (self.runtime / "monitor.sqlite").is_file():
            return {
                "research": research,
                "live_network": live,
                "streaming_network": streaming,
                "runtime_state": "OFFLINE",
                "health": "UNKNOWN",
                "readiness": "NOT_READY",
                "queue_backlog": None,
                "authentication_events": None,
                "ownership": "NONE",
            }
        from soc_agent.gui.queries import stored_counts

        try:
            result = await asyncio.to_thread(status, self.runtime)
            result.update(await asyncio.to_thread(stored_counts, self.runtime))
        except (OSError, ValueError, sqlite3.Error):
            result = {
                "runtime_state": "UNKNOWN",
                "health": "UNKNOWN",
                "readiness": "NOT_READY",
                "last_error": "RUNTIME_STATUS_UNAVAILABLE_OR_INVALID",
                "queue_backlog": None,
                "authentication_events": None,
            }
        # A view may reconnect to a different store; never join unrelated chart histories.
        result["research"] = research
        result["live_network"] = live
        result["streaming_network"] = streaming
        result["metric_scope"] = str(self.runtime)
        result["display_source"] = self.config.source_label
        result["ownership"] = (
            "GUI_CHILD" if self.child and self.child.returncode is None else "EXTERNAL"
        )
        return result

    async def live_start(self, selection="both"):
        choices = {"both": ("quality", "edge"), "quality": ("quality",), "edge": ("edge",)}
        if selection not in choices:
            raise ValueError("LIVE_NETWORK_MODEL_SELECTION_INVALID")
        result = await self.live_monitoring.start(choices[selection])
        return {**result, "observation_started_ns": time.monotonic_ns()}

    async def live_status(self):
        return await asyncio.to_thread(observed_snapshot, self.live_monitoring.snapshot)

    async def live_command(self, session_id):
        return {
            **self.live_monitoring.helper_command(session_id),
            "observation_started_ns": time.monotonic_ns(),
        }

    async def live_stop(self):
        await self.live_monitoring.stop()
        return observed_snapshot(self.live_monitoring.snapshot)

    async def stream_start(self, selection="both", dns_headers=True):
        from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy

        choices = {"both": ("quality", "edge"), "quality": ("quality",), "edge": ("edge",)}
        if selection not in choices or type(dns_headers) is not bool:
            raise ValueError("STREAM_SELECTION_INVALID")
        result = await self.streaming_monitoring.start(
            choices[selection], policy=StreamPolicy(dns_headers=dns_headers)
        )
        return {
            **result,
            "os_auth": self.streaming_auth.snapshot(),
            "observation_started_ns": time.monotonic_ns(),
        }

    async def stream_status(self):
        value = await asyncio.to_thread(observed_snapshot, self.streaming_monitoring.snapshot)
        return {**value, "os_auth": self.streaming_auth.snapshot()}

    async def stream_command(self, session_id):
        return {
            **self.streaming_monitoring.command(session_id),
            "observation_started_ns": time.monotonic_ns(),
        }

    async def stream_authenticate(self, session_id, approved_sha):
        if self.streaming_monitoring.command(session_id).get("listener_ready") is not True:
            raise ValueError("OS_AUTH_STALE_SESSION")
        return await self.streaming_auth.start(self.streaming_monitoring, approved_sha)

    async def stream_stop(self, abort=False):
        # Close listener before cancelling a pending OS prompt, so a late approval
        # cannot open capture through a stopped session.
        await self.streaming_monitoring.stop(abort=abort)
        await self.streaming_auth.cancel()
        return {
            **observed_snapshot(self.streaming_monitoring.snapshot),
            "os_auth": self.streaming_auth.snapshot(),
        }

    async def stream_restore(self):
        await self.streaming_monitoring.restore_latest()
        return observed_snapshot(self.streaming_monitoring.snapshot)

    async def investigations(self):
        if self.runtime is None:
            return []
        return await asyncio.to_thread(investigation_rows, self.runtime)

    async def improvement_records(self, kind: str):
        from soc_agent.gui.queries import improvement_records

        return (
            []
            if self.runtime is None
            else await asyncio.to_thread(improvement_records, self.runtime, kind)
        )

    async def operator(self, command: str, **fields):
        if self.runtime is None:
            raise ValueError("RUNTIME_NOT_CONFIGURED")
        allowed = {
            "pending",
            "detail",
            "approve",
            "reject",
            "execute",
            "audit",
            "feedback",
            "feedback-list",
            "experience",
            "feedback-submit",
            "candidates",
            "candidate-review",
            "restricted-list",
            "restricted-request",
            "restricted-approve",
            "restricted-reject",
            "restricted-execute",
            "restricted-rollback-request",
        }
        if command not in allowed:
            raise ValueError("GUI_COMMAND_NOT_ALLOWED")
        # Schema validation excludes actor/paths/shell and oversized or invalid identifiers.
        OperatorRequest(
            command=command,
            challenge=uuid4(),
            request_id=uuid4(),
            created_at=datetime.now(UTC),
            **fields,
        )
        try:
            return await operator_request(self.runtime, command, **fields)
        except (OSError, TimeoutError):
            return {"ok": False, "status": "UNKNOWN", "error": "OPERATOR_UNAVAILABLE_NO_RETRY"}

    async def approvals(self, restricted=False):
        if self.runtime is None:
            return []
        from soc_agent.gui.queries import approval_rows

        return await asyncio.to_thread(approval_rows, self.runtime, restricted)

    async def prepare(self, restricted=False):
        if self.runtime is None:
            raise ValueError("RUNTIME_NOT_CONFIGURED")
        # Existing stopped-runtime CLI takes writer lock. No approvals are fabricated.
        if restricted:
            return await self._cli(
                "soc_agent.linux_runtime.restricted_cli",
                ["--directory", str(self.runtime), "prepare", "--test-mode"],
            )
        return await self._cli(
            "soc_agent.linux_runtime", ["--directory", str(self.runtime), "simulation", "enable"]
        )

    def _models(self, fresh=False):
        if self.model_service is None or fresh:
            location = self.directory / ("model-probe-" + str(uuid4()))
            store = RuntimeGovernanceStore.create_isolated(location)
            ingestion = EventIngestor(store)
            registry = ToolRegistry()
            registry.register(source_report_tool(ingestion))
            self.model_service = compose_application(
                store,
                deployment=DeploymentDescriptor(profile="DESKTOP"),
                registry=registry,
                llm_client=OfflineDesktopClient(),
                ingestion=ingestion,
                external_artifacts=self.model_paths[1],
                external_interpreter=self.model_paths[0],
            ).service
            self.model_incident = None
        return self.model_service

    def _environment(self):
        from soc_agent.gui.environment import environment_root, verified_paths

        paths = (self.config.native_python, self.config.artifacts)
        state = {"status": "UNKNOWN", "reason": "ENVIRONMENT_CHECK_PENDING"}
        if paths == (None, None):
            try:
                paths = verified_paths()
            except FileNotFoundError:
                state = {
                    "status": "ARTIFACT_MISSING"
                    if (environment_root() / "receipt.json").is_file()
                    and not (environment_root() / "artifacts").is_dir()
                    else "SETUP_REQUIRED",
                    "reason": "PERSISTENT_ENVIRONMENT_OR_ARTIFACT_MISSING",
                }
            except (ValueError, OSError):
                state = {"status": "VALIDATION_FAILED", "reason": "ENVIRONMENT_INTEGRITY_FAILED"}
        elif paths[0] is None or paths[1] is None:
            state = {"status": "SETUP_REQUIRED", "reason": "BOTH_NATIVE_PATHS_REQUIRED"}
            paths = (None, None)
        if paths != self.model_paths:
            self.model_service = None
            self.model_incident = None
            self.model_paths = paths
        return state

    async def models(self):
        def query():
            state = self._environment()
            value = (
                self._models()
                .security_ai_status(incident_id=self.model_incident)
                .model_dump(mode="json")
            )
            if self.model_paths != (None, None):
                packages = value["packages"]
                if any("NATIVE_STATUS_UNAVAILABLE" in p["blocking_reasons"] for p in packages):
                    state = {"status": "BACKEND_UNAVAILABLE", "reason": "NATIVE_STATUS_UNAVAILABLE"}
                elif any(p["artifact"] != "VERIFIED" for p in packages):
                    state = {"status": "ARTIFACT_MISSING", "reason": "ARTIFACT_NOT_VERIFIED"}
                elif any(p["backend_dependencies"] != "VERIFIED" for p in packages):
                    state = {
                        "status": "BACKEND_UNAVAILABLE",
                        "reason": "NATIVE_BACKEND_NOT_VERIFIED",
                    }
                elif any(
                    p["package_import"] != "VERIFIED" or p["contract"] != "VERIFIED"
                    for p in packages
                ):
                    state = {
                        "status": "VALIDATION_FAILED",
                        "reason": "PACKAGE_CONTRACT_NOT_VERIFIED",
                    }
                else:
                    state = {"status": "READY", "reason": "PREFLIGHT_ONLY_NO_INFERENCE"}
            value["environment"] = state
            return value

        return await asyncio.to_thread(query)

    async def fixture_probe(self):
        from soc_agent.gui.probe import probe

        if self.busy_probe:
            raise ValueError("FIXTURE_DEMO_ALREADY_RUNNING")
        self.busy_probe = True
        try:
            inventory = await self.models()
            if inventory["environment"]["status"] != "READY":
                return {
                    "status": "BLOCKED",
                    "environment": inventory["environment"],
                    "input_origin": "SYNTHETIC_PRECOMPUTED_FEATURE_FIXTURE",
                    "operational_input": "NOT_INFERABLE",
                    "action_policy": "WRITE_DENIED",
                }
            service = self._models(fresh=True)
            result = await probe(service)
            self.model_incident = UUID(result["incident_id"])
            result["inventory"] = await self.models()
            if result["inventory"]["environment"]["status"] != "READY":
                raise ValueError("ENVIRONMENT_CHANGED_DURING_DEMO")
            return result
        finally:
            self.busy_probe = False

    async def research_status(self):
        runtime = await self.dashboard()
        value = runtime.pop("research")
        value["runtime"] = runtime
        return value

    def research_activity(self):
        process = self.research_demo.adapter.process
        return {
            "worker_running": process is not None and process.returncode is None,
            "active_model": getattr(self.research_demo, "active_model", None),
        }

    async def research_start(self, profile="quality"):
        await self.research_demo.start(profile)
        return await self.research_status()

    async def research_stop(self):
        await self.research_demo.stop()
        return await self.research_status()

    async def research_replay(self, profile: str, flow_index: int):
        if profile not in {"quality", "edge", "both", "dns"}:
            raise ValueError("INVALID_RESEARCH_PROFILE")
        if not self.research_demo.started:
            raise ValueError("EXPLICIT_RESEARCH_START_REQUIRED")
        outcomes = []
        for selected in ("quality", "edge") if profile == "both" else (profile,):
            if not self.research_demo.started:
                break
            outcome = await self.research_demo.replay(selected, flow_index)
            outcomes.append(outcome["status"])
        value = await self.research_status()
        value["replay_outcomes"] = outcomes
        return value

    @staticmethod
    def scenario_catalog():
        descriptions = (
            "Normal authentication",
            "Single PAM failure",
            "Repeated failures",
            "Multiple accounts",
            "Failure then success",
            "sudo PAM failure",
            "Approval requested",
            "Approval rejected",
            "Approval expired",
            "Approval target tampering",
            "Restart and duplicate",
            "Network / DNS inference gate",
        )
        return [
            {
                "id": s.scenario_id,
                "description": desc,
                "origin": "FIXTURE",
                "fixture_identity": s.fixture_identity,
            }
            for s, desc in zip(scenarios(), descriptions, strict=True)
        ]

    async def scenario(self, identity: str):
        if identity not in {s.scenario_id for s in scenarios()}:
            raise ValueError("UNKNOWN_SCENARIO")
        if self.busy_scenario:
            raise ValueError("SCENARIO_ALREADY_RUNNING")
        self.busy_scenario = True
        try:
            location = self.directory / "scenarios"
            create_private_directory(location)
            result = await run_scenario(
                identity, root=location, response_mode="RESPONSE_SIMULATION"
            )
            payload = result.model_dump(mode="json")
            (Path(payload["audit_path"]).parent / "gui-result.json").write_text(
                json.dumps(payload, indent=2)
            )
            self.scenario_results.append(payload)
            return payload
        finally:
            self.busy_scenario = False
