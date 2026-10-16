"""Bounded single-request subprocess adapter. Never grants operating authority."""

import asyncio
import json
import os
from pathlib import Path
from uuid import uuid4

from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.security_ai.research.environment import (
    Paths,
    catalogue,
    defaults,
    read_local,
    verify,
)
from soc_agent.security_ai.research.models import Request, digest, parse_receipt


class ResearchAdapter:
    def __init__(
        self,
        directory: Path,
        *,
        paths: Paths | None = None,
        timeout: float = 30,
        live_metadata: bool = False,
    ):
        if not 0.1 <= timeout <= 30:
            raise ValueError("RESEARCH_TIMEOUT_LIMIT")
        self.directory, self.paths, self.timeout = directory, paths, timeout
        self.process = None
        self.busy = False
        self.cancelled = False
        self.live_metadata = live_metadata
        self.authorize_live = None

    def status(self, profile="quality") -> dict:
        try:
            if profile == "dns":
                from soc_agent.security_ai.research.dns import verify as dns_verify

                return dns_verify(self.paths or defaults())
            return verify(self.paths or defaults(), offline=not self.live_metadata)
        except (OSError, ValueError, KeyError, ImportError):
            return {
                "status": "BLOCKED",
                "reason": "RESEARCH_ENVIRONMENT_OR_ARTIFACT_INVALID",
                "operational_inference": "BLOCKED",
                "write_policy": "WRITE_DENIED",
            }

    async def cancel(self):
        self.cancelled = True
        process = self.process
        if process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 3)
            except TimeoutError:
                process.kill()  # Owned helper only, never a SOC Runtime or external PID.
                await process.wait()

    async def infer(self, request: Request) -> dict:
        from soc_agent.security_ai.research.live_input import LiveRequest, validate_result

        live = isinstance(request, LiveRequest)
        if live:
            from soc_agent.security_ai.operational.network_capture.live_session import unprivileged

            unprivileged()
        if live != self.live_metadata:
            raise ValueError("EXPLICIT_LIVE_RESEARCH_MODE_REQUIRED")
        request = (LiveRequest if live else Request).model_validate_json(request.model_dump_json())
        if self.busy:
            raise ValueError("RESEARCH_WORKER_ALREADY_RUNNING")
        self.busy = True
        self.cancelled = False
        try:
            if live and request.origin == "NATIVE_AF_PACKET":
                if self.authorize_live is None:
                    return {"status": "UNKNOWN", "error": "NATIVE_CAPTURE_SOURCE_NOT_VERIFIED"}
                await asyncio.to_thread(self.authorize_live, request)
            paths = self.paths or defaults()
            if request.profile == "dns":
                from soc_agent.security_ai.research.dns import verify as check
            else:
                check = verify
            if live:
                await asyncio.to_thread(verify, paths, offline=False)
            else:
                await asyncio.to_thread(check, paths)
            if self.cancelled:
                return {"status": "UNKNOWN", "error": "WORKER_CANCELLED_NO_RETRY"}
            work = self.directory / ("worker-" + str(uuid4()))
            create_private_directory(work, exist_ok=False)
            source, result = work / "request.json", work / "result.json"
            with source.open("x") as stream:
                stream.write(request.model_dump_json())
            source.chmod(0o600)
            self.process = await asyncio.create_subprocess_exec(
                str(paths.python),
                "-m",
                "soc_agent.security_ai.research.worker",
                "--parent-pid",
                str(os.getpid()),
                "--request",
                str(source),
                "--result",
                str(result),
                "--ml",
                str(paths.ml),
                "--producer-source",
                str(paths.producer_source or paths.ml),
                *(["--live-metadata"] if live else []),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                env={
                    "PATH": os.defpath,
                    "LANG": "C.UTF-8",
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONPATH": str(paths.soc_source)
                    + os.pathsep
                    + str((paths.producer_source or paths.ml) / "src")
                    + os.pathsep
                    + str((paths.producer_source or paths.ml) / "packages/dns-security-ai/src"),
                    "OMP_NUM_THREADS": "1",
                    "OPENBLAS_NUM_THREADS": "1",
                    "MKL_NUM_THREADS": "1",
                },
            )
            if self.cancelled:
                await self.cancel()
                return {"status": "UNKNOWN", "error": "WORKER_CANCELLED_NO_RETRY"}
            try:
                await asyncio.wait_for(self.process.wait(), self.timeout)
            except TimeoutError:
                await self.cancel()
                return {"status": "UNKNOWN", "error": "WORKER_TIMEOUT_NO_RETRY"}
            if self.process.returncode != 0:
                return {"status": "UNKNOWN", "error": "WORKER_FAILURE_OR_BUDGET_NO_RETRY"}
            receipt = parse_receipt(json.loads(read_local(result, 32 * 1024)))
            if live:
                validate_result(request, receipt)
                return {"status": "SUCCESS", "receipt": receipt.model_dump(mode="json")}
            if request.profile == "dns":
                if (
                    receipt.request_digest != digest(request.model_dump(mode="json"))
                    or receipt.invocation_id != request.invocation_id
                    or receipt.profile != "dns"
                    or receipt.flow_index != request.flow_index
                ):
                    raise ValueError("DNS_REQUEST_BINDING_MISMATCH")
                return {"status": "SUCCESS", "receipt": receipt.model_dump(mode="json")}
            expected = catalogue()["samples"][request.flow_index]
            if (
                receipt.request_digest != digest(request.model_dump(mode="json"))
                or receipt.invocation_id != request.invocation_id
                or receipt.profile != request.profile
                or receipt.flow_index != request.flow_index
                or receipt.flow_id != expected["flow_id"]
                or receipt.feature_digest != expected["feature_digest"]
                or receipt.source_digest != expected["source_digest"]
                or digest(receipt.feature_values) != expected["feature_values_digest"]
                or list(receipt.feature_names) != catalogue()["feature_names"]
            ):
                raise ValueError("RESEARCH_RECEIPT_BINDING_MISMATCH")
            return {"status": "SUCCESS", "receipt": receipt.model_dump(mode="json")}
        except asyncio.CancelledError:
            await self.cancel()
            raise
        except (OSError, ValueError, KeyError, ImportError):
            return {"status": "UNKNOWN", "error": "RESEARCH_VALIDATION_FAILED_NO_RETRY"}
        finally:
            self.busy = False
            self.process = None
