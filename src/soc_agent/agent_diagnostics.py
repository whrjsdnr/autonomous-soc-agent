"""Non-consuming host diagnostics; never enters a namespace or starts a service."""

import importlib.metadata
import os
import re
import shutil
import subprocess
import sys
from typing import Literal

from pydantic import JsonValue

from soc_agent.agent_native import namespace_binding, validate_plan
from soc_agent.continuous import cli as service
from soc_agent.continuous.native import policy
from soc_agent.review.persistence.models import StorageError
from soc_agent.security_ai.research.models import Frozen


class Check(Frozen):
    status: Literal["PASS", "WARN", "BLOCKED", "FAIL"]
    code: str
    scope: str = "HOST_READ_ONLY"
    details: dict[str, JsonValue] = {}


def checked(operation, *, scope="HOST_READ_ONLY", failure="FAIL") -> dict:
    try:
        result = operation()
        return Check(status="PASS", code="VERIFIED", scope=scope, details=result).model_dump()
    except (OSError, ValueError, StorageError, importlib.metadata.PackageNotFoundError) as error:
        message = str(error)
        code = message if re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", message) else type(error).__name__
        return Check(status=failure, code=code, scope=scope).model_dump()


def root_service() -> dict:
    """Fixed read-only systemd query; no user-controlled argv or elevation."""
    try:
        result = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                "soc-continuous-collector.service",
                "--no-pager",
                "--property=LoadState,ActiveState,SubState,MainPID,MemoryMax,CPUQuotaPerSecUSec,TasksMax,NetworkNamespacePath,FragmentPath,User,CapabilityBoundingSet,NoNewPrivileges",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            env={"PATH": os.defpath, "LANG": "C.UTF-8", "SYSTEMD_PAGER": ""},
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError("AGENT_SERVICE_READ_ONLY_QUERY_TIMEOUT") from error
    if result.returncode or len(result.stdout) > 16384:
        raise ValueError("AGENT_SERVICE_READ_ONLY_QUERY_UNAVAILABLE")
    properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if properties.get("LoadState") != "loaded":
        raise ValueError("AGENT_NATIVE_SERVICE_NOT_INSTALLED")
    cpu = re.fullmatch(r"([0-9]+)(us|ms|s)", properties.get("CPUQuotaPerSecUSec", ""))
    if (
        not cpu
        or int(cpu[1]) * {"us": 1, "ms": 1000, "s": 1000000}[cpu[2]] > 250000
        or not 0 < int(properties.get("MemoryMax", "0")) <= 128 * 1024**2
        or not 0 < int(properties.get("TasksMax", "0")) <= 4
        or properties.get("NetworkNamespacePath") != "/run/netns/soc-native-b3"
        or properties.get("User") != "root"
        or properties.get("NoNewPrivileges") != "yes"
        or set(properties.get("CapabilityBoundingSet", "").split())
        != {"cap_bpf", "cap_net_admin", "cap_chown"}
    ):
        raise ValueError("AGENT_NATIVE_SERVICE_RESOURCE_OR_PRIVILEGE_SCOPE")
    return properties


def queue_storage(selected) -> dict:
    from soc_agent.continuous.recovery import inspect_queue

    if not selected.runtime.exists():
        return dict(
            state="NOT_INITIALIZED", writable_parent=os.access(selected.runtime.parent, os.W_OK)
        )
    result = inspect_queue(selected.runtime)
    total = sum(p.stat().st_size for p in selected.runtime.rglob("*") if p.is_file())
    free = shutil.disk_usage(selected.runtime).free
    if total >= selected.configuration.max_storage_bytes:
        raise ValueError("CONTINUOUS_STORAGE_LIMIT_REQUIRES_ARCHIVAL")
    return result | dict(
        used_bytes=total, quota_bytes=selected.configuration.max_storage_bytes, free_bytes=free
    )


def api_settings() -> dict:
    from soc_agent.llm.openai_compatible import OpenAICompatibleSettings

    present = [bool(os.environ.get("SOC_LLM_" + key)) for key in ("BASE_URL", "MODEL", "API_KEY")]
    if any(present):
        OpenAICompatibleSettings()  # Validate without constructing a client or sending a request.
    return dict(
        configured=all(present),
        credential_disclosed=False,
        network_requests=0,
        usage_authority="SEPARATE_APPROVAL_REQUIRED",
        runtime_provider="SCRIPTED",
    )


def target_scope(selected) -> dict:
    from soc_agent.security_ai.ebpf_tc.namespace_isolation import (
        IsolatedScope,
        inspect_current_isolation,
    )

    namespace = selected.configuration.namespace
    if os.readlink("/proc/self/ns/net") != namespace:
        raise ValueError("AGENT_APPROVED_TARGET_ENTRY_REQUIRED_FOR_INTERNAL_CHECK")
    result = inspect_current_isolation(IsolatedScope(namespace=namespace))
    evidence = result.get("observation", {})
    # This TCP-only contract does not require a DNS listener. Never pretend that
    # the legacy DNS-specific assessment passed; validate its actual observations.
    if (
        evidence.get("interfaces") != [[1, "lo"]]
        or evidence.get("loopback_up") is not True
        or evidence.get("routes_outside_lo") != []
        or not evidence.get("socket_cookie")
    ):
        raise ValueError("AGENT_NATIVE_INTERNAL_SCOPE_INCOMPLETE")
    return dict(
        namespace=namespace,
        loopback=True,
        external_routes=[],
        socket_cookie=evidence["socket_cookie"],
        namespace_entered_by_doctor=False,
        legacy_dns_assessment=result["status"],
        dns_not_required_for_tcp_only=True,
    )


def collect(selected, basic, artifact_error=None) -> dict:
    checks = {}
    checks["python"] = checked(
        lambda: dict(executable=sys.executable, version=sys.version.split()[0])
    )
    checks["runtime_dependency"] = checked(
        lambda: {
            name: importlib.metadata.version(name) for name in ("pydantic", "numpy", "scikit-learn")
        }
    )
    if artifact_error:
        checks["artifact_integrity"] = Check(status="FAIL", code=artifact_error).model_dump()
    else:
        checks["artifact_integrity"] = Check(
            status="PASS",
            code="SOURCE_AND_EXECUTABLE_CHECKED",
            details=dict(result=basic.get("artifact_integrity")),
        ).model_dump()
    models = basic.get("models", {})
    checks["model_registry"] = Check(
        status=("PASS" if all(v == "VERIFIED_SHA" for v in models.values()) else "FAIL")
        if models
        else "WARN",
        code="PINNED_MODEL_FILES" if models else "NO_NETWORK_MODEL_ROOT",
        details=dict(models=models, fingerprint=basic.get("model_preflight")),
    ).model_dump()
    checks["namespace_lease"] = checked(lambda: namespace_binding(selected.configuration.namespace))
    if checks["namespace_lease"]["status"] == "PASS":
        checks["namespace_lease"].update(
            status="WARN", code="MOUNT_OBSERVED_REVIEW_BOUND_LEASE_REQUIRED"
        )
    checks["namespace_internal"] = checked(
        lambda: target_scope(selected), scope="TARGET_READ_ONLY", failure="BLOCKED"
    )
    checks["root_installation"] = checked(lambda: policy.installed(), failure="BLOCKED")
    checks["root_service"] = checked(root_service, failure="WARN")
    checks["collector_runtime"] = checked(
        lambda: (
            service.observed_status(selected.runtime)
            if selected.runtime.exists()
            else dict(state="NOT_INITIALIZED")
        )
    )
    checks["queue_storage"] = checked(lambda: queue_storage(selected))
    checks["gui_backend"] = Check(
        status="PASS" if os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY") else "WARN",
        code="UNPRIVILEGED_ATTACHED_STATUS_BACKEND",
        details=dict(
            display_available=bool(os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY")),
            root_commands=False,
            runtime=str(selected.runtime),
        ),
    ).model_dump()
    checks["api_provider"] = checked(api_settings)
    if selected.configuration.source == "NATIVE_SERVICE":
        checks["native_plan"] = checked(lambda: validate_plan(selected), failure="BLOCKED")
    else:
        # Host scope and Root service activation are not Replay prerequisites.
        for key in ("namespace_lease", "namespace_internal", "root_installation"):
            if checks[key]["status"] in ("FAIL", "BLOCKED"):
                checks[key]["status"] = "WARN"
    priority = ["FAIL", "BLOCKED", "WARN", "PASS"]
    overall = next(s for s in priority if any(c["status"] == s for c in checks.values()))
    return dict(readiness=overall, diagnostics=checks, scope="READ_ONLY_NO_ACTIVATION_NO_AUTHORITY")
