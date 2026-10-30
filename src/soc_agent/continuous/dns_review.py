"""Fixed candidate for the existing exact Root review; never installs or starts.

The ordinary Runtime must run in the same approved network Namespace. Only the
separate helper opens AF_PACKET, then drops its effective/permitted/ambient caps.
"""

import hashlib
import re
from pathlib import Path

from soc_agent.continuous.dns_source import MODULE, inspect
from soc_agent.security_ai.research.models import digest

UNIT = "soc-continuous-dns.service"
TARGET = Path("/etc/systemd/system") / UNIT


def candidate(directory: Path, namespace: str, pin: str) -> dict:
    session = inspect(directory, namespace=namespace, sha256=pin)
    # systemd has its own quoting/expansion grammar. Restrict paths rather than
    # guessing shell escaping; these arguments never pass through a shell.
    if any(
        not re.fullmatch(r"/[A-Za-z0-9_./-]+", path) for path in (str(directory), session.python)
    ):
        raise ValueError("CONTINUOUS_DNS_FIXED_SERVICE_PATH_REQUIRED")
    if session.uid != 1000 or session.gid != 1000 or namespace != "net:[4026532232]":
        raise ValueError("CONTINUOUS_DNS_REVIEWED_UID_OR_NAMESPACE_REQUIRED")
    canonical_pin = digest(session.model_dump(mode="json"))
    command = " ".join(
        [
            "/usr/bin/setpriv",
            "--reuid=1000",
            "--regid=1000",
            "--clear-groups",
            "--bounding-set=-all,+net_raw",
            "--inh-caps=-all,+net_raw",
            "--ambient-caps=-all,+net_raw",
            "--no-new-privs",
            session.python,
            "-I",
            "-m",
            MODULE,
            "--directory",
            str(directory),
            "--session-digest",
            canonical_pin,
        ]
    )
    # Bound and explicitly carry the four bootstrap capabilities across exec.
    # setpriv then clears groups, changes UID/GID and retains NET_RAW alone;
    # the helper independently verifies every capability set before opening.
    # A bounding set is an upper limit, not evidence of usable credentials.
    body = f"""[Unit]
Description=SOC approved bounded DNS metadata helper
After=soc-operations-runtime.service
[Service]
Type=exec
User=root
Group=root
NetworkNamespacePath=/run/netns/soc-native-b3
ExecStartPre=/usr/bin/setpriv --dump
ExecStart={command}
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_NET_RAW
AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_NET_RAW
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX AF_PACKET AF_NETLINK
MemoryMax=536870912
CPUQuota=10%
TasksMax=4
LimitNOFILE=64
LimitCORE=0
RuntimeMaxSec={session.seconds}s
TimeoutStartSec=15s
TimeoutStopSec=10s
KillMode=control-group
Restart=no
UMask=0077
"""
    return dict(
        contract="soc-continuous-dns-service-review:v1",
        unit=UNIT,
        target=str(TARGET),
        body=body,
        unit_sha256=hashlib.sha256(body.encode()).hexdigest(),
        session_file=str(directory / "session.json"),
        session_sha256=pin,
        session_id=str(session.session_id),
        namespace=namespace,
        interface="lo",
        seconds=session.seconds,
        helper_module=MODULE,
        helper_uid=1000,
        bootstrap_capabilities=["CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP", "CAP_NET_RAW"],
        helper_initial_capability="CAP_NET_RAW",
        helper_after_open_capabilities=0,
        traffic_generated=False,
        external_connections=False,
        query_names_retained=False,
        dns9="INCOMPLETE",
        required_application_namespace=namespace,
        root_execution_authorized=False,
    )


def verify_review(config, review: Path, request: dict) -> dict:
    if not config.dns_session:
        return dict(state="NOT_CONFIGURED")
    expected = candidate(config.dns_session, config.namespace, config.dns_session_sha256)
    if request.get("dns_service") != expected:
        raise ValueError("AGENT_NATIVE_DNS_EXACT_SCOPE_REVIEW_REQUIRED")
    manifest = request["files"].get(UNIT)
    if (
        manifest is None
        or manifest.get("path") != str(review / UNIT)
        or manifest.get("sha256") != expected["unit_sha256"]
        or (review / UNIT).read_text() != expected["body"]
    ):
        raise ValueError("AGENT_NATIVE_DNS_UNIT_BINDING")
    return expected
