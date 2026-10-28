"""Fixed Namespace Controller entry over existing Root-only admission.

No generic command executor. Namespace entry is one independently approved Root
DNS diagnostic; a later Native request is checked against the post-settlement Ledger and
must obtain its own exact approvals and fresh OS authentication.
"""

import hashlib
import json
import os
import select
import signal
import socket
import subprocess
import time
from pathlib import Path

from soc_agent.security_ai.ebpf_native.contracts import (
    ApplicationPlan,
    local_controller,
    process_identity,
)
from soc_agent.security_ai.ebpf_tc import dns_diagnostic
from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.reassessment import held_json
from soc_agent.security_ai.ebpf_tc.root_operations import RootBinding, RootOperations


def validate_controller(config: dict) -> dict:
    fields = {
        "project",
        "interpreter",
        "interpreter_sha",
        "source_pins",
        "source_pins_sha",
        "target",
        "request_file",
        "docker_group",
    }
    if set(config) != fields:
        raise ValueError("NAMESPACE_CONTROLLER_CONFIG_FIELDS")
    group = config["docker_group"]
    if group is not None and (type(group) is not int or group <= 0):
        raise ValueError("NAMESPACE_CONTROLLER_DOCKER_GROUP")
    target = config["target"]
    if set(target) != {"directory", "manifest", "image_sha", "campaign"}:
        raise ValueError("NAMESPACE_CONTROLLER_TARGET_FIELDS")
    for name in ("project", "interpreter", "source_pins", "request_file"):
        if not Path(config[name]).is_absolute():
            raise ValueError("NAMESPACE_CONTROLLER_ABSOLUTE_PATH")
    for name in ("directory", "campaign"):
        if not Path(target[name]).is_absolute():
            raise ValueError("NAMESPACE_CONTROLLER_ABSOLUTE_PATH")
    for pin in (
        config["interpreter_sha"],
        config["source_pins_sha"],
        target["manifest"],
        target["image_sha"],
    ):
        if not isinstance(pin, str) or len(pin) != 64 or bytes.fromhex(pin).hex() != pin:
            raise ValueError("NAMESPACE_CONTROLLER_PIN")
    return config


def controller_scope(base: dict, config: dict) -> dict:
    validate_controller(config)
    keys = (
        "setup_binding",
        "lease_sha256",
        "namespace",
        "namespace_device",
        "namespace_inode",
        "boot_id",
        "namespace_path",
        "session",
        "root_manifest",
        "source_snapshot",
    )
    return {k: base[k] for k in keys} | dict(
        contract="SOC_NAMESPACE_CONTROLLER_V1",
        controller=config,
        operation="DNS_DIAGNOSTIC_THEN_ENTER_EXISTING_NAMESPACE_CONTROLLER",
        root_cost=1,
        native_cost=0,
        namespace_create=False,
        namespace_delete=False,
        return_authenticated_private_pty_to_invoking_uid=True,
        controller_caps="E_P_I_A_ZERO_ORIGINAL_ORDINARY_BOUNDING_SET",
        no_new_privs=False,
        reason="LATER_SEPARATE_FRESH_SUDO_NOT_A_DELEGATED_GRANT",
        native=False,
        traffic=True,
        udp_queries=2,
        tcp_queries=1,
        sidecar_analysis_seconds=10,
        install=False,
        arbitrary_command=False,
        request_attempts=1,
        request_wait_seconds=300,
        next_approval="FRESH_NATIVE_REQUEST_BOUND_TO_POST_ENTRY_LEDGER",
        root_claim="/run/soc-agent-dns-<approval_sha256>.claimed",
        root_claim_retained_for_replay_protection=True,
    )


def verify_sources(config: dict):
    body = read_held(Path(config["source_pins"]), owner=os.getuid(), limit=2 * 1024**2)
    if hashlib.sha256(body).hexdigest() != config["source_pins_sha"]:
        raise ValueError("NAMESPACE_CONTROLLER_SOURCE_SNAPSHOT")
    pins = json.loads(body)
    if not isinstance(pins, dict) or not 1 <= len(pins) <= 4096:
        raise ValueError("NAMESPACE_CONTROLLER_SOURCE_BOUND")
    root = Path(config["project"]).resolve(strict=True)
    for name, pin in pins.items():
        path = root / name
        if (
            Path(name).is_absolute()
            or ".." in Path(name).parts
            or path.resolve(strict=True) != path
        ):
            raise ValueError("NAMESPACE_CONTROLLER_SOURCE_PATH")
        if (
            hashlib.sha256(
                read_held(path, owner=os.getuid(), limit=64 * 1024**2, allow_empty=True)
            ).hexdigest()
            != pin
        ):
            raise ValueError("NAMESPACE_CONTROLLER_SOURCE_MUTATION")
    interpreter = Path(config["interpreter"])
    if (
        interpreter.resolve(strict=True) != interpreter
        or hashlib.sha256(interpreter.read_bytes()).hexdigest() != config["interpreter_sha"]
    ):
        raise ValueError("NAMESPACE_CONTROLLER_INTERPRETER_CHANGED")


def child_main(config: dict):
    """Ordinary Namespace Controller; no Root authority FD or privileged import."""
    local_controller()
    verify_sources(config)
    if os.readlink("/proc/self/ns/net") != config["namespace"]:
        raise ValueError("NAMESPACE_CONTROLLER_IDENTITY_CHANGED")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        if channel.getsockopt(socket.SOL_SOCKET, 71, 8).hex() != config["cookie"]:
            raise ValueError("NAMESPACE_CONTROLLER_COOKIE_CHANGED")
    deadline = time.monotonic() + 10
    ack = Path(config["ack"])
    while not ack.exists():
        if time.monotonic() > deadline:
            raise TimeoutError("NAMESPACE_CONTROLLER_SETTLEMENT_NOT_OBSERVED")
        time.sleep(0.05)
    value = json.loads(read_held(ack, owner=os.getuid(), limit=65536))
    from soc_agent.security_ai.ebpf_tc.dns_diagnostic_engine import dns_held_json_ledger

    rows = dns_held_json_ledger(config["ledger"], value["ledger_sha"], os.getuid())
    events = [r for r in rows if r.get("attempt_id") == config["attempt"]]
    if (
        not events
        or events[-1].get("event") != "ROOT_OPERATION_FINISHED_V1"
        or events[-1].get("state") != "SUCCEEDED"
    ):
        raise ValueError("NAMESPACE_CONTROLLER_ENTRY_NOT_SETTLED")
    print(
        "Namespace Controller ready with ordinary credentials. Entry is settled.\n"
        "A NEW exact Native approval request must bind the current Ledger; "
        "old approvals cannot be reused."
    )

    # Bounded operator wait, never background execution on missing input.
    def expired(*_):
        raise TimeoutError("NAMESPACE_CONTROLLER_OPERATOR_TIMEOUT")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(300)
    try:
        pin = input("Enter the newly approved execution-request SHA256, or cancel: ").strip()
        if len(pin) != 64 or bytes.fromhex(pin).hex() != pin:
            return
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    request = held_json(Path(config["request_file"]), pin)
    if any(request.get(k) != v for k, v in config["target"].items()):
        raise ValueError("NAMESPACE_CONTROLLER_EXECUTION_TARGET_CHANGED")
    verify_sources(config)
    from soc_agent.security_ai.ebpf_tc.operational_recovery import main

    args = [
        config["target"]["directory"],
        "--request-file",
        config["request_file"],
        "--request-sha",
        pin,
    ]
    if main(["check", *args]) != 0:
        raise SystemExit(2)
    # Existing execute performs its own non-consuming check, foreground Scope
    # confirmation before reservation and fresh sudo. No reused Root entry grant.
    raise SystemExit(main(["execute", *args]))


def run_packet(mode: str, directory: Path, packet: dict) -> dict:
    local_controller()
    if mode == "prepare":
        if packet.get("kind") != "NAMESPACE_CONTROLLER_PREPARATION_V1":
            raise ValueError("NAMESPACE_CONTROLLER_PACKET")
        config = validate_controller(packet["controller"])
        verify_sources(config)
        return dns_diagnostic.prepare(
            directory,
            package=Path(packet["package"]),
            root_manifest=packet["root_manifest"],
            origin=RootBinding.model_validate(packet["origin"]),
            lease_file=Path(packet["lease_file"]),
            lease_sha=packet["lease_sha"],
            source_snapshot=packet["source_snapshot"],
            plan=ApplicationPlan.model_validate(packet["plan"]),
            controller_config=config,
        )
    if (
        mode not in ("check", "execute")
        or packet.get("kind") != "NAMESPACE_CONTROLLER_EXECUTION_V1"
    ):
        raise ValueError("NAMESPACE_CONTROLLER_PACKET")
    binding = RootBinding.model_validate(packet["binding"])
    from soc_agent.security_ai.ebpf_tc.operational_recovery import source_git_identity

    if source_git_identity() != (binding.artifact.git_commit, binding.artifact.git_tree):
        raise ValueError("NAMESPACE_CONTROLLER_GIT_BINDING")
    metadata = dns_diagnostic.verify(directory, binding)
    config = metadata["config"]
    if (
        config.get("admitted_operation") != "ROOT_DNS_DIAGNOSTIC"
        or controller_scope(config["scope"], config["controller"]) != config["scope"]
    ):
        raise ValueError("NAMESPACE_CONTROLLER_SCOPE")
    verify_sources(config["controller"])
    campaign = RootOperations(Path(packet["campaign"]), binding.batch)
    fields = dict(
        policy_file=Path(packet["policy_file"]),
        policy_sha=packet["policy_sha"],
        approval_file=Path(packet["approval_file"]),
        approval_sha=packet["approval_sha"],
        root_manifest_file=Path(packet["root_manifest_file"]),
        dns_directory=directory,
        dns_lease_file=Path(packet["lease_file"]),
    )
    checked = campaign.check_root(binding, **fields)
    if mode == "check":
        return checked
    policy = held_json(fields["policy_file"], fields["policy_sha"])
    if any(label in policy["approver"].upper() for label in ("FIXTURE", "MOCK", "SCRIPTED")):
        raise ValueError("NAMESPACE_CONTROLLER_FIXTURE_EXECUTION_FORBIDDEN")
    return _execute(directory, packet, binding, config, campaign, fields)


def _execute(directory, packet, binding, config, campaign, fields):
    from soc_agent.security_ai.ebpf_tc.auth_session import open_authentication_tty

    tty = open_authentication_tty(os.getuid())
    started = settled = False
    process = None
    attempt = None
    messages = []
    try:
        print(
            json.dumps(
                dict(
                    purpose="DNS UDP2/TCP1; THEN ORDINARY NAMESPACE CONTROLLER; NO NATIVE GRANT",
                    scope=config["scope"],
                    fresh_later_native_approval_required=True,
                ),
                indent=2,
            )
        )
        try:
            answer = input("Approve exactly this Scope? Type yes; otherwise cancel: ")
        except (EOFError, KeyboardInterrupt):
            answer = "no"
        if answer.strip().lower() != "yes":
            return dict(status="CANCELLED_BEFORE_RESERVATION", reserved=False, executed=False)
        from soc_agent.security_ai.ebpf_tc.operational_recovery import source_git_identity

        if source_git_identity() != (binding.artifact.git_commit, binding.artifact.git_tree):
            raise ValueError("NAMESPACE_CONTROLLER_GIT_CHANGED_AFTER_CONFIRMATION")
        verify_sources(config["controller"])
        event = campaign.reserve_root(binding, **fields)
        attempt = event["attempt_id"]

        def evidence(value):
            body = canonical(value)
            pin = hashlib.sha256(body).hexdigest()
            path = directory / ("controller-evidence-" + pin + ".json")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            return pin

        campaign.record_root(
            attempt,
            state="START_INTENT",
            evidence_sha=evidence(dict(state="OS_AUTHENTICATION_INTENT")),
        )
        envelope = {k: str(fields[k]) for k in ("policy_file", "approval_file")}
        ledger = campaign.directory / "execution-ledger.jsonl"
        envelope.update(
            policy_sha=packet["policy_sha"],
            approval_sha=packet["approval_sha"],
            manifest_file=str(directory / "dns-diagnostic.json"),
            manifest_sha=binding.artifact.manifest,
            image_sha=binding.artifact.image,
            ledger_file=str(ledger),
            ledger_sha=hashlib.sha256(ledger.read_bytes()).hexdigest(),
        )
        process = subprocess.Popen(
            dns_diagnostic.command(directory, binding, envelope),
            stdin=tty,
            stderr=tty,
            stdout=subprocess.PIPE,
            close_fds=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
        messages = []
        ready = None
        deadline = time.monotonic() + 80
        while time.monotonic() < deadline:
            if not select.select(
                [process.stdout], [], [], min(1, max(0, deadline - time.monotonic()))
            )[0]:
                continue
            line = process.stdout.readline(16385)
            if not line:
                break
            if len(line) > 16384 or len(messages) >= 4:
                raise ValueError("NAMESPACE_CONTROLLER_REPLY_BOUND")
            value = json.loads(line)
            messages.append(value)
            if value.get("state") == "DNS_ROOT_AUTHENTICATED":
                started = True
                campaign.record_root(attempt, state="STARTED", evidence_sha=evidence(value))
            if value.get("state") == "NAMESPACE_CONTROLLER_READY":
                ready = value
                break
        if (
            not started
            or ready is None
            or not any(m.get("state") == "DNS_DIAGNOSTIC_COMPLETED" for m in messages)
            or ready.get("uid") != os.getuid()
            or ready.get("namespace") != config["namespace"]
        ):
            raise ValueError("NAMESPACE_CONTROLLER_ENTRY_UNVERIFIED")
        identity = process_identity(ready["pid"])
        if (
            identity.uid != os.getuid()
            or os.readlink(f"/proc/{identity.pid}/ns/net") != config["namespace"]
        ):
            raise ValueError("NAMESPACE_CONTROLLER_CHILD_IDENTITY")
        campaign.record_root(
            attempt,
            state="SUCCEEDED",
            evidence_sha=evidence(
                dict(messages=messages, controller=identity.model_dump(mode="json"))
            ),
        )
        settled = True
        from soc_agent.security_ai.collectors.offload_session import publish

        publish(
            directory / (attempt + ".controller-ack.json"),
            dict(ledger_sha=hashlib.sha256(ledger.read_bytes()).hexdigest()),
        )
        # The Root entry is finished. Only an ordinary Controller remains; its
        # eventual Native reservation/settlement uses the independent old path.
        code = process.wait(timeout=750)
        return dict(
            status="CONTROLLER_EXITED",
            returncode=code,
            root_entry="SUCCEEDED",
            native_result="SEE_SEPARATE_NATIVE_LEDGER",
            automatic_retry=False,
        )
    except BaseException as exc:
        if attempt is not None and not settled:
            campaign.record_root(
                attempt,
                state="FAILED" if started else "UNKNOWN",
                evidence_sha=evidence(dict(error_class=type(exc).__name__, messages=messages)),
            )
        # No retry or arbitrary PID signals. sudo/owned Controller EOF and wall
        # deadlines retain their normal scoped cleanup; unknown is not cancellation.
        raise
    finally:
        if process and process.stdout:
            process.stdout.close()
        os.close(tty)
