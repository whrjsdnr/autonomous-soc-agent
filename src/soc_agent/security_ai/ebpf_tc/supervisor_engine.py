"""SHA-embedded privileged sidecar; stdlib only, no project imports or sudo calls.

No entry point in this file. Only the authenticated, reviewed unified image calls
supervisor_prepare. The original process continues through the existing Bootstrap
proof and privilege drop; the sidecar never inherits Link/object/authority FDs.
"""

import array
import ctypes
import errno
import hashlib
import http.client
import json
import os
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import threading
import time

# Supplied by the SHA-embedded existing installation engine, never project imports.
_open_directory: object
_read: object
_ticks: object
SUPERVISOR_CONFIG: dict
SUPERVISOR_REDUCED: bool
start_inspector: object
INSPECT_QUERY_SECONDS: int

SUP_LIMIT = 16384
SUP_MASK = (1 << 39) | (1 << 12)
SUP_COMMANDS = {"STATUS", "START_ZEEK", "STOP_ZEEK", "STOP"}
SUP_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C"}


def sup_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sup_parent_death(parent):
    """Kernel revokes only our child process if its owning parent disappears."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0):  # PR_SET_PDEATHSIG
        raise OSError(ctypes.get_errno(), "SUPERVISOR_PARENT_DEATH_CONTRACT")
    if os.getppid() != parent:
        raise ValueError("SUPERVISOR_PARENT_CHANGED")


def sup_caps(mask, *, initial=False, execute=False):
    """Never called during preparation/tests except explicit fixture doubles."""
    libc = ctypes.CDLL(None, use_errno=True)

    def prctl(option, a=0, b=0):
        if libc.prctl(option, a, b, 0, 0):
            raise OSError(ctypes.get_errno(), "SUPERVISOR_PRIVILEGE_CONTRACT")

    if initial:
        os.setgroups([])
        for cap in range(int(open("/proc/sys/kernel/cap_last_cap").read()) + 1):
            if not mask & (1 << cap):
                prctl(24, cap)  # PR_CAPBSET_DROP, before losing CAP_SETPCAP.
        prctl(28, 3)  # SECBIT_NOROOT | NOROOT_LOCKED: UID0 exec is not cap gain.
        prctl(4, 0)  # PR_SET_DUMPABLE
    prctl(47, 4)  # PR_CAP_AMBIENT_CLEAR_ALL
    header = (ctypes.c_uint32 * 2)(0x20080522, 0)
    data = (ctypes.c_uint32 * 6)(
        mask & 0xFFFFFFFF if execute else 0,
        mask & 0xFFFFFFFF,
        mask & 0xFFFFFFFF if execute else 0,
        mask >> 32 if execute else 0,
        mask >> 32,
        mask >> 32 if execute else 0,
    )
    if libc.capset(header, data):
        raise OSError(ctypes.get_errno(), "SUPERVISOR_CAPSET")
    if execute:
        for cap in (12, 21, 39):
            if mask & (1 << cap):
                prctl(47, 2, cap)  # Ambient scope for this fixed inspected tool.
    prctl(38, 1)  # NO_NEW_PRIVS, including Docker client (not daemon).


def sup_execute(command, mask, *, descriptor=None):
    # No user-supplied argv, executable or environment enters this helper.
    process = sup_tool(command, mask, descriptor=descriptor)
    output = bytearray()
    deadline = time.monotonic() + 5
    try:
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError("SUPERVISOR_QUERY_TIMEOUT")
            if not select.select([process.stdout], [], [], 0.05)[0]:
                continue
            part = os.read(process.stdout.fileno(), 4096)
            if not part:
                break
            output.extend(part)
            if len(output) > SUP_LIMIT:
                raise ValueError("SUPERVISOR_QUERY_OUTPUT_BOUND")
        code = process.wait(timeout=1)
        if code:
            raise ValueError(f"SUPERVISOR_QUERY_FAILED:{code}:{bytes(output)[:512]!r}")
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()  # Only our bounded query process, never a Kernel object.
            process.wait(timeout=2)
        process.stdout.close()


def sup_inventory(config, *, mask=SUP_MASK, allow_existing=False):
    results = {}
    global SUP_ENTRY_STAGE
    for name, args in (
        ("programs", [config["bpftool"], "-j", "prog", "show"]),
        ("maps", [config["bpftool"], "-j", "map", "show"]),
        ("links", [config["bpftool"], "-j", "link", "show"]),
        ("ingress", [config["tc"], "-j", "filter", "show", "dev", "lo", "ingress"]),
        ("egress", [config["tc"], "-j", "filter", "show", "dev", "lo", "egress"]),
    ):
        SUP_ENTRY_STAGE = "RESOURCE_INSPECTION_" + name.upper()
        query_mask = mask
        if mask & (1 << 21):
            query_mask = (1 << 21) if name in {"programs", "maps", "links"} else 0
        body = sup_execute(args, query_mask)
        rows = json.loads(body)
        if (
            not isinstance(rows, list)
            or len(rows) > 128
            or any(not isinstance(row, dict) or "error" in row for row in rows)
            or name in {"programs", "maps", "links"}
            and any(type(row.get("id")) is not int or row["id"] <= 0 for row in rows)
        ):
            raise ValueError("SUPERVISOR_INVENTORY_SCHEMA")
        results[name] = dict(rows=rows, sha256=hashlib.sha256(body).hexdigest())
    if not allow_existing:
        sup_require_clear(results)
    return results


def sup_require_clear(results):
    if results["ingress"]["rows"] or results["egress"]["rows"]:
        raise ValueError("SUPERVISOR_FOREIGN_FILTER_REVIEW_REQUIRED")
    # Initial qualification admits no existing Link: avoid guessing tool-specific
    # TCX field layouts or treating an unknown Link as ours. Never delete it.
    if results["links"]["rows"]:
        raise ValueError("SUPERVISOR_EXISTING_LINK_REVIEW_REQUIRED")


def sup_validate_request(request, expected_sequence, binding):
    if (
        not isinstance(request, dict)
        or set(request) != {"command", "sequence", "binding", "data"}
        or type(request["sequence"]) is not int
        or request["sequence"] != expected_sequence
        or request["binding"] != binding
        or not isinstance(request["command"], str)
        or request["command"] not in SUP_COMMANDS
        or not isinstance(request["data"], dict)
        or (request["command"] != "START_ZEEK" and request["data"])
    ):
        raise ValueError("SUPERVISOR_REQUEST_REJECTED")
    return request["command"]


def sup_identities(rows, fields):
    return sorted(
        tuple(json.dumps(row.get(field), sort_keys=True) for field in fields) for row in rows
    )


class SupervisorCore:
    """Same lifecycle used by Native sidecar and ordinary-user fault fixtures."""

    def __init__(self, ops, binding, before):
        self.ops, self.binding, self.before = ops, binding, before
        self.sequence = 0
        self.state = "TCX_READY"
        self.started = self.closed = False
        self.stop_attempted = False
        self.error = None
        self.chain = "0" * 64
        self.cleanup_errors = []

    def dispatch(self, request):
        command = sup_validate_request(request, self.sequence + 1, self.binding)
        self.sequence += 1
        fd = None
        if self.closed:
            raise ValueError("SUPERVISOR_SESSION_CLOSED")
        try:
            if command == "START_ZEEK":
                if self.started or self.error:
                    raise ValueError("SUPERVISOR_NO_RESTART")
                self.started = True  # A failed start also consumes the attempt.
                fd = self.ops.start(request["data"])
                self.state = (
                    "ZEEK_READY"  # Process prepared; stream READY is verified by the user adapter.
                )
            elif command in {"STOP_ZEEK", "STOP"}:
                self.stop_once()
                self.state = "STOPPING" if command == "STOP" else "TCX_READY"
                self.closed = command == "STOP"
            status = self.ops.status()
        except (OSError, ValueError, TimeoutError) as exc:
            self.error = str(exc)
            if command in {"STOP", "STOP_ZEEK"}:
                self.cleanup_errors.append(str(exc))
            self.state = "ERROR"
            status = {"error": self.error}
        result = dict(
            sequence=self.sequence,
            binding=self.binding,
            state=self.state,
            status=status,
            error=self.error,
            previous=self.chain,
        )
        self.chain = hashlib.sha256(sup_json(result)).hexdigest()
        result["digest"] = self.chain
        return result, fd

    def stop_once(self):
        if not self.stop_attempted:
            self.stop_attempted = True
            self.ops.stop()

    def finish(self):
        failures = list(self.cleanup_errors)
        try:
            self.stop_once()
        except (OSError, ValueError, TimeoutError) as exc:
            failures.append(str(exc))
        try:
            self.ops.quiesce()
        except (OSError, ValueError, TimeoutError) as exc:
            failures.append(str(exc))
        try:
            # IPC to the already isolated Inspector forks no helper in this process.
            # Preserve stream failure but still obtain independent resource evidence.
            after = self.ops.inspect()
            # Compare foreign identities; unrelated concurrent changes are not
            # silently attributed to us or removed to make this pass.
            for key, fields in {
                "programs": ("id", "type", "tag", "map_ids"),
                "maps": ("id", "type", "name"),
                "links": ("id", "type", "prog_id", "ifindex", "netns_ino"),
                "ingress": ("kind", "protocol", "pref", "chain", "options"),
                "egress": ("kind", "protocol", "pref", "chain", "options"),
            }.items():
                if sup_identities(after[key]["rows"], fields) != sup_identities(
                    self.before[key]["rows"], fields
                ):
                    failures.append("SUPERVISOR_RESOURCE_SET_CHANGED:" + key)
        except (OSError, ValueError, TimeoutError) as exc:
            after = None
            failures.append(str(exc))
        try:
            self.ops.close()
        except (OSError, ValueError, TimeoutError) as exc:
            failures.append(str(exc))
        self.closed = True
        self.state = "CLOSED" if not failures else "ERROR"
        return dict(
            state=self.state,
            cleanup="VERIFIED" if not failures else "CLEANUP_UNVERIFIED",
            failures=failures,
            first_error=self.error,
            after=after,
            inspector_exit=getattr(getattr(self.ops, "inspector", None), "exit_evidence", None),
            native_ai="BLOCKED",
            dns9="BLOCKED",
        )


def sup_alive(pid, ticks, uid=None):
    try:
        status = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return (
            status[0] not in {"Z", "X"}
            and int(status[19]) == ticks
            and (uid is None or os.stat(f"/proc/{pid}").st_uid == uid)
        )
    except (OSError, ValueError):
        return False


def sup_validate_plan(plan, config, namespace):
    expected = {
        "contract",
        "session_id",
        "controller_generation",
        "image",
        "interface",
        "duration_seconds",
        "cpu_limit",
        "memory_mib",
        "disk_mib",
        "output_bytes",
        "queue_capacity",
        "packet_limit",
        "event_limit",
        "net_namespace",
        "bundle_digest",
        "capture_integrity",
        "native_inference",
    }
    if set(plan) != expected or any(
        (plan.get(key) != value or type(plan.get(key)) is not type(value))
        for key, value in config["zeek_scope"].items()
    ):
        raise ValueError("SUPERVISOR_ZEEK_SCOPE")
    if plan["net_namespace"] != namespace:
        raise ValueError("SUPERVISOR_ZEEK_NAMESPACE")
    # Names are UUID hex only, never paths or Docker argument fragments.
    from uuid import UUID

    for key in ("session_id", "controller_generation"):
        if not isinstance(plan[key], str):
            raise ValueError("SUPERVISOR_ZEEK_UUID")
        UUID(plan[key])
    return hashlib.sha256(sup_json(plan)).hexdigest()


def sup_executable(path):
    row = globals()["SUPERVISOR_CONFIG"]["tools"][path]
    if row["mode"] & 0o7022:
        raise ValueError("SUPERVISOR_TOOL_PRIVILEGED_OR_MUTABLE_MODE")
    directory, name = path.rsplit("/", 1)
    parent = globals()["_open_directory"](directory, 0)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            globals()["_read"](fd, 0, row["mode"], row["sha256"], 64 * 1024**2)
            try:
                os.getxattr(fd, "security.capability")
            except OSError as exc:
                if exc.errno != errno.ENODATA:
                    raise
            else:
                raise ValueError("SUPERVISOR_TOOL_FILE_CAPABILITIES_FORBIDDEN")
        except BaseException:
            os.close(fd)
            raise
        return fd
    finally:
        os.close(parent)


def sup_tool(command, mask, *, pipe=None, descriptor=None):
    parent = os.getpid()

    def prepare_tool():
        try:
            sup_parent_death(parent)
            sup_caps(mask, initial=not SUPERVISOR_REDUCED, execute=True)
        except OSError as exc:
            # subprocess otherwise replaces preexec errno with SubprocessError.
            if globals().get("SUP_ENTRY_ENVELOPE") is not None:
                try:
                    sup_entry_failure(globals()["SUP_ENTRY_ENVELOPE"], exc)
                except OSError:
                    print("SOC_ENTRY_DIAGNOSTIC_DELIVERY_FAILED", flush=True)
            raise

    fd = sup_executable(command[0]) if descriptor is None else os.dup(descriptor)
    try:
        return subprocess.Popen(
            [f"/proc/self/fd/{fd}", *command[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if pipe is None else pipe,
            stderr=subprocess.STDOUT if pipe is None else subprocess.DEVNULL,
            close_fds=True,
            pass_fds=(fd,),
            env=SUP_ENV,
            preexec_fn=prepare_tool,
        )
    finally:
        os.close(fd)


class DockerAPI:
    """Fixed local daemon, bounded bodies, no CLI/config/context/helper execution."""

    def __init__(self, expected_peer=None):
        self.expected_peer = expected_peer
        self.peer = None

    def connect(self, timeout=5):
        descriptor = os.stat("/run/docker.sock", follow_symlinks=False)
        if not stat.S_ISSOCK(descriptor.st_mode) or descriptor.st_uid or descriptor.st_mode & 2:
            raise ValueError("SUPERVISOR_DOCKER_SOCKET_TRUST")
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        channel.settimeout(timeout)
        try:
            channel.connect("/run/docker.sock")
            pid, uid, gid = struct.unpack(
                "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if uid != 0:
                raise ValueError("SUPERVISOR_DOCKER_PEER")
            self.peer = (pid, globals()["_ticks"](pid))
            if self.expected_peer is not None and tuple(self.expected_peer) != self.peer:
                raise ValueError("SUPERVISOR_DOCKER_DAEMON_RESTARTED")
        except BaseException:
            channel.close()
            raise
        connection = http.client.HTTPConnection("localhost", timeout=timeout)
        connection.sock = channel
        return connection

    def request(self, method, path, data=None, *, stream=False):
        connection = self.connect(5)
        channel = connection.sock
        try:
            body = None if data is None else sup_json(data)
            if body is not None and len(body) > SUP_LIMIT:
                raise ValueError("SUPERVISOR_DOCKER_REQUEST_BOUND")
            api_path = path if path == "/version" else "/v1.51" + path
            connection.request(method, api_path, body, {"Content-Type": "application/json"})
            response = connection.getresponse()
            if response.status not in {200, 201, 204, 304}:
                detail = response.read(1024).decode(errors="replace")
                raise ValueError(f"SUPERVISOR_DOCKER_API:{response.status}:{detail}")
            if stream:
                channel.settimeout(305)  # Bound idle capture after a bounded header handshake.
                connection.supervisor_socket = channel
                return connection, response
            body = response.read(SUP_LIMIT + 1)
            if len(body) > SUP_LIMIT:
                raise ValueError("SUPERVISOR_DOCKER_RESPONSE_BOUND")
            try:
                return json.loads(body) if body else None
            except (TypeError, ValueError) as exc:
                raise ValueError("SUPERVISOR_DOCKER_JSON_SCHEMA") from exc
        except http.client.HTTPException as exc:
            raise ValueError("SUPERVISOR_DOCKER_HTTP_FAILURE") from exc
        finally:
            if not stream or "response" not in locals() or response.status != 200:
                connection.close()


class DaemonCapture:
    def __init__(self, api, identity, write_fd):
        self.api, self.identity, self.write_fd = api, identity, write_fd
        self.error = None
        self.output_bytes = 0
        self.connection, self.response = api.request(
            "POST", f"/containers/{identity}/attach?stream=1&stdout=1&stderr=0", stream=True
        )
        self.worker = threading.Thread(target=self.consume, name="bounded-zeek-metadata")
        self.worker.start()

    def consume(self):
        try:
            os.set_blocking(self.write_fd, False)
            while header := self.response.read(8):
                if len(header) != 8 or header[:4] != bytes([1, 0, 0, 0]):
                    raise ValueError("SUPERVISOR_DOCKER_STREAM_FRAME")
                size = struct.unpack(">I", header[4:])[0]
                if size > 65536:
                    raise ValueError("SUPERVISOR_DOCKER_STREAM_FRAME_BOUND")
                part = self.response.read(size)
                if len(part) != size:
                    raise ValueError("SUPERVISOR_DOCKER_STREAM_TRUNCATED")
                self.output_bytes += size
                if self.output_bytes > 8388608:
                    raise ValueError("SUPERVISOR_ZEEK_OUTPUT_BOUND")
                offset = 0
                deadline = time.monotonic() + 1
                while offset < len(part):
                    if time.monotonic() > deadline:
                        raise ValueError("SUPERVISOR_ZEEK_BACKPRESSURE_CAPTURE_GAP")
                    if select.select([], [self.write_fd], [], 0.05)[1]:
                        offset += os.write(self.write_fd, part[offset:])
        except (OSError, ValueError, TimeoutError, http.client.HTTPException) as exc:
            self.error = str(exc)
        finally:
            os.close(self.write_fd)
            self.response.close()
            self.connection.close()

    def close(self):
        self.worker.join(timeout=5)
        if self.worker.is_alive():
            channel = getattr(self.connection, "supervisor_socket", None)
            if channel is not None:
                try:
                    channel.shutdown(socket.SHUT_RDWR)  # Own attach transport only.
                except OSError:
                    pass
            self.connection.close()
            self.worker.join(timeout=1)
            if self.worker.is_alive():
                raise ValueError("SUPERVISOR_ZEEK_STREAM_CLOSE_UNVERIFIED")


def sup_container(plan, config, policy, identity):
    command = config["zeek_argv"][-3].replace("@NAMESPACE@", plan["net_namespace"])
    return dict(
        Image=config["zeek_scope"]["image"],
        User="0:0",
        WorkingDir="/work",
        Entrypoint=["/bin/sh"],
        Cmd=["-c", command, "soc-zeek", plan["net_namespace"]],
        Labels={"soc.plan": identity, "soc.generation": plan["controller_generation"]},
        AttachStdout=True,
        AttachStderr=False,
        Tty=False,
        OpenStdin=False,
        StopSignal="SIGINT",
        StopTimeout=2,
        HostConfig=dict(
            NetworkMode="host",
            CapDrop=["ALL"],
            CapAdd=["NET_RAW"],
            ReadonlyRootfs=True,
            SecurityOpt=["no-new-privileges"],
            Memory=536870912,
            MemorySwap=536870912,
            NanoCpus=1000000000,
            PidsLimit=64,
            AutoRemove=False,
            RestartPolicy={"Name": "no", "MaximumRetryCount": 0},
            LogConfig={"Type": "none"},
            Tmpfs={"/work": "rw,noexec,nosuid,nodev,size=16m,mode=1777"},
            Ulimits=[{"Name": "fsize", "Soft": 8388608, "Hard": 8388608}],
            Mounts=[
                dict(
                    Type="bind", Source=policy + "/" + name, Target="/policy/" + name, ReadOnly=True
                )
                for name in config["scripts"]
            ],
        ),
    )


class RootOperations:
    def __init__(self, config, namespace, session, inspector):
        self.inspector = inspector
        self.config, self.namespace = config, namespace
        self.api = DockerAPI(config.get("daemon_peer"))
        self.capture = None
        self.plan = self.name = self.identity = None
        self.policy = None
        self.started = self.stopped = self.attempted = False
        self.exit_code = None

    def inspect(self):
        return self.inspector.snapshot()

    def owned(self):
        if self.identity is None:
            raise ValueError("SUPERVISOR_CONTAINER_ID_UNKNOWN")
        row = self.api.request("GET", f"/containers/{self.identity}/json")
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("Config"), dict)
            or not isinstance(row.get("State"), dict)
            or not isinstance(row["Config"].get("Labels"), dict)
            or row.get("Id") != self.identity
            or row["Config"].get("Image") != self.config["zeek_scope"]["image"]
            or row["Config"]["Labels"].get("soc.plan")
            != hashlib.sha256(sup_json(self.plan)).hexdigest()
            or row["Config"]["Labels"].get("soc.generation") != self.plan["controller_generation"]
        ):
            raise ValueError("SUPERVISOR_CONTAINER_OWNERSHIP_UNVERIFIED")
        return row

    def start(self, plan):
        identity = sup_validate_plan(plan, self.config, self.namespace)
        from uuid import UUID

        self.plan = plan
        self.name = "soc-zeek-" + UUID(plan["session_id"]).hex
        # Docker create is atomic NOREPLACE for the name. A 409 is never adopted.
        self.policy = sup_policy(UUID(plan["session_id"]).hex, self.config["scripts"])
        self.attempted = True
        row = self.api.request(
            "POST",
            "/containers/create?name=" + self.name,
            sup_container(plan, self.config, self.policy, identity),
        )
        candidate = row.get("Id")
        if (
            not isinstance(candidate, str)
            or len(candidate) != 64
            or any(c not in "0123456789abcdef" for c in candidate)
        ):
            raise ValueError("SUPERVISOR_CONTAINER_ID_SCHEMA")
        self.identity = candidate
        self.owned()
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        try:
            self.capture = DaemonCapture(self.api, self.identity, write_fd)
            write_fd = -1  # Capture owns the only writer after construction.
            self.api.request("POST", f"/containers/{self.identity}/start")
            self.started = True
        except BaseException:
            os.close(read_fd)
            raise
        finally:
            if write_fd >= 0:
                os.close(write_fd)
        return read_fd

    def status(self):
        if self.identity and not self.stopped:
            row = self.owned()
            if not row["State"]["Running"] and self.started:
                self.exit_code = row["State"]["ExitCode"]
        if self.capture and self.capture.error:
            raise ValueError(self.capture.error)
        return dict(
            zeek_exit=self.exit_code,
            zeek_started=self.started,
            zeek_stopped=self.stopped,
            clock_domains="SEPARATE_TCX_MONOTONIC_ZEEK_EVENT",
            counter_scope="SEPARATE_NO_CROSS_COLLECTOR_ATTESTATION",
        )

    def stop(self):
        if self.stopped:
            return
        if self.attempted and not self.identity:
            # Ambiguous create response: never adopt/delete a name-only container.
            raise ValueError("SUPERVISOR_CONTAINER_CREATE_CLEANUP_UNVERIFIED")
        if self.identity:
            row = self.owned()
            if row["State"]["Running"]:
                self.api.request("POST", f"/containers/{self.identity}/stop?t=2")
                row = self.owned()
            if row["State"]["Running"]:
                raise ValueError("SUPERVISOR_CONTAINER_STOP_UNVERIFIED")
            self.exit_code = row["State"]["ExitCode"]
            if self.capture:
                self.capture.close()
            # Exact created ID + verified immutable labels + stopped state only.
            self.api.request("DELETE", f"/containers/{self.identity}?v=0&force=0")
        self.stopped = True

    def quiesce(self):
        # No fork/preexec helper is started while the metadata thread is active.
        # This also runs after a failed container stop; it affects only our pipe.
        if self.capture:
            self.capture.close()

    def close(self):
        errors = []
        try:
            if self.policy and self.stopped:
                parent = globals()["_open_directory"](self.policy, 0)
                try:
                    for name in self.config["scripts"]:
                        os.unlink(name, dir_fd=parent)
                finally:
                    os.close(parent)
                os.rmdir(self.policy)
                self.policy = None
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
        try:
            self.inspector.close()
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
        if errors:
            raise ValueError("SUPERVISOR_CLOSE_UNVERIFIED:" + ";".join(errors))


def sup_policy(session, scripts):
    """Only fixed embedded scripts, a fresh root-owned directory, no caller paths."""
    import base64

    parent = globals()["_open_directory"]("/run", 0)
    try:
        try:
            os.mkdir("soc-agent-ebpf", 0o700, dir_fd=parent)
        except FileExistsError:
            pass
    finally:
        os.close(parent)
    parent = globals()["_open_directory"]("/run/soc-agent-ebpf", 0)
    try:
        os.mkdir(session, 0o700, dir_fd=parent)  # Existing session is never reused.
    finally:
        os.close(parent)
    path = "/run/soc-agent-ebpf/" + session
    parent = globals()["_open_directory"](path, 0)
    created = []
    try:
        for name, row in scripts.items():
            if name not in {"live.zeek", "network14.zeek", "visibility.zeek"}:
                raise ValueError("SUPERVISOR_POLICY_ALLOWLIST")
            body = base64.b64decode(row["body"], validate=True)
            if hashlib.sha256(body).hexdigest() != row["sha256"]:
                raise ValueError("SUPERVISOR_POLICY_SHA")
            fd = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444, dir_fd=parent
            )
            created.append(name)
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
    except BaseException:
        # This invocation exclusively created the directory; never recurse or
        # remove pre-existing files/directories on collision.
        for name in created:
            os.unlink(name, dir_fd=parent)
        os.rmdir(path)
        raise
    finally:
        os.close(parent)
    return path


def sup_receive(channel, peer):
    body, ancillary, flags, _ = channel.recvmsg(
        SUP_LIMIT, socket.CMSG_SPACE(64), socket.MSG_CMSG_CLOEXEC
    )
    credentials, bad = [], False
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            fds = array.array("i")
            fds.frombytes(data[: len(data) - len(data) % fds.itemsize])
            for fd in fds:
                os.close(fd)
            bad = True
        elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == 12:
            credentials.append(struct.unpack("3i", data))
        else:
            bad = True
    if not body or bad or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or credentials != [peer]:
        raise ValueError("SUPERVISOR_PEER_OR_MESSAGE")
    return json.loads(body)


def sup_send(channel, value, fd=None):
    body = sup_json(value)
    if len(body) > SUP_LIMIT:
        raise ValueError("SUPERVISOR_REPLY_BOUND")
    ancillary = (
        [] if fd is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))]
    )
    try:
        if channel.sendmsg([body], ancillary) != len(body):
            raise ValueError("SUPERVISOR_SHORT_SEND")
    finally:
        if fd is not None:
            os.close(fd)


def sup_entry_failure(envelope, exc):
    """Diagnostic only: no credentials, command strings, paths or exception text."""
    code = str(exc).split(":", 1)[0] if isinstance(exc, ValueError) else type(exc).__name__.upper()
    if (
        not code
        or len(code) > 80
        or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789" for c in code)
    ):
        code = "ENTRY_EXCEPTION"
    evidence = dict(
        contract="SOC_ENTRY_DIAGNOSTIC_V1",
        stage=globals().get("SUP_ENTRY_STAGE", "SUPERVISOR_PREPARE"),
        code=code,
        errno=exc.errno if isinstance(exc, OSError) else None,
        native_actions_started=False,
    )
    uid = struct.unpack_from("<I", envelope, 4)[0]
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(0.5)
        channel.connect(f"\0soc-entry-diagnostic.{uid}.{envelope[64:80].hex()}")
        channel.sendall(sup_json(evidence))


def supervisor_prepare(image, envelope, approval, environment):
    global SUP_ENTRY_STAGE
    SUP_ENTRY_STAGE = "RESOURCE_INSPECTION"
    globals()["SUP_ENTRY_ENVELOPE"] = envelope
    try:
        return _supervisor_prepare(image, envelope, approval, environment)
    except Exception as exc:
        try:
            sup_entry_failure(envelope, exc)
        except OSError:
            # Reporting cannot replace the original failure or authorize execution.
            print("SOC_ENTRY_DIAGNOSTIC_DELIVERY_FAILED", flush=True)
        raise


def _supervisor_prepare(image, envelope, approval, environment):
    # Called only after existing OS parent/policy, scope and installed-release checks.
    # Query failure prevents Bootstrap exec and therefore any BPF load/attach.
    global SUPERVISOR_REDUCED
    SUPERVISOR_REDUCED = False
    config = globals()["SUPERVISOR_CONFIG"]
    globals()["SUP_ENTRY_STAGE"] = "DOCKER_PREFLIGHT"
    api = DockerAPI()
    version = api.request("GET", "/version")
    if not isinstance(version, dict):
        raise ValueError("SUPERVISOR_DOCKER_VERSION_SCHEMA")

    def api_tuple(value):
        if not isinstance(value, str) or len(value.split(".")) != 2:
            raise ValueError("SUPERVISOR_DOCKER_API_VERSION")
        return tuple(int(part) for part in value.split("."))

    if (
        not api_tuple(version.get("MinAPIVersion"))
        <= (1, 51)
        <= api_tuple(version.get("ApiVersion"))
    ):
        raise ValueError("SUPERVISOR_DOCKER_API_UNSUPPORTED")
    if os.readlink(f"/proc/{api.peer[0]}/ns/net") != os.readlink("/proc/self/ns/net"):
        raise ValueError("SUPERVISOR_DOCKER_NAMESPACE")
    config["daemon_peer"] = list(api.peer)
    pid = os.getpid()
    broker_ticks = globals()["_ticks"](pid)
    uid, gid, controller = struct.unpack_from("<III", envelope, 4)
    ticks = struct.unpack_from("<Q", envelope, 16)[0]
    session = envelope[64:80].hex()
    namespace = "net:[" + str(struct.unpack_from("<Q", envelope, 24)[0]) + "]"
    binding = hashlib.sha256(b"SOC_SUPERVISOR_V1\0" + approval + envelope).hexdigest()
    globals()["SUP_ENTRY_STAGE"] = "SIDECAR_PREPARE"
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    child = os.fork()
    if child == 0:
        globals()["SUP_ENTRY_ENVELOPE"] = None  # Later cleanup queries are not entry failures.
        os.close(read_fd)
        # No object, journal, Link or authority FD exists at fork. Keep only ready pipe.
        os.dup2(write_fd, 3, inheritable=False)
        if write_fd != 3:
            os.close(write_fd)
        os.closerange(4, 1048576)
        channel = None
        core = None
        final = None
        inspector = None
        try:
            # Fork before reduction: no capability restoration or second sudo call.
            inspector = globals()["start_inspector"](
                config, binding, namespace, (controller, ticks, uid)
            )
            sup_caps(SUP_MASK, initial=True)
            SUPERVISOR_REDUCED = True
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
            resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            before = inspector.snapshot()
            sup_require_clear(before)  # Inspect first; never authorize an existing/unknown Hook.
            channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            channel.settimeout(2)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            channel.connect(f"\0soc-supervisor.{uid}.{session}")
            peer = struct.unpack(
                "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if peer != (controller, uid, gid):
                raise ValueError("SUPERVISOR_CONTROLLER_PEER")
            hello = dict(
                binding=binding,
                pid=os.getpid(),
                ticks=globals()["_ticks"](os.getpid()),
                before=before,
                state="RESOURCE_VERIFIED",
                capabilities="E0_P_BPF_NETADMIN_I0_A0",
                inspector=inspector.hello,
            )
            sup_send(channel, hello)
            os.write(3, b"1")
            os.close(3)
            core = SupervisorCore(
                RootOperations(config, namespace, session, inspector), binding, before
            )
            deadline, window, count = inspector.started + 300, time.monotonic(), 0
            stopping = []
            signal.signal(signal.SIGTERM, lambda *_: stopping.append("SIGTERM"))
            signal.signal(signal.SIGINT, lambda *_: stopping.append("SIGINT"))
            while not core.closed and not stopping and time.monotonic() < deadline:
                if not sup_alive(controller, ticks, uid) or not sup_alive(pid, broker_ticks):
                    break
                if not select.select([channel], [], [], 0.1)[0]:
                    continue
                if time.monotonic() - window >= 1:
                    window, count = time.monotonic(), 0
                count += 1
                if count > 32:
                    raise ValueError("SUPERVISOR_RATE_BOUND")
                request = sup_receive(channel, peer)
                response, fd = core.dispatch(request)
                sup_send(channel, response, fd)
                if core.error:
                    break
        except (OSError, ValueError, TimeoutError) as exc:
            if core is None:
                try:
                    sup_entry_failure(envelope, exc)
                except OSError:
                    print("SOC_ENTRY_DIAGNOSTIC_DELIVERY_FAILED", flush=True)
            final = dict(error=str(exc), cleanup="CLEANUP_UNVERIFIED")
        finally:
            if core:
                # TCX's existing IPC/controller watcher owns its cleanup. Wait for
                # that FD-owning process; never detach a Link by a global ID.
                until = time.monotonic() + 6
                while sup_alive(pid, broker_ticks) and time.monotonic() < until:
                    time.sleep(0.05)
                cleanup = core.finish()
                final = dict(final or {}, **cleanup)
            elif inspector:
                try:
                    inspector.close()
                except (OSError, ValueError) as exc:
                    final = dict(
                        final or {}, inspector_error=str(exc), cleanup="CLEANUP_UNVERIFIED"
                    )
            if channel:
                try:
                    sup_send(channel, dict(final=final, binding=binding))
                except (OSError, ValueError):
                    pass  # Peer may have crashed; never claim delivery in that case.
                channel.close()
            os._exit(0 if final and final.get("cleanup") == "VERIFIED" else 2)
    os.close(write_fd)
    try:
        if (
            not select.select([read_fd], [], [], globals()["INSPECT_QUERY_SECONDS"] + 2)[0]
            or os.read(read_fd, 1) != b"1"
        ):
            raise ValueError("SUPERVISOR_PREPARE_FAILED")
    finally:
        os.close(read_fd)
