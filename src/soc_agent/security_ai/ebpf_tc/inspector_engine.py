"""SHA-embedded, session-limited inspector. No entry point or authentication API.

Only start_inspector's explicit Root path forks or changes capabilities. The same
InspectorCore/transport runs with ordinary fixture doubles in tests.
"""

import os
import resource
import select
import signal
import socket
import time

# These fixed helpers are supplied by the reviewed, concatenated Supervisor image.
sup_caps: object
sup_inventory: object
sup_receive: object
sup_send: object
sup_json: object
sup_alive: object
_ticks: object

INSPECT_MASK = 1 << 21  # SYS_ADMIN: global BPF IDs; fixed tc GET helpers need no capability.
INSPECT_LIFETIME = 330  # <=300s active including preparation, <=30s final inspection/exit.
INSPECT_QUERY_SECONDS = 28  # Five fixed <=5s tool calls, plus bounded IPC overhead.
INSPECT_PROFILE = dict(
    contract="READ_ONLY_SESSION_INSPECTOR_V1",
    capabilities=["CAP_SYS_ADMIN"],
    idle_effective_inheritable_ambient="ZERO",
    commands=["SNAPSHOT", "STOP"],
    snapshots=2,
    lifetime_seconds=330,
    address_space_mib=256,
    cpu_seconds=20,
    authority_transfer="FORBIDDEN",
    bpftool_without_skeletons=True,
)


def inspector_caps(pid="self"):
    with open(f"/proc/{pid}/status") as stream:
        rows = stream.read().splitlines()
    names = {"CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"}
    return {
        key: int(value.strip(), 16)
        for row in rows
        if ":" in row
        for key, value in [row.split(":", 1)]
        if key in names
    }


def inspector_expected_caps():
    return dict(CapEff=0, CapPrm=INSPECT_MASK, CapInh=0, CapAmb=0, CapBnd=INSPECT_MASK)


class InspectorCore:
    """Exactly two snapshots and STOP; failed snapshots consume the phase too."""

    def __init__(self, binding, namespace, query, scope):
        self.binding, self.namespace, self.query, self.scope = binding, namespace, query, scope
        self.sequence = self.snapshots = 0
        self.failed = self.closed = False

    def dispatch(self, request):
        if (
            not isinstance(request, dict)
            or set(request) != {"binding", "sequence", "command"}
            or request["binding"] != self.binding
            or type(request["sequence"]) is not int
            or request["sequence"] != self.sequence + 1
            or self.sequence >= 3
            or self.closed
            or request["command"] not in ("SNAPSHOT", "STOP")
        ):
            raise ValueError("INSPECTOR_REQUEST_REJECTED")
        self.sequence += 1
        result = dict(binding=self.binding, sequence=self.sequence, command=request["command"])
        if request["command"] == "STOP":
            self.closed = True
            return result | dict(state="CLOSED")
        if self.failed or self.snapshots >= 2:
            raise ValueError("INSPECTOR_NO_RETRY")
        phase = "BEFORE" if self.snapshots == 0 else "AFTER"
        self.snapshots += 1
        try:
            if self.scope() != (self.namespace, 1):
                raise ValueError("INSPECTOR_SCOPE_CHANGED")
            evidence = self.query()
            return result | dict(phase=phase, evidence=evidence)
        except Exception:
            self.failed = True
            raise


class InspectorClient:
    """Private inherited socket only; never exposed to GUI or Broker IPC."""

    def __init__(self, channel, pid, ticks, binding, hello, started):
        self.channel, self.pid, self.ticks = channel, pid, ticks
        self.binding, self.hello, self.started = binding, hello, started
        self.sequence = self.snapshots = 0
        self.closed = False
        self.exit_evidence = None

    def request(self, command):
        if self.closed or command not in ("SNAPSHOT", "STOP"):
            raise ValueError("INSPECTOR_CLIENT_COMMAND")
        if not globals()["sup_alive"](self.pid, self.ticks, 0):
            raise ValueError("INSPECTOR_PROCESS_CHANGED")
        self.sequence += 1
        globals()["sup_send"](
            self.channel, dict(binding=self.binding, sequence=self.sequence, command=command)
        )
        value = globals()["sup_receive"](self.channel, (self.pid, 0, 0))
        if (
            value.get("binding") != self.binding
            or value.get("sequence") != self.sequence
            or value.get("command") != command
        ):
            raise ValueError("INSPECTOR_RESPONSE_BINDING")
        if "error" in value:
            error = value["error"]
            globals()["SUP_ENTRY_STAGE"] = error.get("stage") or "INSPECTOR_QUERY"
            if error.get("errno") is not None:
                raise OSError(error["errno"], error["code"])
            raise ValueError(error["code"])
        return value

    def snapshot(self):
        phase = "BEFORE" if self.snapshots == 0 else "AFTER"
        self.snapshots += 1
        value = self.request("SNAPSHOT")
        if value.get("phase") != phase or not isinstance(value.get("evidence"), dict):
            raise ValueError("INSPECTOR_RESPONSE_PHASE")
        return value["evidence"]

    def close(self):
        if self.closed:
            return self.exit_evidence
        failure = None
        try:
            if self.request("STOP").get("state") != "CLOSED":
                raise ValueError("INSPECTOR_STOP_UNVERIFIED")
        except (OSError, ValueError, EOFError) as exc:
            failure = type(exc).__name__
        finally:
            self.closed = True
            self.channel.close()  # EOF also revokes a failed worker's session.
        until = time.monotonic() + 2
        status = None
        while time.monotonic() < until:
            child, value = os.waitpid(self.pid, os.WNOHANG)
            if child:
                status = os.waitstatus_to_exitcode(value)
                break
            time.sleep(0.02)
        self.exit_evidence = dict(
            pid=self.pid,
            start_ticks=self.ticks,
            exit_code=status,
            channel_closed=True,
            authority_revoked=status is not None,
            cleanup="VERIFIED" if status == 0 and not failure else "CLEANUP_UNVERIFIED",
        )
        if status != 0 or failure:
            raise ValueError("INSPECTOR_EXIT_UNVERIFIED")
        return self.exit_evidence


def inspector_loop(channel, config, binding, namespace, parent, controller, started):
    """Root worker, only called after an explicit authenticated image fork."""
    globals()["sup_parent_death"](parent[0])
    globals()["sup_caps"](INSPECT_MASK, initial=True)
    globals()["SUPERVISOR_REDUCED"] = True
    globals()["SUP_ENTRY_ENVELOPE"] = None
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    caps = inspector_caps()
    if caps != inspector_expected_caps():
        raise ValueError("INSPECTOR_CAPABILITY_CONTRACT")
    globals()["sup_send"](
        channel,
        dict(
            binding=binding,
            pid=os.getpid(),
            ticks=globals()["_ticks"](os.getpid()),
            namespace=namespace,
            interface="lo",
            ifindex=1,
            capabilities=caps,
            lifetime_seconds=INSPECT_LIFETIME,
        ),
    )
    core = InspectorCore(
        binding,
        namespace,
        lambda: globals()["sup_inventory"](config, mask=INSPECT_MASK, allow_existing=True),
        lambda: (os.readlink("/proc/self/ns/net"), socket.if_nametoindex("lo")),
    )
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(True))
    signal.signal(signal.SIGINT, lambda *_: stopping.append(True))
    while not core.closed and not stopping and time.monotonic() < started + INSPECT_LIFETIME:
        if not globals()["sup_alive"](*parent, 0) or not globals()["sup_alive"](*controller):
            raise ValueError("INSPECTOR_OWNER_EXITED")
        if not select.select([channel], [], [], 0.1)[0]:
            continue
        request = globals()["sup_receive"](channel, (parent[0], 0, 0))
        try:
            reply = core.dispatch(request)
        except (OSError, ValueError, TimeoutError) as exc:
            # Fixed stage/code only; tool stderr remains in the Root terminal.
            code = str(exc).split(":", 1)[0]
            if not code.startswith(("INSPECTOR_", "SUPERVISOR_")):
                code = type(exc).__name__.upper()
            reply = dict(
                binding=binding,
                sequence=core.sequence,
                command=request.get("command"),
                error=dict(
                    code=code,
                    errno=exc.errno if isinstance(exc, OSError) else None,
                    stage=globals().get("SUP_ENTRY_STAGE"),
                ),
            )
            print("INSPECTOR_QUERY_ERROR", str(exc)[:1024], flush=True)
        globals()["sup_send"](channel, reply)
    if not core.closed:
        raise ValueError("INSPECTOR_LIFETIME_EXPIRED")


def start_inspector(config, binding, namespace, controller):
    if config.get("inspector") != INSPECT_PROFILE:
        raise ValueError("INSPECTOR_MANIFEST_REQUIRED")
    version = config.get("bpftool_version", {})
    if (
        version.get("version") != "7.4.0"
        or version.get("features", {}).get("skeletons") is not False
    ):
        raise ValueError("INSPECTOR_AUTOLOAD_BUILD_FORBIDDEN")
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0):
        raise ValueError("INSPECTOR_AUTHENTICATED_ROOT_REQUIRED")
    if (os.readlink("/proc/self/ns/net"), socket.if_nametoindex("lo")) != (namespace, 1):
        raise ValueError("INSPECTOR_SCOPE_CHANGED")
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    for channel in (a, b):
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        channel.settimeout(INSPECT_QUERY_SECONDS)
    parent = (os.getpid(), globals()["_ticks"](os.getpid()))
    started = time.monotonic()
    try:
        child = os.fork()
    except BaseException:
        a.close()
        b.close()
        raise
    if child == 0:
        a.close()
        os.dup2(b.fileno(), 3, inheritable=False)  # Replaces Supervisor ready pipe in this child.
        os.closerange(4, 1048576)
        channel = socket.socket(fileno=3)
        code = 2
        try:
            inspector_loop(channel, config, binding, namespace, parent, controller, started)
            code = 0
        except (OSError, ValueError, EOFError) as exc:
            try:
                globals()["sup_send"](
                    channel,
                    dict(
                        binding=binding,
                        error=dict(
                            code=type(exc).__name__.upper(),
                            errno=exc.errno if isinstance(exc, OSError) else None,
                        ),
                    ),
                )
            except OSError:
                print("INSPECTOR_DIAGNOSTIC_UNDELIVERED", flush=True)
            print("INSPECTOR_EXIT", type(exc).__name__, flush=True)
        finally:
            channel.close()
            os._exit(code)
    b.close()
    client = InspectorClient(a, child, globals()["_ticks"](child), binding, None, started)
    try:
        hello = globals()["sup_receive"](a, (child, 0, 0))
        if hello.get("binding") == binding and "error" in hello:
            error = hello["error"]
            if error.get("errno") is not None:
                raise OSError(error["errno"], "INSPECTOR_INITIALIZATION_FAILED")
            raise ValueError("INSPECTOR_INITIALIZATION_FAILED")
        if (
            hello.get("binding") != binding
            or hello.get("pid") != child
            or hello.get("ticks") != client.ticks
            or hello.get("namespace") != namespace
            or (hello.get("interface"), hello.get("ifindex")) != ("lo", 1)
            or hello.get("capabilities") != inspector_expected_caps()
            or inspector_caps(child) != inspector_expected_caps()
        ):
            raise ValueError("INSPECTOR_HELLO_REJECTED")
        client.hello = hello
        return client
    except BaseException:
        a.close()
        # EOF terminates only this newly forked worker. Never signal an unknown PID.
        until = time.monotonic() + 2
        while time.monotonic() < until:
            if os.waitpid(child, os.WNOHANG)[0]:
                break
            time.sleep(0.02)
        raise
