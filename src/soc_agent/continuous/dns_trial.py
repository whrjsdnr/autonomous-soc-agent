"""Build the existing fixed UDP2/TCP1 diagnostic for an exact reviewed trial.

Preparation only: no socket, fork, setns, privilege change or approval issuance.
The admitted Root coordinator owns the child; its ordinary worker reuses the
existing responder, traffic, cookie checks, 35s witness and 45s observation.
"""

import ast
import re
from pathlib import Path

from soc_agent.security_ai.ebpf_tc import dns_diagnostic_engine
from soc_agent.security_ai.ebpf_tc.isolated_dns_launcher import service_source


def source(config: dict) -> bytes:
    if (
        set(config) != {"uid", "gid", "namespace", "namespace_device", "namespace_inode", "boot_id"}
        or config["uid"] != 1000
        or config["gid"] != 1000
        or config["namespace"] != "net:[4026532232]"
        or config["namespace_inode"] != 4026532232
        or type(config["namespace_device"]) is not int
        or config["namespace_device"] < 1
        or not re.fullmatch(r"[a-f0-9-]{36}", config["boot_id"])
    ):
        raise ValueError("CONTINUOUS_DNS_TRIAL_FIXED_SCOPE_REQUIRED")
    tree = ast.parse(Path(dns_diagnostic_engine.__file__).read_text())
    definitions = "\n\n".join(
        ast.unparse(node)
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in {"dns_snapshot", "diagnostic_worker"}
    )
    result = (
        service_source(config)
        + b"\nimport threading\n"
        + definitions.encode()
        + b"\n"
        + _COORDINATOR.encode()
    )
    compile(result, "<fixed-continuous-dns-trial>", "exec")
    return result


_COORDINATOR = '''
class BoundedDNSProbe:
    """One owned child; polling must not block the Collector heartbeat watcher."""
    def __init__(self):
        self.child = None
        self.started = False
        self.ready = False
        self.completed = False
        self.events = []

    def start(self):
        if self.started:
            raise ValueError("CONTINUOUS_DNS_TRIAL_REPLAY")
        # The existing spawn boundary independently requires authenticated Root.
        self.started = True
        self.child = spawn_dns_child(DNS_CONFIG, diagnostic_worker)

    def poll(self):
        if self.child is None or self.completed:
            return
        if time.monotonic() >= self.child.deadline:
            raise TimeoutError("CONTINUOUS_DNS_TRIAL_DEADLINE")
        if not select.select([self.child.channel], [], [], 0)[0]:
            return
        value = self.child.receive()
        self.events.append(value)
        if value["state"] == "LOCAL_DNS_READY":
            if self.ready or value["namespace"] != DNS_CONFIG["namespace"]:
                raise ValueError("CONTINUOUS_DNS_TRIAL_READY_BINDING")
            self.ready = True
        elif value["state"] == "DNS_DIAGNOSTIC_COMPLETED":
            if (not self.ready or len(value.get("exchanges", [])) != 3
                or [x["transport"] for x in value["exchanges"]] != ["UDP", "TCP", "UDP"]
                or value.get("listener_fds_closed") is not True):
                raise ValueError("CONTINUOUS_DNS_TRIAL_RESULT_BINDING")
            code = self.child.finish()
            if code != 0:
                raise ValueError("CONTINUOUS_DNS_TRIAL_CHILD_EXIT:" + str(code))
            self.completed = True
        else:
            raise ValueError("CONTINUOUS_DNS_TRIAL_CHILD_FAILED:" + str(value))

    def close(self):
        return dict(started=self.started, completed=self.completed,
                    child_exit=self.child.close() if self.child is not None else None,
                    events=self.events)


if __name__ == "__main__":
    raise SystemExit("EXACT_ROOT_R1_R2_AND_NATIVE_APPROVAL_REQUIRED")
'''
