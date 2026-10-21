"""Explicit single-run orchestration after terminal scope approval, never automatic retry."""

import json
import time

from soc_agent.security_ai.ebpf_broker.contracts import Command
from soc_agent.security_ai.ebpf_native.contracts import RunIdentity
from soc_agent.security_ai.research.models import digest


def start_live_run(preparation, *, gui: bool = False) -> dict:
    h = preparation._os_handoff
    if (
        not h
        or h.origin not in {"TCX_LIVE_QUALIFICATION_NATIVE", "TCX_UNIFIED_SESSION_NATIVE"}
        or h.state != "BROKER_READY"
    ):
        raise ValueError("APPROVED_NATIVE_HANDOFF_REQUIRED")
    run = RunIdentity(
        application_session=h.plan.broker.application.application_session,
        scope_digest=digest(h.plan.broker.application.scope.model_dump(mode="json")),
        run_number=1,
    )
    try:
        h.command(
            Command(
                command="ATTACH",
                plan_digest=h.plan.approval,
                sequence=h.sequence + 1,
                run=run,
            )
        )
        if gui:
            from soc_agent.security_ai.ebpf_tc.gui import launch

            launch(preparation)
        else:
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline and not h.error:
                h.observe()
                if h.data.adapter and h.data.adapter.flow.closed:
                    break
                time.sleep(0.2)
    finally:
        h.close()  # Once only; never retry a failed auth, attach or capture.
        receipt = preparation.controller.application.directory / "native-live-result.json"
        receipt.write_text(json.dumps(h.snapshot(), indent=2) + "\n")
    return h.snapshot()
