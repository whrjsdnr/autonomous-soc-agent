"""Explicit synthetic demo CLI. Stops at human boundary; never simulates approval."""

import argparse
import asyncio
import json
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from soc_agent.api import SOCApplication
from soc_agent.api.startup import open_store
from soc_agent.demo.composition import compose_demo
from soc_agent.review.authentication import AuthenticatedPrincipal
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.security_ai.packaging import load_package
from soc_agent.state.evidence import utc_now


async def run(args):
    package = None
    if args.auth_package:
        if not args.manifest_digest:
            raise ValueError("Explicit expected manifest digest required")
        package = load_package(args.auth_package, expected_manifest_digest=args.manifest_digest)
    store = open_store(args.database, create=not args.database.exists())
    service = compose_demo(store, package=package)
    token = str(uuid4())
    now = utc_now()

    class Observer:
        """CLI-local demo observer, not a human-authority provider. Cannot confirm anything."""

        def authenticate(self, credential):
            if credential != token:
                raise HumanAuthorizationDenied("Unknown demo observer")
            return AuthenticatedPrincipal(
                subject_id="demo-observer",
                provider_id="synthetic-observer-only",
                session_id=token,
                subject_kind="human",
                authentication_context=("synthetic-demo",),
                authenticated_at=now,
                expires_at=now + timedelta(minutes=10),
                scopes=(),
            )

        def confirm(self, *args):
            raise HumanAuthorizationDenied("Demo CLI never confirms human operations")

    class Access:
        def require_access(self, principal, incident_id, operation):
            if operation not in {
                "POST:events",
                "POST:workflow/start",
                "POST:workflow/step",
                "GET:workflow",
                "GET:trace",
            }:
                raise HumanAuthorizationDenied("Observer cannot perform governance")

    app = SOCApplication(
        lambda: service, provider=Observer(), provider_id="synthetic-observer-only", access=Access()
    )

    async def request(method, path, body=None):
        messages = []

        async def receive():
            return {"type": "http.request", "body": json.dumps(body or {}).encode()}

        async def send(message):
            messages.append(message)

        await app(
            {
                "type": "http",
                "method": method,
                "path": path,
                "headers": [(b"authorization", f"Bearer {token}".encode())],
            },
            receive,
            send,
        )
        result = json.loads(messages[1]["body"])
        if messages[0]["status"] != 200:
            raise ValueError(f"Demo request rejected: {result}")
        return result

    event = json.loads(args.event.read_text())
    if event.get("synthetic") is not True:
        raise ValueError("CLI accepts explicitly synthetic events only")
    ingested = await request("POST", "/events", event)
    base = f"/incidents/{ingested['incident_id']}"
    print("SYNTHETIC DEMO; scripted LLM; no human approval simulation")
    print(
        "Authentication model:", "saved package" if package else "NOT RUN (explicitly unconfigured)"
    )
    print("Incident:", ingested["incident_id"])
    if ingested["duplicate"]:
        # Explicit restart reads the durable cursor; no reset or forced re-analysis.
        workflow = await request("GET", base + "/workflow")
    else:
        workflow = await request("POST", base + "/workflow/start")
    for _ in range(16):
        print(workflow["current_step"], "->", workflow["next_step"], workflow["reason"])
        if workflow["waiting_for_human"] or workflow["terminal"]:
            break
        workflow = await request(
            "POST",
            base + "/workflow/step",
            {
                "run_id": workflow["workflow_id"],
                "expected_revision": workflow["checkpoint_revision"],
            },
        )
    print("WAITING_FOR_HUMAN:", workflow["waiting_for_human"])
    print("Execution: NOT DISPATCHED; use externally authenticated governance endpoints to resume")
    trace = await request("GET", base + "/trace")
    print("Trace entries:", len(trace["entries"]))
    print("Final workflow:", workflow["next_step"], "terminal:", workflow["terminal"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database",
        type=Path,
        required=True,
        help="Absolute SQLite path in an existing private (0700) directory",
    )
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--auth-package", type=Path)
    parser.add_argument("--manifest-digest")
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
