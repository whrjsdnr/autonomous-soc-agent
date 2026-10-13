"""Installed-package probe with a loopback-only TEST transport and TEST identity.

No production server/authentication is supplied. Requires a fresh isolated data
directory; deliberately corrupts its receipt only after successful lifecycle checks.
Run using the clean environment's Python with -I to exclude development imports.
"""

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import subprocess
import sys
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import UUID, uuid4

import soc_agent
from soc_agent.api import SOCApplication
from soc_agent.application import compose_application
from soc_agent.deployment import DeploymentDescriptor
from soc_agent.desktop import OfflineDesktopClient, source_report_tool
from soc_agent.ingestion import EventIngestor
from soc_agent.review.authentication import AuthenticatedPrincipal
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.security_ai.external.runtime_store import RuntimeBinding, RuntimeGovernanceStore
from soc_agent.security_ai.external.storage import ExternalContextStore
from soc_agent.state.evidence import utc_now
from soc_agent.tools import ToolRegistry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("directory", "input", "features", "artifacts", "native_python"):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    parser.add_argument("--profile", choices=("DESKTOP", "SERVER"), required=True)
    args = parser.parse_args()
    assert not args.directory.exists(), "Fresh test-only directory required"
    assert Path(soc_agent.__file__).is_relative_to(Path(sys.prefix)), (
        "Non-editable install required"
    )
    command = [sys.executable, "-I", "-m", "soc_agent.external_runtime"]
    for name, value in (
        ("directory", args.directory),
        ("input", args.input),
        ("external-features", args.features),
        ("artifacts", args.artifacts),
        ("native-python", args.native_python),
        ("profile", args.profile),
    ):
        command += ["--" + name, str(value)]
    outputs = []
    for _ in range(2):
        process = subprocess.run(command, capture_output=True, timeout=180)
        assert process.returncode == 0, "Installed CLI failed closed; inspect test environment"
        output = json.loads(process.stdout.decode("utf-8"))
        assert output["human_boundary"] and output["context_available"]
        outputs.append(output)
    incident = UUID(outputs[-1]["incident_id"])
    directory = args.directory / "external-runtime" if args.profile == "DESKTOP" else args.directory
    path = directory / "external-validation.sqlite"
    store = RuntimeGovernanceStore(path)
    with store.database.transaction(write=False) as connection:
        binding = ledger.decode(
            RuntimeBinding,
            connection.execute("SELECT * FROM external_runtime_incidents").fetchone(),
        )
    context = ExternalContextStore(path, database=store.database).load_context(
        binding.context_digest
    )
    assert len(context.results) == 3 and len(context.correlation_groups) == 2
    for result in context.results:
        assert result.validation.status == "VALIDATED_FOR_ADVISORY"
        for artifact in result.binding.artifact_identity.files:
            with (args.artifacts / artifact.path).open("rb") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == artifact.sha256
    registry = ToolRegistry()
    registry.register(source_report_tool(EventIngestor(store)))
    service = compose_application(
        store,
        deployment=DeploymentDescriptor(profile=args.profile),
        registry=registry,
        ingestion=EventIngestor(store),
        llm_client=OfflineDesktopClient(),
    ).service
    principal = AuthenticatedPrincipal(
        subject_id="gate-d-test-user",
        provider_id="gate-d-test",
        session_id=str(uuid4()),
        subject_kind="human",
        authentication_context=("test-only",),
        authenticated_at=utc_now(),
        expires_at=utc_now() + timedelta(minutes=4),
        scopes=(),
    )
    credential = str(uuid4())  # Test-only, in-memory; never returned or logged.

    class Provider:
        def authenticate(self, value):
            if value != credential:
                raise HumanAuthorizationDenied("Test identity rejected")
            return principal

    class Access:
        denied = False

        def require_access(self, subject, identity, operation):
            if self.denied or identity != incident:
                raise HumanAuthorizationDenied("Test incident access rejected")

    access = Access()
    app = SOCApplication(
        lambda: service, provider=Provider(), provider_id="gate-d-test", access=access
    )

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            return

        def dispatch(self):
            size = int(self.headers.get("Content-Length", "0"))
            if size < 0 or size > 32768:
                self.send_error(413)
                return
            body = self.rfile.read(size)
            output = []

            async def receive():
                return {"type": "http.request", "body": body}

            async def send(message):
                output.append(message)

            asyncio.run(
                app(
                    {
                        "type": "http",
                        "method": self.command,
                        "path": self.path,
                        "headers": [
                            (name.lower().encode(), value.encode())
                            for name, value in self.headers.items()
                        ],
                    },
                    receive,
                    send,
                )
            )
            self.send_response(output[0]["status"])
            self.end_headers()
            self.wfile.write(output[1]["body"])

        do_GET = dispatch
        do_POST = dispatch

    def lifecycle():
        events = iter(({"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}))
        output = []

        async def receive():
            return next(events)

        async def send(message):
            output.append(message["type"])

        asyncio.run(app({"type": "lifespan"}, receive, send))
        assert output == ["lifespan.startup.complete", "lifespan.shutdown.complete"]

    responses = []
    for _ in range(2):
        lifecycle()
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def request(method, operation, body=None, authenticated=True, *, server=server):
            headers = {"Authorization": "Bearer " + credential} if authenticated else {}
            value = json.dumps(body).encode() if body is not None else None
            url = f"http://127.0.0.1:{server.server_port}/incidents/{incident}/{operation}"
            try:
                with build_opener(ProxyHandler({})).open(
                    Request(url, data=value, headers=headers, method=method), timeout=20
                ) as r:
                    return r.status
            except HTTPError as error:
                return error.code

        try:
            assert request("GET", "workflow", authenticated=False) == 401
            assert request("GET", "workflow") == 200
            access.denied = True
            assert request("GET", "workflow") == 403
            access.denied = False
            assert request("POST", "approval-requests", {"execute": True}) == 422
            checkpoint = service.checkpoint(incident)
            body = {"run_id": str(checkpoint.run_id), "expected_revision": checkpoint.revision}
            assert request("POST", "workflow/resume", body) == 200
            assert request("POST", "workflow/resume", body) == 409
            responses.append("PASS")
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
            assert not thread.is_alive()
    with store.database.transaction(write=False) as connection:
        assert connection.execute("SELECT COUNT(*) FROM execution_records").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM external_security_audit").fetchone()[0] > 0
    # Fault injection affects only the fresh directory created by this probe.
    with store.database.transaction() as connection:
        connection.execute("UPDATE external_decision_receipts SET digest=?", ("0" * 64,))
    try:
        service.runtime_factory().restore(incident)
    except StoredDataError:
        pass
    else:
        raise AssertionError("Tampered receipt permitted restore")
    print(
        json.dumps(
            {
                "status": "PASS",
                "profile": args.profile,
                "installed_module": soc_agent.__file__,
                "python": sys.version.split()[0],
                "version": importlib.metadata.version("autonomous-soc-agent"),
                "models": [r.binding.model_id for r in context.results],
                "native_cli_start_restart": "PASS",
                "loopback_test_asgi_cycles": responses,
                "tampered_receipt_restore_denied": True,
                "execution_records": 0,
            }
        )
    )


if __name__ == "__main__":
    main()
