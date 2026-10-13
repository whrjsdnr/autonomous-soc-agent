"""Loopback-only read-only ASGI forwarding host for explicit synthetic demos."""

import asyncio
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

from soc_agent.demo.command_center import observation_app

BANNER = (
    '<div class="empty" role="note">DEMO / SYNTHETIC · Scripted analysis · '
    "Read-only local observer · No human approval or WRITE execution</div>"
)


async def read_response(app, observer, path: str):
    messages = []

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        messages.append(message)

    await app(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": [(b"authorization", ("Bearer " + observer._credential).encode())],
        },
        receive,
        send,
    )
    status = messages[0]["status"]
    headers = dict(messages[0].get("headers", []))
    body = b"".join(m.get("body", b"") for m in messages[1:])
    if headers.get(b"content-type", b"").startswith(b"text/html"):
        banner = BANNER
        if getattr(observer, "live_local", False):
            banner = (
                '<div class="empty" role="note">LIVE LOCAL RUNTIME · SYNTHETIC inputs · '
                "AUTO REFRESH · 3s · Read-only observer · Runtime Health: UNKNOWN</div>"
            )
            body = body.replace(b"</head>", b'<meta http-equiv="refresh" content="3"></head>', 1)
        body = body.replace(b"<body>", ("<body>" + banner).encode(), 1)
    return status, headers, body


def local_server(directory, port: int = 8765) -> HTTPServer:
    app, observer = observation_app(directory)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            # No headers, query strings, credentials or raw request content are logged.
            pass

        def reject(self, status):
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def do_POST(self):
            self.reject(405)

        do_PUT = do_POST
        do_PATCH = do_POST
        do_DELETE = do_POST
        do_HEAD = do_POST

        def do_GET(self):
            origin = f"http://127.0.0.1:{self.server.server_port}"
            if (
                self.headers.get_all("Host") != [origin.removeprefix("http://")]
                or self.headers.get_all("Origin", []) not in ([], [origin])
                or self.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none")
                or self.headers.get("Authorization") is not None
                or len(self.path) > 2048
            ):
                self.reject(403)
                return
            try:
                parsed = urlsplit(self.path)
            except ValueError:
                self.reject(400)
                return
            if parsed.query or parsed.fragment or parsed.scheme or parsed.netloc:
                self.reject(400)
                return
            path = parsed.path
            if path == "/":
                path = "/dashboard"
            if path not in (
                "/dashboard",
                "/dashboard/governance",
                "/dashboard/security-ai",
                "/dashboard/self-improvement",
                "/api/dashboard/overview",
                "/api/dashboard/security-ai",
                "/api/dashboard/self-improvement",
            ) and not path.startswith(("/dashboard/incidents/", "/api/dashboard/incidents/")):
                self.reject(404)
                return
            try:
                status, headers, body = asyncio.run(read_response(app, observer, path))
            except Exception:
                # Unexpected errors fail closed without traceback or provider values in HTTP.
                self.reject(500)
                return
            self.send_response(status)
            for name, value in headers.items():
                if name.lower() not in (b"content-length", b"connection", b"transfer-encoding"):
                    self.send_header(name.decode("ascii"), value.decode("ascii"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return HTTPServer(("127.0.0.1", port), Handler)
