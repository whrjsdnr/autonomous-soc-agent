"""Seed or serve a private synthetic SOC Command Center; no provider or privileged actions."""

import argparse
import asyncio
from pathlib import Path

from soc_agent.demo.command_center import seed
from soc_agent.demo.local_server import local_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("seed", "serve"):
        command = commands.add_parser(name)
        command.add_argument("--directory", type=Path, required=True)
        if name == "seed":
            command.add_argument("--scenario", choices=("a", "b", "c", "all"), default="all")
        else:
            command.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if args.command == "seed":
        value = asyncio.run(seed(args.directory, args.scenario))
        print(value.label)
        print("Seeded incidents:", len(value.incidents))
        print("Human boundary preserved; no approvals, promotions or response execution")
    else:
        server = local_server(args.directory, args.port)
        print("DEMO / SYNTHETIC; loopback-only read-only observer; use on a trusted local machine")
        print(f"Browser: http://127.0.0.1:{server.server_port}/dashboard", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
