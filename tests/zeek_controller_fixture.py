"""Owned child lifecycle fixture. Never authenticates, invokes Docker or captures traffic."""

import argparse
import asyncio
import json
import signal
from pathlib import Path

import tests.zeek_live_verification_guard  # noqa:F401
from soc_agent.security_ai.collectors.live import LiveZeekCollector
from soc_agent.security_ai.collectors.offline import OfflineZeek


def ready(directory, session):
    (directory / "fixture-ready.json").write_text(
        json.dumps(dict(scope="CONTROLLER_LIFECYCLE_FIXTURE_NO_CAPTURE", session=str(session)))
    )


async def controller(directory):
    OfflineZeek.environment = lambda _: {}
    c = LiveZeekCollector(directory)
    await c.prepare()
    await c.start()
    ready(directory, c.directory)
    ended = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        loop.add_signal_handler(sig, ended.set)
    try:
        await asyncio.wait_for(ended.wait(), 45)
    finally:
        await c.close("CONTROLLER_EXIT")


def gui(directory):
    OfflineZeek.environment = lambda _: {}
    from soc_agent.gui import production
    from soc_agent.gui.__main__ import main

    base = production.Desktop

    class FixtureDesktop(base):
        def __init__(self, root, config):
            super().__init__(root, config)
            root.after(50, self.prepare_fixture)

        def prepare_fixture(self):
            if self.busy or not self.startup_complete:
                self.root.after(50, self.prepare_fixture)
                return
            self.start()
            self.root.after(50, self.publish_ready)

        def publish_ready(self):
            if self.snapshot.get("command_valid"):
                ready(directory, self.worker.backend._owners["zeek_collector"].directory)
            elif not self.closing:
                self.root.after(50, self.publish_ready)

    production.Desktop = FixtureDesktop
    return main(["--data-directory", str(directory), "--collector", "zeek-live"])


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("directory", type=Path)
    p.add_argument("--gui", action="store_true")
    args = p.parse_args()
    args.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.gui:
        raise SystemExit(gui(args.directory))
    asyncio.run(controller(args.directory))
