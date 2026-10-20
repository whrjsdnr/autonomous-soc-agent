"""C compilation and B-1 fixtures only. No privileged executable is admitted."""

from pathlib import Path

from soc_agent.security_ai.ebpf_broker.controller import Controller
from soc_agent.security_ai.ebpf_tc.bridge import Preparation
from soc_agent.security_ai.ebpf_tc.build import compile_native
from tests.ebpf_native_support import application


def preparation(path: Path) -> Preparation:
    artifacts = path / "native-build"
    compile_native(artifacts)
    return Preparation(Controller(application(path / "app")), artifacts)
