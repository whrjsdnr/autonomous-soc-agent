"""One immutable compiled release shared by OS handoff transport tests."""

import pytest
from tests.ebpf_broker_support import controller

from soc_agent.security_ai.ebpf_tc.bridge import Preparation
from soc_agent.security_ai.ebpf_tc.build import compile_native
from soc_agent.security_ai.ebpf_tc.installation import create_package


@pytest.fixture(scope="session")
def release(tmp_path_factory):
    directory = tmp_path_factory.mktemp("os-handoff")
    hashes = compile_native(directory / "build")
    manifest = create_package(directory / "build", directory / "package", "0.2.11")
    return directory, hashes, manifest


@pytest.fixture
def session(release, tmp_path):
    directory, _, manifest = release
    owner = controller(tmp_path / "application", authenticate=False)
    prep = Preparation(owner, directory / "build")
    handoff = prep.os_auth_handoff(directory / "package", manifest.identity)
    try:
        yield handoff, prep
    finally:
        handoff.close()
        owner.close()
