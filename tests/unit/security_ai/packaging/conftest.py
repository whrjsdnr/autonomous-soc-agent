import pytest
from tests.packaging_support import development_models

from soc_agent.security_ai.packaging import load_package, save_package


@pytest.fixture(scope="module")
def packages(tmp_path_factory):
    directory = tmp_path_factory.mktemp("packages")
    result = {}
    # Round-trip a newly frozen selection in this environment, not a historical release.
    for name, (selection, rows) in development_models(directory).items():
        path = directory / name
        pin = save_package(selection, path)
        result[name] = (
            selection,
            rows,
            path,
            pin,
            load_package(path, expected_manifest_digest=pin),
        )
    return result
