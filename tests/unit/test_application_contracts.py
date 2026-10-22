"""Metadata definitions live below composition and retain the old public API."""

import ast
from pathlib import Path

from soc_agent import application_contracts, deployment


def test_deployment_public_api_reexports_the_shared_definitions():
    assert deployment.DeploymentDescriptor is application_contracts.DeploymentDescriptor
    assert deployment.DeploymentProfile is application_contracts.DeploymentProfile
    assert application_contracts.DeploymentDescriptor.__module__ == application_contracts.__name__
    assert application_contracts.DeploymentDescriptor(profile="DESKTOP").model_dump_json() == (
        '{"profile":"DESKTOP"}'
    )


def test_contract_definitions_have_no_reverse_adapter_or_composition_dependency():
    tree = ast.parse(Path(application_contracts.__file__).read_text())
    imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert imports == ["enum", "soc_agent.review.models"]
    assert {node.name for node in tree.body if isinstance(node, ast.ClassDef)} == {
        "DeploymentProfile",
        "DeploymentDescriptor",
    }
