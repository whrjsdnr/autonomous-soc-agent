"""Explicit test-only trusted artifact/environment roots for independent Git Export."""

import os
from pathlib import Path

import soc_agent
from soc_agent.security_ai.research.environment import Paths


def research_paths():
    root = Path(
        os.environ.get("SOC_RESEARCH_VALIDATION_REPOSITORY", Path(__file__).resolve().parents[1])
    )
    return Paths(
        root.parent / "ML",
        root / ".security-ai-demo/inference/bin/python",
        Path(soc_agent.__file__).resolve().parents[1],
        Path(os.environ["SOC_RESEARCH_VALIDATION_ML_SOURCE"])
        if os.environ.get("SOC_RESEARCH_VALIDATION_ML_SOURCE")
        else None,
    )
