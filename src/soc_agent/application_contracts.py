"""Shared application metadata; no deployment adapter or execution authority.

Composition and adapters depend on these values. The deployment module retains
its public re-exports, so moving the definitions does not change callers' data.
"""

from enum import StrEnum

from soc_agent.review.models import Frozen


class DeploymentProfile(StrEnum):
    DESKTOP = "DESKTOP"
    SERVER = "SERVER"
    DEMO = "DEMO"


class DeploymentDescriptor(Frozen):
    profile: DeploymentProfile
