"""Deployment metadata only: never identity, policy or execution authority."""

from enum import StrEnum

from soc_agent.review.models import Frozen


class DeploymentProfile(StrEnum):
    DESKTOP = "DESKTOP"
    SERVER = "SERVER"
    DEMO = "DEMO"


class DeploymentDescriptor(Frozen):
    profile: DeploymentProfile
