"""Identical Tk profiling harness; change only the explicit Fixture session policy."""

import os

from tests.loopback_visual_profile import main

if __name__ == "__main__":
    if os.environ.get("SOC_PROFILE_DIRECTION_V3") == "1":
        from soc_agent.security_ai.operational.network_capture import calibrated_policy
        from soc_agent.security_ai.operational.network_capture.direction_policy import (
            DirectionPolicy,
        )

        # Test-only policy injection into the existing capture-free profiling harness.
        calibrated_policy.policy = lambda _name: DirectionPolicy()
    main()
