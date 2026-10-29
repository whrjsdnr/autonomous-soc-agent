from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from soc_agent.continuous.tcx_producer import TCXProducer


@pytest.mark.asyncio
async def test_receiver_timeout_preserves_stage_and_does_not_claim_cleanup():
    producer = TCXProducer(SimpleNamespace())
    loop = SimpleNamespace(sock_recv=AsyncMock(side_effect=TimeoutError))
    with pytest.raises(ValueError, match="CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT") as caught:
        await producer.receive_message(loop)
    assert isinstance(caught.value.__cause__, TimeoutError)
    assert producer.failure["timeout_seconds"] == 5
    assert producer.failure["stage"] == "AUTHENTICATED_ROOT_RECEIVE"
    assert producer.failure["last_message_age_seconds"] is None
    await producer.close()
    assert producer.snapshot["state"] == "STOPPED"
    assert producer.snapshot["failure"] == producer.failure
    assert producer.snapshot["cleanup"] == "UNKNOWN"
