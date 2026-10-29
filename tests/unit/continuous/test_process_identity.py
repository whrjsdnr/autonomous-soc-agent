"""Post-exec identity remains strict; no Root/service/Kernel execution."""

import pytest

from soc_agent.continuous.process_identity import validate_ordinary_process

GOOD = "\n".join(
    ["Uid:\t1000\t1000\t1000\t1000", "NoNewPrivs:\t1"]
    + [f"{name}:\t0000000000000000" for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")]
)


def test_fully_dropped_post_exec_identity():
    assert validate_ordinary_process(GOOD) is None


@pytest.mark.parametrize("uids", ["0 0 0 0", "1000 0 0 0", "1000 1000 0 1000", "1000 1000 1000"])
def test_pre_exec_or_wrong_identity_never_admits(uids):
    with pytest.raises(ValueError, match="ORDINARY_PROCESS_UID_MISMATCH:" + uids.replace(" ", ",")):
        validate_ordinary_process(GOOD.replace("1000\t1000\t1000\t1000", uids))


@pytest.mark.parametrize("name", ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"])
def test_any_remaining_capability_is_rejected(name):
    with pytest.raises(ValueError, match="CAPABILITY_NONZERO:" + name):
        validate_ordinary_process(
            GOOD.replace(name + ":\t0000000000000000", name + ":\t0000000000000001")
        )


@pytest.mark.parametrize(
    "fault", ["missing", "duplicate", "no_new_privileges", "invalid_capability"]
)
def test_incomplete_identity_and_changed_security_contract_rejected(fault):
    body = {
        "missing": GOOD.replace("CapBnd:\t0000000000000000", ""),
        "duplicate": GOOD + "\nUid: 1000 1000 1000 1000",
        "no_new_privileges": GOOD.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        "invalid_capability": GOOD.replace("CapEff:\t0000000000000000", "CapEff:\tinvalid"),
    }[fault]
    with pytest.raises(ValueError, match="ORDINARY_PROCESS_"):
        validate_ordinary_process(body)
