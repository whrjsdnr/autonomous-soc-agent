import pytest

from soc_agent.security_ai.collectors.live_contract import bundle
from soc_agent.security_ai.ebpf.__main__ import main
from soc_agent.security_ai.ebpf.models import Event, Plan
from soc_agent.security_ai.research.models import digest


def test_zeek_bundle_changes_only_for_reviewed_failure_certificate_order():
    # B-1 persists failure evidence before a concurrent stop; old approval is invalid.
    assert digest(bundle()) == "2b005190106f94d0ee3d28adab3a18af1601b7bc2b5ebbabebc75ada803f2045"
    assert bundle()["live_process.py"] == (
        "d47439e384c301265e32daee906a927b668c4f7d8961f834bc55abf90b748dda"
    )


def test_no_native_attach_or_zeek_selection_on_preparation_cli():
    for args in [
        ["load"],
        ["attach"],
        ["prepare", "--collector", "zeek-live"],
        ["prepare", "--interface", "eth0"],
        ["prepare", "--sudo"],
    ]:
        with pytest.raises(SystemExit):
            main(args)


def test_explicit_extra_fields_cannot_request_payload_or_alter_gate():
    from tests.ebpf_support import plan

    p = plan()
    with pytest.raises(ValueError):
        Plan.model_validate(p.model_dump() | dict(native_ai="ENABLED"))
    with pytest.raises(ValueError):
        Event.model_validate(dict(payload=b"forbidden"))


def test_verification_guard_distinguishes_compilation_output_from_execution():
    from tests.ebpf_verification_guard import no_bpf_tools

    no_bpf_tools("subprocess.Popen", ("cc", ["cc", "-o", "ring-consumer"], None, None))
    for argv in [["ring-consumer", "3"], ["bpftool", "prog", "load"], ["tc", "filter", "add"]]:
        with pytest.raises(PermissionError):
            no_bpf_tools("subprocess.Popen", (argv[0], argv, None, None))
