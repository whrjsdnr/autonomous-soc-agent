import json
from pathlib import Path

import pytest

from soc_agent.security_ai.collectors.live_contract import bundle
from soc_agent.security_ai.ebpf.__main__ import main
from soc_agent.security_ai.ebpf.models import Event, Plan
from soc_agent.security_ai.research.models import digest


def test_zeek_bundle_changes_only_for_reviewed_failure_certificate_order():
    # B-1 persists failure evidence before a concurrent stop; old approval is invalid.
    amendment = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "docs/linux-soc-v1/tcx-packet-data-plane-amendment.json"
        ).read_text()
    )
    assert (
        amendment["previous_zeek_bundle_digest"]
        == "2b005190106f94d0ee3d28adab3a18af1601b7bc2b5ebbabebc75ada803f2045"
    )
    # The old certificate pins a historical release, never today's source.
    historical = amendment["current_zeek_bundle"]
    assert {k for k in historical if historical[k] != amendment["previous_zeek_bundle"][k]} == {
        "packet_producer.py"
    }
    assert digest(historical) == amendment["current_zeek_bundle_digest"]
    assert amendment["native_approval_required"] is True
    assert historical["live_process.py"] == (
        "d47439e384c301265e32daee906a927b668c4f7d8961f834bc55abf90b748dda"
    )
    import hashlib

    root = Path(__file__).resolve().parents[3] / "docs/linux-soc-v1"
    successor = json.loads((root / "phase-d-063-rca-source-amendment.json").read_text())
    assert (
        successor["previous_amendment_sha256"]
        == hashlib.sha256((root / "tcx-packet-data-plane-amendment.json").read_bytes()).hexdigest()
    )
    assert successor["previous_zeek_bundle"] == historical
    assert bundle() == successor["current_zeek_bundle"]
    assert digest(bundle()) == successor["current_zeek_bundle_digest"]
    assert (
        sorted(k for k in set(bundle()) | set(historical) if bundle().get(k) != historical.get(k))
        == successor["zeek_changed_sources"]
    )
    assert successor["native_approval_required"] and successor["native_release"] == "BLOCKED"


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
