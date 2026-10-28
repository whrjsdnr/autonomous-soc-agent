"""Real R1 adapter and chain; simulated reviews only, no Native execution."""

import json

from tests.unit.ebpf_tc.test_batch3_admission import prepare
from tests.unit.ebpf_tc.test_batch3_admission import transition as transition
from tests.unit.ebpf_tc.test_development_session import policy_case as policy_case
from tests.unit.ebpf_tc.test_native_campaign import fixture as fixture
from tests.unit.ebpf_tc.test_r1r2_operational import h, rewrite_receipt
from tests.unit.ebpf_tc.test_r1r2_operational import review as review
from tests.unit.ebpf_tc.test_stabilization_campaign import stable as stable

from soc_agent.security_ai.ebpf_tc import development_session as dev
from soc_agent.security_ai.ebpf_tc import reassessment_admission as admission
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.phase_d import SCOPE
from soc_agent.security_ai.native_campaign import sha


def test_development_policy_uses_real_r1_checks_and_nonconsuming_preview(transition, policy_case):
    review, stable, _, _ = transition
    campaign, policy, packet = policy_case
    scope = SCOPE | dict(namespace=policy.namespace)
    binding = review["expected_binding"].model_copy(update=dict(scope_sha=dev.digest(scope)))
    review["expected_binding"] = binding
    policy = policy.model_copy(update=dict(artifacts=[binding.next_artifact]))
    path = campaign.directory / "dev-policy.json"
    path.write_bytes(canonical(policy.model_dump(mode="json")))
    packet = packet | dict(policy_sha=sha(path.read_bytes()))
    recorded = dev.activate(campaign, packet)
    procedure = review["procedure_file"]
    procedure.write_bytes(
        canonical(
            json.loads(procedure.read_bytes()) | dict(binding_sha=dev.digest(binding.model_dump()))
        )
    )
    review["procedure_sha"] = h(procedure.read_bytes())
    rewrite_receipt(
        review,
        binding=binding.model_dump(),
        procedure_sha=review["procedure_sha"],
        ledger_tip_sha=recorded["record_sha256"],
    )
    ledger, args, identity, execution = prepare(transition)
    amendment = args["amendment_file"]
    amendment.write_bytes(
        canonical(
            json.loads(amendment.read_bytes())
            | dict(batch_allocation=None, development_session_sha=packet["policy_sha"])
        )
    )
    args["amendment_sha"] = h(amendment.read_bytes())
    dns = stable[3] | dict(namespace=policy.namespace)
    execution.update(
        development_session_sha=packet["policy_sha"],
        admission_amendment_sha=args["amendment_sha"],
        scope=scope,
        dns_scope=dns,
    )
    stable[1].write_bytes(canonical(execution))
    before = (ledger.directory / "execution-ledger.jsonl").read_bytes()
    preview = admission.preview_reservation(
        ledger.directory,
        **args,
        identity=identity,
        scope=scope,
        dns_scope=dns,
        approval_file=stable[1],
        approval_sha=h(stable[1].read_bytes()),
        root_cost=1,
        git_commit=binding.next_artifact.git_commit,
    )
    assert preview["status"] == "PREVIEW_ONLY_NOT_RESERVED"
    assert preview["native_admission"] is False
    assert (ledger.directory / "execution-ledger.jsonl").read_bytes() == before
    adapter = admission.ReassessedCampaign(ledger.directory, **args)
    event = adapter.reserve(identity, scope, dns, stable[1], h(stable[1].read_bytes()), root_cost=1)
    assert event["development_session_sha"] == packet["policy_sha"]
    assert event["count_policy"] == "ISOLATED_DEVELOPMENT_OBSERVE_ONLY_V1"
    assert event["reassessment_record_sha"] == adapter.amendment.reassessment_record_sha
    assert event["scope"]["namespace"] == policy.namespace
    assert any(
        json.loads(line).get("safe_for_next_attempt") is False for line in before.splitlines()
    )
