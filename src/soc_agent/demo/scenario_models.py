"""Explicit fixture contracts; no live authority or model inference permission."""

from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from soc_agent.security_ai.external.models import Snapshot, content_digest_payload

InputMode = Literal["LIVE_LINUX", "SCENARIO"]
AssessmentMode = Literal["SCRIPTED", "REAL_LLM"]
ResponseMode = Literal["DISABLED", "RESPONSE_SIMULATION"]
StageStatus = Literal["PASS", "FAIL", "SKIPPED", "BLOCKED", "NOT_IMPLEMENTED"]
START = datetime(2026, 1, 1, tzinfo=UTC)


class Scenario(Snapshot):
    scenario_id: str
    scenario_version: Literal["1.0.0"] = "1.0.0"
    input_origin: Literal["FIXTURE"] = "FIXTURE"
    messages: tuple[str, ...]
    expected_detection: tuple[str, ...] = ()
    expected_investigation: Literal["READ_ONLY_COMPLETED"] = "READ_ONLY_COMPLETED"
    expected_policy_decision: Literal["REQUIRE_APPROVAL"] = "REQUIRE_APPROVAL"
    expected_approval_outcome: str = "NOT_REQUESTED"
    expected_execution_outcome: str = "DISABLED"

    @property
    def fixture_identity(self) -> str:
        return content_digest_payload(self.model_dump(mode="json"))


def ssh(result: str, account: str = "fixture-user") -> str:
    return f"{result} password for {account} from 192.0.2.5 port 34567 ssh2"


PAM = (
    "pam_unix(sudo:auth): authentication failure; "
    "logname= uid=1000 euid=0 tty=/dev/pts/0 ruser= rhost=  user=fixture-user"
)


def scenarios() -> tuple[Scenario, ...]:
    failure = ssh("Failed")
    return (
        Scenario(scenario_id="S01", messages=(ssh("Accepted"),)),
        Scenario(
            scenario_id="S02", messages=(PAM,), expected_detection=("SUDO_PAM_MODULE_FAILURE",)
        ),
        Scenario(
            scenario_id="S03",
            messages=(failure,) * 5,
            expected_detection=("REPEATED_AUTH_FAILURE",),
        ),
        Scenario(
            scenario_id="S04",
            messages=tuple(ssh("Failed", f"fixture-user-{i}") for i in range(3)),
            expected_detection=("MULTI_ACCOUNT_FAILURE",),
        ),
        Scenario(
            scenario_id="S05",
            messages=(failure, ssh("Accepted")),
            expected_detection=("FAILURE_THEN_SUCCESS",),
        ),
        Scenario(
            scenario_id="S06", messages=(PAM,), expected_detection=("SUDO_PAM_MODULE_FAILURE",)
        ),
        Scenario(
            scenario_id="S07",
            messages=(failure,),
            expected_approval_outcome="APPROVED_SIMULATION_ONLY",
            expected_execution_outcome="SIMULATED",
        ),
        Scenario(
            scenario_id="S08",
            messages=(failure,),
            expected_approval_outcome="REJECTED",
            expected_execution_outcome="DENIED",
        ),
        Scenario(
            scenario_id="S09",
            messages=(failure,),
            expected_approval_outcome="EXPIRED",
            expected_execution_outcome="DENIED",
        ),
        Scenario(
            scenario_id="S10",
            messages=(failure,),
            expected_approval_outcome="BINDING_MISMATCH_DENIED",
            expected_execution_outcome="DENIED",
        ),
        Scenario(
            scenario_id="S11",
            messages=(failure, ssh("Accepted")),
            expected_detection=("FAILURE_THEN_SUCCESS",),
        ),
        Scenario(scenario_id="S12", messages=(ssh("Accepted"),)),
    )


def journal_fixture(scenario: Scenario, index: int, replay_run_id: UUID) -> dict[str, object]:
    message = scenario.messages[index]
    pam = message == PAM
    return {
        "_MACHINE_ID": "a" * 32,
        "__CURSOR": f"fixture-{scenario.scenario_id}-{replay_run_id}-{index}",
        "__REALTIME_TIMESTAMP": str(int((START + timedelta(seconds=index)).timestamp() * 1e6)),
        "_COMM": "sudo" if pam else "sshd",
        "_EXE": "/usr/bin/sudo" if pam else "/usr/sbin/sshd",
        "_UID": "1000" if pam else "0",
        "PRIORITY": "6",
        "MESSAGE": message,
    }


class Stage(Snapshot):
    status: StageStatus
    outcome: str


class ScenarioResult(Snapshot):
    contract_version: Literal["soc-linux-scenario-result:v1"] = "soc-linux-scenario-result:v1"
    scenario_id: str
    scenario_version: str
    input_mode: InputMode = "SCENARIO"
    input_origin: Literal["FIXTURE", "NATIVE_OS"] = "FIXTURE"
    assessment_mode: AssessmentMode = "SCRIPTED"
    llm_request_count: int = 0
    fixture_identity: str
    replay_run_id: UUID
    response_mode: ResponseMode
    stages: dict[str, Stage]
    detections: tuple[str, ...]
    verified_events: int
    duplicate_events: int
    simulated_handler_calls: int | None
    real_os_handler_calls: Literal[0] = 0
    inference_status: Literal["NOT_INFERABLE"] = "NOT_INFERABLE"
    action_policy: Literal["WRITE_DENIED"] = "WRITE_DENIED"
    audit_receipt: str
    audit_path: str
    overall_status: StageStatus
