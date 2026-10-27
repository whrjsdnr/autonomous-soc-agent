"""Pinned launch packet for existing CLI arguments, never a grant or executable."""

from pathlib import Path

from soc_agent.security_ai.ebpf_tc.reassessment import Contract, Hash, held_json


class ExecutionRequest(Contract):
    directory: str
    manifest: Hash
    image_sha: Hash
    campaign: str
    amendment_file: str
    amendment_sha: Hash
    approval_file: str
    approval_sha: Hash
    traffic_file: str
    traffic_sha: Hash
    claim_file: str
    management_file: str | None = None
    management_sha: Hash | None = None

    def arguments(self, directory: Path) -> dict:
        if not Path(self.directory).is_absolute() or Path(self.directory) != directory:
            raise ValueError("EXECUTION_REQUEST_DIRECTORY_BINDING")
        result = self.model_dump(exclude={"directory"})
        for key in (
            "campaign",
            "amendment_file",
            "approval_file",
            "traffic_file",
            "claim_file",
            "management_file",
        ):
            if result[key] is not None:
                value = Path(result[key])
                if not value.is_absolute():
                    raise ValueError("EXECUTION_REQUEST_ABSOLUTE_PATH_REQUIRED")
                result[key] = value
        if (self.management_file is None) != (self.management_sha is None):
            raise ValueError("EXECUTION_MANAGEMENT_POLICY_REQUIRED")
        return result


def load_request(path: Path, pin: str, directory: Path) -> dict:
    return ExecutionRequest.model_validate(held_json(path, pin)).arguments(directory)
