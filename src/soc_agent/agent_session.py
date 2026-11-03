"""Fresh unapproved Native draft from an integrity-checked installed review.

Only fixed files of the existing review are rebound. No subprocess, installer,
service operation, authorization issuer, capture or network operation is used.
"""

import ast
import json
import shutil
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from soc_agent.agent_native import bind_installation_scope, ledger_snapshot, namespace_binding
from soc_agent.agent_release import save
from soc_agent.agent_runtime import sha, verify_review
from soc_agent.continuous.dns_review import candidate
from soc_agent.continuous.dns_source import prepare as prepare_dns
from soc_agent.continuous.models import ContinuousConfig
from soc_agent.continuous.store import Store
from soc_agent.security_ai.research.models import digest


def draft_expiry(review_expiry: str, *, now: datetime) -> str:
    """A fresh Session cannot extend the frozen review's validity or renew it."""
    upper = datetime.fromisoformat(review_expiry)
    if upper.tzinfo is None or now.tzinfo is None:
        raise ValueError("AGENT_REVIEW_TIMEZONE_REQUIRED")
    if upper <= now:
        raise ValueError("AGENT_INSTALLED_RELEASE_EXPIRED_NEW_REVIEW_REQUIRED")
    return min(now + timedelta(hours=24), upper).isoformat()


def bind_api_limits(source: str, *, calls: int, budget_usd: str) -> str:
    """Narrow the existing exact-input request; never broaden the template scope."""
    tree = ast.parse(source)
    matches = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "dict"
        ):
            fields = {key.arg: key for key in node.keywords}
            if {"budget_usd", "max_calls", "incident_id", "evidence_revision"} <= fields.keys():
                matches.append(fields)
    if len(matches) != 1:
        raise ValueError("AGENT_API_EXACT_REQUEST_TEMPLATE_REQUIRED")
    fields = matches[0]
    budget = Decimal(budget_usd)
    if (
        type(calls) is not int
        or not 1 <= calls <= 2
        or calls > ast.literal_eval(fields["max_calls"].value)
        or not budget.is_finite()
        or budget <= 0
        or budget > Decimal(ast.literal_eval(fields["budget_usd"].value))
    ):
        raise ValueError("AGENT_API_TEMPLATE_LIMIT_EXPANSION_FORBIDDEN")
    fields["max_calls"].value = ast.Constant(calls)
    fields["budget_usd"].value = ast.Constant(budget_usd)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + "\n"


def draft(template: Path, parent: Path) -> Path:
    old = verify_review(template, require_active=False)
    expiry = draft_expiry(old["expires_at"], now=datetime.now(UTC))
    namespace_binding(old["namespace"]["target"], template, old)
    directory = parent / "native"
    directory.mkdir(mode=0o700)
    old_parent = template.parent
    # Frozen Git and interpreter remain part of the installed Release, independent
    # of development HEAD. Never copy an editable Source tree or an old runtime.
    shared = (old["frozen_execution_source"], old["dns_runtime"]["directory"])

    def rebind(text: str) -> str:
        for index, path in enumerate(shared):
            text = text.replace(path, f"__SOC_SHARED_{index}__")
        text = text.replace(str(old_parent), str(parent))
        text = text.replace(old["expires_at"], expiry)
        for index, path in enumerate(shared):
            text = text.replace(f"__SOC_SHARED_{index}__", path)
        return text

    def load(name: str) -> dict:
        return json.loads(rebind((template / name).read_text()))

    # These are static candidate files, not runtime sockets, locks or receipts.
    for name in (
        "trial-limit.conf",
        "soc-operations-runtime.service",
        "soc-continuous-tcp-trial.service",
        "soc-continuous-dnsmasq.service",
        "dns-trial-deadline.conf",
        "dnsmasq-source.json",
        "local-dns-probe-image.py",
        "model-manifest.json",
        "deadline-plan.json",
        "collector-service.py",
        "controller-python-binding.json",
        "dns-python-files.json",
        "source-files.json",
        "source-snapshot.tar",
    ):
        target = directory / name
        if name == "source-snapshot.tar":
            shutil.copyfile(template / name, target)
        else:
            target.write_text(rebind((template / name).read_text()))
        target.chmod(0o600)
    # Copy only validated source files. Copying symlinks or untracked extensions
    # would silently add executable content outside the Release file contract.
    sources = json.loads((template / "source-files.json").read_text())
    for name, pin in sources.items():
        target = directory / "export" / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(template / "export" / name, target)
        target.chmod(0o600)
        if sha(target) != pin:
            raise ValueError("AGENT_INSTALLED_SOURCE_CHANGED_DURING_PREPARATION")
    dns_session = prepare_dns(
        directory / "dns-session",
        namespace=old["namespace"]["target"],
        python=Path(shared[1]) / "bin/python",
        seconds=old["dns_service"]["seconds"],
    )
    dns = candidate(
        directory / "dns-session",
        dns_session.namespace,
        sha(directory / "dns-session/session.json"),
    )
    save(directory / "dns-service-candidate.json", dns)
    (directory / "soc-continuous-dns.service").write_text(dns["body"])
    (directory / "soc-continuous-dns.service").chmod(0o600)
    scope = load("scope-input-v2.json")
    scope.update(
        prepared_at=datetime.now(UTC).isoformat(),
        expires_at=expiry,
        review_id=parent.name,
        dns_service=dns,
        status="PENDING_NEW_HUMAN_APPROVAL_AND_POLICY_VALIDITY_RENEWAL",
    )
    scope["risk"]["decision"] = "PENDING_NEW_EXACT_R1_CONFIRMATION"
    scope["ordinary_runtime"]["system_unit_candidate_sha256"] = sha(
        directory / "soc-operations-runtime.service"
    )
    for name in ("scope-input-v2.json", "scope-input.json"):
        save(directory / name, scope)
    policy = load("continuous-installation-v2.json")
    policy.update(
        expires_at=expiry,
        human_review_sha256=sha(directory / "scope-input-v2.json"),
        risk_review_sha256=sha(directory / "scope-input-v2.json"),
    )
    save(directory / "continuous-installation-v2.json", policy)
    cfg = load("runtime-config-v2.json")
    cfg.update(
        input_sha256=sha(directory / "continuous-installation-v2.json"),
        dns_session_sha256=sha(directory / "dns-session/session.json"),
    )
    config = ContinuousConfig.model_validate(cfg)
    for name in ("runtime-config.json", "runtime-config-v2.json"):
        save(directory / name, config.model_dump(mode="json"))
    store = Store.create(directory / "future-runtime", config)
    identity = directory / "future-runtime/code-identity"
    identity.write_text(old["code_identity"])
    identity.chmod(0o600)
    manifest = load("root-install-manifest-v3.json")
    manifest.update(
        approved=False,
        backup_directory="/var/lib/soc-agent/continuous/backups/" + parent.name,
        scope_input_sha256=sha(directory / "scope-input-v2.json"),
    )
    for row in manifest["replacements"]:
        target = Path(row["target"])
        if target.is_symlink():
            raise ValueError("AGENT_ROOT_TARGET_SYMLINK")
        info = target.stat()
        row.update(
            current_sha256=sha(target),
            new_sha256=sha(Path(row["new_source"])),
            current_mode=oct(info.st_mode & 0o777),
            current_inode=info.st_ino,
            current_mtime_ns=info.st_mtime_ns,
            repair_mode=False,
        )
    manifest["installed_file_map_canonical_digest"] = digest(
        {row["target"]: row["new_sha256"] for row in manifest["replacements"]}
    )
    save(directory / "root-install-manifest-v3.json", manifest)
    request = load("approval-request-final-v2.json")
    from soc_agent.agent_native import evidence_directory

    ledger = ledger_snapshot(
        evidence_directory(template)
        / "native-stabilization-batch1/execution-v1/execution-ledger.jsonl"
    )
    # Existing Root trial explicitly fixes the historical Ledger anchor. A changed
    # anchor requires separate reviewed preparation, not silent contract expansion.
    if any(ledger[k] != old["ledger"][k] for k in ("rows", "sha256")):
        raise ValueError("AGENT_INSTALLED_LEDGER_CHANGED_REVIEW_REQUIRED")
    request.update(
        review_id=parent.name,
        prepared_at=scope["prepared_at"],
        expires_at=expiry,
        runtime_session=str(store.database.store_id),
        dns_service=dns,
        root_file_map_release_identity=manifest["installed_file_map_canonical_digest"],
        status="PENDING_NEW_POLICY_ROOT_NATIVE_DNS_R1_APPROVAL",
    )
    for item in request["human_decisions_required"]:
        item["decision"] = "PENDING"
        if "expires_at" in item:
            item["expires_at"] = expiry
        if item["item"].startswith("CONTINUOUS_PASSIVE"):
            item["scope"] = dns
        if "changed_configurations" in item:
            item["changed_configurations"] = sum(
                r["current_sha256"] != r["new_sha256"] for r in manifest["replacements"]
            )
    for row in request["files"].values():
        row["sha256"] = sha(Path(row["path"]))
    save(directory / "approval-request-final-v2.json", request)
    text = (
        "# Installed Research MVP — fresh unapproved execution draft\n\n"
        "All A/B/C decisions PENDING. No authority or receipt inherited.\n\n"
        "A: Direct TTY Scope/R1 and sudo; existing Namespace lo/Ingress only. "
        "Whole deadline 600s, pure capture target 360s. TCP <=4, DNS UDP2/TCP1. "
        "Collector128MiB/25%, Runtime512MiB/50%, Queue32; storage checks256MiB/64MiB. "
        "No external Namespace connection. No automatic retry.\n\n"
        "B: Exact sealed ELIGIBLE jobs, GUI batch human decisions; no future grants.\n\n"
        "C: Exact Incident/Revision GUI approval; Plan/Assessment only, <=2 calls, "
        "20s, no retry; Provider/model unchanged. Costs UNKNOWN if Usage absent.\n\n"
        "Past UNKNOWN/FAILED/UNVERIFIED retained. TCX ACK, Helper CLOSED/final counter/ACK, "
        "Root and Runtime Cleanup need independent proof; Exit0 is insufficient.\n\n"
        "## Exact binding\n\n```json\n"
        + json.dumps(
            {
                key: request[key]
                for key in (
                    "git_commit",
                    "git_tree",
                    "code_identity",
                    "source_sha256",
                    "runtime_session",
                    "expires_at",
                    "namespace",
                    "ledger",
                    "api",
                    "model_action_review",
                )
            },
            indent=2,
        )
        + "\n```\n\n## Root fixed paths\n\n"
    )
    for row in manifest["replacements"]:
        action = "CHANGE" if row["current_sha256"] != row["new_sha256"] else "VERIFY_ONLY"
        text += f"- {row['target']}: {action}; {row['new_sha256']}\n"
    (directory / "approval-package-final.md").write_text(text)
    (directory / "approval-package-final.md").chmod(0o600)
    for name in ("api-scope-proposal.json", "single-approval-integration-scope.json"):
        value = json.loads(rebind((old_parent / name).read_text()))
        for key in ("native_runtime_session", "runtime_session"):
            if key in value:
                value[key] = request["runtime_session"]
        if name == "api-scope-proposal.json":
            value["budget_usd"] = request["api"]["cost_limit"]
            value["max_calls"] = request["api"]["calls"]
        save(parent / name, value)
    replacements = {
        old["runtime_session"]: request["runtime_session"],
        sha(template / "approval-request-final-v2.json"): sha(
            directory / "approval-request-final-v2.json"
        ),
        sha(template / "approval-package-final.md"): sha(directory / "approval-package-final.md"),
    }
    replacements.update(
        {row["sha256"]: request["files"][name]["sha256"] for name, row in old["files"].items()}
    )

    def executable(path: Path, target: Path) -> None:
        text = rebind(path.read_text())
        for before, after in replacements.items():
            text = text.replace(before, after)
        if target.name == "root-trial.py":
            text = bind_installation_scope(text, manifest["replacements"])
        if target.name == "run-api-followup.py":
            text = bind_api_limits(
                text, calls=request["api"]["calls"], budget_usd=request["api"]["cost_limit"]
            )
        if target.suffix == ".py":
            compile(text, str(target), "exec")  # Never import or execute a launcher.
        target.write_text(text)
        target.chmod(0o600)

    execution = directory / "execution"
    execution.mkdir(mode=0o700)
    pins = json.loads((template / "execution/execution-pins.json").read_text())
    for name in pins:
        source = Path(name)
        if source.parent == template / "execution":
            executable(source, execution / source.name)
    api = parent / "llm-review"
    api.mkdir(mode=0o700)
    executable(old_parent / "llm-review/run-retained-api.py", api / "run-retained-api.py")
    new_pins = {rebind(name): sha(Path(rebind(name))) for name in pins}
    save(execution / "execution-pins.json", new_pins)
    return directory
