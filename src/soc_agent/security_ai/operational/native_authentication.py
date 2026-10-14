"""Conservative journal authentication projection; no raw messages retained downstream."""

import re
from ipaddress import ip_address
from typing import Literal
from uuid import UUID

from soc_agent.realtime.collectors import (
    CollectorUnavailable,
    CursorUnavailable,
    LinuxJournalCollector,
    bounded_command,
)
from soc_agent.realtime.models import CommonEvent
from soc_agent.security_ai.authentication.aggregation import AuthenticationEvent
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.security_ai.operational.provenance import (
    OperationalProvenanceReceipt,
    build_receipt,
)
from soc_agent.security_ai.operational.source_records import AuthenticationSource, SourceHeader
from soc_agent.security_ai.operational.source_store import (
    OperationalSourceStore,
    SourceAdmission,
)
from soc_agent.state.evidence import utc_now

FIELDS = (
    "__CURSOR",
    "__REALTIME_TIMESTAMP",
    "_MACHINE_ID",
    "_COMM",
    "_EXE",
    "_UID",
    "SYSLOG_IDENTIFIER",
    "PRIORITY",
    "MESSAGE",
)
PROFILE = "openssh-auth-log:v1"
COLLECTOR = "journald-auth:v1"
PAM_COLLECTOR = "journald-auth-pam-failure:v1"
SCENARIO_COLLECTOR = "scenario-auth-pam:v1"
SCENARIO_IDENTITY = "scenario:authentication:v1"
PAM_PROFILE = "pam-unix-sudo-auth-failure:v1"
_PAM_FAILURE = re.compile(
    r"pam_unix\(sudo:auth\): authentication failure; "
    r"logname=[^\s;]{0,99} uid=(?P<uid>[0-9]{1,10}) euid=0 "
    r"tty=[^\s;]{0,128} ruser=[^\s;]{0,99} rhost=  "
    r"user=(?P<user>[A-Za-z0-9_.@-]{1,99})\Z"
)
# OpenSSH V_8_9_P1 auth.c::auth_log; only final Accepted/Failed, no PAM sessions.
_AUTH = re.compile(
    r"(?P<result>Accepted|Failed) (?P<method>password|publickey|keyboard-interactive/pam) "
    r"for (?P<invalid>invalid user )?(?P<user>[A-Za-z0-9_.@-]{1,99}) "
    r"from (?P<address>[0-9A-Fa-f:.]+) port (?P<port>[0-9]{1,5}) ssh2"
    r"(?:: [^\r\n]{1,1024})?\Z"
)


def project_journal(row: dict[str, object], *, include_pam_failures: bool = False) -> CommonEvent:
    """Parse a reviewed format; this function alone does not attest native origin."""
    if type(include_pam_failures) is not bool:
        raise CollectorUnavailable("Invalid authentication parser option")
    if type(row) is not dict:
        raise CollectorUnavailable("Invalid authentication journal record")
    retained = {k: row[k] for k in FIELDS if k in row}
    if any(type(v) is not str or len(v) > 4096 for v in retained.values()):
        raise CollectorUnavailable("Non-scalar or oversized authentication journal record")
    if re.fullmatch(r"[0-9]{1,20}", retained.get("__REALTIME_TIMESTAMP", "")) is None:
        raise CollectorUnavailable("Invalid authentication journal timestamp")
    event = LinuxJournalCollector.parse(retained)
    raw_digest = content_digest_payload(retained)
    fields = [("raw_record_digest", raw_digest), ("parse_status", "NOT_INFERABLE")]
    # _EXE/_UID/_COMM are journal-added fields; SYSLOG_IDENTIFIER alone is not trusted.
    trusted = (retained.get("_EXE"), retained.get("_UID"), retained.get("_COMM")) == (
        "/usr/sbin/sshd",
        "0",
        "sshd",
    )
    match = _AUTH.fullmatch(retained.get("MESSAGE", "")) if trusted else None
    if match is not None:
        try:
            address = ip_address(match["address"])
            port = int(match["port"])
            if not 1 <= port <= 65535 or (match["result"] == "Accepted" and match["invalid"]):
                raise ValueError
        except ValueError:
            match = None
    if match is not None:
        # Stable pseudonymous account scoped to machine. Failed account is an attempted
        # account assertion, not proof that this user exists or authenticated successfully.
        account = content_digest_payload(
            {"machine": retained["_MACHINE_ID"], "user": match["user"]}
        )
        remote = content_digest_payload(
            {"machine": retained["_MACHINE_ID"], "address": str(address)}
        )
        fields = [
            ("raw_record_digest", raw_digest),
            ("parse_status", "MAPPED_AUTHENTICATION"),
            ("parser", PROFILE),
            ("account_id", account),
            ("source_identifier", remote),
            ("authentication_result", "success" if match["result"] == "Accepted" else "failure"),
        ]
    if (
        include_pam_failures
        and match is None
        and (retained.get("_EXE"), retained.get("_COMM")) == ("/usr/bin/sudo", "sudo")
    ):
        pam = _PAM_FAILURE.fullmatch(retained.get("MESSAGE", ""))
        # Sudo is setuid: journal real UID need not be root. Bind the explicit
        # logged UID to the kernel-added UID; do not weaken the SSH root rule.
        if pam is not None and pam["uid"] == retained.get("_UID"):
            account = content_digest_payload(
                {
                    "machine": retained["_MACHINE_ID"],
                    "service": "sudo:pam_unix",
                    "user": pam["user"],
                }
            )
            origin = content_digest_payload(
                {"machine": retained["_MACHINE_ID"], "local_caller_uid": pam["uid"]}
            )
            fields = [
                ("raw_record_digest", raw_digest),
                ("parse_status", "MAPPED_AUTHENTICATION"),
                ("parser", PAM_PROFILE),
                ("account_id", account),
                ("source_identifier", origin),
                ("authentication_result", "failure"),
            ]
    return CommonEvent.model_validate(
        event.model_dump()
        | {
            "collector_id": PAM_COLLECTOR if include_pam_failures else COLLECTOR,
            "normalized_fields": tuple(fields),
        }
    )


class LinuxAuthenticationCollector:
    identity = "linux:journal:authentication:v1"

    def __init__(self, *, include_pam_failures: bool = False) -> None:
        if type(include_pam_failures) is not bool:
            raise CollectorUnavailable("Invalid authentication parser option")
        self.include_pam_failures = include_pam_failures
        self.collector_id = PAM_COLLECTOR if include_pam_failures else COLLECTOR
        if include_pam_failures:
            self.identity = "linux:journal:authentication:pam-failure:v1"
        self.native = LinuxJournalCollector()

    def poll(self, cursor: CommonEvent | None = None, limit: int = 16) -> list[CommonEvent]:
        import json

        if type(limit) is not int or not 1 <= limit <= 256:
            raise CollectorUnavailable("Invalid authentication batch limit")
        base = [
            self.native.command,
            "--no-pager",
            "--quiet",
            "--output=json",
            "--output-fields=" + ",".join(FIELDS),
        ]
        # Read only auth/authpriv facilities OR sshd records. Other PAM/session records
        # stay NOT_INFERABLE; no broad journal MESSAGE collection.
        filters = ["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", "+", "_COMM=sshd"]
        if cursor is not None:
            if (
                cursor.collector_id != self.collector_id
                or cursor.source.namespace != "systemd-journal"
            ):
                raise CursorUnavailable("Authentication cursor binding mismatch")
            probe = bounded_command(
                base + ["--cursor=" + cursor.source.record, "--lines=+1"] + filters
            )
            lines = probe.splitlines()
            if (
                not lines
                or project_journal(
                    json.loads(lines[0]), include_pam_failures=self.include_pam_failures
                ).source_digest
                != cursor.source_digest
            ):
                raise CursorUnavailable("Authentication journal cursor changed or expired")
            base += ["--after-cursor=" + cursor.source.record]
        data = bounded_command(base + [f"--lines=+{limit}"] + filters)
        try:
            rows = [
                project_journal(json.loads(line), include_pam_failures=self.include_pam_failures)
                for line in data.splitlines()
            ]
        except (ValueError, TypeError) as error:
            raise CollectorUnavailable("Authentication journal response rejected") from error
        if len(rows) > limit:
            raise CollectorUnavailable("Authentication batch response exceeded limit")
        return rows


class NativeAuthenticationReceipt(Snapshot):
    contract_version: Literal["soc-native-authentication-link:v1"] = (
        "soc-native-authentication-link:v1"
    )
    incident_id: UUID
    event_id: UUID
    native_projection_digest: Hash
    raw_record_digest: Hash
    authentication_source_digest: Hash
    admission: SourceAdmission
    provenance: OperationalProvenanceReceipt
    window_provenance: tuple[OperationalProvenanceReceipt, ...] = ()
    inference_status: Literal["NOT_INFERABLE"] = "NOT_INFERABLE"
    write_disposition: Literal["WRITE_DENIED"] = "WRITE_DENIED"


def authentication_source(
    event: CommonEvent,
    *,
    expected_event_digest: str,
    incident_id: UUID,
) -> AuthenticationSource | None:
    """Pure checked conversion; hash linkage does not attest native origin."""
    event = CommonEvent.model_validate(event.model_dump())
    if event.source_digest != expected_event_digest:
        raise ValueError("NATIVE_AUTH_PROJECTION_DIGEST_MISMATCH")
    fixture = (
        event.platform == "validated_fixture"
        and event.provenance == "explicit_log_fixture"
        and event.collector_id == SCENARIO_COLLECTOR
        and event.schema_version == "soc-common-event:v2"
    )
    native = event.platform == "linux" and event.collector_id in (COLLECTOR, PAM_COLLECTOR)
    if not (fixture or native) or event.event_type != "os_record":
        raise ValueError("NATIVE_AUTH_COLLECTOR_MISMATCH")
    fields = dict(event.normalized_fields)
    if re.fullmatch(r"[0-9a-f]{64}", fields.get("raw_record_digest", "")) is None:
        raise ValueError("NATIVE_AUTH_REFERENCE_REJECTED")
    if (
        set(fields) == {"raw_record_digest", "parse_status"}
        and fields["parse_status"] == "NOT_INFERABLE"
    ):
        return None
    if set(fields) != {
        "raw_record_digest",
        "parse_status",
        "parser",
        "account_id",
        "source_identifier",
        "authentication_result",
    } or (
        fields["parser"]
        not in (
            (PROFILE, PAM_PROFILE)
            if event.collector_id in (PAM_COLLECTOR, SCENARIO_COLLECTOR)
            else (PROFILE,)
        )
        or fields["parse_status"] != "MAPPED_AUTHENTICATION"
    ):
        raise ValueError("NATIVE_AUTH_PROJECTION_CONTRACT_REJECTED")
    for name in ("raw_record_digest", "account_id", "source_identifier"):
        if re.fullmatch(r"[0-9a-f]{64}", fields[name]) is None:
            raise ValueError("NATIVE_AUTH_REFERENCE_REJECTED")
    if fields["parser"] == PAM_PROFILE and fields["authentication_result"] != "failure":
        raise ValueError("PAM_FAILURE_PROFILE_RESULT_MISMATCH")
    source = AuthenticationSource(
        header=SourceHeader(
            incident_id=incident_id,
            event_id=str(event.event_id),
            source=event.source,
            collector_id=event.collector_id,
            collector_version="1.0.0",
            observed_at=event.event_timestamp,
        ),
        event=AuthenticationEvent(
            event_id=str(event.event_id),
            event_time=event.event_timestamp,
            account_id=fields["account_id"],
            source_identifier=fields["source_identifier"],
            authentication_result=fields["authentication_result"],
        ),
    )
    return source


def ingest_authentication(
    event: CommonEvent,
    *,
    expected_event_digest: str,
    store: OperationalSourceStore,
    incident_id: UUID,
) -> NativeAuthenticationReceipt | None:
    source = authentication_source(
        event, expected_event_digest=expected_event_digest, incident_id=incident_id
    )
    if source is None:
        return None
    admission = store.ingest(
        source,
        expected_incident=incident_id,
        expected_source_digest=source.content_digest,
        received_at=utc_now(),
    )
    windows = tuple(
        w for w in store.windows(incident_id) if str(event.event_id) in w.window.event_ids
    )
    with store.database.transaction(write=False) as connection:
        rows = connection.execute(
            "SELECT * FROM operational_sources WHERE incident_id=?", (str(incident_id),)
        ).fetchall()
        retained_sources = {item.content_digest: item for item in (store._decode(r) for r in rows)}
    window_provenance = tuple(
        build_receipt(
            store,
            incident_id=incident_id,
            sources=tuple(retained_sources[d] for d in w.source_digests),
            authentication=w,
        )
        for w in windows
    )
    return NativeAuthenticationReceipt(
        incident_id=incident_id,
        event_id=event.event_id,
        native_projection_digest=event.source_digest,
        raw_record_digest=dict(event.normalized_fields)["raw_record_digest"],
        authentication_source_digest=source.content_digest,
        admission=admission,
        provenance=build_receipt(store, incident_id=incident_id, sources=(source,)),
        window_provenance=window_provenance,
    )
