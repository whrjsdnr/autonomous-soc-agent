"""Static dynamic-loading evidence, never authentication or Native admission.

NSS actions/order are preserved as configuration, not reimplemented lookup logic.
A missing DSO, runtime helper, mapped image or Native probe cannot become VERIFIED.
"""

import hashlib
import os
import re
from pathlib import Path
from typing import Literal

from pydantic import Field

from soc_agent.review.models import Hash
from soc_agent.security_ai.research.models import Frozen


class NSSPolicy(Frozen):
    databases: dict[str, tuple[str, ...]]
    services: tuple[str, ...] = Field(max_length=64)
    direct_identity_databases: tuple[Literal["passwd"], ...] = ("passwd",)
    pam_account_databases: tuple[Literal["shadow"], ...] = ("shadow",)
    scope_policy: Literal["ROLE_SCOPED_AUTH_PASSWD_SHADOW_BROKER_NUMERIC"] = (
        "ROLE_SCOPED_AUTH_PASSWD_SHADOW_BROKER_NUMERIC"
    )
    source: Literal["STATIC_CONFIG_NOT_LOOKUP"] = "STATIC_CONFIG_NOT_LOOKUP"


def nss_policy(body: bytes) -> NSSPolicy:
    if len(body) > 16384 or b"\0" in body or b"\\" in body:
        raise ValueError("NSS_CONFIGURATION_INVALID")
    rows = {}
    services = set()
    for line in body.decode("ascii").splitlines():
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        database, separator, tail = text.partition(":")
        if not separator or not re.fullmatch(r"[a-z_]{1,32}", database) or database in rows:
            raise ValueError("NSS_CONFIGURATION_INVALID")
        tokens = re.findall(r"\[[^\]]*\]|\S+", tail)
        if not 1 <= len(tokens) <= 16 or len(rows) >= 32:
            raise ValueError("NSS_CONFIGURATION_BOUND")
        for token in tokens:
            if token.startswith("["):
                if not re.fullmatch(r"\[(?:!?[A-Z]+=(?:return|continue|merge)\s*)+\]", token):
                    raise ValueError("NSS_ACTION_UNSUPPORTED")
            elif re.fullmatch(r"[a-z][a-z0-9_]{0,31}", token):
                services.add(token)
            else:
                raise ValueError("NSS_SERVICE_INVALID")
        rows[database] = tuple(tokens)
    if not {"passwd", "group", "shadow"} <= set(rows) or len(services) > 64:
        raise ValueError("NSS_ACCOUNT_DATABASE_MISSING")
    return NSSPolicy(databases=rows, services=tuple(sorted(services)))


class ELFIdentity(Frozen):
    sha256: Hash
    needed: tuple[str, ...] = Field(max_length=32)
    interpreter: str | None
    soname: str | None
    imports: tuple[str, ...] = Field(max_length=512)
    bind_now: bool
    relro: bool
    executable_stack: bool | None
    source: Literal["STATIC_READELF_NOT_EXECUTED"] = "STATIC_READELF_NOT_EXECUTED"


def elf_identity(body: bytes) -> ELFIdentity:
    from soc_agent.security_ai.ebpf_tc.dependencies import elf_metadata, inspect_elf, soname

    needed, interpreter = elf_metadata(body)
    text = inspect_elf(body, symbols=True)
    imports = tuple(sorted(set(re.findall(r"\bUND\s+([A-Za-z_][A-Za-z0-9_]*)(?:@|\s|$)", text))))
    stack = next((line for line in text.splitlines() if "GNU_STACK" in line), None)
    return ELFIdentity(
        sha256=hashlib.sha256(body).hexdigest(),
        needed=needed,
        interpreter=interpreter,
        soname=soname(body),
        imports=imports,
        bind_now="BIND_NOW" in text,
        relro="GNU_RELRO" in text,
        executable_stack=bool(re.search(r"\bRWE\b", stack)) if stack else None,
    )


class DynamicTrust(Frozen):
    contract: Literal["soc-pam-nss-static-trust:v1"] = "soc-pam-nss-static-trust:v1"
    elf: dict[str, ELFIdentity]
    static_entry_sha256: Hash
    static_entry_contract: Literal["X86_64_EXEC_NO_INTERPRETER_NO_DYNAMIC_SEGMENT_NO_IMPORTS"] = (
        "X86_64_EXEC_NO_INTERPRETER_NO_DYNAMIC_SEGMENT_NO_IMPORTS"
    )
    broker_nss_contract: Literal["NO_DIRECT_NSS_IMPORTS_NUMERIC_AUTHORIZATION"] = (
        "NO_DIRECT_NSS_IMPORTS_NUMERIC_AUTHORIZATION"
    )
    unresolved_required_nss_services: tuple[str, ...] = Field(max_length=64)
    nss: NSSPolicy
    libc_version: str = Field(max_length=64)
    builtin_source: Literal["GLIBC_FILES_DNS_SOURCE_NOT_RUNTIME_PROOF"] = (
        "GLIBC_FILES_DNS_SOURCE_NOT_RUNTIME_PROOF"
    )
    pam_service: Literal["soc-agent-ebpf"] = "soc-agent-ebpf"
    pam_modules: tuple[str, ...] = Field(min_length=1, max_length=1)
    nss_modules: tuple[str, ...] = Field(max_length=64)
    unresolved_nss_services: tuple[str, ...] = Field(max_length=64)
    environment_contract: Literal["NEW_EXEC_FIXED_PATH_LANG_ONLY_AT_SECURE_ENTRY_REQUIRED"] = (
        "NEW_EXEC_FIXED_PATH_LANG_ONLY_AT_SECURE_ENTRY_REQUIRED"
    )
    mapping_contract: Literal["PROCESS_WIDE_EXECUTABLE_SNAPSHOT_NOT_EXECUTION_HISTORY"] = (
        "PROCESS_WIDE_EXECUTABLE_SNAPSHOT_NOT_EXECUTION_HISTORY"
    )
    nss_exclusion_policy: Literal["UNUSED_BY_DIRECT_CODE_IS_NOT_PROOF_UNUSED_BY_PAM"] = (
        "UNUSED_BY_DIRECT_CODE_IS_NOT_PROOF_UNUSED_BY_PAM"
    )
    unresolved_nss_databases: dict[str, tuple[str, ...]]
    loader_search: Literal["STATIC_CANDIDATES_ACTUAL_MAPPINGS_REQUIRE_C_VERIFICATION"] = (
        "STATIC_CANDIDATES_ACTUAL_MAPPINGS_REQUIRE_C_VERIFICATION"
    )
    runtime_closure: Literal["BLOCKED_NATIVE_PAM_NSS_LOADER_NOT_OBSERVED"] = (
        "BLOCKED_NATIVE_PAM_NSS_LOADER_NOT_OBSERVED"
    )
    native_release: Literal["BLOCKED"] = "BLOCKED"


def dependency_trust(bodies: dict[str, bytes], dependencies) -> DynamicTrust:
    from soc_agent.security_ai.ebpf_tc.dependencies import _library, read_held

    policy = nss_policy(read_held(Path("/etc/nsswitch.conf"), owner=0))
    paths = {d.path for d in dependencies}
    modules, missing = [], []
    for service in policy.services:
        if service in {"files", "dns"}:
            continue
        try:
            path = str(_library("libnss_" + service + ".so.2"))
        except ValueError:
            missing.append(service)
            continue
        if path not in paths:
            raise ValueError("NSS_DEPENDENCY_CLOSURE_MISMATCH")
        modules.append(path)
    pam = str(_library("security/pam_unix.so"))
    if pam not in paths:
        raise ValueError("PAM_DEPENDENCY_MISSING")
    required_services = {
        service
        for database in ("passwd", "shadow")
        for service in policy.databases[database]
        if not service.startswith("[")
    }
    entry_text = inspect_entry(bodies["entry"])
    if not entry_text:
        raise ValueError("STATIC_ENTRY_REQUIRED")
    identities = {
        name: elf_identity(bodies[name]) for name in ("bootstrap", "broker", "libnative-tc.so")
    }
    if any(
        not x.bind_now or not x.relro or x.executable_stack is not False
        for x in identities.values()
    ):
        raise ValueError("ELF_HARDENING_REQUIRED")
    forbidden = {
        "getpwnam",
        "getpwnam_r",
        "getpwuid",
        "getpwuid_r",
        "getgrnam",
        "getgrnam_r",
        "getgrgid",
        "getgrgid_r",
        "initgroups",
        "getgrouplist",
        "pam_start",
    }
    if forbidden & set(identities["broker"].imports):
        raise ValueError("BROKER_NUMERIC_IDENTITY_REQUIRED")
    return DynamicTrust(
        elf=identities,
        static_entry_sha256=hashlib.sha256(bodies["entry"]).hexdigest(),
        unresolved_required_nss_services=tuple(sorted(set(missing) & required_services)),
        nss=policy,
        libc_version=os.confstr("CS_GNU_LIBC_VERSION") or "UNKNOWN",
        pam_modules=(pam,),
        nss_modules=tuple(sorted(modules)),
        unresolved_nss_services=tuple(sorted(missing)),
        unresolved_nss_databases={
            database: tuple(service for service in tokens if service in missing)
            for database, tokens in policy.databases.items()
            if any(service in missing for service in tokens)
        },
    )


def inspect_entry(body: bytes) -> bool:
    """Structural ELF proof; never execute inspected bytes or treat it as Root proof."""
    import struct

    from soc_agent.security_ai.ebpf_tc.dependencies import elf_metadata, inspect_elf

    needed, interpreter = elf_metadata(body)
    text = inspect_elf(body, symbols=True)
    return (
        len(body) >= 64
        and body[:6] == b"\x7fELF\x02\x01"
        and struct.unpack_from("<HH", body, 16) == (2, 62)
        and not needed
        and interpreter is None
        and "There is no dynamic section" in text
        and "GNU_STACK" in text
        and not any("GNU_STACK" in line and "RWE" in line for line in text.splitlines())
        and not re.search(r"\bUND\s+[A-Za-z_]", text)
    )
