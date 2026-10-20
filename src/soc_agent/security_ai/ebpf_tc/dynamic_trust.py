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
    nss: NSSPolicy
    libc_version: str = Field(max_length=64)
    builtin_source: Literal["GLIBC_FILES_DNS_SOURCE_NOT_RUNTIME_PROOF"] = (
        "GLIBC_FILES_DNS_SOURCE_NOT_RUNTIME_PROOF"
    )
    pam_service: Literal["soc-agent-ebpf"] = "soc-agent-ebpf"
    pam_modules: tuple[str, ...] = Field(min_length=1, max_length=1)
    nss_modules: tuple[str, ...] = Field(max_length=64)
    unresolved_nss_services: tuple[str, ...] = Field(max_length=64)
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
    identities = {
        name: elf_identity(bodies[name]) for name in ("bootstrap", "broker", "libnative-tc.so")
    }
    if any(
        not x.bind_now or not x.relro or x.executable_stack is not False
        for x in identities.values()
    ):
        raise ValueError("ELF_HARDENING_REQUIRED")
    return DynamicTrust(
        elf=identities,
        nss=policy,
        libc_version=os.confstr("CS_GNU_LIBC_VERSION") or "UNKNOWN",
        pam_modules=(pam,),
        nss_modules=tuple(sorted(modules)),
        unresolved_nss_services=tuple(sorted(missing)),
    )
