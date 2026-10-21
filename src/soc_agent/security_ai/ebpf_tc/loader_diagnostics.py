"""Bounded diagnostic journal decoding; no verifier text, syscalls or authority."""

import struct

DETAIL = struct.Struct("<4I2i2I32s4I")
STAGES = (
    "LOAD_PREPARE",
    "OBJECT_OPEN",
    "OBJECT_VERIFY",
    "BPF_OBJECT_LOAD",
    "MAP_INIT",
    "RING_BUFFER_INIT",
    "TCX_ATTACH",
    "CLEANUP",
    "DATA_PLANE",
)
APIS = (
    "soc_validate",
    "soc_environment_contract",
    "soc_release_check",
    "soc_broker_capabilities",
    "fstat",
    "object_size_contract",
    "pread",
    "allocate",
    "bpf_object__open_mem",
    "program_schema_contract",
    "bpf_program__set_autoload",
    "bpf_program__set_expected_attach_type",
    "map_schema_contract",
    "bpf_object__load",
    "bpf_obj_get_info_by_fd(map)",
    "bpf_program__fd",
    "bpf_obj_get_info_by_fd(program)",
    "bpf_object__find_map_fd_by_name",
    "ring_buffer__new",
    "soc_snapshot_tcx",
    "soc_final_drain_counters",
    "object_release",
    "soc_tcx_attach",
    "enable_observation",
    "capture_failure_sticky",
    "soc_tcx_detach",
    "LOAD_REQUESTED_record_and_notification",
    "LOAD_VERIFIED_record_and_notification",
    "send_data",
    "object_fd_closed_check",
)
SOURCES = (
    "CONTRACT_ERRNO_NOT_EXPOSED",
    "SYSCALL_ERRNO",
    "LIBBPF_RETURN",
    "LIBBPF_POINTER",
    "ALLOCATOR_ERRNO",
)


def decode_diagnostic(body: bytes) -> dict:
    if len(body) != DETAIL.size:
        raise ValueError("LOADER_DIAGNOSTIC_SIZE")
    version, stage, api, source, result, saved, flags, size, sha, maps, programs, link, reserved = (
        DETAIL.unpack(body)
    )
    if (
        version != 1
        or not 1 <= stage <= len(STAGES)
        or not 1 <= api <= len(APIS)
        or source >= len(SOURCES)
        or saved < 0
        or saved > 65535
        or source == 0
        and saved != 0
        or flags & ~511
        or size > 65536
        or (not size and any(sha))
        or (size and not any(sha))
        or maps > 3
        or programs > 2
        or link > 1
        or reserved
    ):
        raise ValueError("LOADER_DIAGNOSTIC_SCHEMA")
    return dict(
        stage=STAGES[stage - 1],
        api=APIS[api - 1],
        return_value=result,
        saved_errno=saved if source else None,
        error_source=SOURCES[source],
        resources=flags,
        fd_inventory_available=bool(flags & 256),
        map_fds_observed=maps if flags & 256 else None,
        program_fds_observed=programs if flags & 256 else None,
        link_fd_observed=bool(link),
        kernel_load_api_called=bool(flags & 16),
        owned_object_released=bool(flags & 32),
        kernel_log_bytes=size,
        kernel_log_sha256=sha.hex() if size else None,
        kernel_log_scope="LIBBPF_SHARED_BTF_OR_PROGRAM_LOG_LAST_CONTENTS",
        kernel_log_at_bound=bool(flags & 128),
        raw_kernel_log_retained=False,
    )
