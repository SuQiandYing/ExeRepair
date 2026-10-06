"""Immutable repair contracts. No file I/O, runtime handles or secret reprs."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


class RecoveryError(ValueError):
    """Unsupported identity, invalid evidence or an incomplete repair."""


@dataclass(frozen=True, slots=True)
class PayloadSpec:
    source_rva: int
    source_offset: int
    size: int
    flags: int
    crc32: int
    clear_sha256: str


@dataclass(frozen=True, slots=True)
class RepairProfile:
    name: str
    baseline_sha256: str
    baseline_size: int
    engine_sha256: str
    engine_base_delta: int
    vm_table_offset: int
    vm_table_count: int
    payloads: tuple[PayloadSpec, ...]
    dialog_index: int = 0x26DE
    dialog_destination: int = 0x26E2
    predicate_index: int = 0x4AD3
    true_index: int = 0x153
    ksa_index: int = 0x489F
    prga_index: int = 0x48A6
    ksa_operand: int = 0x668A4
    prga_operand: int = 0x667E0


@dataclass(frozen=True, slots=True)
class NativeCallProfile:
    """Native call repair profile.

    Known samples may populate this from the fast identity cache.  Unknown
    samples can be represented by a structurally verified candidate whose
    runtime call site is still pending discovery.
    """
    name: str
    baseline_sha256: str
    baseline_size: int
    engine_sha256: str
    engine_base_delta: int
    dispatch_rva: int
    dispatch_global_rva: int
    relocation_offset: int
    guard_rva: int
    call_rva: int
    guard_bytes: bytes
    bootstrap_size_offsets: tuple[int, ...]
    bootstrap_source_offsets: tuple[int, ...]
    payloads: tuple[PayloadSpec, ...] = field(default=(), init=False)
    requires_runtime_discovery: bool = False


@dataclass(frozen=True, slots=True)
class PortableSetupProfile:
    """Guarded setup calls using an engine-owned UTF-16 directory string.

    Each site is (RVA, original bytes). Query callers pass the destination in
    ECX and retain ownership of their stack argument. assign_string copies a
    24-byte engine string (callee pops 8); assign_text copies UTF-16 code units
    from EAX into the ESI destination (callee pops 4). These ABIs must be proven
    for the exact input identity; this is not a general registry API shim.
    """
    key_check: tuple[int, bytes]
    directory_queries: tuple[tuple[int, bytes], ...]
    setup_query: tuple[int, bytes]
    directory_object_rva: int
    assign_string: tuple[int, bytes]
    assign_text: tuple[int, bytes]
    installed_value: str = "full"


@dataclass(frozen=True, slots=True)
class DiscCheckProfile:
    """Exact-build late-loaded disc-check sites, independent of file names."""
    name: str
    baseline_sha256: str
    baseline_size: int
    image_base: int
    entry_rva: int
    entry_bytes: bytes
    module_image_size: int
    caller_return_rva: int
    caller_guard: bytes
    return_rva: int
    return_guard: bytes
    success_flag_rva: int
    region_ready_rva: int | None = None
    region_ready_bytes: bytes = b""
    region_patch_sites: tuple[tuple[int, bytes, bytes], ...] = ()
    # Exact runtime setup/installation-gate patches in the wrapper image.
    # These are process-local byte changes; they do not write the host
    # registry and are intentionally separate from the V1 dispatch shim.
    setup_patch_sites: tuple[tuple[int, bytes, bytes], ...] = ()
    # Optional process-local registry compatibility.  These fields describe
    # only an exact, already-identified dispatch table; they do not authorize
    # writes to the host registry.
    registry_open_slot_rva: int | None = None
    registry_query_slot_rva: int | None = None
    registry_key_prefix: bytes = b""
    registry_value_names: tuple[bytes, ...] = ()
    registry_ready_rva: int | None = None
    registry_ready_bytes: bytes = b""
    allow_dynamic_base_without_relocations: bool = False
    portable_setup: PortableSetupProfile | None = None
    payloads: tuple[PayloadSpec, ...] = field(default=(), init=False)


@dataclass(frozen=True, slots=True)
class RecoveredPayload:
    spec: PayloadSpec
    data: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class RepairInspection:
    source_path: Path
    profile: RepairProfile | NativeCallProfile | DiscCheckProfile
    entry_rva: int
    image_base: int
    size_of_image: int
    section_count: int


@dataclass(frozen=True, slots=True)
class RepairResult:
    output_path: Path
    output_sha256: str
    diff_path: Path
    verification_path: Path
    rollback_path: Path
    recovered_payload_count: int
    original_unchanged: bool
