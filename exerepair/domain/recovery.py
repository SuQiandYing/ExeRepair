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
class RecoveredPayload:
    spec: PayloadSpec
    data: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class RepairInspection:
    source_path: Path
    profile: RepairProfile | NativeCallProfile
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
