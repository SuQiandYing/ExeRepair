"""Build-independent discovery for the Enigma native-call repair adapter.

This module is deliberately offline.  It identifies the stable Enigma/PE
structure and binds separately collected runtime evidence to that structure.
The process-spawning adapter lives under ``exerepair.adapters`` so static
inspection never starts a target executable.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
import struct

from ..domain.recovery import NativeCallProfile, RecoveryError
from ..formats.enigma import (
    EnigmaFormatError,
    PEImage,
    bcj_transform,
    decode_enigma_bootstrap,
    extract_enigma_engine,
)


_BOOTSTRAP_ENGINE = re.compile(
    rb"\x68(.{4})\x68(.{4})\x01\x2C\x24(?:\x68.{4}|\x51)\xE8",
    re.DOTALL,
)


def _u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _locate_dispatch(engine: bytes, pe: PEImage) -> tuple[int, int]:
    """Find the unique dispatch-table load in an unpacked Enigma engine."""
    base = pe.image_base
    candidates: list[tuple[int, int]] = []
    for section in pe.sections:
        start = section.raw_offset
        end = min(section.raw_offset + section.raw_size, len(engine))
        for offset in range(start, max(start, end - 16)):
            if engine[offset] != 0xA1:
                continue
            global_address = _u32(engine, offset + 1)
            if not base <= global_address < base + pe.size_of_image:
                continue
            if engine[offset + 5:offset + 8] != b"\x8B\x1C\xB0":
                continue
            if engine[offset + 8:offset + 10] != b"\x03\x1D":
                continue
            second_address = _u32(engine, offset + 10)
            if second_address != global_address - 4:
                continue
            if engine[offset + 14:offset + 16] != b"\x8B\x03":
                continue
            dispatch_rva = section.virtual_address + offset - section.raw_offset
            global_rva = global_address - base
            try:
                code_section = pe.section_for_rva(dispatch_rva)
                global_section = pe.section_for_rva(global_rva - 4)
            except EnigmaFormatError:
                continue
            if not code_section.characteristics & 0x20000000:
                continue
            if not global_section.characteristics & 0x80000000:
                continue
            candidates.append((dispatch_rva, global_rva))
    if len(candidates) != 1:
        raise RecoveryError(
            f"通用 Enigma 调度入口候选数为 {len(candidates)}；拒绝猜测"
        )
    return candidates[0]


def _locate_relocation(engine: bytes, pe: PEImage, target_rva: int) -> int:
    """Return the file offset of the HIGHLOW entry for one instruction operand."""
    nt = _u32(engine, 0x3C)
    relocation_rva = _u32(engine, nt + 24 + 96 + 5 * 8)
    position = pe.rva_to_offset(relocation_rva)
    while position + 8 <= len(engine):
        page, size = struct.unpack_from("<II", engine, position)
        if page == 0 and size == 0:
            break
        if size < 8 or size % 2 or position + size > len(engine):
            raise RecoveryError("Enigma 重定位块范围无效")
        for entry in range(position + 8, position + size, 2):
            value = struct.unpack_from("<H", engine, entry)[0]
            if value >> 12 == 3 and page + (value & 0xFFF) == target_rva:
                return entry
        position += size
    raise RecoveryError("没有找到调度指令操作数的 HIGHLOW 重定位记录")


def _locate_bootstrap_pairs(
    bootstrap_image: bytes,
    pe: PEImage,
    entry_offset: int,
    packed_size: int,
    source_rva: int,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Find all duplicated engine-capacity/source-RVA operands.

    The operands are accepted only when they are part of Enigma's complete
    engine-package push sequence.  This avoids treating an unrelated integer
    in a changed bootstrap as a repair location.
    """
    entry_section = pe.section_for_rva(pe.entry_rva)
    scan_end = min(
        entry_section.raw_offset + entry_section.raw_size,
        entry_offset + 0x10000,
        len(bootstrap_image),
    )
    region = bootstrap_image[entry_offset:scan_end]
    size_offsets: list[int] = []
    source_offsets: list[int] = []
    expected_size = struct.pack("<I", packed_size)
    expected_source = struct.pack("<I", source_rva)
    for match in _BOOTSTRAP_ENGINE.finditer(region):
        if match.group(1) != expected_size or match.group(2) != expected_source:
            continue
        position = entry_offset + match.start() + 1
        size_offsets.append(position - entry_offset)
        source_offsets.append(position + 5 - entry_offset)
    if not size_offsets:
        raise RecoveryError("未找到引导层中的引擎容量/RVA 参数对")
    return tuple(size_offsets), tuple(source_offsets)


def _locate_engine_base(pe: PEImage, engine_pe: PEImage) -> int:
    candidates = [
        section.virtual_address
        for section in pe.sections
        if section.virtual_size == engine_pe.size_of_image
        and section.virtual_address
        and section.characteristics & 0x20000000
    ]
    if len(candidates) != 1:
        raise RecoveryError(
            f"外层 PE 中与引擎镜像等大的运行区候选数为 {len(candidates)}；拒绝猜测"
        )
    return candidates[0]


def discover_native_static(data: bytes) -> NativeCallProfile:
    """Discover all static fields except the unpacked outer guard call."""
    try:
        outer_pe = PEImage.parse(data)
        bootstrap = decode_enigma_bootstrap(data, outer_pe)
        analysis, _container_offset, encoded_engine = extract_enigma_engine(
            data, outer_pe, bootstrap
        )
        decoded_engine = bcj_transform(encoded_engine, encode=False)
        engine_pe = PEImage.parse(decoded_engine)
        dispatch_rva, dispatch_global_rva = _locate_dispatch(
            decoded_engine, engine_pe
        )
        relocation_offset = _locate_relocation(
            decoded_engine, engine_pe, dispatch_rva + 1
        )
        size_offsets, source_offsets = _locate_bootstrap_pairs(
            bootstrap.decoded_image,
            outer_pe,
            bootstrap.entry_offset,
            analysis.packed_size,
            analysis.source_rva,
        )
        engine_base_delta = _locate_engine_base(outer_pe, engine_pe)
    except (EnigmaFormatError, struct.error, IndexError) as error:
        raise RecoveryError(
            f"无法从样本结构发现通用 Enigma 原生调用适配：{error}"
        ) from error
    return NativeCallProfile(
        name=f"enigma-{bootstrap.version}-native-call-candidate",
        baseline_sha256=hashlib.sha256(data).hexdigest(),
        baseline_size=len(data),
        engine_sha256=hashlib.sha256(encoded_engine).hexdigest(),
        engine_base_delta=engine_base_delta,
        dispatch_rva=dispatch_rva,
        dispatch_global_rva=dispatch_global_rva,
        relocation_offset=relocation_offset,
        guard_rva=0,
        call_rva=0,
        guard_bytes=b"",
        bootstrap_size_offsets=size_offsets,
        bootstrap_source_offsets=source_offsets,
        requires_runtime_discovery=True,
    )


def bind_runtime_evidence(
    static: NativeCallProfile,
    data: bytes,
    evidence: dict,
) -> NativeCallProfile:
    """Bind one semantically checked runtime candidate to static structure."""
    if not static.requires_runtime_discovery:
        return static
    if not isinstance(evidence, dict):
        raise RecoveryError("运行时原生调用证据不是对象")
    if evidence.get("candidate_count") != 1:
        raise RecoveryError("运行时原生调用候选不是唯一结果")
    if evidence.get("export") != "executeAPI":
        raise RecoveryError("运行时候选未绑定到 executeAPI 导出")
    if str(evidence.get("module_name", "")).lower() != "plugin.dll":
        raise RecoveryError("运行时候选未绑定到 plugin.dll")
    try:
        pe = PEImage.parse(data)
        guard_rva = int(evidence["guard_rva"])
        call_rva = int(evidence["call_rva"])
        return_rva = int(evidence["return_rva"])
        main_base = int(evidence["main_base"], 0) if isinstance(
            evidence["main_base"], str
        ) else int(evidence["main_base"])
        guard_bytes = bytes.fromhex(str(evidence["guard_bytes"]))
    except (EnigmaFormatError, KeyError, TypeError, ValueError) as error:
        raise RecoveryError("运行时原生调用证据不可解析") from error
    if pe.bitness != 32 or main_base != pe.image_base:
        raise RecoveryError("运行时原生调用证据的映像基址不匹配")
    if call_rva != guard_rva + 5 or return_rva != guard_rva + 7:
        raise RecoveryError("运行时原生调用证据的 CALL/返回地址不连续")
    if (
        len(guard_bytes) != 10
        or guard_bytes[0] != 0x68
        or guard_bytes[5:7] != b"\xff\xd0"
        or guard_bytes[7:10] != b"\x83\xc4\x04"
    ):
        raise RecoveryError("运行时原生调用证据不是完整的 CALL EAX 保护序列")
    try:
        section = pe.section_for_rva(guard_rva)
    except EnigmaFormatError as error:
        raise RecoveryError("运行时原生调用位置不在外层 PE 节内") from error
    if (
        guard_rva + len(guard_bytes)
        > section.virtual_address + section.virtual_size
        or not section.characteristics & 0x80000000
    ):
        raise RecoveryError("运行时原生调用位置不在经过验证的可写节内")
    return replace(
        static,
        guard_rva=guard_rva,
        call_rva=call_rva,
        guard_bytes=guard_bytes,
        requires_runtime_discovery=False,
    )


def _cache_path(work_dir: Path) -> Path:
    return work_dir / "native-discovery.json"


def load_native_cache(
    static: NativeCallProfile, data: bytes, work_dir: Path,
) -> tuple[NativeCallProfile | None, dict | None]:
    """Load a cache only after rebinding its evidence to the current bytes."""
    path = _cache_path(work_dir)
    try:
        cache = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None, None
    if cache.get("format") != "exerepair.native-discovery.v2":
        return None, cache
    if cache.get("baseline_sha256") != static.baseline_sha256:
        return None, cache
    expected = {
        "engine_sha256": static.engine_sha256,
        "engine_base_delta": static.engine_base_delta,
        "dispatch_rva": static.dispatch_rva,
        "dispatch_global_rva": static.dispatch_global_rva,
        "relocation_offset": static.relocation_offset,
        "bootstrap_size_offsets": list(static.bootstrap_size_offsets),
        "bootstrap_source_offsets": list(static.bootstrap_source_offsets),
    }
    if any(cache.get(key) != value for key, value in expected.items()):
        return None, cache
    evidence = cache.get("evidence")
    if not isinstance(evidence, dict):
        return None, cache
    try:
        return bind_runtime_evidence(static, data, evidence), cache
    except RecoveryError:
        return None, cache


def save_native_cache(
    path_root: Path,
    profile: NativeCallProfile,
    source: Path,
    evidence: dict,
) -> None:
    payload = {
        "format": "exerepair.native-discovery.v2",
        "source": str(source),
        "baseline_sha256": profile.baseline_sha256,
        "outer_pe_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "engine_sha256": profile.engine_sha256,
        "engine_base_delta": profile.engine_base_delta,
        "dispatch_rva": profile.dispatch_rva,
        "dispatch_global_rva": profile.dispatch_global_rva,
        "relocation_offset": profile.relocation_offset,
        "bootstrap_size_offsets": list(profile.bootstrap_size_offsets),
        "bootstrap_source_offsets": list(profile.bootstrap_source_offsets),
        "evidence": evidence,
    }
    path = _cache_path(path_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
