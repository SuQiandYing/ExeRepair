"""Deterministic target-only runtime-copy repair; no activation state is stored."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import struct
from typing import Callable
import zlib

from ..domain.recovery import RecoveredPayload, RecoveryError, RepairProfile
from ..formats.enigma import (
    PEImage, bcj_transform, decode_enigma_bootstrap, extract_enigma_engine,
)


def sha256(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) // boundary * boundary


def validate_payloads(
    original: bytes, profile: RepairProfile, payloads: tuple[RecoveredPayload, ...]
) -> None:
    if sha256(original) != profile.baseline_sha256 or len(original) != profile.baseline_size:
        raise RecoveryError("原始样本身份不匹配")
    if tuple(p.spec for p in payloads) != profile.payloads:
        raise RecoveryError("恢复载荷集合、顺序或描述符不匹配")
    pe = PEImage.parse(original)
    for payload in payloads:
        spec = payload.spec
        section = pe.section_for_rva(spec.source_rva)
        offset = pe.rva_to_offset(spec.source_rva)
        if offset != spec.source_offset or spec.size <= 0:
            raise RecoveryError("载荷源地址不匹配")
        if offset + spec.size > section.raw_offset + section.raw_size:
            raise RecoveryError("载荷超出原始节的文件范围")
        if len(payload.data) != spec.size:
            raise RecoveryError("恢复载荷大小不匹配")
        if sha256(payload.data) != spec.clear_sha256:
            raise RecoveryError("恢复载荷 SHA-256 不匹配")
        if zlib.crc32(payload.data) != spec.crc32:
            raise RecoveryError("恢复载荷 CRC32 不匹配")


def helper_and_data(payloads: tuple[RecoveredPayload, ...]) -> tuple[bytes, int]:
    """Build PIC code preserving all guest registers and EFLAGS.

    EBX = the original 80-byte descriptor, ESI = its runtime input buffer.
    The PRGA replacement must use RET 8, not RET.
    """
    if not payloads or len({p.spec.source_rva for p in payloads}) != len(payloads):
        raise RecoveryError("运行时复制表必须非空且 source RVA 唯一")
    code = bytearray(b"\x9c\x60\xe8\x00\x00\x00\x00\x5a\x89\xd5")
    call_return = 7
    code += b"\x81\xc2"
    table_displacement = len(code)
    code += bytes(4)
    code += b"\x8b\x43\x10\xb9" + struct.pack("<I", len(payloads))
    loop = len(code)
    code += b"\x3b\x02\x74"
    match_jump = len(code)
    code += b"\x00\x83\xc2\x08\xe2"
    code += bytes([(loop - (len(code) + 1)) & 255])
    code += b"\x61\x9d\xc3"
    match = len(code)
    code[match_jump] = (match - match_jump - 1) & 255
    code += b"\x89\xf7\x8b\x72\x04\x01\xee\x8b\x4b\x08\xfc\xf3\xa4\x61\x9d\xc3"
    no_op = len(code)
    code += b"\xc2\x08\x00"
    table = align(len(code), 16)
    struct.pack_into("<I", code, table_displacement, table - call_return)
    result = code + bytes(table - len(code)) + bytes(len(payloads) * 8)
    for index, payload in enumerate(payloads):
        start = align(len(result), 16)
        result += bytes(start - len(result))
        struct.pack_into("<II", result, table + index * 8,
                         payload.spec.source_rva, start - call_return)
        result += payload.data
    return bytes(result), no_op


def _instruction(engine: bytes | bytearray, profile: RepairProfile, index: int) -> int:
    if not 0 <= index < profile.vm_table_count:
        raise RecoveryError("VM 索引越界")
    table = profile.vm_table_offset
    if table + profile.vm_table_count * 4 > len(engine):
        raise RecoveryError("VM 表超出引擎")
    offset = struct.unpack_from("<I", engine, table + index * 4)[0]
    if offset + 72 > len(engine):
        raise RecoveryError("VM 指令记录越界")
    return offset


def patch_gate(engine: bytes, profile: RepairProfile) -> tuple[bytearray, list[dict]]:
    """Only the verified dialog/predicate edits; useful for bounded capture too."""
    if sha256(engine) != profile.engine_sha256:
        raise RecoveryError("解压引擎身份不匹配")
    decoded = bcj_transform(engine, encode=False)
    if bcj_transform(decoded, encode=True) != engine:
        raise RecoveryError("原引擎 BCJ 往返失败")
    changed = bytearray(decoded)
    edits: list[dict] = []

    def edit(offset: int, old: bytes, new: bytes, symbol: str) -> None:
        if decoded[offset:offset + len(old)] != old or len(old) != len(new):
            raise RecoveryError(f"原始指令字节不匹配：{symbol}")
        changed[offset:offset + len(new)] = new
        edits.append({"symbol": symbol, "engine_offset": hex(offset),
                      "expected_bytes": old.hex(), "replacement_bytes": new.hex()})

    if (profile.dialog_index is None) != (profile.dialog_destination is None):
        raise RecoveryError("可选注册分支配置不完整")
    if profile.dialog_index is not None:
        dialog = _instruction(decoded, profile, profile.dialog_index)
        if struct.unpack_from("<I", decoded, dialog + 28)[0] != profile.dialog_destination:
            raise RecoveryError("注册分支的原目标索引不匹配")
        edit(dialog, struct.pack("<I", 0x2C), struct.pack("<I", 0x2B),
             f"VM[{profile.dialog_index:#x}] JZ -> JMP")
    predicate = _instruction(decoded, profile, profile.predicate_index)
    truth = _instruction(decoded, profile, profile.true_index)
    if predicate != profile.predicate_record_offset or truth != profile.true_record_offset:
        raise RecoveryError("注册谓词及现有 MOV AL,1 指令地址不匹配")
    old_record = struct.pack(
        "<18I", 0x60, 0, 0, 0x8D, 0x28, 0, 0x202000, 0x184, 0x8F,
        0, 0, 0x2000, profile.predicate_return_operand, 0, 0, 0, 0x200000, 0,
    )
    if decoded[predicate:predicate + 72] != old_record:
        raise RecoveryError("待退休谓词 CALL 记录不匹配")
    truth_record = struct.pack(
        "<18I", 0x52, 0, 0, 0x8C, 1, 0, 0x200800, 0, 0x8F,
        0, 0, 0x200800, 1, 0, 0, 0, 0x200000, 0,
    )
    if decoded[truth:truth + 72] != truth_record:
        raise RecoveryError("复用的 MOV AL,1 指令记录不匹配")
    table = profile.vm_table_offset
    pointers = struct.unpack_from(f"<{profile.vm_table_count}I", decoded, table)
    if pointers.count(predicate) != 1:
        raise RecoveryError("原谓词 CALL 存在其他 VM 表引用，不能退休")
    edit(table + profile.predicate_index * 4,
         struct.pack("<I", predicate), struct.pack("<I", truth),
         f"VM table[{profile.predicate_index:#x}] CALL -> existing MOV AL,1")
    edit(predicate, old_record, bytes(72), "retire sole-referenced predicate CALL")
    return changed, edits


def _encrypt_container(engine: bytes, analysis, compressor: Callable[[bytes], bytes]) -> bytes:
    packed = compressor(engine)
    if len(packed) > analysis.packed_size:
        raise RecoveryError(
            f"修改引擎压缩后 {len(packed)} 字节，超过原容器 {analysis.packed_size} 字节；未写出"
        )
    padded = packed + bytes(analysis.packed_size - len(packed))
    return b"".join(
        struct.pack("<I", value[0] ^ analysis.xor_key)
        for value in struct.iter_unpack("<I", padded)
    )


def build_capture_image(
    original: bytes, profile: RepairProfile, compressor: Callable[[bytes], bytes]
) -> bytes:
    """Create a disposable gate-only copy, never modify the input."""
    if sha256(original) != profile.baseline_sha256:
        raise RecoveryError("捕获样本身份不匹配")
    pe = PEImage.parse(original)
    analysis, offset, engine = extract_enigma_engine(
        original, pe, decode_enigma_bootstrap(original, pe)
    )
    decoded, _ = patch_gate(engine, profile)
    modified = bytearray(original)
    modified[offset:offset + analysis.packed_size] = _encrypt_container(
        bcj_transform(decoded, encode=True), analysis, compressor
    )
    return bytes(modified)


@dataclass(frozen=True, slots=True)
class BuiltRepair:
    data: bytes
    patch: dict
    report: dict


def apply_binary_patch(original: bytes, patch: dict) -> bytes:
    """Validate and replay the same v2 replace/append patch used by the lab."""
    if patch.get("format") != "seep.binary-patch.v2":
        raise RecoveryError("不支持的补丁格式")
    if len(original) != patch["length"] or sha256(original) != patch["baseline_sha256"]:
        raise RecoveryError("补丁的基线身份不匹配")
    out = bytearray(original)
    occupied: list[tuple[int, int]] = []
    for record in patch["edits"]:
        offset, length = record["offset"], record["length"]
        replacement = base64.b64decode(record["replacement_base64"], validate=True)
        if not isinstance(offset, int) or not isinstance(length, int) or offset < 0 or length < 1:
            raise RecoveryError("补丁范围无效")
        if len(replacement) != length:
            raise RecoveryError("补丁长度不匹配")
        if any(offset < end and offset + length > start for start, end in occupied):
            raise RecoveryError("补丁范围重叠")
        if record.get("mode") == "append":
            if offset != len(out):
                raise RecoveryError("附加补丁不在文件尾")
            out.extend(replacement)
        else:
            if offset + length > len(original):
                raise RecoveryError("替换补丁超出原始文件")
            out[offset:offset + length] = replacement
        occupied.append((offset, offset + length))
    if len(out) != patch["modified_length"] or sha256(out) != patch["modified_sha256"]:
        raise RecoveryError("补丁重放结果不匹配")
    return bytes(out)


def build_repair(
    original: bytes,
    profile: RepairProfile,
    payloads: tuple[RecoveredPayload, ...],
    compressor: Callable[[bytes], bytes],
) -> BuiltRepair:
    validate_payloads(original, profile, payloads)
    pe = PEImage.parse(original)
    pe_offset = struct.unpack_from("<I", original, 0x3C)[0]
    optional = pe_offset + 24
    optional_size = struct.unpack_from("<H", original, pe_offset + 20)[0]
    if pe.bitness != 32 or pe.image_base != 0x400000:
        raise RecoveryError("修复配置要求 PE32 首选基址 0x400000")
    if (struct.unpack_from("<H", original, optional + 0x46)[0] & 0x40
            and not profile.allow_dynamic_base):
        raise RecoveryError("该 VM 原生调用适配不支持启用 ASLR 的样本")
    header = optional + optional_size + len(pe.sections) * 40
    if header + 40 > pe.size_of_headers or original[header:header + 40] != bytes(40):
        raise RecoveryError("没有安全的空白 PE 节表槽")
    section, no_op = helper_and_data(payloads)
    new_rva = pe.size_of_image
    analysis, container_offset, engine = extract_enigma_engine(
        original, pe, decode_enigma_bootstrap(original, pe)
    )
    changed, edits = patch_gate(engine, profile)
    decoded = bcj_transform(engine, encode=False)
    for index, old_operand, relative, symbol in (
        (profile.ksa_index, profile.ksa_operand, new_rva - profile.engine_base_delta,
         "KSA -> runtime recovered-copy helper"),
        (profile.prga_index, profile.prga_operand,
         new_rva - profile.engine_base_delta + no_op, "PRGA -> RET 8 no-op"),
    ):
        instruction = _instruction(decoded, profile, index)
        if struct.unpack_from("<I", decoded, instruction)[0] != 0x60:
            raise RecoveryError("预期的 VM 原生 CALL opcode 不匹配")
        if (profile.native_call_target_type is not None
                and struct.unpack_from("<I", decoded, instruction + 12)[0]
                != profile.native_call_target_type):
            raise RecoveryError("VM 原生 CALL 的目标寻址类型不匹配")
        offset = instruction + 28
        old = struct.pack("<I", old_operand)
        if decoded[offset:offset + 4] != old:
            raise RecoveryError("VM 原生 CALL 的原目标不匹配")
        replacement = struct.pack("<I", relative)
        changed[offset:offset + 4] = replacement
        edits.append({"symbol": f"VM[{index:#x}] {symbol}", "engine_offset": hex(offset),
                      "expected_bytes": old.hex(), "replacement_bytes": replacement.hex()})
    new_engine = bcj_transform(changed, encode=True)
    if bcj_transform(new_engine, encode=False) != bytes(changed):
        raise RecoveryError("修改引擎 BCJ 往返失败")
    encrypted = _encrypt_container(new_engine, analysis, compressor)
    modified = bytearray(original)
    modified[container_offset:container_offset + len(encrypted)] = encrypted
    raw_start = align(len(original), pe.file_alignment)
    raw_size = align(len(section), pe.file_alignment)
    struct.pack_into("<8sIIIIIIHHI", modified, header, b".repair\0",
                     len(section), new_rva, raw_size, raw_start,
                     0, 0, 0, 0, 0x60000020)
    struct.pack_into("<H", modified, pe_offset + 6, len(pe.sections) + 1)
    struct.pack_into("<I", modified, optional + 0x38,
                     align(new_rva + len(section), pe.section_alignment))
    size_of_code = struct.unpack_from("<I", original, optional + 4)[0]
    struct.pack_into("<I", modified, optional + 4, size_of_code + raw_size)
    appended = bytes(raw_start - len(original)) + section + bytes(raw_size - len(section))
    modified += appended
    for payload in payloads:
        spec = payload.spec
        if modified[spec.source_offset:spec.source_offset + spec.size] != (
            original[spec.source_offset:spec.source_offset + spec.size]
        ):
            raise RecoveryError("原始密文被改变")
    new_pe = PEImage.parse(modified)
    if len(new_pe.sections) != len(pe.sections) + 1:
        raise RecoveryError("新增节验证失败")
    _, _, reopened_engine = extract_enigma_engine(
        bytes(modified), new_pe, decode_enigma_bootstrap(bytes(modified), new_pe)
    )
    if reopened_engine != new_engine:
        raise RecoveryError("修改镜像引擎重解压不匹配")
    def encoded(data: bytes | bytearray) -> str:
        return base64.b64encode(data).decode("ascii")
    patch = {
        "format": "seep.binary-patch.v2",
        "baseline_sha256": profile.baseline_sha256,
        "modified_sha256": sha256(modified),
        "length": len(original),
        "modified_length": len(modified),
        "edits": [
            {"offset": 0, "length": pe.size_of_headers,
             "replacement_base64": encoded(modified[:pe.size_of_headers])},
            {"offset": container_offset, "length": len(encrypted),
             "replacement_base64": encoded(encrypted)},
            {"offset": len(original), "length": len(appended), "mode": "append",
             "replacement_base64": encoded(appended)},
        ],
    }
    if apply_binary_patch(original, patch) != bytes(modified):
        raise RecoveryError("完整补丁重放失败")
    report = {
        "profile": profile.name, "baseline_sha256": profile.baseline_sha256,
        "modified_sha256": patch["modified_sha256"], "engine_edits": edits,
        "original_encrypted_payloads_unchanged": True,
        "bcj_round_trip_verified": True, "engine_reextracted_verified": True,
        "payload_count": len(payloads), "payload_hashes_and_crcs_verified": True,
        "new_section_rva": hex(new_rva), "new_section_size": len(section),
        "activation_component_written": False, "runtime_launch_verified": False,
    }
    return BuiltRepair(bytes(modified), patch, report)
