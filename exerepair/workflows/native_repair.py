"""Pure, exact-build native call repair with a guarded Enigma dispatch detour."""
from __future__ import annotations

import base64
import struct
from typing import Callable

from ..domain.recovery import NativeCallProfile, RecoveryError
from ..formats.enigma import (
    PEImage, aplib_decompress, bcj_transform, decode_enigma_bootstrap,
    extract_enigma_engine,
)
from .repair import BuiltRepair, align, apply_binary_patch, sha256


def native_trampoline(profile: NativeCallProfile, image_base: int, helper_rva: int) -> bytes:
    """Preserve guest GPRs/EFLAGS, guard ten bytes, replace only CALL EAX."""
    guard = profile.guard_bytes
    if (len(guard) != 10 or guard[5:7] != b"\xff\xd0" or
            profile.requires_runtime_discovery or
            profile.call_rva != profile.guard_rva + 5):
        raise RecoveryError("原生调用保护字节或调用位置无效")
    code = bytearray(b"\x9c\x60\xba" + struct.pack("<I", image_base+profile.guard_rva))
    jumps = []
    for instruction in (
        b"\x81\x3a" + guard[:4],
        b"\x80\x7a\x04" + guard[4:5],
        b"\x81\x7a\x05" + guard[5:9],
        b"\x80\x7a\x09" + guard[9:10],
    ):
        code += instruction + b"\x75\x00"
        jumps.append(len(code)-1)
    code += b"\x66\xc7\x42\x05\x90\x90"
    done = len(code)
    for jump in jumps:
        code[jump] = done-jump-1
    code += b"\x61\x9d\xa1" + struct.pack(
        "<I", image_base+profile.engine_base_delta+profile.dispatch_global_rva
    )
    continuation = image_base+profile.engine_base_delta+profile.dispatch_rva+5
    code += b"\xe9" + struct.pack("<i", continuation-(image_base+helper_rva+len(code)+5))
    return bytes(code)


def _retire_dispatch_relocation(engine: bytearray, pe: PEImage, profile) -> None:
    """Check the actual relocation block, not just a coincidental 16-bit value."""
    nt = struct.unpack_from("<I", engine, 0x3C)[0]
    relocation_rva = struct.unpack_from("<I", engine, nt+24+96+5*8)[0]
    position = pe.rva_to_offset(relocation_rva)
    expected_rva = profile.dispatch_rva+1
    while position+8 <= len(engine):
        page, size = struct.unpack_from("<II", engine, position)
        if page == 0 and size == 0:
            break
        if size < 8 or size % 2 or position+size > len(engine):
            raise RecoveryError("Enigma 自定义重定位块范围无效")
        if position+8 <= profile.relocation_offset < position+size:
            offset = profile.relocation_offset
            if (offset-position) % 2:
                raise RecoveryError("重定位记录未对齐")
            value = struct.unpack_from("<H", engine, offset)[0]
            if value >> 12 != 3 or page+(value & 0xFFF) != expected_rva:
                raise RecoveryError("调度指令的 HIGHLOW 重定位记录不匹配")
            struct.pack_into("<H", engine, offset, 0)
            return
        position += size
    raise RecoveryError("没有找到调度指令的重定位记录")


def build_native_repair(
    original: bytes, profile: NativeCallProfile, compressor: Callable[[bytes], bytes],
) -> BuiltRepair:
    if sha256(original) != profile.baseline_sha256 or len(original) != profile.baseline_size:
        raise RecoveryError("原始样本身份不匹配")
    pe = PEImage.parse(original)
    nt = struct.unpack_from("<I", original, 0x3C)[0]
    optional = nt+24
    if pe.bitness != 32 or pe.image_base != 0x400000:
        raise RecoveryError("原生调用配置要求固定基址 0x400000 的 PE32")
    if struct.unpack_from("<H", original, optional+0x46)[0] & 0x40:
        raise RecoveryError("该原生调用配置不支持 ASLR")
    target_section = pe.section_for_rva(profile.guard_rva)
    if (profile.guard_rva+10 > target_section.virtual_address+target_section.virtual_size or
            not target_section.characteristics & 0x80000000):
        raise RecoveryError("运行时调用位置不在经过验证的可写代码节内")
    bootstrap = decode_enigma_bootstrap(original, pe)
    analysis, old_container, engine = extract_enigma_engine(original, pe, bootstrap)
    if sha256(engine) != profile.engine_sha256:
        raise RecoveryError("解压引擎身份不匹配")
    decoded = bcj_transform(engine, encode=False)
    if bcj_transform(decoded, encode=True) != engine:
        raise RecoveryError("原引擎 BCJ 往返失败")
    changed = bytearray(decoded)
    expected = b"\xa1" + struct.pack("<I", pe.image_base+profile.dispatch_global_rva)
    dispatch = profile.dispatch_rva
    if changed[dispatch:dispatch+5] != expected:
        raise RecoveryError("Enigma 调度入口的原始 MOV 指令不匹配")
    _retire_dispatch_relocation(changed, PEImage.parse(decoded), profile)
    helper_rva = pe.size_of_image
    helper = native_trampoline(profile, pe.image_base, helper_rva)
    changed[dispatch:dispatch+5] = b"\xe9" + struct.pack(
        "<i", helper_rva-(profile.engine_base_delta+dispatch+5)
    )
    encoded = bcj_transform(changed, encode=True)
    if bcj_transform(encoded, encode=False) != bytes(changed):
        raise RecoveryError("修改引擎 BCJ 往返失败")
    packed = compressor(encoded)
    if not packed or aplib_decompress(packed) != encoded:
        raise RecoveryError("压缩引擎重解压不匹配")
    packed_size = align(len(packed), 4)
    packed_rva = align(helper_rva+len(helper), pe.section_alignment)
    encrypted = bytearray(packed + bytes(packed_size-len(packed)))
    for offset in range(0, packed_size, 4):
        value = struct.unpack_from("<I", encrypted, offset)[0] ^ analysis.xor_key
        struct.pack_into("<I", encrypted, offset, value)
    modified = bytearray(bootstrap.decoded_image)
    for offsets, old, new in (
        (profile.bootstrap_size_offsets, analysis.packed_size, packed_size),
        (profile.bootstrap_source_offsets, analysis.source_rva, packed_rva),
    ):
        for relative in offsets:
            offset = bootstrap.entry_offset+relative
            if offset < 0 or offset+4 > len(modified):
                raise RecoveryError("引导参数越界")
            if struct.unpack_from("<I", modified, offset)[0] != old:
                raise RecoveryError("引导容器大小或 RVA 参数不匹配")
            struct.pack_into("<I", modified, offset, new)
    for layer in reversed(bootstrap.layers):
        start = pe.rva_to_offset(pe.entry_rva+layer.relative_offset)
        for offset in range(start, start+layer.length):
            modified[offset] ^= layer.xor_byte
    optional_size = struct.unpack_from("<H", original, nt+20)[0]
    slot = optional+optional_size+len(pe.sections)*40
    if slot+80 > pe.size_of_headers or original[slot:slot+80] != bytes(80):
        raise RecoveryError("没有安全的两个空白 PE 节表槽")
    raw_start = align(len(original), pe.file_alignment)
    helper_raw_size = align(len(helper), pe.file_alignment)
    packed_raw_size = align(packed_size, pe.file_alignment)
    struct.pack_into("<8sIIIIIIHHI", modified, slot, b".repair\0", len(helper),
                     helper_rva, helper_raw_size, raw_start, 0,0,0,0,0x60000020)
    struct.pack_into("<8sIIIIIIHHI", modified, slot+40, b".epack\0\0", packed_size,
                     packed_rva, packed_raw_size, raw_start+helper_raw_size,
                     0,0,0,0,0xC0000040)
    struct.pack_into("<H", modified, nt+6, len(pe.sections)+2)
    struct.pack_into("<I", modified, optional+0x38,
                     align(packed_rva+packed_size, pe.section_alignment))
    for offset, increment in ((4,helper_raw_size),(8,packed_raw_size)):
        size = struct.unpack_from("<I", original, optional+offset)[0]
        struct.pack_into("<I", modified, optional+offset, size+increment)
    appended = (bytes(raw_start-len(original))+helper+bytes(helper_raw_size-len(helper))+
                encrypted+bytes(packed_raw_size-packed_size))
    modified += appended
    new_pe = PEImage.parse(modified)
    reopened_analysis, _, reopened_engine = extract_enigma_engine(
        bytes(modified), new_pe, decode_enigma_bootstrap(bytes(modified), new_pe)
    )
    if reopened_engine != encoded or reopened_analysis.source_rva != packed_rva:
        raise RecoveryError("修改文件引擎重提取不匹配")
    if modified[old_container:old_container+analysis.packed_size] != original[
            old_container:old_container+analysis.packed_size]:
        raise RecoveryError("原始引擎容器发生变化")
    for section in pe.sections:
        if section.virtual_address == profile.engine_base_delta:
            continue
        # Bootstrap parameters are the only original section bytes edited.
        if section is pe.section_for_rva(pe.entry_rva):
            continue
        start, end = section.raw_offset, section.raw_offset+section.raw_size
        if modified[start:end] != original[start:end]:
            raise RecoveryError("原始游戏载荷发生变化")
    # Diff only contiguous changed runs plus one append, avoiding unchanged data.
    edits = []
    start = 0
    while start < len(original):
        if original[start] == modified[start]:
            start += 1
            continue
        end = start+1
        while end < len(original) and original[end] != modified[end]:
            end += 1
        edits.append({"offset":start,"length":end-start,
                      "replacement_base64":base64.b64encode(modified[start:end]).decode("ascii")})
        start = end
    edits.append({"offset":len(original),"length":len(appended),"mode":"append",
                  "replacement_base64":base64.b64encode(appended).decode("ascii")})
    patch = {"format":"seep.binary-patch.v2","baseline_sha256":profile.baseline_sha256,
             "modified_sha256":sha256(modified),"length":len(original),
             "modified_length":len(modified),"edits":edits}
    if apply_binary_patch(original, patch) != bytes(modified):
        raise RecoveryError("补丁完整重放失败")
    report = {
        "profile":profile.name,"strategy":"guarded-native-call",
        "baseline_sha256":profile.baseline_sha256,"modified_sha256":sha256(modified),
        "changed_symbol":f"main module RVA {profile.call_rva:#x} native CALL -> NOP NOP",
        "guard_rva":hex(profile.guard_rva),"guard_bytes":profile.guard_bytes.hex(),
        "dispatch_rva":hex(profile.dispatch_rva),"retired_relocation":hex(profile.relocation_offset),
        "helper_rva":hex(helper_rva),"helper_size":len(helper),
        "packed_container_rva":hex(packed_rva),"packed_size":len(packed),
        "original_packed_capacity":analysis.packed_size,
        "original_game_payloads_unchanged":True,"original_engine_container_unchanged":True,
        "bcj_round_trip_verified":True,"engine_reextracted_verified":True,
        "activation_component_written":False,"key_search_performed":False,
        "runtime_launch_verified":False,
    }
    return BuiltRepair(bytes(modified), patch, report)
