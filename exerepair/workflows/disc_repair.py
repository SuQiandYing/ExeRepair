"""Pure PE32 disc-check compatibility builder, without capture or compression.

An RX entry helper temporarily redirects one process-local API dispatch slot.
Only the bound module, caller and full scalar-return epilogue permit a write.
Separate RW state holds resolved APIs; the original packed sections stay intact.
"""
from __future__ import annotations

import base64
import struct

from ..domain.recovery import DiscCheckProfile, RecoveryError
from ..formats.enigma import PEImage
from .repair import BuiltRepair, align, apply_binary_patch, sha256


class _X86:
    """Small rel32 emitter. Labels are resolved after both code paths exist."""

    def __init__(self, base: int) -> None:
        self.base = base
        self.code = bytearray()
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, str]] = []

    def emit(self, value: str) -> None:
        self.code.extend(bytes.fromhex(value))

    def imm(self, prefix: str, value: int) -> None:
        self.emit(prefix)
        self.code.extend(struct.pack("<I", value & 0xFFFFFFFF))

    def label(self, name: str) -> None:
        if name in self.labels:
            raise RecoveryError("重复的机器码标签")
        self.labels[name] = len(self.code)

    def branch(self, opcode: str, name: str) -> None:
        self.emit(opcode)
        self.fixups.append((len(self.code), name))
        self.code.extend(bytes(4))

    def finish(self) -> bytes:
        for offset, name in self.fixups:
            struct.pack_into("<i", self.code, offset, self.labels[name]-offset-4)
        return bytes(self.code)


def _validate_profile(profile: DiscCheckProfile) -> None:
    if (not profile.entry_bytes or len(profile.caller_guard) < 10 or
            profile.return_guard != bytes.fromhex("8b45e88b4df464890d000000008be55dc3")):
        raise RecoveryError("光盘检查配置的完整保护字节无效")
    if not 0x1000 <= profile.module_image_size <= 0x10000000:
        raise RecoveryError("光盘模块映像范围无效")
    for rva, size in ((profile.caller_return_rva, len(profile.caller_guard)),
                      (profile.return_rva, len(profile.return_guard)),
                      (profile.success_flag_rva, 4)):
        if not 0x1000 <= rva <= profile.module_image_size-size:
            raise RecoveryError("光盘模块保护范围越界")
    if any(profile.success_flag_rva < rva+size and rva < profile.success_flag_rva+4
           for rva, size in ((profile.return_rva, len(profile.return_guard)),
                             (profile.caller_return_rva, len(profile.caller_guard)))):
        raise RecoveryError("光盘模块成功字段与保护代码重叠")


def disc_helper(
    profile: DiscCheckProfile, code_va: int, state_va: int, original_entry_va: int,
) -> tuple[bytes, bytes, dict]:
    """Return RX code, RW state and layout; no addresses belong to this host."""
    _validate_profile(profile)
    if any(not 0 <= value <= 0xFFFFEFFF for value in
           (code_va, state_va, original_entry_va)):
        raise RecoveryError("光盘检查 helper 地址超出 32 位范围")
    gp, vp, slot, original, old_slot, old_code, scratch, done, flush, query, old_flag = (
        state_va+i*4 for i in range(11)
    )
    mbi = state_va+0x40
    state = bytearray(0x100)
    names = {}
    for offset, name in ((0x80, "VirtualProtect"), (0x90, "GetDriveTypeA"),
                         (0xA0, "FlushInstructionCache"), (0xC0, "VirtualQuery")):
        raw = name.encode("ascii")+b"\0"
        state[offset:offset+len(raw)] = raw
        names[name] = state_va+offset
    a = _X86(code_va)
    hook_va = code_va+0x400
    a.emit("9c 60")
    a.emit("64 a1 30 00 00 00 8b 40 0c 8d 78 14 8b 37")
    a.label("module")
    a.emit("39 fe")
    a.branch("0f84", "entry_done")
    a.emit("66 83 7e 24 18")
    a.branch("0f85", "next_module")
    # x86 BaseDllName.Buffer is +28h from InMemoryOrderLinks, not +2Ch.
    a.emit("8b 56 28")
    for offset, word in enumerate(("ke", "rn", "el", "32", ".d", "ll")):
        a.emit(f"8b 42 {offset*4:02x}")
        a.imm("0d", 0x00200020)
        a.imm("3d", int.from_bytes(word.encode("utf-16le"), "little"))
        a.branch("0f85", "next_module")
    a.emit("8b 5e 10")
    a.branch("e9", "exports")
    a.label("next_module")
    a.emit("8b 36")
    a.branch("e9", "module")
    a.label("exports")
    a.emit("8b 43 3c 8b 6c 03 78 01 dd 8b 4d 18 8b 75 20 01 de")
    a.label("export")
    a.emit("49")
    a.branch("0f88", "entry_done")
    a.emit("8b 3c 8e 01 df")
    for offset, word in ((0, b"GetP"), (4, b"rocA"), (8, b"ddre")):
        a.imm(f"81 7f {offset:02x}", int.from_bytes(word, "little"))
        a.branch("0f85", "export")
    a.emit("66 81 7f 0c 73 73")
    a.branch("0f85", "export")
    a.emit("80 7f 0e 00")
    a.branch("0f85", "export")
    a.emit("8b 45 24 01 d8 0f b7 04 48 8b 55 1c 01 da 8b 04 82 01 d8")
    a.imm("a3", gp)
    # A forwarded export points inside the export directory, not to code.
    a.emit("39 e8")
    a.branch("0f82", "gp_ready")
    a.emit("8b 53 3c 8b 54 13 7c 01 ea 39 d0")
    a.branch("0f82", "entry_done")
    a.label("gp_ready")
    for name, destination in (("VirtualProtect", vp), ("FlushInstructionCache", flush),
                              ("VirtualQuery", query)):
        a.imm("68", names[name])
        a.emit("53")
        a.imm("ff 15", gp)
        a.emit("85 c0")
        a.branch("0f84", "entry_done")
        a.imm("a3", destination)
    a.imm("68", names["GetDriveTypeA"])
    a.emit("53")
    a.imm("ff 15", gp)
    a.emit("85 c0")
    a.branch("0f84", "entry_done")
    a.emit("66 81 38 ff 25")
    a.branch("0f85", "entry_done")
    a.emit("8b 40 02")
    a.imm("a3", slot)
    a.emit("8b 10 85 d2")
    a.branch("0f84", "entry_done")
    a.imm("89 15", original)
    a.imm("68", old_slot)
    a.emit("6a 04 6a 04 50")
    a.imm("ff 15", vp)
    a.emit("85 c0")
    a.branch("0f84", "entry_done")
    a.imm("a1", slot)
    a.imm("c7 00", hook_va)
    a.imm("68", scratch)
    a.imm("ff 35", old_slot)
    a.emit("6a 04")
    a.imm("ff 35", slot)
    a.imm("ff 15", vp)
    a.label("entry_done")
    a.emit("61 9d")
    a.imm("e9", original_entry_va-(code_va+len(a.code)+5))
    entry_size = len(a.code)
    if entry_size > 0x400:
        raise RecoveryError("光盘检查入口超出机器码布局")
    a.code.extend(b"\xcc"*(0x400-len(a.code)))
    a.label("hook")
    a.emit("9c 60")
    a.imm("83 3d", done)
    a.emit("00")
    a.branch("0f85", "pass")
    a.emit("8b 44 24 24 89 c2 81 e2 ff ff 00 00")
    a.imm("81 fa", profile.caller_return_rva & 0xFFFF)
    a.branch("0f85", "pass")
    a.imm("2d", profile.caller_return_rva)
    a.emit("89 c3")
    # Check allocation and committed readable header before dereferencing it.
    a.emit("6a 1c")
    a.imm("68", mbi)
    a.emit("53")
    a.imm("ff 15", query)
    a.emit("83 f8 1c")
    a.branch("0f85", "pass")
    a.imm("39 1d", mbi+4)
    a.branch("0f85", "pass")
    a.imm("81 3d", mbi+0x10)
    a.emit("00 10 00 00")
    a.branch("0f85", "pass")
    a.imm("f7 05", mbi+0x14)
    a.imm("", 0x101)
    a.branch("0f85", "pass")
    a.imm("81 3d", mbi+0x0C)
    a.emit("00 10 00 00")
    a.branch("0f82", "pass")
    a.emit("66 81 3b 4d 5a")
    a.branch("0f85", "pass")
    a.emit("8b 43 3c 83 f8 40")
    a.branch("0f82", "pass")
    a.emit("3d 00 0f 00 00")
    a.branch("0f87", "pass")
    a.emit("01 d8 81 38 50 45 00 00")
    a.branch("0f85", "pass")
    a.emit("66 81 78 04 4c 01")
    a.branch("0f85", "pass")
    a.emit("66 81 78 18 0b 01")
    a.branch("0f85", "pass")
    a.imm("81 78 50", profile.module_image_size)
    a.branch("0f85", "pass")
    # A valid header is not proof that all candidate code/data pages are mapped.
    # Query each complete access range before any byte comparison or write.
    for rva, length in ((profile.caller_return_rva, len(profile.caller_guard)),
                        (profile.return_rva, len(profile.return_guard)),
                        (profile.success_flag_rva, 4)):
        a.emit("6a 1c")
        a.imm("68", mbi)
        a.imm("8d 83", rva)
        a.emit("50")
        a.imm("ff 15", query)
        a.emit("83 f8 1c")
        a.branch("0f85", "pass")
        a.imm("39 1d", mbi+4)
        a.branch("0f85", "pass")
        a.imm("81 3d", mbi+0x10)
        a.emit("00 10 00 00")
        a.branch("0f85", "pass")
        a.imm("f7 05", mbi+0x14)
        a.imm("", 0x101)
        a.branch("0f85", "pass")
        a.imm("a1", mbi)
        a.imm("03 05", mbi+0x0C)
        a.branch("0f82", "pass")
        a.imm("8d 93", rva+length)
        a.emit("39 d0")
        a.branch("0f82", "pass")
    for rva, guard in ((profile.caller_return_rva, profile.caller_guard),
                       (profile.return_rva, profile.return_guard)):
        offset = 0
        while offset < len(guard):
            size = 4 if len(guard)-offset >= 4 else (2 if len(guard)-offset >= 2 else 1)
            a.imm({4:"81 bb", 2:"66 81 bb", 1:"80 bb"}[size], rva+offset)
            a.code.extend(guard[offset:offset+size])
            a.branch("0f85", "pass")
            offset += size
    a.imm("83 bb", profile.success_flag_rva)
    a.emit("00")
    a.branch("0f85", "pass")
    a.imm("68", old_code)
    a.emit("6a 40 6a 03")
    a.imm("8d 83", profile.return_rva)
    a.emit("50")
    a.imm("ff 15", vp)
    a.emit("85 c0")
    a.branch("0f84", "pass")
    a.imm("68", old_flag)
    a.emit("6a 04 6a 04")
    a.imm("8d 83", profile.success_flag_rva)
    a.emit("50")
    a.imm("ff 15", vp)
    a.emit("85 c0")
    a.branch("0f84", "restore_code")
    # Replace only MOV EAX,[EBP-18h]; preserve the full SEH restoration epilogue.
    a.imm("66 c7 83", profile.return_rva)
    a.emit("33 c0")
    a.imm("c6 83", profile.return_rva+2)
    a.emit("40")
    a.imm("c7 83", profile.success_flag_rva)
    a.emit("01 00 00 00")
    a.emit("6a 03")
    a.imm("8d 83", profile.return_rva)
    a.emit("50 6a ff")
    a.imm("ff 15", flush)
    a.imm("c7 05", done)
    a.emit("01 00 00 00")
    a.imm("68", scratch)
    a.imm("ff 35", old_flag)
    a.emit("6a 04")
    a.imm("8d 83", profile.success_flag_rva)
    a.emit("50")
    a.imm("ff 15", vp)
    a.label("restore_code")
    a.imm("68", scratch)
    a.imm("ff 35", old_code)
    a.emit("6a 03")
    a.imm("8d 83", profile.return_rva)
    a.emit("50")
    a.imm("ff 15", vp)
    # Do not replace a later third-party dispatch update with our stale value.
    a.imm("a1", slot)
    a.imm("81 38", hook_va)
    a.branch("0f85", "pass")
    a.imm("68", old_slot)
    a.emit("6a 04 6a 04 50")
    a.imm("ff 15", vp)
    a.emit("85 c0")
    a.branch("0f84", "pass")
    a.imm("a1", slot)
    a.imm("8b 15", original)
    a.emit("89 10")
    a.imm("68", scratch)
    a.imm("ff 35", old_slot)
    a.emit("6a 04")
    a.imm("ff 35", slot)
    a.imm("ff 15", vp)
    a.label("pass")
    a.emit("61 9d")
    a.imm("ff 25", original)
    return a.finish(), bytes(state), {
        "entry_size":entry_size, "hook_offset":0x400, "state_size":len(state),
        "dispatch_state_offset":8, "original_api_state_offset":12, "done_state_offset":28,
    }


def build_disc_repair(original: bytes, profile: DiscCheckProfile) -> BuiltRepair:
    """Generate a separate PE copy and v2 patch; never launch or access files."""
    _validate_profile(profile)
    if sha256(original) != profile.baseline_sha256 or len(original) != profile.baseline_size:
        raise RecoveryError("原始样本身份不匹配")
    try:
        pe = PEImage.parse(original)
        nt = struct.unpack_from("<I", original, 0x3C)[0]
        optional = nt+24
        optional_size = struct.unpack_from("<H", original, nt+20)[0]
        if pe.bitness != 32 or pe.image_base != profile.image_base or optional_size < 0xE0:
            raise RecoveryError("光盘检查配置要求匹配固定基址的 PE32")
        if struct.unpack_from("<H", original, optional+0x46)[0] & 0x40:
            raise RecoveryError("光盘检查配置不支持 ASLR；不会关闭该保护")
        if any(struct.unpack_from("<II", original, optional+96+4*8)):
            raise RecoveryError("不修改带有数字签名的输入")
        if (pe.entry_rva != profile.entry_rva or
                original[pe.rva_to_offset(pe.entry_rva):
                         pe.rva_to_offset(pe.entry_rva)+len(profile.entry_bytes)] != profile.entry_bytes):
            raise RecoveryError("入口保护字节不匹配")
        if not pe.section_for_rva(pe.entry_rva).characteristics & 0x20000000:
            raise RecoveryError("原入口不在可执行节中")
        for boundary in (pe.file_alignment, pe.section_alignment):
            if boundary & (boundary-1):
                raise RecoveryError("PE 对齐必须为二次幂")
        if pe.section_alignment < pe.file_alignment:
            raise RecoveryError("PE 文件对齐大于节对齐")
        end_rva = max(s.virtual_address+max(s.virtual_size,s.raw_size) for s in pe.sections)
        if end_rva > pe.size_of_image or pe.size_of_image % pe.section_alignment:
            raise RecoveryError("原 PE 映像范围无效")
        slot = optional+optional_size+40*len(pe.sections)
        if slot+80 > pe.size_of_headers or original[slot:slot+80] != bytes(80):
            raise RecoveryError("没有安全的两个空白 PE 节表槽")
        helper_rva = pe.size_of_image
        state_rva = align(helper_rva+0x1000, pe.section_alignment)
        helper, state, layout = disc_helper(
            profile, pe.image_base+helper_rva, pe.image_base+state_rva,
            pe.image_base+pe.entry_rva,
        )
        if len(helper) > 0x1000:
            raise RecoveryError("光盘检查 helper 超出已分配范围")
        raw_start = align(len(original), pe.file_alignment)
        helper_raw = align(len(helper), pe.file_alignment)
        state_raw = align(len(state), pe.file_alignment)
        modified = bytearray(original)
        for index, (name, data, rva, raw_size, raw_offset, flags) in enumerate((
            (b".repair", helper, helper_rva, helper_raw, raw_start, 0x60000020),
            (b".rstate", state, state_rva, state_raw, raw_start+helper_raw, 0xC0000040),
        )):
            struct.pack_into("<8sIIIIIIHHI",modified,slot+index*40,name,len(data),rva,
                             raw_size,raw_offset,0,0,0,0,flags)
        struct.pack_into("<H",modified,nt+6,len(pe.sections)+2)
        struct.pack_into("<I",modified,optional+0x10,helper_rva)
        struct.pack_into("<I",modified,optional+0x38,
                         align(state_rva+len(state),pe.section_alignment))
        for offset, increment in ((4,helper_raw),(8,state_raw)):
            value = struct.unpack_from("<I",original,optional+offset)[0]+increment
            struct.pack_into("<I",modified,optional+offset,value)
        appended = (bytes(raw_start-len(original))+helper+bytes(helper_raw-len(helper))+
                    state+bytes(state_raw-len(state)))
        modified.extend(appended)
        parsed = PEImage.parse(modified)
    except (ValueError, struct.error, OverflowError) as error:
        if isinstance(error, RecoveryError):
            raise
        raise RecoveryError(f"光盘检查 PE 构建失败：{error}") from error
    if parsed.entry_rva != helper_rva or parsed.sections[-2].characteristics != 0x60000020:
        raise RecoveryError("修复 PE 重读校验失败")
    for section in pe.sections:
        start, end = section.raw_offset, section.raw_offset+section.raw_size
        if modified[start:end] != original[start:end]:
            raise RecoveryError("原始打包节发生变化")
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
    if apply_binary_patch(original,patch) != bytes(modified):
        raise RecoveryError("光盘检查补丁重放失败")
    return BuiltRepair(bytes(modified),patch,{
        "profile":profile.name,"strategy":"guarded-disc-check",
        "baseline_sha256":profile.baseline_sha256,"modified_sha256":sha256(modified),
        "changed_symbol":f"disc module RVA {profile.return_rva:#x} scalar return -> 1; "
                         f"RVA {profile.success_flag_rva:#x} success flag -> 1",
        "caller_return_rva":hex(profile.caller_return_rva),
        "caller_guard":profile.caller_guard.hex(),"return_rva":hex(profile.return_rva),
        "return_guard":profile.return_guard.hex(),"replacement_hex":"33c040",
        "success_flag_rva":hex(profile.success_flag_rva),
        "helper_rva":hex(helper_rva),"helper_size":len(helper),"state_rva":hex(state_rva),
        "original_entry_rva":hex(pe.entry_rva),"helper_layout":layout,
        "original_packed_sections_unchanged":True,"patch_replay_verified":True,
        "new_rwx_sections":False,"activation_component_written":False,
        "key_search_performed":False,"runtime_launch_verified":False,
        "runtime_api_entry_required":"kernel32 GetDriveTypeA: FF 25 <absolute dispatch slot>",
    })
