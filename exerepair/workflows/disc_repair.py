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
from .portable_setup import STUB_OFFSET, build_portable_setup, validate_directory_object
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

    def imm16(self, prefix: str, value: int) -> None:
        self.emit(prefix)
        self.code.extend(struct.pack("<H", value & 0xFFFF))

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
    registry_fields = (
        profile.registry_open_slot_rva, profile.registry_query_slot_rva,
        profile.registry_ready_rva,
    )
    registry_enabled = any(value is not None for value in registry_fields)
    if registry_enabled:
        if (profile.registry_open_slot_rva is None or
                profile.registry_query_slot_rva is None or
                profile.registry_ready_rva is None or
                not profile.registry_key_prefix or
                not profile.registry_value_names or
                not profile.registry_ready_bytes):
            raise RecoveryError("注册表兼容配置不完整")
        for rva in (profile.registry_open_slot_rva,
                    profile.registry_query_slot_rva,
                    profile.registry_ready_rva):
            assert rva is not None
            if not 0x1000 <= rva < profile.module_image_size:
                raise RecoveryError("注册表兼容地址越界")
        if profile.registry_ready_rva > (
                profile.module_image_size-len(profile.registry_ready_bytes)):
            raise RecoveryError("注册表兼容运行时锚点越界")
        if len(profile.registry_key_prefix) > 64:
            raise RecoveryError("注册表兼容键前缀过长")
        if len(set(profile.registry_value_names)) != len(profile.registry_value_names):
            raise RecoveryError("注册表兼容值名重复")
        if any(not name or len(name) > 64 for name in profile.registry_value_names):
            raise RecoveryError("注册表兼容值名无效")
    for rva, expected, replacement in profile.setup_patch_sites:
        if len(expected) != len(replacement) or not expected:
            raise RecoveryError("运行时 setup 补丁长度无效")
        # setup_patch_sites may target the decrypted wrapper image, whose RVA
        # is not constrained by the late-loaded module_image_size field.
        if not 0x1000 <= rva <= 0xFFFFEFFF-len(expected):
            raise RecoveryError("运行时 setup 补丁地址越界")


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
    thread_api = state_va+0x2C
    sleep_api = state_va+0x30
    region_old_protect = state_va+0x34
    region_done = state_va+0x38
    mbi = state_va+0x40
    region_mbi = state_va+0x60
    region_sites = tuple(profile.region_patch_sites)
    portable = None
    if profile.portable_setup is not None:
        if not region_sites or profile.registry_open_slot_rva is not None:
            raise RecoveryError("安装目录兼容需要独立的运行时 worker，不能混用注册表分派")
        portable = build_portable_setup(
            profile.portable_setup, profile.image_base, code_va, profile.module_image_size,
        )
        existing_sites = (*region_sites, *profile.setup_patch_sites)
        for rva, expected in portable.guards:
            if any(rva < other + len(before) and other < rva + len(expected)
                   for other, before, _ in existing_sites):
                raise RecoveryError("安装目录保护点与现有运行时补丁重叠")
        region_sites += portable.patches
    region_enabled = bool(region_sites)
    setup_sites = tuple(profile.setup_patch_sites)
    setup_enabled = bool(setup_sites)
    registry_enabled = profile.registry_open_slot_rva is not None
    if registry_enabled != (profile.registry_query_slot_rva is not None):
        raise RecoveryError("注册表兼容分派槽配置不对称")
    worker_enabled = region_enabled or setup_enabled or registry_enabled
    registry_open_slot = (
        profile.image_base + profile.registry_open_slot_rva
        if registry_enabled else None
    )
    registry_query_slot = (
        profile.image_base + profile.registry_query_slot_rva
        if registry_enabled else None
    )
    # Keep the API-name string at state+0x100 separate from mutable registry
    # state; the string is 21 bytes including its NUL terminator.
    registry_open_original = state_va+0x140
    registry_query_original = state_va+0x144
    registry_fake_handle = state_va+0x148
    registry_done = state_va+0x14C
    registry_get_cwd = state_va+0x150
    registry_cwd_length = state_va+0x154
    registry_cwd = state_va+0x160
    registry_open_hook_va = code_va+0x800
    registry_query_hook_va = code_va+0x980
    registry_worker_va = code_va+0xB00
    thread_va = code_va+0x800 if (region_enabled or setup_enabled) else registry_worker_va
    state = bytearray(0x400 if registry_enabled else 0x100)
    names = {}
    api_names = (
        (0x80, "VirtualProtect"), (0x90, "GetDriveTypeA"),
        (0xA0, "FlushInstructionCache"), (0xC0, "VirtualQuery"),
        (0xD0, "CreateThread"), (0xE0, "Sleep"),
    )
    if registry_enabled:
        api_names += ((0x100, "GetCurrentDirectoryA"),)
    for offset, name in api_names:
        raw = name.encode("ascii")+b"\0"
        state[offset:offset+len(raw)] = raw
        names[name] = state_va+offset
    if registry_enabled:
        struct.pack_into("<I", state, registry_fake_handle-state_va, 0x52454731)
    if region_enabled:
        if profile.region_ready_rva is None or not profile.region_ready_bytes:
            raise RecoveryError("地区检查运行时锚点不完整")
        for rva, expected, replacement in region_sites:
            if len(expected) != len(replacement) or not expected:
                raise RecoveryError("地区检查运行时补丁长度无效")
            if not 0x1000 <= rva <= profile.module_image_size-len(expected):
                raise RecoveryError("地区检查运行时补丁越界")
        if not 0x1000 <= profile.region_ready_rva <= (
                profile.module_image_size-len(profile.region_ready_bytes)):
            raise RecoveryError("地区检查运行时锚点越界")
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
    if registry_enabled:
        a.imm("68", names["GetCurrentDirectoryA"])
        a.emit("53")
        a.imm("ff 15", gp)
        a.emit("85 c0")
        a.branch("0f84", "entry_done")
        a.imm("a3", registry_get_cwd)
        a.imm("68", registry_cwd)
        a.emit("68")
        a.code.extend(struct.pack("<I", 0x1FF))
        a.imm("ff 15", registry_get_cwd)
        a.emit("85 c0")
        a.branch("0f84", "entry_done")
        a.imm("a3", registry_cwd_length)
    if worker_enabled:
        for name, destination in (("CreateThread", thread_api), ("Sleep", sleep_api)):
            a.imm("68", names[name])
            a.emit("53")
            a.imm("ff 15", gp)
            a.emit("85 c0")
            a.branch("0f84", "entry_done")
            a.imm("a3", destination)
        # Start the polling worker before the original entry decrypts the
        # packed engine.  It exits after the runtime guard sites/dispatch
        # slots are handled or after their bounded wait expires.
        a.emit("6a 00 6a 00 6a 00")
        a.imm("68", thread_va)
        a.emit("6a 00 6a 00")
        a.imm("ff 15", thread_api)
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
    helper = a.finish()
    thread_size = 0
    if region_enabled or setup_enabled:
        def emit_abs_cmp_word(code: _X86, address: int, value: int) -> None:
            code.emit("66 81 3d")
            code.code.extend(struct.pack("<I", address))
            code.code.extend(struct.pack("<H", value & 0xFFFF))

        def emit_abs_cmp_byte(code: _X86, address: int, value: int) -> None:
            code.emit("80 3d")
            code.code.extend(struct.pack("<I", address))
            code.code.append(value & 0xFF)

        def emit_abs_write(code: _X86, address: int, data: bytes) -> None:
            offset = 0
            while len(data)-offset >= 4:
                code.imm("c7 05", address+offset)
                code.code.extend(struct.pack("<I", int.from_bytes(
                    data[offset:offset+4], "little"
                )))
                offset += 4
            if len(data)-offset >= 2:
                code.emit("66 c7 05")
                code.code.extend(struct.pack("<I", address+offset))
                code.code.extend(struct.pack("<H", int.from_bytes(
                    data[offset:offset+2], "little"
                )))
                offset += 2
            if len(data)-offset == 1:
                code.emit("c6 05")
                code.code.extend(struct.pack("<I", address+offset))
                code.code.append(data[offset])

        def emit_abs_cmp(code: _X86, address: int, data: bytes) -> None:
            offset = 0
            while len(data)-offset >= 4:
                code.imm("81 3d", address+offset)
                code.code.extend(struct.pack(
                    "<I", int.from_bytes(data[offset:offset+4], "little")
                ))
                code.branch("0f85", "sleep")
                offset += 4
            if len(data)-offset >= 2:
                emit_abs_cmp_word(
                    code, address+offset,
                    int.from_bytes(data[offset:offset+2], "little"),
                )
                code.branch("0f85", "sleep")
                offset += 2
            if len(data)-offset == 1:
                emit_abs_cmp_byte(code, address+offset, data[offset])
                code.branch("0f85", "sleep")

        def emit_virtual_protect(
            code: _X86, address: int, size: int, old_protect: int,
        ) -> None:
            code.imm("68", old_protect)
            code.emit("6a 40")
            code.emit("68")
            code.code.extend(struct.pack("<I", size))
            code.imm("68", address)
            code.imm("ff 15", vp)
            code.emit("85 c0")
            code.branch("0f84", "finish")

        def emit_flush_and_restore(
            code: _X86, address: int, size: int, old_protect: int,
        ) -> None:
            code.emit("68")
            code.code.extend(struct.pack("<I", size))
            code.imm("68", address)
            code.emit("6a ff")
            code.imm("ff 15", flush)
            code.imm("68", old_protect)
            code.imm("ff 35", old_protect)
            code.emit("68")
            code.code.extend(struct.pack("<I", size))
            code.imm("68", address)
            code.imm("ff 15", vp)

        thread = _X86(thread_va)
        thread.emit("9c 60")
        thread.imm("bf", 60000)
        thread.label("poll")
        thread.imm("83 3d", region_done)
        thread.emit("00")
        thread.branch("0f85", "finish")
        if region_enabled:
            assert profile.region_ready_rva is not None
            ready_va = profile.image_base + profile.region_ready_rva
            ready = profile.region_ready_bytes
            thread.emit("6a 1c")
            thread.imm("68", region_mbi)
            thread.imm("68", ready_va)
            thread.imm("ff 15", query)
            thread.emit("83 f8 1c")
            thread.branch("0f85", "sleep")
            thread.imm("81 3d", region_mbi+0x10)
            thread.emit("00 10 00 00")
            thread.branch("0f85", "sleep")
            thread.imm("a1", region_mbi)
            thread.imm("3d", ready_va)
            thread.branch("0f87", "sleep")
            thread.imm("8b 15", region_mbi+0x0C)
            thread.emit("01 c2")
            thread.imm("81 fa", ready_va+len(ready))
            thread.branch("0f82", "sleep")
            thread.imm("83 3d", region_mbi+0x14)
            thread.emit("00")
            thread.branch("0f84", "sleep")
            thread.imm("f7 05", region_mbi+0x14)
            thread.imm("", 0x6E)
            thread.branch("0f84", "sleep")
            thread.imm("f7 05", region_mbi+0x14)
            thread.imm("", 0x101)
            thread.branch("0f85", "sleep")
            emit_abs_cmp(thread, ready_va, ready)
        for rva, expected, _ in setup_sites:
            emit_abs_cmp(thread, profile.image_base+rva, expected)
        if portable is not None:
            for rva, expected in portable.guards:
                emit_abs_cmp(thread, profile.image_base+rva, expected)
        thread.branch("e9", "patch")
        thread.label("sleep")
        thread.emit("6a 01")
        thread.imm("ff 15", sleep_api)
        thread.emit("4f")
        thread.branch("0f85", "poll")
        # A timeout must not fall through into unverified code writes.
        thread.branch("e9", "finish")
        thread.label("patch")
        for rva, expected, replacement in setup_sites:
            address = profile.image_base+rva
            size = len(expected)
            emit_virtual_protect(thread, address, size, region_old_protect)
            emit_abs_write(thread, address, replacement)
            emit_flush_and_restore(thread, address, size, region_old_protect)
        if region_enabled:
            patch_base = profile.image_base + min(rva for rva, _, _ in region_sites)
            patch_end = max(rva+len(expected) for rva, expected, _ in region_sites)
            patch_size = patch_end-min(rva for rva, _, _ in region_sites)
            emit_virtual_protect(thread, patch_base, patch_size, region_old_protect)
            for rva, _, replacement in region_sites:
                emit_abs_write(thread, profile.image_base+rva, replacement)
            emit_flush_and_restore(thread, patch_base, patch_size, region_old_protect)
        thread.imm("c7 05", region_done)
        thread.emit("01 00 00 00")
        thread.label("finish")
        thread.emit("61 9d 33 c0 c2 04 00")
        thread_code = thread.finish()
        thread_size = len(thread_code)
        if len(helper) > thread_va-code_va:
            raise RecoveryError("地区检查 worker 与 disc helper 重叠")
        helper += bytes(thread_va-code_va-len(helper))
        helper += thread_code
    registry_worker_size = 0
    registry_stub_sizes = {}
    if registry_enabled:
        if region_enabled or setup_enabled:
            raise RecoveryError("当前配置不允许地区 worker 与注册表 worker 共用布局")
        assert registry_open_slot is not None
        assert registry_query_slot is not None
        prefix = profile.registry_key_prefix
        if len(prefix) < 9:
            raise RecoveryError("注册表兼容键前缀必须包含完整的 ANSI 前缀")

        def emit_abs_dword(code: _X86, address: int, value: int) -> None:
            code.emit("c7 05")
            code.code.extend(struct.pack("<I", address))
            code.code.extend(struct.pack("<I", value & 0xFFFFFFFF))

        open_hook = _X86(registry_open_hook_va)
        open_hook.emit("60")
        open_hook.emit("8b 44 24 24")  # root
        open_hook.imm("3d", 0x80000002)
        open_hook.branch("0f85", "forward")
        open_hook.emit("8b 74 24 28")  # ANSI subkey
        open_hook.emit("85 f6")
        open_hook.branch("0f84", "forward")
        open_hook.imm("81 3e", int.from_bytes(prefix[:4], "little"))
        open_hook.branch("0f85", "forward")
        open_hook.imm("81 7e 04", int.from_bytes(prefix[4:8], "little"))
        open_hook.branch("0f85", "forward")
        open_hook.emit(f"80 7e 08 {prefix[8]:02x}")
        open_hook.branch("0f85", "forward")
        open_hook.emit("8b 7c 24 34")  # result HKEY*
        open_hook.emit("85 ff")
        open_hook.branch("0f85", "success")
        open_hook.imm("c7 07", 0x52454731)
        open_hook.label("success")
        open_hook.emit("c7 44 24 1c 00 00 00 00")  # saved EAX = ERROR_SUCCESS
        open_hook.emit("61 c2 14 00")
        open_hook.label("forward")
        open_hook.emit("61")
        open_hook.imm("ff 25", registry_open_original)
        open_hook_code = open_hook.finish()

        query_hook = _X86(registry_query_hook_va)
        query_hook.emit("60")
        query_hook.emit("8b 44 24 24")  # HKEY
        query_hook.imm("3b 05", registry_fake_handle)
        query_hook.branch("0f85", "forward")
        query_hook.emit("8b 74 24 28")  # value name
        query_hook.emit("85 f6")
        query_hook.branch("0f84", "forward")
        for index, value_name in enumerate(profile.registry_value_names):
            next_label = (
                f"try_value_{index+1}"
                if index+1 < len(profile.registry_value_names) else "forward"
            )
            if len(value_name) < 4:
                raise RecoveryError("注册表兼容值名过短")
            query_hook.imm("81 3e", int.from_bytes(
                value_name[:4].ljust(4, b"\0"), "little"
            ))
            query_hook.branch("0f85", next_label)
            if len(value_name) > 4:
                if len(value_name) >= 8:
                    query_hook.imm("81 7e 04", int.from_bytes(
                        value_name[4:8].ljust(4, b"\0"), "little"
                    ))
                    query_hook.branch("0f85", next_label)
                if len(value_name) > 8:
                    query_hook.imm16("66 81 7e 08", int.from_bytes(
                        value_name[8:10].ljust(2, b"\0"), "little"
                    ))
                    query_hook.branch("0f85", next_label)
            query_hook.branch("e9", "value")
            if index+1 < len(profile.registry_value_names):
                query_hook.label(next_label)
        query_hook.label("value")
        query_hook.emit("8b 7c 24 30")  # type DWORD*
        query_hook.emit("85 ff")
        query_hook.branch("0f84", "no_type")
        query_hook.imm("c7 07", 1)  # REG_SZ
        query_hook.label("no_type")
        query_hook.imm("a1", registry_cwd_length)
        query_hook.emit("40")  # include the terminating NUL
        query_hook.emit("8b 7c 24 38")  # lpcbData
        query_hook.emit("85 ff")
        query_hook.branch("0f84", "no_size")
        query_hook.emit("89 07")
        query_hook.label("no_size")
        query_hook.emit("8b 7c 24 34")  # destination buffer
        query_hook.emit("85 ff")
        query_hook.branch("0f84", "success")
        query_hook.imm("be", registry_cwd)
        query_hook.emit("89 c1")  # copy the returned byte count to ECX
        query_hook.emit("f3 a4")  # rep movsb
        query_hook.label("success")
        query_hook.emit("c7 44 24 1c 00 00 00 00")
        query_hook.emit("61 c2 18 00")
        query_hook.label("forward")
        query_hook.emit("61")
        query_hook.imm("ff 25", registry_query_original)
        query_hook_code = query_hook.finish()

        registry_worker = _X86(registry_worker_va)
        registry_worker.emit("9c 60")
        registry_worker.imm("bf", 60000)
        registry_worker.label("poll")
        ready_va = profile.image_base + profile.registry_ready_rva
        ready = profile.registry_ready_bytes
        offset = 0
        while len(ready)-offset >= 4:
            registry_worker.imm("81 3d", ready_va+offset)
            registry_worker.code.extend(ready[offset:offset+4])
            registry_worker.branch("0f85", "sleep")
            offset += 4
        if len(ready)-offset >= 2:
            registry_worker.emit("66 81 3d")
            registry_worker.code.extend(struct.pack("<I", ready_va+offset))
            registry_worker.code.extend(struct.pack(
                "<H", int.from_bytes(ready[offset:offset+2], "little")
            ))
            registry_worker.branch("0f85", "sleep")
            offset += 2
        if len(ready)-offset == 1:
            registry_worker.emit("80 3d")
            registry_worker.code.extend(struct.pack("<I", ready_va+offset))
            registry_worker.code.append(ready[offset])
            registry_worker.branch("0f85", "sleep")
        registry_worker.imm("a1", registry_open_slot)
        registry_worker.emit("85 c0")
        registry_worker.branch("0f84", "sleep")
        registry_worker.imm("a3", registry_open_original)
        registry_worker.imm("a1", registry_query_slot)
        registry_worker.emit("85 c0")
        registry_worker.branch("0f84", "sleep")
        registry_worker.imm("a3", registry_query_original)
        emit_abs_dword(registry_worker, registry_open_slot, registry_open_hook_va)
        emit_abs_dword(registry_worker, registry_query_slot, registry_query_hook_va)
        emit_abs_dword(registry_worker, registry_done, 1)
        registry_worker.branch("e9", "finish")
        registry_worker.label("sleep")
        registry_worker.emit("6a 01")
        registry_worker.imm("ff 15", sleep_api)
        registry_worker.emit("4f")
        registry_worker.branch("0f85", "poll")
        registry_worker.label("finish")
        registry_worker.emit("61 9d c2 04 00")
        registry_worker_code = registry_worker.finish()

        registry_stub_sizes = {
            "open": len(open_hook_code), "query": len(query_hook_code),
        }
        registry_worker_size = len(registry_worker_code)
        if len(helper) > registry_open_hook_va-code_va:
            raise RecoveryError("注册表兼容 stub 与 disc helper 重叠")
        helper += bytes(registry_open_hook_va-code_va-len(helper))
        helper += open_hook_code
        if len(helper) > registry_query_hook_va-code_va:
            raise RecoveryError("注册表查询 stub 与开键 stub 重叠")
        helper += bytes(registry_query_hook_va-code_va-len(helper))
        helper += query_hook_code
        if len(helper) > registry_worker_va-code_va:
            raise RecoveryError("注册表 worker 与查询 stub 重叠")
        helper += bytes(registry_worker_va-code_va-len(helper))
        helper += registry_worker_code
    if portable is not None:
        if len(helper) > STUB_OFFSET:
            raise RecoveryError("安装目录 stub 与运行时 worker 重叠")
        helper += b"\xcc" * (STUB_OFFSET - len(helper)) + portable.code
    return helper, bytes(state), {
        "entry_size":entry_size, "hook_offset":0x400, "state_size":len(state),
        "dispatch_state_offset":8, "original_api_state_offset":12, "done_state_offset":28,
        "region_worker_offset":(thread_va-code_va if region_enabled else None),
        "region_worker_size":thread_size,
        "registry_worker_offset":(
            registry_worker_va-code_va if registry_enabled else None
        ),
        "registry_worker_size":registry_worker_size,
        "registry_stub_offsets":(
            {"open":registry_open_hook_va-code_va,
             "query":registry_query_hook_va-code_va}
            if registry_enabled else {}
        ),
        "registry_stub_sizes":registry_stub_sizes,
        "portable_installation": portable is not None,
        "portable_stub_offset": STUB_OFFSET if portable is not None else None,
        "portable_directory_wstring_va": (
            hex(portable.directory_object_va) if portable is not None else None
        ),
        "registry_slots":(
            {"open":hex(profile.registry_open_slot_rva),
             "query":hex(profile.registry_query_slot_rva)}
            if registry_enabled else {}
        ),
        "region_patch_sites":([
            {"rva":hex(rva),"expected":expected.hex(),"replacement":replacement.hex()}
            for rva, expected, replacement in region_sites
        ] if region_enabled else []),
        "setup_patch_sites":([
            {"rva":hex(rva),"expected":expected.hex(),"replacement":replacement.hex()}
            for rva, expected, replacement in setup_sites
        ] if setup_enabled else []),
    }


def build_disc_repair(original: bytes, profile: DiscCheckProfile) -> BuiltRepair:
    """Generate a separate PE copy and v2 patch; never launch or access files."""
    _validate_profile(profile)
    if sha256(original) != profile.baseline_sha256 or len(original) != profile.baseline_size:
        raise RecoveryError("原始样本身份不匹配")
    try:
        pe = PEImage.parse(original)
        if profile.portable_setup is not None:
            validate_directory_object(profile.portable_setup, pe.size_of_image)
        nt = struct.unpack_from("<I", original, 0x3C)[0]
        optional = nt+24
        optional_size = struct.unpack_from("<H", original, nt+20)[0]
        if pe.bitness != 32 or pe.image_base != profile.image_base or optional_size < 0xE0:
            raise RecoveryError("光盘检查配置要求匹配固定基址的 PE32")
        dynamic_base = bool(struct.unpack_from("<H", original, optional+0x46)[0] & 0x40)
        reloc_dir_rva, reloc_dir_size = struct.unpack_from(
            "<II", original, optional+96+5*8
        )
        if dynamic_base and not (
            profile.allow_dynamic_base_without_relocations
            and reloc_dir_rva == 0
            and reloc_dir_size == 0
            and not any(section.name.rstrip("\0") == ".reloc" for section in pe.sections)
        ):
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
    registry_note = ""
    if profile.registry_open_slot_rva is not None:
        registry_note = (
            f"; process-local registry shim slots "
            f"{profile.registry_open_slot_rva:#x}/{profile.registry_query_slot_rva:#x} "
            f"serve the current working directory for the identified values "
            f"(no host registry writes)"
        )
    setup_note = ""
    if profile.setup_patch_sites:
        setup_note = (
            "; runtime setup gate "
            + ", ".join(
                f"RVA {rva:#x} {expected.hex()} -> {replacement.hex()}"
                for rva, expected, replacement in profile.setup_patch_sites
            )
            + " (process-local; no host registry writes)"
        )
    runtime_note = ""
    if layout["region_patch_sites"]:
        runtime_note = "; runtime patch sites " + ", ".join(
            site["rva"] for site in layout["region_patch_sites"]
        )
    if profile.portable_setup is not None:
        registry_note += (
            "; setup calls use the engine-owned UTF-16 executable directory; "
            f"installation type = {profile.portable_setup.installed_value!r}; "
            "no installation registry access"
        )
    return BuiltRepair(bytes(modified),patch,{
        "profile":profile.name,"strategy":"guarded-disc-check",
        "baseline_sha256":profile.baseline_sha256,"modified_sha256":sha256(modified),
        "changed_symbol":(
            f"disc module RVA {profile.return_rva:#x} "
            f"scalar return -> 1; RVA {profile.success_flag_rva:#x} success flag -> 1"
            f"{registry_note}{setup_note}{runtime_note}"
        ),
        "caller_return_rva":hex(profile.caller_return_rva),
        "caller_guard":profile.caller_guard.hex(),"return_rva":hex(profile.return_rva),
        "return_guard":profile.return_guard.hex(),"replacement_hex":"33c040",
        "success_flag_rva":hex(profile.success_flag_rva),
        "helper_rva":hex(helper_rva),"helper_size":len(helper),"state_rva":hex(state_rva),
        "original_entry_rva":hex(pe.entry_rva),"helper_layout":layout,
        "original_packed_sections_unchanged":True,"patch_replay_verified":True,
        "new_rwx_sections":False,"activation_component_written":False,
        "key_search_performed":False,"runtime_launch_verified":False,
        "dynamic_base_flag":dynamic_base,
        "preferred_base_required":dynamic_base,
        "relocations_present":bool(reloc_dir_rva or reloc_dir_size),
        "runtime_api_entry_required":"kernel32 GetDriveTypeA: FF 25 <absolute dispatch slot>",
    })
