"""Structural discovery for a bounded PE32 disc-check family."""
from __future__ import annotations

from dataclasses import replace
import re
import struct

from ..domain.recovery import DiscCheckProfile, RecoveryError
from ..formats.enigma import EnigmaFormatError, PEImage
from .repair import sha256


_RETURN_GUARD = bytes.fromhex("8b45e88b4df464890d000000008be55dc3")
_CALLER_PREFIX = bytes.fromhex("9083f8050f85")
_PROLOGUE = bytes.fromhex("558bec")
_STORE_EAX = re.compile(rb"\x8b\x45\xe8\xa3(.{4})", re.DOTALL)
_STORE_ECX = re.compile(rb"\x8b\x4d\xe8\x89\x0d(.{4})", re.DOTALL)
_MAIN_CHECK = re.compile(rb"\xe8....\x83\xc4\x08\x84\xc0\x0f\x85....", re.DOTALL)
_MAIN_RETRY = re.compile(rb"\xe8....\x83\xc4\x08\x84\xc0\x0f\x84....", re.DOTALL)
_MAIN_REGISTER_CHECK = re.compile(
    rb"\xe8....\x83\xc4\x08\x84\xc0\x0f\x85....", re.DOTALL,
)
_MAIN_REGISTER_CHECK_SHORT = re.compile(
    rb"\xe8....\x83\xc4\x08\x84\xc0\x75.", re.DOTALL,
)
_MAIN_REGISTER_RETRY = re.compile(
    rb"\xe8....\x83\xc4\x08\x84\xc0\x74.", re.DOTALL,
)
_MAX_MODULE_SIZE = 64 * 1024 * 1024


def discover_disc_candidate(data: bytes) -> DiscCheckProfile:
    """Identify a loader candidate without executing the input."""
    try:
        pe = PEImage.parse(data)
        if pe.bitness != 32:
            raise RecoveryError("仅支持 PE32 检查候选")
        nt = struct.unpack_from("<I", data, 0x3C)[0]
        optional = nt + 24
        optional_size = struct.unpack_from("<H", data, nt + 20)[0]
        if optional_size < 0xE0 or pe.image_base + pe.size_of_image > 0x100000000:
            raise RecoveryError("PE32 映像范围无效")
        entry = pe.rva_to_offset(pe.entry_rva)
        section = pe.section_for_rva(pe.entry_rva)
        if not section.characteristics & 0x20000000:
            raise RecoveryError("入口不在可执行节")
        if entry + 25 > min(len(data), section.raw_offset + section.raw_size):
            raise RecoveryError("入口引导代码不完整")
        code = data[entry:entry + 25]
        if (
            code[:11] != bytes.fromhex("6800000000680100000068")
            or struct.unpack_from("<I", code, 11)[0] != pe.image_base
            or code[15] != 0x68
            or code[20] != 0xE9
        ):
            raise RecoveryError("入口不匹配受支持的加载结构")
        bootstrap_address = struct.unpack_from("<I", code, 16)[0]
        if not pe.image_base <= bootstrap_address < pe.image_base + pe.size_of_image:
            raise RecoveryError("加载器地址不在映像中")
        branch_rva = pe.entry_rva + 25 + struct.unpack_from("<i", code, 21)[0]
        if not pe.section_for_rva(branch_rva).characteristics & 0x20000000:
            raise RecoveryError("加载器跳转不在可执行节")
        pe.rva_to_offset(branch_rva)
        slot = optional + optional_size + len(pe.sections) * 40
        if slot + 80 > pe.size_of_headers or data[slot:slot + 80] != bytes(80):
            raise RecoveryError("PE 缺少两个空白节表槽")
        if any(struct.unpack_from("<II", data, optional + 96 + 4 * 8)):
            raise RecoveryError("不修改带有数字签名的输入")
        dynamic = bool(struct.unpack_from("<H", data, optional + 0x46)[0] & 0x40)
        reloc = struct.unpack_from("<II", data, optional + 96 + 5 * 8)
        if dynamic and (
            any(reloc) or any(section.name == ".reloc" for section in pe.sections)
        ):
            raise RecoveryError("运行时检查候选不支持带重定位的 ASLR")
    except (EnigmaFormatError, struct.error, OverflowError) as error:
        raise RecoveryError(f"无法识别 PE32 加载结构：{error}") from error
    return DiscCheckProfile(
        name="pe32-runtime-disc-candidate",
        baseline_sha256=sha256(data),
        baseline_size=len(data),
        image_base=pe.image_base,
        entry_rva=pe.entry_rva,
        entry_bytes=code,
        module_image_size=0,
        caller_return_rva=0,
        caller_guard=b"",
        return_rva=0,
        return_guard=b"",
        success_flag_rva=0,
        allow_dynamic_base_without_relocations=dynamic,
        requires_runtime_discovery=True,
    )


def _contains_direct_call(image: bytes, start: int, end: int, target: int) -> bool:
    position = start
    while True:
        position = image.find(b"\xe8", position, end)
        if position < 0 or position + 5 > end:
            return False
        displacement = struct.unpack_from("<i", image, position + 1)[0]
        if position + 5 + displacement == target:
            return True
        position += 1


def bind_disc_evidence(
    pending: DiscCheckProfile,
    original: bytes,
    image: bytes,
    runtime_base: int,
    caller_rva: int,
) -> DiscCheckProfile:
    """Bind one observed API call to a unique guarded scalar-return function."""
    if not pending.requires_runtime_discovery:
        raise RecoveryError("光盘配置不是待验证候选")
    if sha256(original) != pending.baseline_sha256 or len(original) != pending.baseline_size:
        raise RecoveryError("运行时证据与原始文件不匹配")
    if not isinstance(image, bytes) or not 0x1000 <= len(image) <= _MAX_MODULE_SIZE:
        raise RecoveryError("运行时模块大小无效")
    if not isinstance(runtime_base, int) or not 0 <= runtime_base <= 0xFFFFFFFF - len(image):
        raise RecoveryError("运行时模块基址无效")
    if not isinstance(caller_rva, int):
        raise RecoveryError("运行时调用位置无效")
    try:
        pe = PEImage.parse(image)
    except (EnigmaFormatError, struct.error) as error:
        raise RecoveryError("运行时模块不是完整的 PE32 映像") from error
    if pe.bitness != 32 or pe.size_of_image != len(image):
        raise RecoveryError("运行时模块位数或映像大小不匹配")
    sections = []
    for section in pe.sections:
        start = section.virtual_address
        end = start + max(section.virtual_size, section.raw_size)
        if start < 0x1000 or end > len(image) or end <= start:
            raise RecoveryError("运行时模块节范围无效")
        if section.characteristics & 0x20000000:
            sections.append((start, end))
    if not sections or any(
        start < other_end and other_start < end
        for index, (start, end) in enumerate(sections)
        for other_start, other_end in sections[index + 1:]
    ):
        raise RecoveryError("运行时可执行节无效或重叠")
    caller_section = next(
        ((start, end) for start, end in sections if start + 5 <= caller_rva <= end - 10),
        None,
    )
    if caller_section is None:
        raise RecoveryError("运行时调用点不在可执行节内")
    caller_guard = image[caller_rva:caller_rva + 10]
    if image[caller_rva - 5] != 0xE8 or not caller_guard.startswith(_CALLER_PREFIX):
        raise RecoveryError("运行时调用点不是受支持的驱动器检查")
    caller_start = image.rfind(
        _PROLOGUE, max(caller_section[0], caller_rva - 0x4000), caller_rva
    )
    if caller_start < 0:
        raise RecoveryError("无法验证驱动器检查函数入口")

    candidates: list[tuple[int, int]] = []
    for section_start, section_end in sections:
        position = section_start
        while True:
            epilogue = image.find(_RETURN_GUARD, position, section_end)
            if epilogue < 0:
                break
            position = epilogue + 1
            function_start = image.rfind(
                _PROLOGUE, max(section_start, epilogue - 0x4000), epilogue
            )
            if function_start < 0 or not _contains_direct_call(
                image, function_start, epilogue, caller_start
            ):
                continue
            body = image[function_start:epilogue]
            first = {match.group(1) for match in _STORE_EAX.finditer(body)}
            second = {match.group(1) for match in _STORE_ECX.finditer(body)}
            for encoded in first & second:
                flag = struct.unpack("<I", encoded)[0] - runtime_base
                if not 0x1000 <= flag <= len(image) - 4:
                    continue
                if any(
                    flag < start + size and start < flag + 4
                    for start, size in (
                        (caller_rva, len(caller_guard)),
                        (epilogue, len(_RETURN_GUARD)),
                    )
                ):
                    continue
                candidates.append((epilogue, flag))
    if len(candidates) != 1:
        raise RecoveryError(f"运行时检查点不是唯一结果（{len(candidates)} 个）")
    epilogue, flag = candidates[0]
    return replace(
        pending,
        name="pe32-runtime-disc-verified",
        module_image_size=len(image),
        caller_return_rva=caller_rva,
        caller_guard=caller_guard,
        return_rva=epilogue,
        return_guard=_RETURN_GUARD,
        success_flag_rva=flag,
        requires_runtime_discovery=False,
    )


def bind_main_disc_evidence(
    profile: DiscCheckProfile,
    original: bytes,
    image: bytes,
    runtime_base: int,
    message_return_rva: int,
) -> DiscCheckProfile:
    """Find a uniquely guarded message/retry check in the unpacked main image."""
    if (
        profile.requires_runtime_discovery or profile.region_patch_sites
        or profile.setup_patch_sites or profile.registry_open_slot_rva is not None
        or profile.portable_setup is not None or profile.static_patch_sites
    ):
        raise RecoveryError("主映像检查需要已验证且未使用附加补丁的配置")
    if sha256(original) != profile.baseline_sha256 or len(original) != profile.baseline_size:
        raise RecoveryError("主映像证据与原始文件不匹配")
    if not isinstance(image, bytes) or not 0x1000 <= len(image) <= _MAX_MODULE_SIZE:
        raise RecoveryError("主映像大小无效")
    if runtime_base != profile.image_base:
        raise RecoveryError("主映像运行时基址与 PE 首选基址不一致")
    try:
        pe = PEImage.parse(image)
        original_pe = PEImage.parse(original)
    except (EnigmaFormatError, struct.error) as error:
        raise RecoveryError("主映像不是完整的 PE32 映像") from error
    if (
        pe.bitness != 32 or pe.image_base != runtime_base
        or pe.size_of_image != len(image)
        or pe.size_of_image != original_pe.size_of_image
        or len(pe.sections) != len(original_pe.sections)
        or [
            (
                section.virtual_size,
                section.virtual_address,
                section.raw_size,
                section.characteristics & 0x20000000,
            )
            for section in pe.sections
        ]
        != [
            (
                section.virtual_size,
                section.virtual_address,
                section.raw_size,
                section.characteristics & 0x20000000,
            )
            for section in original_pe.sections
        ]
    ):
        raise RecoveryError("主映像位数、基址或节布局不匹配")
    if not isinstance(message_return_rva, int) or not 6 <= message_return_rva < len(image):
        raise RecoveryError("主映像消息框返回位置无效")
    call_rva = message_return_rva - 6
    observed_call = image[call_rva:message_return_rva]
    register_call = image[message_return_rva - 2:message_return_rva] == b"\xff\xd3"
    if observed_call[:2] != b"\xff\x15" and not register_call:
        raise RecoveryError("消息框调用不是受支持的间接调用")
    if register_call:
        call_rva = message_return_rva - 2
    try:
        section = pe.section_for_rva(call_rva)
    except EnigmaFormatError as error:
        raise RecoveryError("消息框调用不在主映像节内") from error
    if not section.characteristics & 0x20000000:
        raise RecoveryError("消息框调用不在可执行节")
    if register_call:
        prefix_start = max(section.virtual_address, call_rva - 0x200)
        prefixes = list(re.finditer(rb"\x8b\x1d(.{4})", image[prefix_start:call_rva], re.DOTALL))
        if not prefixes:
            raise RecoveryError("消息框寄存器没有可验证的导入槽")
        iat = struct.unpack("<I", prefixes[-1].group(1))[0]
    else:
        iat = struct.unpack_from("<I", observed_call, 2)[0]
    if not runtime_base <= iat <= runtime_base + len(image) - 4:
        raise RecoveryError("消息框导入槽不在主映像内")
    candidates: list[tuple[int, int, bytes, bytes]] = []
    for current_section in pe.sections:
        if not current_section.characteristics & 0x20000000:
            continue
        start = current_section.virtual_address
        end = start + max(current_section.virtual_size, current_section.raw_size)
        if not 0x1000 <= start < end <= len(image):
            raise RecoveryError("主映像可执行节范围无效")
        first_checks = (
            _MAIN_CHECK.finditer(image, start, end) if not register_call else ()
        )
        for first in first_checks:
            pos = first.start()
            target = pos + 16 + struct.unpack_from("<i", image, pos + 12)[0]
            callee = pos + 5 + struct.unpack_from("<i", image, pos + 1)[0]
            for second in _MAIN_RETRY.finditer(image, pos + 16, min(end, pos + 0x500)):
                again = second.start()
                retry_target = again + 16 + struct.unpack_from("<i", image, again + 12)[0]
                if (
                    again + 5 + struct.unpack_from("<i", image, again + 1)[0] != callee
                    or target != again + 16
                    or not pos + 16 <= retry_target < again
                    or not start <= callee < end
                ):
                    continue
                message = call_rva
                if (
                    not retry_target <= message < again
                    or image[message + 6:message + 10] != b"\x83\xf8\x01\x75"
                ):
                    continue
                guard = image[pos:pos + 16]
                expected = guard[10:16]
                displacement = struct.unpack_from("<i", expected, 2)[0]
                if displacement == 0x7FFFFFFF:
                    continue
                replacement = b"\xe9" + struct.pack("<i", displacement + 1) + b"\x90"
                candidates.append((pos, pos + 10, guard, replacement))
        if register_call and start <= call_rva < end:
            firsts = (
                *_MAIN_REGISTER_CHECK.finditer(image, max(start, call_rva - 0x200), call_rva),
                *_MAIN_REGISTER_CHECK_SHORT.finditer(
                    image, max(start, call_rva - 0x200), call_rva,
                ),
            )
            for first in firsts:
                pos = first.start()
                short = len(first.group()) == 12
                target = (
                    pos + 12 + struct.unpack_from("<b", image, pos + 11)[0]
                    if short else pos + 16 + struct.unpack_from("<i", image, pos + 12)[0]
                )
                callee = pos + 5 + struct.unpack_from("<i", image, pos + 1)[0]
                for second in _MAIN_REGISTER_RETRY.finditer(
                    image, message_return_rva, min(end, message_return_rva + 0x100),
                ):
                    again = second.start()
                    retry_target = again + 12 + struct.unpack_from("<b", image, again + 11)[0]
                    if (
                        again + 5 + struct.unpack_from("<i", image, again + 1)[0] != callee
                        or target != again + 12
                        or not pos <= retry_target < call_rva
                        or not start <= callee < end
                        or image[message_return_rva:message_return_rva + 4]
                        != b"\x83\xf8\x01\x75"
                    ):
                        continue
                    guard = first.group()
                    if short:
                        replacement = b"\xeb" + guard[11:12]
                    else:
                        displacement = struct.unpack_from("<i", guard, 12)[0]
                        if displacement == 0x7FFFFFFF:
                            continue
                        replacement = b"\xe9" + struct.pack("<i", displacement + 1) + b"\x90"
                    candidates.append((pos, pos + 10, guard, replacement))
    if len(candidates) > 1:
        raise RecoveryError(f"主映像消息检查不是唯一结果（{len(candidates)} 个）")
    if not candidates:
        return replace(
            profile,
            runtime_note="未识别到受支持的附加主程序检查；生成结果尚未验证完整启动。",
        )
    guard_rva, patch_rva, guard, replacement = candidates[0]
    try:
        original_section = original_pe.section_for_rva(patch_rva)
    except EnigmaFormatError as error:
        raise RecoveryError("主映像补丁位置不在原始映像节内") from error
    if (
        not original_section.characteristics & 0x20000000
        or patch_rva + len(replacement) > original_pe.size_of_image
        or guard_rva + len(guard) > original_pe.size_of_image
        or guard_rva + len(guard) > profile.module_image_size
        or (profile.image_base + guard_rva) // 0x1000
        != (profile.image_base + guard_rva + len(guard) - 1) // 0x1000
    ):
        raise RecoveryError("主映像补丁位置不在原始可执行映像内")
    return replace(
        profile,
        region_ready_rva=guard_rva,
        region_ready_bytes=guard,
        region_patch_sites=((patch_rva, guard[10:16], replacement),),
        runtime_note="已定位模块及主映像检查；仍需在实际运行环境中验证启动。",
    )
