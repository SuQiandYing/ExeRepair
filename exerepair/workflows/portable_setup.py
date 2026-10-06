"""Pure, configuration-driven setup-call replacements for a verified x86 ABI."""
from __future__ import annotations

from dataclasses import dataclass
import struct

from ..domain.recovery import PortableSetupProfile, RecoveryError

STUB_OFFSET = 0xC00
TEXT_OFFSET = 0x40
LITERAL_OFFSET = 0x70
HELPER_CAPACITY = 0x1000
STRING_OBJECT_SIZE = 24


@dataclass(frozen=True, slots=True)
class PortableSetupPlan:
    code: bytes
    patches: tuple[tuple[int, bytes, bytes], ...]
    guards: tuple[tuple[int, bytes], ...]
    directory_object_va: int


def _relative_call(instruction_va: int, destination_va: int) -> bytes:
    displacement = destination_va - instruction_va - 5
    if not -(1 << 31) <= displacement < (1 << 31):
        raise RecoveryError("安装目录调用超出 rel32 范围")
    return b"\xe8" + struct.pack("<i", displacement)


def validate_directory_object(spec: PortableSetupProfile, image_size: int) -> None:
    """The directory belongs to the wrapper image, not the late disc module."""
    if (spec.directory_object_rva % 4 or
            not 0x1000 <= spec.directory_object_rva <= image_size - STRING_OBJECT_SIZE):
        raise RecoveryError("安装目录字符串对象未对齐或超出输入映像")


def build_portable_setup(
    spec: PortableSetupProfile, image_base: int, code_va: int, module_size: int,
) -> PortableSetupPlan:
    """Bind validated call sites and generate stubs without I/O or game labels."""
    if not spec.directory_queries:
        raise RecoveryError("安装目录查询调用点不能为空")
    calls = (spec.key_check, *spec.directory_queries, spec.setup_query)
    guards = (*calls, spec.assign_string, spec.assign_text)
    for rva, expected in guards:
        if not expected or not 0x1000 <= rva <= module_size - len(expected):
            raise RecoveryError("安装目录代码保护范围无效")
    for _, expected in calls:
        if len(expected) != 5 or expected[0] != 0xE8:
            raise RecoveryError("安装目录调用点必须是完整的 CALL rel32")
    ordered = sorted((rva, rva + len(expected)) for rva, expected in guards)
    if any(end > next_start for (_, end), (next_start, _) in zip(ordered, ordered[1:])):
        raise RecoveryError("安装目录代码保护范围重叠")
    if (image_base < 0 or image_base + module_size > 1 << 32 or
            not 0 <= code_va <= (1 << 32) - HELPER_CAPACITY):
        raise RecoveryError("安装目录 helper 地址超出 32 位范围")
    validate_directory_object(spec, (1 << 32) - image_base)
    if not spec.installed_value or "\0" in spec.installed_value:
        raise RecoveryError("安装类型值必须是非空、无内嵌 NUL 的字符串")
    try:
        literal = (spec.installed_value + "\0").encode("utf-16-le")
    except UnicodeEncodeError as error:
        raise RecoveryError("安装类型值不是有效的 UTF-16 字符串") from error
    if len(literal) > HELPER_CAPACITY - STUB_OFFSET - LITERAL_OFFSET:
        raise RecoveryError("安装类型值超出 helper 容量")

    path_va = code_va + STUB_OFFSET
    text_va = path_va + TEXT_OFFSET
    literal_va = path_va + LITERAL_OFFSET
    directory_va = image_base + spec.directory_object_rva
    # Copy with the engine allocator, preserving the source string's ownership.
    path_code = b"\x6a\x00\x68" + struct.pack("<I", directory_va) + b"\x83\xc8\xff"
    path_code += _relative_call(path_va + len(path_code), image_base + spec.assign_string[0])
    path_code += b"\xb8\x01\x00\x00\x00\xc3"
    text_code = b"\x56\x8b\xf1\xb8" + struct.pack("<I", literal_va)
    # PUSH imm8 is sign-extended; use imm32 for longer configuration values.
    units = len(literal) // 2 - 1
    text_code += b"\x6a" + bytes([units]) if units < 0x80 else b"\x68" + struct.pack("<I", units)
    text_code += _relative_call(text_va + len(text_code), image_base + spec.assign_text[0])
    text_code += b"\x5e\xb8\x01\x00\x00\x00\xc3"
    if len(path_code) > TEXT_OFFSET or len(text_code) > LITERAL_OFFSET - TEXT_OFFSET:
        raise RecoveryError("安装目录 stub 布局重叠")
    code = (path_code.ljust(TEXT_OFFSET, b"\xcc") +
            text_code.ljust(LITERAL_OFFSET - TEXT_OFFSET, b"\xcc") + literal)
    patches = [(spec.key_check[0], spec.key_check[1], bytes.fromhex("b001909090"))]
    patches.extend(
        (rva, expected, _relative_call(image_base + rva, path_va))
        for rva, expected in spec.directory_queries
    )
    rva, expected = spec.setup_query
    patches.append((rva, expected, _relative_call(image_base + rva, text_va)))
    return PortableSetupPlan(code, tuple(patches), tuple(guards), directory_va)
