from __future__ import annotations

import struct

from exerepair.crypto import crc32, xor_in_place


STUB_SPECS = {
    0x00576453: (0x140, 0x1000, 16, "v1", 0),
    0x32576453: (0x1180, 0x2000, 16, "v2", 0),
    0x33576453: (0x1280, 0x2000, 16, "v2", 0x100),
    0x34576453: (0x9540, 0x10000, 256, "v3", 0x100),
    0x35576453: (0x9540, 0x10000, 256, "v3", 0x100),
    0x36576453: (0x9540, 0x10000, 256, "v3", 0x100),
    0x37576453: (0x9540, 0x10000, 256, "v3", 0x100),
}


def make_pe(bitness: int = 32, raw_size: int = 0x400) -> bytearray:
    machine = 0x014C if bitness == 32 else 0x8664
    optional_size = 0xE0 if bitness == 32 else 0xF0
    pe_offset = 0x80
    raw_offset = 0x200
    image = bytearray(raw_offset + raw_size)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        image,
        pe_offset + 4,
        machine,
        1,
        0,
        0,
        0,
        optional_size,
        0x0102,
    )
    optional_offset = pe_offset + 24
    struct.pack_into("<H", image, optional_offset, 0x10B if bitness == 32 else 0x20B)
    section_offset = optional_offset + optional_size
    struct.pack_into(
        "<8sIIIIIIHHI",
        image,
        section_offset,
        b".text\0\0\0",
        raw_size,
        0x1000,
        raw_size,
        raw_offset,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    return image


def encrypted_resource(
    payload: bytes, position: int, signature1: int, signature2: int
) -> bytes:
    if len(payload) < 4:
        raise ValueError("payload must include a four-byte signature")
    data = bytearray(payload)
    struct.pack_into("<I", data, 0, signature2)
    xor_in_place(memoryview(data)[4:], position)
    return bytes(data)


def _write_c_string(target: memoryview, value: str) -> None:
    encoded = value.encode("cp932")
    if len(encoded) >= len(target):
        raise ValueError("test string does not fit")
    target[: len(encoded)] = encoded
    target[len(encoded)] = 0


def make_stub(
    version: int,
    mode: int,
    patches: list[dict[str, int | str]] | None = None,
    executable_name: str = "",
    key: int = 0x13572468,
) -> tuple[bytes, int]:
    size, align_size, patch_count, patch_format, name_tail_size = STUB_SPECS[version]
    arguments = bytearray(size)
    struct.pack_into("<I", arguments, 0x3C, mode)
    patches = patches or []
    records = memoryview(arguments)[0x40 : size - name_tail_size]

    for index, patch in enumerate(patches):
        if index >= patch_count:
            raise ValueError("too many patches")
        if patch_format == "v1":
            struct.pack_into(
                "<IIII",
                records,
                index * 0x10,
                int(patch.get("position", 0)),
                int(patch.get("signature1", 0)),
                int(patch.get("signature2", 0)),
                int(patch.get("reserve1", 0)),
            )
            continue

        name_size = 0x100 if patch_format == "v2" else 0x80
        record_size = name_size + 0x14
        offset = index * record_size
        file_name = str(patch.get("file_name", ""))
        if file_name:
            _write_c_string(records[offset : offset + name_size], file_name)
        struct.pack_into(
            "<IIIII",
            records,
            offset + name_size,
            int(patch.get("position", 0)),
            int(patch.get("signature1", 0)),
            int(patch.get("length", 0)),
            int(patch.get("signature2", 0)),
            int(patch.get("reserve1", 0)),
        )

    if name_tail_size and executable_name:
        _write_c_string(memoryview(arguments)[-name_tail_size:], executable_name)

    checksum = crc32(arguments)
    encrypted = bytearray(arguments)
    xor_in_place(encrypted, key)
    return struct.pack("<IIII", version, checksum, key, 0) + encrypted, align_size


def make_embedded_wrapper(stub: bytes, align_size: int, executable: bytes) -> bytes:
    wrapper = make_pe(32)
    overlay = len(wrapper)
    result = bytearray(overlay + align_size + len(executable))
    result[:overlay] = wrapper
    result[overlay : overlay + len(stub)] = stub
    result[overlay + align_size :] = executable
    return bytes(result)


def make_external_wrapper(stub: bytes) -> bytes:
    wrapper = make_pe(32)
    return bytes(wrapper) + stub
