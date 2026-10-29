"""Enigma configuration and packed section recovery.

This module implements the data-driven Enigma unpacking layer. Loader instruction
interpretation is intentionally injected through the metadata RVA and optional
layout object; callers that have a static entry analyzer can feed those values
without pulling runtime capture or GPU dependencies into the format layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import md5
from typing import Callable, Iterable, Sequence
import struct

from .enigma import EnigmaFormatError, PEImage
from .enigma_common import (
    SectionProbe,
    crc32,
    decipher,
    expanded_size,
    fix_branches,
    lz_decompress,
    plausible_prefix,
    section_key,
)


@dataclass(frozen=True, slots=True)
class EnigmaLayout:
    """Serialized Loader copy ranges needed to materialize the context."""

    copies: tuple[tuple[int, int], ...]

    @property
    def context_size(self) -> int:
        return max((destination + size for destination, size in self.copies), default=0)


@dataclass(frozen=True, slots=True)
class Recovered:
    rva: int
    bytes: bytes


@dataclass(frozen=True, slots=True)
class Descriptor:
    index: int
    enabled: bool
    flags: int
    packed_size: int
    expanded_size: int
    rva: int
    characteristics: int
    seed: bytes
    crc32: int


@dataclass(frozen=True, slots=True)
class Configuration:
    descriptors: tuple[Descriptor, ...]
    entry_patch: Recovered | None
    context: bytes | None
    loader: bytes | None
    layout: EnigmaLayout | None
    metadata_rva: int
    metadata_key: bytes

    @property
    def ctx(self) -> bytes | None:
        """Alias for the serialized Loader context."""

        return self.context


@dataclass(frozen=True, slots=True)
class StoredSection:
    descriptor: Descriptor
    ciphertext: bytes


@dataclass(frozen=True, slots=True)
class ImportRecord:
    dll: str
    name: str | None
    ordinal: int | None
    iat_rva: int


def _read_rva(data: bytes | bytearray | memoryview, pe: PEImage, rva: int, size: int) -> bytes:
    if rva < 0 or size < 0:
        raise EnigmaFormatError("negative PE read range")
    end = rva + size
    if end < rva or end > pe.size_of_image:
        raise EnigmaFormatError("RVA range is outside the image")
    if end <= pe.size_of_headers:
        offset = rva
    else:
        section = pe.section_for_rva(rva)
        delta = rva - section.virtual_address
        next_starts = [
            item.virtual_address
            for item in pe.sections
            if item.virtual_address > section.virtual_address
            and (item.virtual_size or item.raw_size)
        ]
        if next_starts and end > min(next_starts):
            raise EnigmaFormatError("RVA range overlaps the next section")
        if delta + size > section.raw_size:
            raise EnigmaFormatError("RVA range is not file backed")
        offset = section.raw_offset + delta
    if offset + size > len(data):
        raise EnigmaFormatError("file-backed RVA range exceeds the input")
    return bytes(memoryview(data)[offset : offset + size])


def _section_bytes(data: bytes, section) -> bytes:
    if not section.raw_size:
        return b""
    end = section.raw_offset + section.raw_size
    if end > len(data):
        raise EnigmaFormatError("section raw range exceeds the input")
    return data[section.raw_offset:end]


def _derive_key(data: bytes, pe: PEImage, count: int, skip_shared: bool) -> bytes:
    key = bytearray(16)
    for section in pe.sections[:count]:
        if skip_shared and section.characteristics & 0x10000000:
            continue
        digest = md5(_section_bytes(data, section)).digest()
        for index, value in enumerate(digest):
            key[index] ^= value
    return bytes(key)


def _layout_copies(layout: EnigmaLayout | object | Sequence[tuple[int, int]] | None):
    if layout is None:
        return None
    if isinstance(layout, EnigmaLayout):
        return layout.copies
    copies = getattr(layout, "copies", layout)
    result = tuple((int(destination), int(size)) for destination, size in copies)
    if any(destination < 0 or size < 0 for destination, size in result):
        raise EnigmaFormatError("negative Loader copy range")
    return result


def parse_configuration(
    data: bytes | bytearray | memoryview,
    pe: PEImage,
    metadata_rva: int,
    *,
    loader: bytes | None = None,
    layout: EnigmaLayout | object | Sequence[tuple[int, int]] | None = None,
) -> Configuration:
    """Decode the Enigma metadata stream at an explicitly proven RVA."""

    raw = bytes(data)
    header = _read_rva(raw, pe, metadata_rva, 28)
    count, packed_size, expected = struct.unpack_from("<III", header, 0)
    if not 0 < count <= len(pe.sections):
        raise EnigmaFormatError("invalid metadata key section count")
    if packed_size == 0:
        raise EnigmaFormatError("empty metadata ciphertext")
    expanded_size(expected)
    ciphertext = _read_rva(raw, pe, metadata_rva + 28, packed_size)
    if md5(ciphertext).digest() != header[12:28]:
        raise EnigmaFormatError("metadata ciphertext MD5 mismatch")

    plain = None
    metadata_key = None
    for skip_shared in (True, False):
        candidate_key = _derive_key(raw, pe, count, skip_shared)
        packed = decipher(ciphertext, candidate_key)
        try:
            candidate = lz_decompress(packed, expected, strict=True)
        except EnigmaFormatError:
            continue
        if len(candidate) >= 16 and md5(candidate[16:]).digest() == candidate[:16]:
            plain = candidate
            metadata_key = candidate_key
            break
    if plain is None or metadata_key is None:
        raise EnigmaFormatError("metadata RC4/LZ/plaintext MD5 verification failed")

    if len(plain) < 24:
        raise EnigmaFormatError("metadata plaintext is truncated")
    patch_size = struct.unpack_from("<I", plain, 16)[0]
    patch = None
    if patch_size:
        patch_rva = struct.unpack_from("<I", plain, 20)[0]
        patch_data = plain[24 : 24 + patch_size]
        if len(patch_data) != patch_size:
            raise EnigmaFormatError("metadata entry patch is truncated")
        patch = Recovered(patch_rva, bytes(patch_data))
    count_at = 24 + patch_size
    if count_at + 4 > len(plain):
        raise EnigmaFormatError("metadata descriptor count is truncated")
    descriptor_count = struct.unpack_from("<I", plain, count_at)[0]
    if not 0 < descriptor_count <= len(pe.sections):
        raise EnigmaFormatError("invalid descriptor count")
    table_at = count_at + 4
    table_size = descriptor_count * 80
    table = plain[table_at : table_at + table_size]
    if len(table) != table_size:
        raise EnigmaFormatError("metadata descriptor table is truncated")
    descriptors = []
    for index in range(descriptor_count):
        raw_descriptor = table[index * 80 : (index + 1) * 80]
        enabled = raw_descriptor[0] != 0
        packed = struct.unpack_from("<I", raw_descriptor, 8)[0]
        expanded = struct.unpack_from("<I", raw_descriptor, 12)[0]
        if enabled:
            expanded_size(expanded)
        descriptors.append(
            Descriptor(
                index=index,
                enabled=enabled,
                flags=struct.unpack_from("<I", raw_descriptor, 4)[0],
                packed_size=packed,
                expanded_size=expanded,
                rva=struct.unpack_from("<I", raw_descriptor, 16)[0],
                characteristics=struct.unpack_from("<I", raw_descriptor, 36)[0],
                seed=bytes(raw_descriptor[20:36]),
                crc32=struct.unpack_from("<I", raw_descriptor, 60)[0],
            )
        )

    at = table_at + table_size
    if at + 4 > len(plain):
        raise EnigmaFormatError("metadata record count is truncated")
    records20 = struct.unpack_from("<I", plain, at)[0]
    if records20 > 0x10000:
        raise EnigmaFormatError("invalid 20-byte record count")
    at += 4 + records20 * 20
    if at + 4 > len(plain):
        raise EnigmaFormatError("metadata pair count is truncated")
    pairs = struct.unpack_from("<I", plain, at)[0]
    if pairs > 0x10000:
        raise EnigmaFormatError("invalid pair count")
    at += 4 + pairs * 8
    if at > len(plain):
        raise EnigmaFormatError("metadata serialized tables are truncated")

    copies = _layout_copies(layout)
    context = None
    resolved_layout = layout if isinstance(layout, EnigmaLayout) else None
    if copies is not None:
        expected_tail = sum(size for _, size in copies)
        if len(plain) - at != expected_tail:
            raise EnigmaFormatError("serialized config length disagrees with Loader layout")
        size = max((destination + length for destination, length in copies), default=0)
        context_buffer = bytearray(size)
        for destination, length in copies:
            end = at + length
            if end > len(plain):
                raise EnigmaFormatError("serialized Loader copy exceeds metadata")
            context_buffer[destination : destination + length] = plain[at:end]
            at = end
        context = bytes(context_buffer)
        if resolved_layout is None:
            resolved_layout = EnigmaLayout(tuple(copies))
    else:
        # Unknown Loader layouts may leave a fixed serialized tail. Preserve
        # the descriptors while withholding a guessed context projection.
        pass

    return Configuration(
        descriptors=tuple(descriptors),
        entry_patch=patch,
        context=context,
        loader=loader,
        layout=resolved_layout,
        metadata_rva=metadata_rva,
        metadata_key=metadata_key,
    )


def stored_sections(
    data: bytes | bytearray | memoryview,
    pe: PEImage,
    config: Configuration,
) -> tuple[StoredSection, ...]:
    raw = bytes(data)
    sections = []
    for descriptor in config.descriptors:
        if descriptor.rva == 0:
            break
        if not descriptor.enabled:
            continue
        if descriptor.rva + descriptor.expanded_size > pe.size_of_image:
            raise EnigmaFormatError("section expansion is outside the image")
        ciphertext = (
            b""
            if descriptor.packed_size == 0
            else _read_rva(raw, pe, descriptor.rva, descriptor.packed_size)
        )
        sections.append(StoredSection(descriptor, ciphertext))
    if not sections:
        raise EnigmaFormatError("no enabled sections")

    if config.entry_patch is not None:
        patch = config.entry_patch
        matches = []
        for index, section in enumerate(sections):
            offset = patch.rva - section.descriptor.rva
            end = offset + len(patch.bytes)
            if offset >= 0 and end <= len(section.ciphertext):
                matches.append((index, offset, end))
        if len(matches) != 1:
            raise EnigmaFormatError("bootstrap patch destination is missing or ambiguous")
        index, offset, end = matches[0]
        mutable = bytearray(sections[index].ciphertext)
        mutable[offset:end] = patch.bytes
        sections[index] = StoredSection(sections[index].descriptor, bytes(mutable))
    return tuple(sections)


def decode_section(section: StoredSection, salt: int | None = None, *, filter_branches: bool = False) -> bytes:
    descriptor = section.descriptor
    if descriptor.packed_size == 0:
        return bytes(descriptor.expanded_size)
    if descriptor.flags & 8:
        key = descriptor.seed if salt is None else section_key(descriptor.seed, salt)
        packed = decipher(section.ciphertext, key)
    else:
        packed = section.ciphertext
    actual_crc = crc32(packed)
    if actual_crc != descriptor.crc32:
        raise EnigmaFormatError(
            f"section {descriptor.index} CRC32 mismatch: {actual_crc:08x} != {descriptor.crc32:08x}"
        )
    if descriptor.flags & 1:
        expanded = lz_decompress(packed, descriptor.expanded_size, strict=True)
    else:
        if len(packed) != descriptor.expanded_size:
            raise EnigmaFormatError("uncompressed section size mismatch")
        expanded = packed
    return fix_branches(expanded) if filter_branches and descriptor.flags & 4 else expanded


def verify_sections(sections: Iterable[StoredSection], salt: int | None = None) -> None:
    for section in sections:
        decode_section(section, salt)


def recover_sections(
    sections: Iterable[StoredSection], salt: int | None = None
) -> tuple[Recovered, ...]:
    return tuple(
        Recovered(section.descriptor.rva, decode_section(section, salt, filter_branches=True))
        for section in sections
    )


def _screen_matches(section: StoredSection, salt: int) -> bool:
    descriptor = section.descriptor
    cipher = SectionProbe(descriptor.seed).cipher(salt)
    clear = bytearray()
    for value in section.ciphertext:
        clear.append(cipher.byte(value))
    if descriptor.flags & 1:
        for length in (min(8, len(clear)), min(64, len(clear))):
            if not plausible_prefix(clear[:length], len(clear), descriptor.expanded_size):
                return False
    return crc32(clear) == descriptor.crc32


def search_salt(
    sections: Sequence[StoredSection],
    *,
    start: int = 0,
    count: int = 1 << 32,
    backend: str = "cpu",
    progress: Callable[[int], None] | None = None,
) -> int | None:
    """Search the 32-bit section salt with complete section verification.

    The bounded exact backend is intended for small ranges and correctness
    checks. The accelerated adapters can be used for larger ranges.
    """

    if backend not in ("cpu", "auto"):
        raise EnigmaFormatError(f"unsupported static Enigma search backend: {backend}")
    if not 0 <= start < 1 << 32 or not 0 < count <= (1 << 32) - start:
        raise ValueError("invalid 32-bit salt search range")
    if all(_try_verify_without_salt(section) for section in sections):
        return None
    candidates = [
        section
        for section in sections
        if section.descriptor.flags & 8 and section.ciphertext
    ]
    if not candidates:
        raise EnigmaFormatError("no nonempty RC4 section to search")
    screen = min(candidates, key=lambda item: len(item.ciphertext))
    end = start + count
    for salt in range(start, end):
        if _screen_matches(screen, salt):
            try:
                verify_sections(sections, salt)
            except EnigmaFormatError:
                pass
            else:
                if progress is not None:
                    progress(salt - start + 1)
                return salt
        if progress is not None:
            progress(salt - start + 1)
    raise EnigmaFormatError("no salt passed section verification")


def _try_verify_without_salt(section: StoredSection) -> bool:
    try:
        decode_section(section, None)
    except EnigmaFormatError:
        return False
    return True


class _Cursor:
    __slots__ = ("data", "at")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def read(self, size: int) -> bytes:
        end = self.at + size
        if size < 0 or end > len(self.data):
            raise EnigmaFormatError("truncated import record stream")
        value = self.data[self.at:end]
        self.at = end
        return value

    def byte(self) -> int:
        return self.read(1)[0]

    def word(self) -> int:
        return struct.unpack("<H", self.read(2))[0]

    def dword(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def name(self, idea) -> str:
        size = self.word()
        if not 1 <= size < 0x8000:
            raise EnigmaFormatError("invalid import name length")
        plain = idea.decrypt(self.read(size))
        if not all(32 <= value < 127 for value in plain):
            raise EnigmaFormatError("invalid decrypted import name")
        return plain.decode("ascii")


def parse_import_records(plain: bytes, key: bytes, flag_size: int) -> tuple[ImportRecord, ...]:
    from .enigma_common import Idea

    if len(key) != 16 or flag_size not in (1, 4):
        raise ValueError("invalid import record key or flag width")
    idea = Idea(key)
    cursor = _Cursor(bytes(plain))
    dll = None
    symbols = []
    slots = set()
    while True:
        flags = cursor.dword() if flag_size == 4 else cursor.byte()
        if flags in (0xFF, 0xFFFFFFFF):
            break
        if flags & 1:
            dll = cursor.name(idea)
            continue
        if dll is None:
            raise EnigmaFormatError("API record precedes its DLL")
        if flags & 4:
            name = cursor.name(idea)
            ordinal = None
        else:
            ordinal = cursor.dword() & 0x7FFFFFFF
            if ordinal > 0xFFFF:
                raise EnigmaFormatError("invalid import ordinal")
            name = None
        references = cursor.word()
        if references == 0:
            raise EnigmaFormatError("API record has no references")
        for _ in range(references):
            first = cursor.dword()
            iat_rva = cursor.dword()
            if first != 0 or iat_rva == 0 or iat_rva % 4 or iat_rva in slots:
                raise EnigmaFormatError("invalid or duplicate IAT slot")
            slots.add(iat_rva)
            symbols.append(ImportRecord(dll, name, ordinal, iat_rva))
        if len(symbols) > 65536:
            raise EnigmaFormatError("too many import slots")
    if cursor.at != len(cursor.data) or not symbols:
        raise EnigmaFormatError("incomplete import record consumption")
    return tuple(symbols)


def recovered_read(recovered: Iterable[Recovered], rva: int, size: int) -> bytes:
    for section in recovered:
        offset = rva - section.rva
        if 0 <= offset < len(section.bytes) and offset + size <= len(section.bytes):
            return section.bytes[offset : offset + size]
    raise EnigmaFormatError("RVA outside recovered sections")


def engine_section(pe: PEImage, image: bytes) -> object:
    if len(image) < 0x40:
        raise EnigmaFormatError("Loader image is truncated")
    nt = struct.unpack_from("<I", image, 0x3C)[0]
    if nt + 84 > len(image):
        raise EnigmaFormatError("Loader PE header is truncated")
    image_size = struct.unpack_from("<I", image, nt + 80)[0]
    candidates = [section for section in pe.sections if section.virtual_size == image_size]
    if len(candidates) != 1:
        raise EnigmaFormatError("cannot uniquely locate original Loader mapping")
    return candidates[0]


def restore_recovered_sections(
    data: bytes | bytearray | memoryview,
    pe: PEImage,
    recovered: Iterable[Recovered],
) -> bytes:
    """Restore recovered bytes when the original raw section capacity suffices.

    Full Loader removal, IAT synthesis, TLS restoration and VM native code
    generation remain separate rebuild steps. This safe primitive preserves the
    original PE layout and refuses to truncate an expanded section.
    """

    output = bytearray(data)
    for item in recovered:
        section = pe.section_for_rva(item.rva)
        if item.rva != section.virtual_address:
            raise EnigmaFormatError("recovered section does not start at a PE section")
        if len(item.bytes) > section.raw_size:
            raise EnigmaFormatError(
                f"recovered section {section.name} exceeds original raw capacity"
            )
        start = section.raw_offset
        end = start + section.raw_size
        if end > len(output):
            raise EnigmaFormatError("recovered section raw range exceeds output")
        output[start : start + len(item.bytes)] = item.bytes
        output[start + len(item.bytes) : end] = b"\0" * (section.raw_size - len(item.bytes))
    return bytes(output)


__all__ = [
    "Configuration",
    "Descriptor",
    "EnigmaLayout",
    "ImportRecord",
    "Recovered",
    "StoredSection",
    "decode_section",
    "engine_section",
    "parse_configuration",
    "parse_import_records",
    "recover_sections",
    "recovered_read",
    "restore_recovered_sections",
    "search_salt",
    "stored_sections",
    "verify_sections",
]
