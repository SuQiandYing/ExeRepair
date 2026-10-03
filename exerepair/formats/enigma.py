"""Shared, bounded Enigma 1.x PE/bootstrap/aPLib parsing (no I/O)."""
from __future__ import annotations

from dataclasses import dataclass
import re
import struct

class EnigmaFormatError(ValueError):
    """Raised when an Enigma image is malformed or unsupported."""


@dataclass(frozen=True, slots=True)
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int


@dataclass(frozen=True, slots=True)
class PEImage:
    machine: int
    bitness: int
    timestamp: int
    image_base: int
    entry_rva: int
    section_alignment: int
    file_alignment: int
    size_of_image: int
    size_of_headers: int
    subsystem: int
    sections: tuple[Section, ...]
    file_size: int

    _COFF = struct.Struct("<HHIIIHH")
    _SECTION = struct.Struct("<8sIIIIIIHHI")

    @classmethod
    def parse(cls, data: bytes | bytearray | memoryview) -> "PEImage":
        view = memoryview(data).cast("B")
        if len(view) < 0x40 or bytes(view[:2]) != b"MZ":
            raise EnigmaFormatError("missing DOS header")
        pe_offset = struct.unpack_from("<I", view, 0x3C)[0]
        if pe_offset > len(view) - 4 - cls._COFF.size:
            raise EnigmaFormatError("PE header is outside the file")
        if bytes(view[pe_offset : pe_offset + 4]) != b"PE\0\0":
            raise EnigmaFormatError("missing PE signature")

        (
            machine,
            section_count,
            timestamp,
            _symbol_table,
            _symbol_count,
            optional_size,
            _characteristics,
        ) = cls._COFF.unpack_from(view, pe_offset + 4)
        if machine == 0x014C:
            bitness = 32
            expected_magic = 0x10B
            image_base_offset = 0x1C
        elif machine == 0x8664:
            bitness = 64
            expected_magic = 0x20B
            image_base_offset = 0x18
        else:
            raise EnigmaFormatError(f"unsupported PE machine 0x{machine:04X}")
        if section_count == 0:
            raise EnigmaFormatError("PE has no sections")

        optional_offset = pe_offset + 4 + cls._COFF.size
        section_offset = optional_offset + optional_size
        if optional_size < 0x46 or section_offset > len(view):
            raise EnigmaFormatError("truncated optional header")
        if struct.unpack_from("<H", view, optional_offset)[0] != expected_magic:
            raise EnigmaFormatError("optional-header magic does not match machine")
        table_size = section_count * cls._SECTION.size
        if table_size > len(view) - section_offset:
            raise EnigmaFormatError("truncated section table")

        image_base_format = "<I" if bitness == 32 else "<Q"
        image_base = struct.unpack_from(
            image_base_format, view, optional_offset + image_base_offset
        )[0]
        entry_rva = struct.unpack_from("<I", view, optional_offset + 0x10)[0]
        section_alignment = struct.unpack_from("<I", view, optional_offset + 0x20)[0]
        file_alignment = struct.unpack_from("<I", view, optional_offset + 0x24)[0]
        size_of_image = struct.unpack_from("<I", view, optional_offset + 0x38)[0]
        size_of_headers = struct.unpack_from("<I", view, optional_offset + 0x3C)[0]
        subsystem = struct.unpack_from("<H", view, optional_offset + 0x44)[0]
        if not section_alignment or not file_alignment or not size_of_image:
            raise EnigmaFormatError("invalid PE alignment or image size")
        if size_of_headers > len(view):
            raise EnigmaFormatError("PE headers extend beyond the file")

        sections: list[Section] = []
        for index in range(section_count):
            values = cls._SECTION.unpack_from(
                view, section_offset + index * cls._SECTION.size
            )
            raw_end = values[4] + values[3]
            if values[3] and (values[4] < size_of_headers or raw_end > len(view)):
                raise EnigmaFormatError(f"section {index} raw range is outside the file")
            name = values[0].split(b"\0", 1)[0].decode("ascii", errors="replace")
            sections.append(
                Section(
                    name=name,
                    virtual_size=values[1],
                    virtual_address=values[2],
                    raw_size=values[3],
                    raw_offset=values[4],
                    characteristics=values[9],
                )
            )

        return cls(
            machine=machine,
            bitness=bitness,
            timestamp=timestamp,
            image_base=image_base,
            entry_rva=entry_rva,
            section_alignment=section_alignment,
            file_alignment=file_alignment,
            size_of_image=size_of_image,
            size_of_headers=size_of_headers,
            subsystem=subsystem,
            sections=tuple(sections),
            file_size=len(view),
        )

    def rva_to_offset(self, rva: int) -> int:
        if rva < self.size_of_headers:
            return rva
        # Protector containers may have raw padding which overlaps a later
        # section's RVA range. The most specific (latest-starting) section
        # must win, matching the actual loader rather than the first span.
        for section in sorted(self.sections, key=lambda s: s.virtual_address, reverse=True):
            if section.virtual_address <= rva < section.virtual_address + section.raw_size:
                offset = section.raw_offset + rva - section.virtual_address
                if offset < self.file_size:
                    return offset
        raise EnigmaFormatError(f"RVA 0x{rva:08X} has no file-backed byte")

    def section_for_rva(self, rva: int) -> Section:
        for section in sorted(self.sections, key=lambda s: s.virtual_address, reverse=True):
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + span:
                return section
        raise EnigmaFormatError(f"RVA 0x{rva:08X} is outside every section")


@dataclass(frozen=True, slots=True)
class DecoderLayer:
    relative_offset: int
    length: int
    xor_byte: int


@dataclass(frozen=True, slots=True)
class BootstrapAnalysis:
    entry_offset: int
    version: str
    layers: tuple[DecoderLayer, ...]
    decoded_image: bytes


@dataclass(frozen=True, slots=True)
class EngineAnalysis:
    source_rva: int
    packed_size: int
    xor_key: int
    unpacked_size: int
    entry_rva: int
    has_registration_api: bool


_DECODER_SUFFIX = b"\x03\xC5\x81\xC0"


_DECODER_TAIL = b"\x30\x10\x40\x49\x0F\x85\xF6\xFF\xFF\xFF\xE9\x04\x00\x00\x00"


_VERSION_RE = re.compile(rb"The Enigma Protector version ([0-9.]+)")


_ENGINE_RE = re.compile(
    rb"\x68(.{4})\x68(.{4})\x01\x2C\x24\x68(.{4})\xE8",
    re.DOTALL,
)


def _decoder_candidates(
    image: bytearray, pe: PEImage, entry_offset: int, scan_end: int
) -> list[tuple[int, DecoderLayer]]:
    entry_imm = struct.pack("<I", pe.entry_rva)
    candidates: list[tuple[int, DecoderLayer]] = []
    cursor = entry_offset
    prefix = b"\xB8" + entry_imm + _DECODER_SUFFIX
    while True:
        position = image.find(prefix, cursor, scan_end)
        if position < 0:
            return candidates
        cursor = position + 1
        if position + 48 > len(image):
            continue
        relative_offset = struct.unpack_from("<I", image, position + 9)[0]
        if image[position + 13] != 0xB9:
            continue
        length = struct.unpack_from("<I", image, position + 14)[0]
        if image[position + 18] != 0xBA:
            continue
        xor_byte = image[position + 19]
        if bytes(image[position + 23 : position + 38]) != _DECODER_TAIL:
            continue
        if not length:
            continue
        try:
            start = pe.rva_to_offset(pe.entry_rva + relative_offset)
        except EnigmaFormatError:
            continue
        start_rva = pe.entry_rva + relative_offset
        entry_section = pe.section_for_rva(pe.entry_rva)
        raw_rva_end = entry_section.virtual_address + entry_section.raw_size
        if start_rva + length > raw_rva_end or start + length > len(image):
            continue
        candidates.append(
            (position, DecoderLayer(relative_offset, length, xor_byte))
        )


def decode_enigma_bootstrap(data: bytes, pe: PEImage | None = None) -> BootstrapAnalysis:
    pe = pe or PEImage.parse(data)
    if pe.bitness != 32:
        raise EnigmaFormatError("Enigma bootstrap fixture is not PE32")
    entry_offset = pe.rva_to_offset(pe.entry_rva)
    entry_section = pe.section_for_rva(pe.entry_rva)
    if not (entry_section.characteristics & 0x20000000):
        raise EnigmaFormatError("target entry section is not executable")
    if entry_offset + 80 > len(data):
        raise EnigmaFormatError("truncated target entry point")

    prologue = data[entry_offset : entry_offset + 38]
    expected = (
        prologue[:2] == b"\xEB\x08"
        and prologue[10:17] == b"\x60\xE8\x00\x00\x00\x00\x5D"
        and prologue[17:23] == b"\x81\xED\x10\x00\x00\x00"
        and prologue[23:25] == b"\x81\xED"
        and prologue[25:29] == struct.pack("<I", pe.entry_rva)
        and prologue[29:34] == b"\xE9\x04\x00\x00\x00"
    )
    if not expected:
        raise EnigmaFormatError("target OEP does not match the Enigma self-decoder")

    work = bytearray(data)
    applied: set[tuple[int, int, int]] = set()
    layers: list[DecoderLayer] = []
    scan_end = min(
        entry_section.raw_offset + entry_section.raw_size,
        entry_offset + 0x10000,
    )
    for _ in range(12):
        candidates = _decoder_candidates(work, pe, entry_offset, scan_end)
        fresh = [
            layer
            for _position, layer in candidates
            if (layer.relative_offset, layer.length, layer.xor_byte) not in applied
        ]
        if not fresh:
            break
        if len(fresh) != 1:
            raise EnigmaFormatError(
                f"ambiguous Enigma decoder layer: {len(fresh)} candidates"
            )
        # Nested stages become visible one at a time.  Decode the earliest one
        # and rescan so bytes revealed by it are interpreted only afterwards.
        layer = fresh[0]
        start = pe.rva_to_offset(pe.entry_rva + layer.relative_offset)
        for index in range(start, start + layer.length):
            work[index] ^= layer.xor_byte
        applied.add((layer.relative_offset, layer.length, layer.xor_byte))
        layers.append(layer)
    if not layers:
        raise EnigmaFormatError("no Enigma decoder layer was found at the target OEP")

    decoded_region = bytes(work[entry_offset:scan_end])
    marker = _VERSION_RE.search(decoded_region)
    if marker is None:
        raise EnigmaFormatError("decoded OEP has no Enigma version marker")
    version = marker.group(1).decode("ascii")
    return BootstrapAnalysis(
        entry_offset=entry_offset,
        version=version,
        layers=tuple(layers),
        decoded_image=bytes(work),
    )


class _AplibBits:
    __slots__ = ("data", "index", "tag", "remaining")

    def __init__(self, data: bytes | bytearray) -> None:
        self.data = data
        self.index = 0
        self.tag = 0
        self.remaining = 0

    def byte(self) -> int:
        if self.index >= len(self.data):
            raise EnigmaFormatError("truncated aPLib stream")
        value = self.data[self.index]
        self.index += 1
        return value

    def bit(self) -> int:
        if self.remaining == 0:
            self.tag = self.byte()
            self.remaining = 8
        value = self.tag >> 7
        self.tag = (self.tag << 1) & 0xFF
        self.remaining -= 1
        return value


def _aplib_gamma(bits: _AplibBits) -> int:
    value = 1
    while True:
        value = (value << 1) | bits.bit()
        if bits.bit() == 0:
            return value


def aplib_decompress(data: bytes | bytearray, max_output: int = 128 * 1024 * 1024) -> bytes:
    """Decode the aPLib variant emitted by the Enigma 1.x bootstrap."""

    if max_output < 1:
        raise EnigmaFormatError("aPLib output exceeds the configured limit")
    bits = _AplibBits(data)
    output = bytearray([bits.byte()])
    state = 2
    previous_offset = 0

    def copy(offset: int, length: int) -> None:
        if offset <= 0 or offset > len(output):
            raise EnigmaFormatError("invalid aPLib back-reference")
        if len(output) + length > max_output:
            raise EnigmaFormatError("aPLib output exceeds the configured limit")
        for _ in range(length):
            output.append(output[-offset])

    while True:
        if bits.bit() == 0:
            if len(output) >= max_output:
                raise EnigmaFormatError("aPLib output exceeds the configured limit")
            output.append(bits.byte())
            state = 2
            continue
        if bits.bit() == 0:
            offset = _aplib_gamma(bits) - state
            if offset == 0:
                offset = previous_offset
                length = _aplib_gamma(bits)
            else:
                offset = ((offset - 1) << 8) | bits.byte()
                previous_offset = offset
                length = _aplib_gamma(bits)
                length += int(offset >= 0x7D00)
                length += int(offset >= 0x500)
                length += 2 * int(offset < 0x80)
            copy(offset, length)
            state = 1
            continue
        if bits.bit() == 0:
            value = bits.byte()
            offset = value >> 1
            if offset == 0:
                return bytes(output)
            previous_offset = offset
            copy(offset, 2 + (value & 1))
            state = 1
            continue
        offset = 0
        for _ in range(4):
            offset = (offset << 1) | bits.bit()
        if offset:
            copy(offset, 1)
        else:
            if len(output) >= max_output:
                raise EnigmaFormatError("aPLib output exceeds the configured limit")
            output.append(0)
        state = 2


def extract_enigma_engine(
    target: bytes, pe: PEImage, bootstrap: BootstrapAnalysis
) -> tuple[EngineAnalysis, int, bytes]:
    """Decode once; return container analysis, file offset and encoded engine."""
    entry_offset = bootstrap.entry_offset
    entry_section = pe.section_for_rva(pe.entry_rva)
    scan_end = min(
        entry_section.raw_offset + entry_section.raw_size,
        entry_offset + 0x10000,
    )
    region = bootstrap.decoded_image[entry_offset:scan_end]
    packages: list[tuple[int, int, int]] = []
    for match in _ENGINE_RE.finditer(region):
        packed_size = struct.unpack("<I", match.group(1))[0]
        source_rva = struct.unpack("<I", match.group(2))[0]
        xor_key = struct.unpack("<I", match.group(3))[0]
        if packed_size < 0x1000 or packed_size % 4:
            continue
        try:
            source_offset = pe.rva_to_offset(source_rva)
        except EnigmaFormatError:
            continue
        if source_offset + packed_size <= len(target):
            packages.append((source_rva, packed_size, xor_key))
    if len(packages) != 1:
        raise EnigmaFormatError(
            f"expected one encrypted Enigma engine package, found {len(packages)}"
        )

    source_rva, packed_size, xor_key = packages[0]
    source_offset = pe.rva_to_offset(source_rva)
    packed = bytearray(target[source_offset : source_offset + packed_size])
    for offset in range(0, packed_size, 4):
        value = struct.unpack_from("<I", packed, offset)[0] ^ xor_key
        struct.pack_into("<I", packed, offset, value)
    engine = aplib_decompress(packed)
    engine_pe = PEImage.parse(engine)
    if engine_pe.bitness != 32 or engine_pe.image_base != pe.image_base:
        raise EnigmaFormatError("embedded validation engine has an unexpected PE layout")
    analysis = EngineAnalysis(
        source_rva=source_rva,
        packed_size=packed_size,
        xor_key=xor_key,
        unpacked_size=len(engine),
        entry_rva=engine_pe.entry_rva,
        has_registration_api=b"EP_RegCheckKey" in engine,
    )
    return analysis, source_offset, engine


def inspect_enigma_engine(
    target: bytes, pe: PEImage, bootstrap: BootstrapAnalysis
) -> EngineAnalysis:
    return extract_enigma_engine(target, pe, bootstrap)[0]


def bcj_transform(data: bytes | bytearray, *, encode: bool) -> bytes:
    """The observed Enigma 1.31 transform, NOT a generic x86 BCJ codec."""
    out = bytearray(data)
    index = 0
    indirect_delta = 0
    while index < len(out) - 5:
        if out[index] in (0xE8, 0xE9):
            value = struct.unpack_from("<I", out, index + 1)[0]
            value = value + index if encode else value - index
            struct.pack_into("<I", out, index + 1, value & 0xFFFFFFFF)
            index += 5
        elif out[index:index + 2] == b"\xff\x25":
            value = struct.unpack_from("<I", out, index + 2)[0]
            value = value + indirect_delta if encode else value - indirect_delta
            struct.pack_into("<I", out, index + 2, value & 0xFFFFFFFF)
            indirect_delta -= 4
            index += 6
        else:
            index += 1
    return bytes(out)

