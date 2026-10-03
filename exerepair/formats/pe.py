"""Minimal, bounds-checked PE32/PE64 parser."""

from __future__ import annotations

from dataclasses import dataclass
import struct


class PEFormatError(ValueError):
    """Raised when a byte sequence is not a supported PE image."""


@dataclass(frozen=True, slots=True)
class ImageSectionHeader:
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    characteristics: int

    @property
    def SectionName(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class PEFile:
    bitness: int
    machine: int
    pe_offset: int
    optional_header_size: int
    sections: tuple[ImageSectionHeader, ...]

    _COFF_HEADER = struct.Struct("<HHIIIHH")
    _SECTION_HEADER = struct.Struct("<8sIIIIIIHHI")

    @classmethod
    def from_bytes(
        cls,
        data: bytes | bytearray | memoryview,
        expected_bitness: int | None = None,
    ) -> "PEFile":
        view = memoryview(data).cast("B")
        if len(view) < 0x40 or bytes(view[0:2]) != b"MZ":
            raise PEFormatError("missing DOS header")

        pe_offset = struct.unpack_from("<I", view, 0x3C)[0]
        if pe_offset > len(view) - 4 - cls._COFF_HEADER.size:
            raise PEFormatError("PE header is outside the file")
        if bytes(view[pe_offset : pe_offset + 4]) != b"PE\0\0":
            raise PEFormatError("missing PE signature")

        (
            machine,
            section_count,
            _timestamp,
            _symbol_table,
            _symbol_count,
            optional_header_size,
            _characteristics,
        ) = cls._COFF_HEADER.unpack_from(view, pe_offset + 4)

        if machine == 0x014C:
            bitness = 32
        elif machine == 0x8664:
            bitness = 64
        else:
            raise PEFormatError(f"unsupported PE machine: 0x{machine:04X}")
        if expected_bitness is not None and bitness != expected_bitness:
            raise PEFormatError(f"expected PE{expected_bitness}, got PE{bitness}")

        optional_offset = pe_offset + 4 + cls._COFF_HEADER.size
        section_offset = optional_offset + optional_header_size
        section_table_size = section_count * cls._SECTION_HEADER.size
        if section_offset > len(view) or section_table_size > len(view) - section_offset:
            raise PEFormatError("truncated optional header or section table")

        sections: list[ImageSectionHeader] = []
        for index in range(section_count):
            values = cls._SECTION_HEADER.unpack_from(
                view, section_offset + index * cls._SECTION_HEADER.size
            )
            raw_name = values[0].split(b"\0", 1)[0]
            sections.append(
                ImageSectionHeader(
                    name=raw_name.decode("ascii", errors="replace"),
                    virtual_size=values[1],
                    virtual_address=values[2],
                    size_of_raw_data=values[3],
                    pointer_to_raw_data=values[4],
                    characteristics=values[9],
                )
            )

        return cls(
            bitness=bitness,
            machine=machine,
            pe_offset=pe_offset,
            optional_header_size=optional_header_size,
            sections=tuple(sections),
        )

    @classmethod
    def Load(
        cls,
        data: bytes | bytearray | memoryview,
        expected_bitness: int | None = None,
    ) -> "PEFile":
        return cls.from_bytes(data, expected_bitness)

    @property
    def overlay_data_file_offset(self) -> int:
        if not self.sections:
            return 0
        last = self.sections[-1]
        return last.pointer_to_raw_data + last.size_of_raw_data

    @property
    def OverlayDataFileOffset(self) -> int:
        return self.overlay_data_file_offset

    @property
    def ImageSectionHeaders(self) -> tuple[ImageSectionHeader, ...]:
        return self.sections

    def rva_to_foa(self, rva: int) -> int:
        if not self.sections:
            return 0
        first = self.sections[0]
        if rva < first.virtual_address and rva < first.pointer_to_raw_data:
            return rva
        for section in self.sections:
            if (
                section.virtual_address
                <= rva
                < section.virtual_address + section.size_of_raw_data
            ):
                return rva - section.virtual_address + section.pointer_to_raw_data
        return 0

    def RVAToFOA(self, rva: int) -> int:
        return self.rva_to_foa(rva)

    def __str__(self) -> str:
        return f"PE{self.bitness}"


class PEParser:
    """Named parser seam for future PE variants."""

    @staticmethod
    def parse(
        data: bytes | bytearray | memoryview,
        expected_bitness: int | None = None,
    ) -> PEFile:
        return PEFile.from_bytes(data, expected_bitness)

    @staticmethod
    def try_parse(
        data: bytes | bytearray | memoryview,
        expected_bitness: int | None = None,
    ) -> PEFile | None:
        try:
            return PEFile.from_bytes(data, expected_bitness)
        except (PEFormatError, struct.error, ValueError):
            return None
