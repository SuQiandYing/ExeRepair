"""Reader for the supported executable-container layouts."""

from __future__ import annotations

from dataclasses import dataclass
import io
import struct
from typing import BinaryIO, ClassVar, Protocol

from ..domain.models import (
    ContainerConfig,
    ContainerFlags,
    ContainerHeader,
    ContainerParseResult,
    ContainerVersion,
    PatchMode,
    PatchRecord,
)
from ..security import crc32, xor_in_place


@dataclass(frozen=True, slots=True)
class _Layout:
    version: ContainerVersion
    argument_size: int
    alignment: int
    record_count: int
    record_reader: "PatchRecordFormat"
    name_tail_size: int = 0


class PatchRecordFormat(Protocol):
    @property
    def record_size(self) -> int: ...

    def parse(self, data: memoryview, offset: int) -> PatchRecord: ...


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = stream.read(size - len(result))
        if not chunk:
            break
        result.extend(chunk)
    return bytes(result)


def _decode_name(
    data: bytes | bytearray | memoryview,
    limit: int = -1,
) -> str:
    raw = bytes(data)
    end_limit = len(raw) if limit < 0 else min(limit, len(raw))
    if end_limit == 0 or raw[0] == 0:
        return ""
    end = raw.find(b"\0", 0, end_limit)
    if end < 0:
        return ""
    return raw[:end].decode("cp932", errors="replace")


@dataclass(frozen=True, slots=True)
class _V1Records:
    layout: ClassVar[struct.Struct] = struct.Struct("<IIII")

    @property
    def record_size(self) -> int:
        return self.layout.size

    def parse(self, data: memoryview, offset: int) -> PatchRecord:
        position, signature1, signature2, _ = self.layout.unpack_from(data, offset)
        return PatchRecord(
            position=position,
            signature1=signature1,
            signature2=signature2,
        )


@dataclass(frozen=True, slots=True)
class _NamedRecords:
    name_size: int
    name_limit: int = -1
    layout: ClassVar[struct.Struct] = struct.Struct("<IIIII")

    @property
    def record_size(self) -> int:
        return self.name_size + self.layout.size

    def parse(self, data: memoryview, offset: int) -> PatchRecord:
        name = _decode_name(data[offset : offset + self.name_size], self.name_limit)
        position, signature1, length, signature2, reserve1 = self.layout.unpack_from(
            data, offset + self.name_size
        )
        return PatchRecord(
            file_name=name,
            position=position,
            length=length,
            signature1=signature1,
            signature2=signature2,
            reserve1=reserve1,
        )


_V1 = _V1Records()
_V2 = _NamedRecords(0x100, 0x80)
_V3 = _NamedRecords(0x80)

_LAYOUTS: dict[int, _Layout] = {
    0x00576453: _Layout(ContainerVersion.V1, 0x140, 0x1000, 16, _V1),
    0x32576453: _Layout(ContainerVersion.V2, 0x1180, 0x2000, 16, _V2),
    0x33576453: _Layout(ContainerVersion.V3, 0x1280, 0x2000, 16, _V2, 0x100),
    0x34576453: _Layout(ContainerVersion.V4, 0x9540, 0x10000, 256, _V3, 0x100),
    0x35576453: _Layout(ContainerVersion.V5, 0x9540, 0x10000, 256, _V3, 0x100),
    0x36576453: _Layout(ContainerVersion.V6, 0x9540, 0x10000, 256, _V3, 0x100),
    0x37576453: _Layout(ContainerVersion.V7, 0x9540, 0x10000, 256, _V3, 0x100),
}


class ContainerStub:
    """Decoded configuration and normalized patch records."""

    HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIII")
    CONFIG_SIZE: ClassVar[int] = 0x40

    __slots__ = (
        "header",
        "config",
        "_layout",
        "_patches",
        "_configured_executable_file_name",
    )

    def __init__(self, header: ContainerHeader, layout: _Layout) -> None:
        self.header = header
        self.config = ContainerConfig(ContainerFlags(0))
        self._layout = layout
        self._patches: list[PatchRecord] = []
        self._configured_executable_file_name = ""

    @property
    def level(self) -> ContainerVersion:
        return self._layout.version

    @property
    def size(self) -> int:
        return self._layout.argument_size

    @property
    def align_size(self) -> int:
        return self._layout.alignment

    @property
    def patches(self) -> tuple[PatchRecord, ...]:
        return tuple(self._patches)

    @property
    def executable_file_name(self) -> str:
        configured = bool(
            self.config.mode
            & (
                ContainerFlags.UseExecutableFileNameArgument
                | ContainerFlags.ExecutableFileNotPack
            )
        )
        if configured and self._configured_executable_file_name:
            return self._configured_executable_file_name
        return "main.bin"

    @classmethod
    def parse(
        cls,
        stream: BinaryIO | bytes | bytearray | memoryview,
    ) -> tuple[ContainerParseResult, "ContainerStub | None"]:
        if isinstance(stream, (bytes, bytearray, memoryview)):
            stream = io.BytesIO(stream)

        header_data = _read_exact(stream, cls.HEADER_STRUCT.size)
        if len(header_data) != cls.HEADER_STRUCT.size:
            return ContainerParseResult.StubInvalid, None

        header = ContainerHeader(*cls.HEADER_STRUCT.unpack(header_data))
        layout = _LAYOUTS.get(header.version)
        if layout is None:
            return ContainerParseResult.StubUnknowVersion, None

        encrypted = _read_exact(stream, layout.argument_size)
        if len(encrypted) != layout.argument_size:
            return ContainerParseResult.StubInvalid, None

        instance = cls(header, layout)
        result = instance.set_arguments(encrypted)
        return result, instance if result.succeeded else None

    @classmethod
    def create_factory(
        cls,
        stream: BinaryIO | bytes | bytearray | memoryview,
    ) -> tuple[ContainerParseResult, "ContainerStub | None"]:
        return cls.parse(stream)

    def set_arguments(
        self,
        encrypted_arguments: bytes | bytearray | memoryview,
    ) -> ContainerParseResult:
        if len(encrypted_arguments) != self.size:
            return ContainerParseResult.StubInvalid

        arguments = bytearray(encrypted_arguments)
        xor_in_place(arguments, self.header.key)
        if crc32(arguments) != self.header.hash:
            return ContainerParseResult.StubHashInvalid

        self.config = ContainerConfig(
            ContainerFlags(struct.unpack_from("<I", arguments, 0x3C)[0])
        )
        self._patches = self._read_patch_records(
            memoryview(arguments)[self.CONFIG_SIZE :]
        )
        self._set_patch_modes()
        return ContainerParseResult.Successed

    def _read_patch_records(self, arguments: memoryview) -> list[PatchRecord]:
        tail = self._layout.name_tail_size
        patch_length = len(arguments) - tail if tail else len(arguments)
        patch_data = arguments[:patch_length]
        reader = self._layout.record_reader
        records = [
            reader.parse(patch_data, index * reader.record_size)
            for index in range(self._layout.record_count)
        ]
        if tail:
            self._configured_executable_file_name = _decode_name(arguments[-tail:])
        return records

    def _set_patch_modes(self) -> None:
        executable_only = bool(self.config.mode & ContainerFlags.UseTempPath)
        for patch in self._patches:
            if patch.position == 0 and not patch.file_name:
                patch.mode = PatchMode.None_
            elif executable_only:
                patch.mode = PatchMode.ExecutableOnly
            elif patch.file_name:
                patch.mode = PatchMode.File
            else:
                patch.mode = PatchMode.Memory

    def decrypt_resource(
        self,
        data: bytearray | memoryview,
        key: int,
        signature1: int,
        signature2: int,
        packed_mode: bool = False,
    ) -> bool:
        view = memoryview(data).cast("B")
        if view.readonly:
            raise TypeError("data must be writable")
        if len(view) < 4:
            return False

        expected, replacement = (
            (signature1, signature2) if packed_mode else (signature2, signature1)
        )
        if struct.unpack_from("<I", view, 0)[0] != expected:
            return False

        struct.pack_into("<I", view, 0, replacement & 0xFFFFFFFF)
        if len(view) > 4:
            xor_in_place(view[4:], key)
        return True

    @property
    def Level(self) -> ContainerVersion:
        return self.level

    @property
    def Size(self) -> int:
        return self.size

    @property
    def AlignSize(self) -> int:
        return self.align_size

    @property
    def Config(self) -> ContainerConfig:
        return self.config

    @property
    def Patches(self) -> tuple[PatchRecord, ...]:
        return self.patches

    @property
    def ExecutableFileName(self) -> str:
        return self.executable_file_name

    def SetArguments(
        self,
        encrypted_arguments: bytes | bytearray | memoryview,
    ) -> ContainerParseResult:
        return self.set_arguments(encrypted_arguments)

    def DecryptResource(
        self,
        data: bytearray | memoryview,
        key: int,
        signature1: int,
        signature2: int,
        packed_mode: bool = False,
    ) -> bool:
        return self.decrypt_resource(data, key, signature1, signature2, packed_mode)


class StubParser:
    """Parser seam for adding later layouts without changing callers."""

    @staticmethod
    def parse(
        stream: BinaryIO | bytes | bytearray | memoryview,
    ) -> tuple[ContainerParseResult, ContainerStub | None]:
        return ContainerStub.parse(stream)
