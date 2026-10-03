"""Load one executable container into an immutable application object."""

from __future__ import annotations

from dataclasses import dataclass
import io
from pathlib import Path
import struct

from ..adapters.filesystem import FileSystem, LocalFileSystem
from ..domain.errors import ErrorCode, LoadError
from ..domain.models import ContainerFlags, ContainerParseResult
from ..domain.paths import join_relative
from ..formats.pe import PEFile, PEFormatError, PEParser
from ..formats.stub import ContainerStub, StubParser


@dataclass(frozen=True, slots=True)
class LoadedProgram:
    source_path: Path
    source_directory: Path
    source_name: str
    wrapper_size: int
    wrapper_pe: PEFile
    stub: ContainerStub
    executable_bytes: bytes
    executable_pe: PEFile

    @property
    def executable_version(self) -> str:
        return str(self.executable_pe)

    @property
    def executable_size(self) -> int:
        return len(self.executable_bytes)


class ProgramLoader:
    """Read and validate a source without producing output side effects."""

    def __init__(
        self,
        filesystem: FileSystem | None = None,
        pe_parser: type[PEParser] = PEParser,
        stub_parser: type[StubParser] = StubParser,
    ) -> None:
        self.filesystem = filesystem or LocalFileSystem()
        self.pe_parser = pe_parser
        self.stub_parser = stub_parser

    def load(self, executable_path: str | Path) -> LoadedProgram:
        path = Path(executable_path).expanduser()
        raw = self._read_source(path)
        wrapper_pe = self._parse_wrapper(raw)

        source_path = path.resolve()
        wrapper_size = wrapper_pe.overlay_data_file_offset
        result, stub = self._parse_container(raw, wrapper_size)
        if not result.succeeded or stub is None:
            raise LoadError(self._result_code(result), result.error_message)

        executable = self._read_executable(
            raw,
            source_path.parent,
            wrapper_size,
            stub,
        )
        executable_pe = self._parse_executable(executable)
        return LoadedProgram(
            source_path=source_path,
            source_directory=source_path.parent,
            source_name=source_path.name,
            wrapper_size=wrapper_size,
            wrapper_pe=wrapper_pe,
            stub=stub,
            executable_bytes=bytes(executable),
            executable_pe=executable_pe,
        )

    def _read_source(self, path: Path) -> bytes:
        if not self.filesystem.is_file(path):
            raise LoadError(ErrorCode.FILE_NOT_FOUND, "容器主程序文件不存在")
        try:
            return self.filesystem.read_bytes(path)
        except OSError as error:
            raise LoadError(
                ErrorCode.FILE_NOT_FOUND,
                "容器主程序文件不存在",
                error,
            ) from error

    def _parse_wrapper(self, raw: bytes) -> PEFile:
        try:
            return self.pe_parser.parse(raw, expected_bitness=32)
        except (PEFormatError, struct.error, ValueError) as error:
            raise LoadError(
                ErrorCode.WRAPPER_NOT_PE32,
                "容器主程序仅支持32位",
                error,
            ) from error

    def _parse_container(
        self,
        raw: bytes,
        wrapper_size: int,
    ) -> tuple[ContainerParseResult, ContainerStub | None]:
        stream = io.BytesIO(raw)
        stream.seek(wrapper_size)
        return self.stub_parser.parse(stream)

    @staticmethod
    def _result_code(result: ContainerParseResult) -> ErrorCode:
        return {
            ContainerParseResult.StubInvalid: ErrorCode.STUB_INVALID,
            ContainerParseResult.StubUnknowVersion: ErrorCode.STUB_UNKNOWN_VERSION,
            ContainerParseResult.StubHashInvalid: ErrorCode.STUB_HASH_INVALID,
        }.get(result, ErrorCode.STUB_INVALID)

    def _read_executable(
        self,
        raw: bytes,
        source_directory: Path,
        wrapper_size: int,
        stub: ContainerStub,
    ) -> bytes:
        if stub.config.mode & ContainerFlags.ExecutableFileNotPack:
            return self._read_external_executable(source_directory, stub)

        offset = wrapper_size + stub.align_size
        return raw[offset:] if offset <= len(raw) else b""

    def _read_external_executable(
        self,
        source_directory: Path,
        stub: ContainerStub,
    ) -> bytes:
        executable_path = join_relative(source_directory, stub.executable_file_name)
        if executable_path is None or not self.filesystem.is_file(executable_path):
            raise LoadError(ErrorCode.EXECUTABLE_NOT_FOUND, "游戏EXE文件不存在")
        try:
            return self.filesystem.read_bytes(executable_path)
        except OSError as error:
            raise LoadError(
                ErrorCode.EXECUTABLE_NOT_FOUND,
                "游戏EXE文件不存在",
                error,
            ) from error

    def _parse_executable(self, executable: bytes) -> PEFile:
        for bitness in (32, 64):
            try:
                return self.pe_parser.parse(executable, expected_bitness=bitness)
            except (PEFormatError, struct.error, ValueError):
                continue
        raise LoadError(ErrorCode.EXECUTABLE_INVALID, "游戏主程序不是合法EXE文件")
