"""Patch planning and output writing for a loaded program."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from ..adapters.filesystem import FileSystem, LocalFileSystem
from ..domain.models import PatchMode, PatchRecord
from ..domain.paths import join_relative, safe_relative_parts
from .loader import LoadedProgram
from .results import (
    ExtractionOptions,
    ExtractionProgress,
    ExtractionResult,
    PatchFailure,
    ProgressCallback,
)


class PatchEngine:
    """Apply one byte-range patch without touching the filesystem."""

    @staticmethod
    def decrypt_executable(
        executable: bytearray,
        patch: PatchRecord,
        file_offset: int,
        decrypt_resource: Callable[..., bool],
    ) -> tuple[bool, str]:
        end = file_offset + patch.length
        valid_range = (
            patch.length >= 4
            and file_offset >= 0
            and end >= file_offset
            and end <= len(executable)
        )
        if not valid_range:
            return False, "主程序区块超出文件范围"

        ok = decrypt_resource(
            memoryview(executable)[file_offset:end],
            patch.position,
            patch.signature1,
            patch.signature2,
        )
        return ok, "" if ok else "签名不匹配"


class ProgramExtractor:
    """Deterministically materialize a recovered program and its resources."""

    def __init__(self, filesystem: FileSystem | None = None) -> None:
        self.filesystem = filesystem or LocalFileSystem()

    def extract(
        self,
        program: LoadedProgram,
        options: ExtractionOptions | None = None,
        progress: ProgressCallback | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> ExtractionResult:
        options = options or ExtractionOptions()
        output, destination = self._destination(program, options)
        try:
            self.filesystem.make_directory(output)
        except OSError as error:
            return ExtractionResult(False, error=f"无法创建输出目录: {error}")

        executable = bytearray(program.executable_bytes)
        failures: list[PatchFailure] = []
        copied: set[tuple[str, ...]] = set()
        patches = program.stub.patches
        total = len(patches)
        if progress:
            progress(ExtractionProgress(0, total))

        for index, patch in enumerate(patches):
            if cancelled and cancelled():
                return ExtractionResult(False, output, tuple(failures), "操作已取消")

            if patch.mode is not PatchMode.None_:
                try:
                    success, reason = self._apply(
                        program,
                        executable,
                        patch,
                        output,
                        copied,
                    )
                except (OSError, OverflowError, ValueError, MemoryError) as error:
                    success, reason = False, str(error)
                if not success:
                    failures.append(PatchFailure(index, reason))

            if progress:
                progress(
                    ExtractionProgress(index + 1, total, index, patch.file_name)
                )

        try:
            self.filesystem.write_bytes(destination, executable)
        except OSError as error:
            return ExtractionResult(
                False,
                None,
                tuple(failures),
                f"无法写入主程序: {error}",
            )
        return ExtractionResult(not failures, output, tuple(failures))

    @staticmethod
    def _destination(
        program: LoadedProgram,
        options: ExtractionOptions,
    ) -> tuple[Path, Path]:
        if options.output_exe is not None:
            destination = options.output_exe.expanduser().resolve()
            return destination.parent, destination

        output = (
            options.output_directory.expanduser().resolve()
            if options.output_directory is not None
            else program.source_directory / options.output_name
        )
        return output, output / program.source_name

    def _apply(
        self,
        program: LoadedProgram,
        executable: bytearray,
        patch: PatchRecord,
        output: Path,
        copied: set[tuple[str, ...]],
    ) -> tuple[bool, str]:
        if patch.mode is PatchMode.ExecutableOnly:
            return PatchEngine.decrypt_executable(
                executable,
                patch,
                patch.position,
                program.stub.decrypt_resource,
            )

        if patch.mode is PatchMode.Memory:
            file_offset = program.executable_pe.rva_to_foa(patch.position)
            return PatchEngine.decrypt_executable(
                executable,
                patch,
                file_offset,
                program.stub.decrypt_resource,
            )

        if patch.file_name == program.stub.executable_file_name:
            return PatchEngine.decrypt_executable(
                executable,
                patch,
                patch.position,
                program.stub.decrypt_resource,
            )

        return self._apply_file(program, patch, output, copied)

    def _apply_file(
        self,
        program: LoadedProgram,
        patch: PatchRecord,
        output: Path,
        copied: set[tuple[str, ...]],
    ) -> tuple[bool, str]:
        parts = safe_relative_parts(patch.file_name)
        if parts is None:
            return False, "资源路径无效"

        source = join_relative(program.source_directory, patch.file_name)
        destination = output.joinpath(*parts)
        if source is None or not self.filesystem.is_file(source):
            return False, "资源文件不存在"

        if parts not in copied:
            self.filesystem.copy_file(source, destination)
            copied.add(parts)

        file_size = self.filesystem.file_size(destination)
        end = patch.position + patch.length
        if (
            patch.length < 4
            or end < patch.position
            or patch.position > file_size
            or end > file_size
        ):
            return False, "资源区块超出文件范围"

        block = bytearray(
            self.filesystem.read_range(destination, patch.position, patch.length)
        )
        if len(block) != patch.length:
            return False, "资源区块读取不完整"

        if not program.stub.decrypt_resource(
            block,
            patch.position,
            patch.signature1,
            patch.signature2,
        ):
            return False, "签名不匹配"

        self.filesystem.write_range(destination, patch.position, block)
        return True, ""
