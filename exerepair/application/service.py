"""Application facade used by the command line and desktop presentations."""

from __future__ import annotations

from pathlib import Path

from ..adapters.filesystem import FileSystem, LocalFileSystem
from .extractor import ProgramExtractor
from .loader import LoadedProgram, ProgramLoader
from .results import (
    ExtractionOptions,
    ExtractionResult,
    InspectionReport,
    PatchInfo,
    ProgressCallback,
)


class ContainerService:
    """Coordinate loading, inspection, and extraction."""

    def __init__(
        self,
        filesystem: FileSystem | None = None,
        loader: ProgramLoader | None = None,
        extractor: ProgramExtractor | None = None,
    ) -> None:
        fs = filesystem or LocalFileSystem()
        self.loader = loader or ProgramLoader(fs)
        self.extractor = extractor or ProgramExtractor(fs)

    def load(self, executable_path: str | Path) -> LoadedProgram:
        return self.loader.load(executable_path)

    def inspect(self, executable_path: str | Path) -> InspectionReport:
        return self.inspect_loaded(self.load(executable_path))

    def extract(
        self,
        executable_path: str | Path,
        options: ExtractionOptions | None = None,
        progress: ProgressCallback | None = None,
    ) -> ExtractionResult:
        return self.extract_loaded(self.load(executable_path), options, progress)

    def extract_loaded(
        self,
        program: LoadedProgram,
        options: ExtractionOptions | None = None,
        progress: ProgressCallback | None = None,
    ) -> ExtractionResult:
        return self.extractor.extract(program, options, progress)

    def inspect_loaded(self, program: LoadedProgram) -> InspectionReport:
        patches = tuple(
            PatchInfo.from_patch(index, patch)
            for index, patch in enumerate(program.stub.patches)
        )
        return InspectionReport(
            source_path=program.source_path,
            wrapper_size=program.wrapper_size,
            stub_level=str(program.stub.level),
            stub_size=program.stub.size,
            stub_align_size=program.stub.align_size,
            mode_text=str(program.stub.config.mode),
            executable_version=program.executable_version,
            executable_size=program.executable_size,
            patches=patches,
        )
