"""Stateful facade for scripts that prefer a small object-oriented API."""

from __future__ import annotations

from pathlib import Path

from .application import ContainerService, ExtractionOptions
from .application.loader import LoadedProgram
from .domain.errors import OperationError
from .formats.stub import ContainerStub


class WrappedProgram:
    def __init__(self, service: ContainerService | None = None) -> None:
        self._service = service or ContainerService()
        self._loaded: LoadedProgram | None = None
        self._last_error = ""
        self._output_directory: Path | None = None

    @property
    def stub(self) -> ContainerStub | None:
        loaded = self._loaded
        return loaded.stub if loaded else None

    @property
    def executable_version(self) -> str:
        return self._loaded.executable_version if self._loaded else ""

    @property
    def executable_size(self) -> int:
        return self._loaded.executable_size if self._loaded else 0

    @property
    def size(self) -> int:
        return self._loaded.wrapper_size if self._loaded else 0

    @property
    def last_error(self) -> str:
        return self._last_error

    @property
    def is_valid(self) -> bool:
        return self._loaded is not None

    @property
    def output_directory(self) -> Path | None:
        return self._output_directory

    def load(self, executable_path: str | Path) -> bool:
        try:
            loaded = self._service.load(executable_path)
        except OperationError as error:
            self._loaded = None
            self._last_error = error.message
            return False

        self._loaded = loaded
        self._last_error = ""
        self._output_directory = None
        return True

    def extract(self, output_directory: str | Path | None = None) -> bool:
        if self._loaded is None:
            self._last_error = "容器未初始化"
            return False

        options = (
            ExtractionOptions(output_directory=Path(output_directory))
            if output_directory
            else ExtractionOptions()
        )
        result = self._service.extract_loaded(self._loaded, options)
        self._output_directory = result.output_directory
        self._last_error = result.last_error
        return result.success
