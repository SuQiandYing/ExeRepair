"""Immutable application DTOs used by CLI, GUI, and integrations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..domain.models import PatchRecord, PatchMode


@dataclass(frozen=True, slots=True)
class ExtractionOptions:
    output_directory: Path | None = None
    output_exe: Path | None = None
    output_name: str = "Recovered"  # legacy; unwrap workflow passes output_exe


@dataclass(frozen=True, slots=True)
class ExtractionProgress:
    processed: int
    total: int
    patch_index: int | None = None
    file_name: str = ""

    @property
    def fraction(self) -> float:
        return self.processed / self.total if self.total else 1.0


@dataclass(frozen=True, slots=True)
class PatchFailure:
    index: int
    reason: str


@dataclass(frozen=True, slots=True)
class PatchInfo:
    """Immutable public description of one normalized patch."""

    index: int
    file_name: str
    position: int
    length: int
    signature1: int
    signature2: int
    reserve1: int
    mode: PatchMode

    @classmethod
    def from_patch(cls, index: int, patch: PatchRecord) -> "PatchInfo":
        return cls(
            index=index,
            file_name=patch.file_name,
            position=patch.position,
            length=patch.length,
            signature1=patch.signature1,
            signature2=patch.signature2,
            reserve1=patch.reserve1,
            mode=patch.mode,
        )


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    success: bool
    output_directory: Path | None = None
    failures: tuple[PatchFailure, ...] = ()
    error: str = ""

    @property
    def failed_indices(self) -> tuple[int, ...]:
        return tuple(failure.index for failure in self.failures)

    @property
    def last_error(self) -> str:
        if self.error:
            return self.error
        if not self.failures:
            return ""
        chunks = [
            ", ".join(str(failure.index) for failure in self.failures[start : start + 16])
            for start in range(0, len(self.failures), 16)
        ]
        return "\r\n".join(f"{chunk}, " for chunk in chunks)


@dataclass(frozen=True, slots=True)
class InspectionReport:
    source_path: Path
    wrapper_size: int
    stub_level: str
    stub_size: int
    stub_align_size: int
    mode_text: str
    executable_version: str
    executable_size: int
    patches: tuple[PatchInfo, ...]


ProgressCallback = Callable[[ExtractionProgress], None]
