"""ExeRepair - offline recovery workbench for visual-novel DRM wrappers."""

from .application import (
    ExtractionOptions,
    ExtractionProgress,
    ExtractionResult,
    InspectionReport,
    PatchFailure,
    PatchInfo,
    ProgramExtractor,
    ProgramLoader,
    ContainerService,
)
from .crypto import RandomV1, crc32, xor_in_place
from .domain.models import ContainerFlags, PatchRecord
from .pe import PEFile, PEFormatError
from .program import WrappedProgram

__all__ = [
    "PEFile",
    "PEFormatError",
    "ExtractionOptions",
    "ExtractionProgress",
    "ExtractionResult",
    "InspectionReport",
    "PatchFailure",
    "PatchInfo",
    "ProgramExtractor",
    "ProgramLoader",
    "RandomV1",
    "ContainerFlags",
    "PatchRecord",
    "WrappedProgram",
    "ContainerService",
    "crc32",
    "xor_in_place",
]
