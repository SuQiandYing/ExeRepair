"""Application use cases and stable result types."""

from .extractor import ProgramExtractor
from .loader import LoadedProgram, ProgramLoader
from .results import (
    ExtractionOptions,
    ExtractionProgress,
    ExtractionResult,
    InspectionReport,
    PatchFailure,
    PatchInfo,
)
from .service import ContainerService

__all__ = [
    "ExtractionOptions",
    "ExtractionProgress",
    "ExtractionResult",
    "InspectionReport",
    "LoadedProgram",
    "PatchFailure",
    "PatchInfo",
    "ProgramExtractor",
    "ProgramLoader",
    "ContainerService",
]
