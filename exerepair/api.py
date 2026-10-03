"""Supported integration API."""

from .application import (
    ExtractionOptions,
    ExtractionProgress,
    ExtractionResult,
    InspectionReport,
    PatchFailure,
    PatchInfo,
    ContainerService,
)
from .domain.errors import (
    ErrorCode,
    ExtractError,
    LoadError,
    OperationError,
)
from .program import WrappedProgram
from .application.recovery import RepairService
from .domain.recovery import RecoveryError, RepairInspection, RepairResult

__all__ = [
    "ErrorCode",
    "ExtractionOptions",
    "ExtractionProgress",
    "ExtractionResult",
    "InspectionReport",
    "PatchFailure",
    "PatchInfo",
    "ExtractError",
    "LoadError",
    "OperationError",
    "WrappedProgram",
    "ContainerService",
    "RepairService",
    "RecoveryError",
    "RepairInspection",
    "RepairResult",
]
