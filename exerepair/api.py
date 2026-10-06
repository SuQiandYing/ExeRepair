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
from .domain.recovery import (
    DiscCheckProfile,
    NativeCallProfile,
    PortableSetupProfile,
    RecoveryError,
    RepairInspection,
    RepairResult,
)
from .workflows.profiles import EXHIBIT_DMM_TP02

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
    "DiscCheckProfile",
    "NativeCallProfile",
    "PortableSetupProfile",
    "EXHIBIT_DMM_TP02",
    "RecoveryError",
    "RepairInspection",
    "RepairResult",
]
