"""Supported integration API."""

from .application import (
    ExtractionOptions,
    ExtractionProgress,
    ExtractionResult,
    InspectionReport,
    PatchFailure,
    PatchInfo,
    ContainerService,
    EnigmaInspection,
    EnigmaRecoveryResult,
    EnigmaService,
)
from .formats import EnigmaFormatError
from .domain.errors import (
    ErrorCode,
    ExtractError,
    LoadError,
    OperationError,
)
from .program import WrappedProgram
from .application.recovery import RepairService
from .application.disc_profiles import load_disc_profile
from .domain.recovery import (
    DiscCheckProfile,
    NativeCallProfile,
    PortableSetupProfile,
    RecoveryError,
    RepairInspection,
    RepairResult,
)
from .workflows.profiles import NATIVE_CALL_X86_V2

__all__ = [
    "EnigmaFormatError",
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
    "EnigmaInspection",
    "EnigmaRecoveryResult",
    "EnigmaService",
    "RepairService",
    "load_disc_profile",
    "DiscCheckProfile",
    "NativeCallProfile",
    "PortableSetupProfile",
    "NATIVE_CALL_X86_V2",
    "RecoveryError",
    "RepairInspection",
    "RepairResult",
]
