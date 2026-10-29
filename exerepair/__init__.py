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
    EnigmaInspection,
    EnigmaRecoveryResult,
    EnigmaService,
)
from .crypto import RandomV1, crc32, xor_in_place
from .formats import EnigmaFormatError
from .domain.models import ContainerFlags, PatchRecord
from .pe import PEFile, PEFormatError
from .program import WrappedProgram
from .launcher import LaunchResult, launch_from_folder

__all__ = [
    "PEFile",
    "PEFormatError",
    "EnigmaFormatError",
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
    "LaunchResult",
    "launch_from_folder",
    "ContainerService",
    "EnigmaInspection",
    "EnigmaRecoveryResult",
    "EnigmaService",
    "crc32",
    "xor_in_place",
]
