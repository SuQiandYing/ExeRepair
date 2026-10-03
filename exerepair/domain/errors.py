"""Typed failures that cross the application boundary."""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    FILE_NOT_FOUND = "file_not_found"
    WRAPPER_NOT_PE32 = "wrapper_not_pe32"
    STUB_INVALID = "stub_invalid"
    STUB_UNKNOWN_VERSION = "stub_unknown_version"
    STUB_HASH_INVALID = "stub_hash_invalid"
    EXECUTABLE_NOT_FOUND = "executable_not_found"
    EXECUTABLE_INVALID = "executable_invalid"
    NOT_LOADED = "not_loaded"
    OUTPUT_ERROR = "output_error"


class OperationError(Exception):
    """An expected failure with a stable code and a display message."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.cause = cause

    def __str__(self) -> str:
        return self.message


class LoadError(OperationError):
    """The source file could not be loaded or validated."""


class ExtractError(OperationError):
    """The extraction output could not be prepared."""
