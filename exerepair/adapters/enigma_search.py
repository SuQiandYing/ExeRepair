"""Accelerated Enigma section-salt search adapters.

The format layer owns the exact decoder and verifier. This adapter only supplies
candidate enumeration through the existing Numba/OpenCL prefix filters and
always sends candidates back through the complete format-layer verification.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from ..formats.enigma import EnigmaFormatError
from ..formats.enigma_unpack import (
    StoredSection,
    search_salt as exact_search_salt,
    verify_sections,
)

Progress = Callable[[int, int, str], None]


def _validate_range(start: int, count: int) -> None:
    if not 0 <= start < 1 << 32 or not 0 < count <= (1 << 32) - start:
        raise ValueError("invalid 32-bit salt search range")


def _screen_section(sections: Sequence[StoredSection]) -> StoredSection | None:
    candidates = [
        section
        for section in sections
        if section.descriptor.flags & 8 and section.ciphertext
    ]
    return min(candidates, key=lambda section: len(section.ciphertext), default=None)


def _exact_fallback(
    sections: Sequence[StoredSection],
    start: int,
    count: int,
    progress: Progress | None,
) -> int | None:
    del progress
    return exact_search_salt(sections, start=start, count=count, backend="cpu")


def _scan_with_cpu(
    screen: StoredSection,
    sections: Sequence[StoredSection],
    start: int,
    count: int,
    progress: Progress | None,
) -> int | None:
    try:
        import numba
        import numpy as np
        from .cpu_filter import scan
    except ImportError:
        return _exact_fallback(sections, start, count, progress)

    numba.set_num_threads(min(8, numba.config.NUMBA_NUM_THREADS))
    prefix = np.frombuffer(screen.descriptor.seed, dtype=np.uint8)
    cipher = np.frombuffer(screen.ciphertext, dtype=np.uint8)
    end = start + count
    step = 1 << 20
    for chunk_start in range(start, end, step):
        chunk_count = min(step, end - chunk_start)
        flags = scan(
            prefix,
            cipher[:128],
            chunk_start,
            chunk_count,
            screen.descriptor.expanded_size,
        )
        for offset in np.flatnonzero(flags):
            salt = chunk_start + int(offset)
            if _verified_candidate(sections, salt):
                if progress is not None:
                    progress(chunk_start + chunk_count - start, count, "CPU")
                return salt
        if progress is not None:
            progress(chunk_start + chunk_count - start, count, "CPU")
    return None


def _scan_with_opencl(
    screen: StoredSection,
    sections: Sequence[StoredSection],
    start: int,
    count: int,
    progress: Progress | None,
) -> int | None:
    try:
        import numpy as np
        from .opencl_filter import OpenCLFilter
    except ImportError as error:
        raise RuntimeError("OpenCL 搜索需要 numpy 和 OpenCL 适配器") from error

    engine = OpenCLFilter()
    try:
        prefix = np.frombuffer(screen.descriptor.seed, dtype=np.uint8)
        cipher = np.frombuffer(screen.ciphertext, dtype=np.uint8)
        end = start + count
        step = 1 << 23
        for chunk_start in range(start, end, step):
            chunk_count = min(step, end - chunk_start)
            flags = engine.scan(
                prefix,
                cipher[:128],
                chunk_start,
                chunk_count,
                screen.descriptor.expanded_size,
            )
            for offset in np.flatnonzero(flags):
                salt = chunk_start + int(offset)
                if _verified_candidate(sections, salt):
                    if progress is not None:
                        progress(chunk_start + chunk_count - start, count, "OpenCL")
                    return salt
            if progress is not None:
                progress(chunk_start + chunk_count - start, count, "OpenCL")
        return None
    finally:
        engine.close()


def _verified_candidate(sections: Sequence[StoredSection], salt: int) -> bool:
    try:
        verify_sections(sections, salt)
    except EnigmaFormatError:
        return False
    return True


def search_salt(
    sections: Sequence[StoredSection],
    *,
    start: int = 0,
    count: int = 1 << 32,
    backend: str = "auto",
    progress: Progress | None = None,
) -> int | None:
    """Find a section salt using OpenCL, Numba, or the exact bounded fallback."""

    _validate_range(start, count)
    if backend not in ("auto", "cpu", "opencl"):
        raise ValueError("backend must be auto, cpu, or opencl")
    if all(_verified_without_salt(section) for section in sections):
        return None
    screen = _screen_section(sections)
    if screen is None:
        raise EnigmaFormatError("no nonempty RC4 section to search")
    if not screen.descriptor.flags & 1 or len(screen.ciphertext) < 128:
        return _exact_fallback(sections, start, count, progress)

    if backend in ("auto", "opencl"):
        try:
            result = _scan_with_opencl(screen, sections, start, count, progress)
        except (OSError, RuntimeError) as error:
            if backend == "opencl":
                raise EnigmaFormatError(f"OpenCL search failed: {error}") from error
            result = None
        if result is not None:
            return result
        if backend == "opencl":
            raise EnigmaFormatError("no salt passed section verification")

    result = _scan_with_cpu(screen, sections, start, count, progress)
    if result is not None:
        return result
    raise EnigmaFormatError("no salt passed section verification")


def _verified_without_salt(section: StoredSection) -> bool:
    try:
        verify_sections((section,), None)
    except EnigmaFormatError:
        return False
    return True


__all__ = ["search_salt"]