"""Path policy for filenames stored in a Windows game archive."""

from __future__ import annotations

from pathlib import Path, PureWindowsPath


def safe_relative_parts(file_name: str) -> tuple[str, ...] | None:
    """Return normalized Windows path parts, rejecting rooted/traversal paths."""

    path = PureWindowsPath(file_name)
    if not file_name or path.is_absolute() or path.drive:
        return None
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if not parts or any(part == ".." for part in parts):
        return None
    return parts


def join_relative(base: Path, file_name: str) -> Path | None:
    parts = safe_relative_parts(file_name)
    return base.joinpath(*parts) if parts is not None else None
