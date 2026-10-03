"""File-system seam used by loading and extraction use cases."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol
import shutil


class FileSystem(Protocol):
    def is_file(self, path: Path) -> bool: ...

    def read_bytes(self, path: Path) -> bytes: ...

    def make_directory(self, path: Path) -> None: ...

    def copy_file(self, source: Path, destination: Path) -> None: ...

    def file_size(self, path: Path) -> int: ...

    def read_range(self, path: Path, offset: int, length: int) -> bytes: ...

    def write_bytes(self, path: Path, data: bytes | bytearray) -> None: ...

    def write_range(self, path: Path, offset: int, data: bytes | bytearray) -> None: ...


class LocalFileSystem:
    """Concrete adapter over pathlib and shutil."""

    def is_file(self, path: Path) -> bool:
        return path.is_file()

    def read_bytes(self, path: Path) -> bytes:
        return path.read_bytes()

    def make_directory(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)

    def copy_file(self, source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)

    def file_size(self, path: Path) -> int:
        return path.stat().st_size

    def read_range(self, path: Path, offset: int, length: int) -> bytes:
        with path.open("rb") as stream:
            stream.seek(offset)
            return stream.read(length)

    def write_bytes(self, path: Path, data: bytes | bytearray) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def write_range(self, path: Path, offset: int, data: bytes | bytearray) -> None:
        with path.open("r+b") as stream:
            stream.seek(offset)
            stream.write(data)
