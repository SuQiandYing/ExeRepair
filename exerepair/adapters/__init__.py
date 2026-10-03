"""Infrastructure adapters used by application modules."""

from .filesystem import FileSystem, LocalFileSystem

__all__ = ["FileSystem", "LocalFileSystem"]
