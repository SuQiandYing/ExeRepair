"""Lazy aPLib compressor binding; ship the COMPLETE, unchanged upstream archive."""
from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import zipfile

from ..domain.recovery import RecoveryError

ARCHIVE_SHA256 = "c35c6d3d96cca8a29fa863efb22fa2e9e03f5bc2c0293c3256d7af2e112583b3"


def resolve_library(path: str | Path | None = None) -> Path:
    path = path or os.environ.get("EXEREPAIR_APLIB_DLL")
    if path:
        resolved = Path(path).expanduser().resolve(strict=True)
        if not resolved.is_file():
            raise RecoveryError("aPLib 路径不是文件")
        return resolved
    archive = Path(__file__).with_name("native") / "aPLib-1.1.1.zip"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise RecoveryError("内置 aPLib 完整发行包校验失败")
    architecture = "dll64" if struct.calcsize("P") == 8 else "dll"
    with zipfile.ZipFile(archive) as package:
        names = [n for n in package.namelist()
                 if n.replace("\\", "/").endswith(f"lib/{architecture}/aplib.dll")]
        if len(names) != 1:
            raise RecoveryError("aPLib 发行包中没有唯一的匹配架构 DLL")
        data = package.read(names[0])
    directory = Path(tempfile.gettempdir()) / "exerepair-aplib" / ARCHIVE_SHA256[:16]
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{architecture}-aplib.dll"
    if not destination.is_file() or destination.read_bytes() != data:
        descriptor, name = tempfile.mkstemp(dir=directory, suffix=".dll")
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    return destination


class AplibCompressor:
    def __init__(self, path: str | Path | None = None) -> None:
        if os.name != "nt":
            raise RecoveryError("当前原生 aPLib 压缩适配器只支持 Windows")
        try:
            self.library_path = resolve_library(path)
            self.lib = ctypes.WinDLL(str(self.library_path))
        except (OSError, zipfile.BadZipFile) as error:
            raise RecoveryError(f"无法加载匹配 Python 位数的 aPLib DLL：{error}") from error
        for name in ("aP_workmem_size", "aP_max_packed_size"):
            function = getattr(self.lib, name)
            function.argtypes = [ctypes.c_uint]
            function.restype = ctypes.c_uint
        self.lib.aP_pack.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ]
        self.lib.aP_pack.restype = ctypes.c_uint

    def __call__(self, data: bytes) -> bytes:
        if not data or len(data) > 128 * 1024 * 1024:
            raise RecoveryError("aPLib 输入大小超出限制")
        work_size = self.lib.aP_workmem_size(len(data))
        capacity = self.lib.aP_max_packed_size(len(data))
        if not work_size or not capacity or max(work_size, capacity) > 512 * 1024 * 1024:
            raise RecoveryError("aPLib 返回了无效的缓冲区大小")
        source = ctypes.create_string_buffer(data)
        work = ctypes.create_string_buffer(work_size)
        destination = ctypes.create_string_buffer(capacity)
        size = self.lib.aP_pack(source, destination, len(data), work, None, None)
        if size in (0, 0xFFFFFFFF) or size > capacity:
            raise RecoveryError("aPLib 压缩失败")
        return destination.raw[:size]
