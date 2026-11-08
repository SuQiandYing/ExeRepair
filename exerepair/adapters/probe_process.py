"""Wait for processes owned by disposable Windows probes to terminate."""
from __future__ import annotations

from ..domain.recovery import RecoveryError


def wait_for_probe_exit(pid: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x00100000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return
        raise RecoveryError("无法确认临时探测进程是否已退出")
    try:
        if kernel.WaitForSingleObject(handle, 5000) != 0:
            raise RecoveryError("临时探测进程未在时限内退出")
    finally:
        kernel.CloseHandle(handle)
