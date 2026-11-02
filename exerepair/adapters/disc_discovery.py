"""Capture a bounded, process-local disc-check candidate from a temporary copy."""
from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
import stat
import tempfile
from threading import Event
from time import monotonic

from ..domain.recovery import DiscCheckProfile, RecoveryError
from ..workflows.disc_discovery import bind_disc_evidence, bind_main_disc_evidence
from ..workflows.repair import sha256


_RESOURCE_EXTENSIONS = {
    ".arc", ".bin", ".cfg", ".dat", ".idx", ".ini", ".json",
    ".pac", ".pak", ".res", ".xml",
}
_MAX_RESOURCE = 8 * 1024 * 1024
_MAX_RESOURCES = 64 * 1024 * 1024
_MAX_RESOURCE_COUNT = 128


def _stage_resources(resource_dir: Path, directory: Path) -> int:
    """Copy only bounded, regular sibling data files into the probe directory."""
    total = 0
    count = 0
    for item in sorted(resource_dir.iterdir(), key=lambda path: path.name.casefold()):
        if count >= _MAX_RESOURCE_COUNT:
            break
        if item.suffix.casefold() not in _RESOURCE_EXTENSIONS:
            continue
        info = item.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            continue
        size = info.st_size
        if size > _MAX_RESOURCE or total + size > _MAX_RESOURCES:
            continue
        with item.open("rb") as handle:
            content = handle.read(_MAX_RESOURCE + 1)
        if len(content) != size:
            raise RecoveryError("临时资源复制期间源文件发生变化")
        (directory / item.name).write_bytes(content)
        total += size
        count += 1
    return total


def _open_probe_handle(pid: int):
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    handle = kernel.OpenProcess(0x00101000, False, pid)
    if not handle:
        raise RecoveryError("无法打开临时进程状态句柄")
    return handle


def _probe_exit_code(handle) -> int | None:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    if kernel.WaitForSingleObject(handle, 1000) != 0:
        return None
    code = wintypes.DWORD()
    if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
        raise RecoveryError("无法读取临时进程退出状态")
    return code.value


def _close_probe_handle(handle) -> None:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.CloseHandle(handle)


def _dismiss_cancel_dialogs(pid: int) -> None:
    """Cancel only visible standard dialogs belonging to the probe process."""
    import ctypes
    from ctypes import wintypes

    user = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = (callback_type, wintypes.LPARAM)
    user.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
    user.GetClassNameW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    user.IsWindowVisible.argtypes = (wintypes.HWND,)
    user.GetDlgItem.argtypes = (wintypes.HWND, ctypes.c_int)
    user.GetDlgItem.restype = wintypes.HWND
    user.PostMessageW.argtypes = (wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    @callback_type
    def visit(hwnd, _parameter):
        owner = wintypes.DWORD()
        user.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value != pid or not user.IsWindowVisible(hwnd):
            return True
        name = ctypes.create_unicode_buffer(32)
        user.GetClassNameW(hwnd, name, len(name))
        if name.value == "#32770" and user.GetDlgItem(hwnd, 2):
            user.PostMessageW(hwnd, 0x111, 2, 0)
        return True

    user.EnumWindows(visit, 0)


def _wait_for_probe_exit(pid: int) -> None:
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


def discover_disc_runtime(
    source: Path,
    original: bytes,
    pending: DiscCheckProfile,
    *,
    progress=None,
    timeout: float = 20.0,
    resource_dir: Path | None = None,
) -> DiscCheckProfile:
    """Run only a temporary EXE copy and bind observed executable-code evidence."""
    if os.name != "nt":
        raise RecoveryError("运行时光盘检查定位需要 Windows")
    if not pending.requires_runtime_discovery or (
        sha256(original) != pending.baseline_sha256 or len(original) != pending.baseline_size
    ):
        raise RecoveryError("运行时检查候选与输入不匹配")
    try:
        import frida
    except ImportError as error:
        raise RecoveryError("运行时定位需要 frida；请安装 exerepair[recovery]") from error
    script_path = Path(__file__).with_suffix(".js")
    try:
        script_source = script_path.read_text(encoding="utf-8")
    except OSError as error:
        raise RecoveryError("运行时检查脚本不可用") from error
    report = progress or (lambda _message: None)
    finished = Event()
    module_evidence: dict = {}
    main_evidence: dict = {}
    failures: list[str] = []
    detached_reasons: list[str] = []
    device = frida.get_local_device()
    pid = None
    process_handle = None
    session = None
    with tempfile.TemporaryDirectory(prefix="exerepair-disc-probe-") as temporary:
        probe = Path(temporary) / source.name
        probe.write_bytes(original)
        staged = _stage_resources(resource_dir or source.parent, probe.parent)
        try:
            pid = device.spawn([str(probe)], cwd=temporary, stdio="pipe")
            process_handle = _open_probe_handle(pid)
            session = device.attach(pid)

            def detached(reason, *_args):
                detached_reasons.append(reason)
                if not module_evidence:
                    failures.append(f"临时进程已结束：{reason}")
                finished.set()

            def receive(message, data):
                if message.get("type") == "error":
                    failures.append(str(message.get("description", "运行时脚本错误")))
                    finished.set()
                    return
                payload = message.get("payload")
                if message.get("type") != "send" or not isinstance(payload, dict):
                    return
                if payload.get("event") == "disc_error":
                    failures.append(str(payload.get("message", "无法读取运行时检查代码")))
                    finished.set()
                elif payload.get("event") == "disc_evidence":
                    try:
                        if not isinstance(data, bytes):
                            raise RecoveryError("运行时检查证据缺少模块代码")
                        bound = bind_disc_evidence(
                            pending, original, data, int(payload["base"], 0),
                            int(payload["caller_rva"]),
                        )
                        script.post({
                            "type": "disc_patch",
                            "epilogue": bound.return_rva,
                            "flag": bound.success_flag_rva,
                        })
                        module_evidence["profile"] = bound
                        report("已验证模块检查，继续观察临时进程中的主映像")
                    except Exception as error:
                        failures.append(f"运行时模块证据无效：{error}")
                        finished.set()
                elif payload.get("event") == "main_disc_evidence":
                    if not isinstance(data, bytes):
                        failures.append("运行时检查证据缺少主映像代码")
                    else:
                        main_evidence.update(payload)
                        main_evidence["image"] = data
                    finished.set()

            session.on("detached", detached)
            script = session.create_script(script_source)
            script.on("message", receive)
            script.load()
            report(f"已启动临时 EXE 副本（数据文件 {staged} 字节），等待检查证据")
            device.resume(pid)
            deadline = monotonic() + timeout
            while not finished.wait(min(0.1, max(0, deadline - monotonic()))):
                if monotonic() >= deadline:
                    break
                _dismiss_cancel_dialogs(pid)
            if not finished.is_set() and not module_evidence:
                raise RecoveryError("运行时未观察到受支持的驱动器检查")
            if failures:
                raise RecoveryError(failures[0])
            if detached_reasons and detached_reasons[0] == "process-terminated":
                exit_code = _probe_exit_code(process_handle)
                if exit_code is not None and exit_code != 0:
                    raise RecoveryError(
                        f"临时副本异常退出（0x{exit_code:08X}），未生成修复文件；"
                        "请检查资源及运行环境"
                    )
        except RecoveryError:
            raise
        except Exception as error:
            raise RecoveryError(f"临时进程探测失败：{type(error).__name__}: {error}") from error
        finally:
            try:
                if pid is not None:
                    try:
                        device.kill(pid)
                    except Exception:
                        pass
                    _wait_for_probe_exit(pid)
            finally:
                if session is not None:
                    try:
                        session.detach()
                    except Exception:
                        pass
                if process_handle is not None:
                    _close_probe_handle(process_handle)
    try:
        bound = module_evidence["profile"]
        if main_evidence:
            main_base = int(main_evidence["base"], 0)
            message_return = int(main_evidence["return_rva"])
            main_image = main_evidence["image"]
    except (KeyError, TypeError, ValueError) as error:
        raise RecoveryError("运行时检查证据格式无效") from error
    if main_evidence:
        bound = bind_main_disc_evidence(
            bound, original, main_image, main_base, message_return,
        )
    else:
        bound = replace(
            bound,
            runtime_note="未观察到可验证的主映像消息调用；生成结果尚未验证完整启动。",
        )
    report(bound.runtime_note)
    return bound
