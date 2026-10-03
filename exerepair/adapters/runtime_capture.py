"""Own and clean up one disposable Win32 probe; do not touch other processes."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import shutil
import struct
import tempfile
import threading

from ..domain.recovery import RecoveryError
from ..workflows.repair import build_capture_image


def capture_context(
    original, game_root, profile, compressor, work_dir, timeout=60, progress=None
) -> dict:
    report = progress or (lambda _: None)
    if os.name != "nt" or struct.calcsize("P") != 8:
        raise RecoveryError("自动运行时捕获当前需要 Windows + 64 位 Python；离线清单重放不需要 Frida")
    try:
        import frida
        import psutil
    except ImportError as error:
        raise RecoveryError("自动捕获缺少 frida/psutil；请安装 exerepair[recovery]") from error
    # All native breakpoint addresses belong only to this verified identity.
    if profile.name != "tayutama-zero-dl-enigma-1.31":
        raise RecoveryError("该配置尚无经过验证的运行时捕获适配器")
    image = build_capture_image(original, profile, compressor)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    ready = threading.Event()
    errors: list[str] = []
    device = frida.get_local_device()
    pid = None
    session = None
    thread_handle = None
    owned_process = None
    with tempfile.TemporaryDirectory(prefix="capture-", dir=work_dir) as temporary:
        root = Path(temporary)
        if not root.resolve().is_relative_to(work_dir.resolve()):
            raise RecoveryError("隔离临时目录越界")
        executable = root / "probe.exe"
        executable.write_bytes(image)
        # Initialization needs adjacent DLLs, but we park before game loading.
        for source in Path(game_root).glob("*.dll"):
            if source.is_file():
                shutil.copyfile(source, root / source.name)
        try:
            pid = device.spawn([str(executable)], cwd=str(root))
            owned_process = psutil.Process(pid)
            report(f"隔离探测进程已启动 PID={pid}")
            session = device.attach(pid)
            def detached(reason, *_args):
                errors.append(f"隔离会话终止：{reason}")
                ready.set()
            session.on("detached", detached)
            script = session.create_script(Path(__file__).with_suffix(".js").read_text(encoding="utf-8"))

            def receive(message, _data):
                if message.get("type") == "send":
                    if message.get("payload", {}).get("event") == "context_ready":
                        ready.set()
                elif message.get("type") == "error":
                    # Do NOT write the RPC result or debugger locals to disk.
                    errors.append(message.get("description", "runtime capture failed"))
                    ready.set()

            script.on("message", receive)
            script.load()
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel.OpenThread.restype = wintypes.HANDLE
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            for name in ("SuspendThread", "ResumeThread"):
                function = getattr(kernel, name)
                function.argtypes = [wintypes.HANDLE]
                function.restype = wintypes.DWORD
            for name in ("Wow64GetThreadContext", "Wow64SetThreadContext"):
                function = getattr(kernel, name)
                function.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
                function.restype = wintypes.BOOL
            threads = psutil.Process(pid).threads()
            if not threads:
                raise RecoveryError("隔离进程没有可捕获的线程")
            thread_handle = kernel.OpenThread(0x1A, False, threads[0].id)
            if not thread_handle:
                raise ctypes.WinError(ctypes.get_last_error())
            suspended = kernel.SuspendThread(thread_handle) != 0xFFFFFFFF
            if not suspended:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                context = ctypes.create_string_buffer(716)
                struct.pack_into("<I", context, 0, 0x10010)
                if not kernel.Wow64GetThreadContext(thread_handle, context):
                    raise ctypes.WinError(ctypes.get_last_error())
                # DR0=verified VM CALL handler; switch to dispatch at predicate.
                for offset, value in ((4, 0x987935), (8, 0), (12, 0), (16, 0), (20, 0), (24, 1)):
                    struct.pack_into("<I", context, offset, value)
                if not kernel.Wow64SetThreadContext(thread_handle, context):
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                kernel.ResumeThread(thread_handle)
            kernel.CloseHandle(thread_handle)
            thread_handle = None
            device.resume(pid)
            if not ready.wait(timeout):
                raise RecoveryError("运行时捕获超时；隔离进程将被终止，未写出修复文件")
            if errors:
                raise RecoveryError(f"运行时捕获失败：{errors[0]}")
            result = script.exports_sync.take()
            if not isinstance(result, dict) or not result.get("descriptors"):
                raise RecoveryError("没有捕获到完整载荷上下文")
            report(f"已捕获 {len(result['descriptors'])} 个描述符；未读取激活分量")
            return result
        except (RecoveryError, OSError):
            raise
        except Exception as error:
            raise RecoveryError(f"运行时捕获失败：{type(error).__name__}: {error}") from error
        finally:
            if thread_handle:
                kernel.CloseHandle(thread_handle)
            if pid is not None:
                try:
                    device.kill(pid)
                except (frida.ProcessNotFoundError, frida.InvalidOperationError):
                    pass
            if session is not None:
                try:
                    session.detach()
                except frida.InvalidOperationError:
                    pass
            if owned_process is not None:
                try:
                    owned_process.wait(timeout=10)
                except psutil.TimeoutExpired:
                    # psutil protects against PID reuse on terminate/kill.
                    owned_process.kill()
                    owned_process.wait(timeout=10)
                except psutil.NoSuchProcess:
                    pass
