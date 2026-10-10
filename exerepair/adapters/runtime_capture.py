"""Own and clean up one disposable Win32 probe; do not touch other processes."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import threading

from ..domain.recovery import RecoveryError
from ..workflows.repair import build_capture_image


def _capture_config(profile) -> dict:
    if not profile.runtime_capture_supported:
        raise RecoveryError("该配置尚无经过验证的运行时捕获适配器")
    return {
        "engineBaseDelta": profile.engine_base_delta,
        "dispatchRVA": profile.dispatch_rva,
        "dispatchGlobalRVA": profile.dispatch_global_rva,
        "tableOffset": profile.vm_table_offset,
        "tableCount": profile.vm_table_count,
        "predicateIndex": profile.predicate_index,
        "trueIndex": profile.true_index,
        "trueRecordOffset": profile.true_record_offset,
        "optionsIndex": profile.options_index,
        "ksaIndex": profile.ksa_index,
        "ksaOperand": profile.ksa_operand,
        "prgaIndex": profile.prga_index,
        "prgaOperand": profile.prga_operand,
        "nativeTargetType": profile.native_call_target_type,
    }


def capture_context(
    original, game_root, profile, compressor, work_dir, timeout=60, progress=None
) -> dict:
    report = progress or (lambda _: None)
    if os.name != "nt" or struct.calcsize("P") != 8:
        raise RecoveryError("自动运行时捕获当前需要 Windows + 64 位 Python；离线清单重放不需要 Frida")
    config = _capture_config(profile)
    try:
        import frida
        import psutil
    except ImportError as error:
        raise RecoveryError("自动捕获缺少 frida/psutil；请安装 exerepair[recovery]") from error
    image = build_capture_image(original, profile, compressor)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    ready = threading.Event()
    errors: list[str] = []
    device = frida.get_local_device()
    pid = session = owned_process = None
    with tempfile.TemporaryDirectory(prefix="capture-", dir=work_dir) as temporary:
        root = Path(temporary)
        if not root.resolve().is_relative_to(work_dir.resolve()):
            raise RecoveryError("隔离临时目录越界")
        executable = root / "probe.exe"
        executable.write_bytes(image)
        # Park before game loading; only adjacent DLLs are needed for initialization.
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
            agent = Path(__file__).with_suffix(".js").read_text(encoding="utf-8")
            script = session.create_script(agent.replace("__CONFIG__", json.dumps(config)))

            def receive(message, _data):
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if payload.get("event") == "context_ready":
                        ready.set()
                    elif payload.get("event") == "capture_error":
                        errors.append(payload.get("error", "runtime capture failed"))
                        ready.set()
                elif message.get("type") == "error":
                    # Never serialize the RPC result, activation material or locals.
                    errors.append(message.get("description", "runtime capture failed"))
                    ready.set()

            script.on("message", receive)
            script.load()
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
