"""One-shot, read-only runtime locator for structurally discovered native calls."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import time

from ..domain.recovery import NativeCallProfile, RecoveryError
from ..formats.enigma import PEImage
from ..workflows.native_discovery import (
    bind_runtime_evidence,
    load_native_cache,
    save_native_cache,
)


def _copy_probe_tree(source: Path, destination: Path) -> Path:
    """Copy the target and its sibling runtime files into an owned directory."""
    destination.mkdir(parents=True, exist_ok=True)
    for child in source.parent.iterdir():
        if child.name in {"lab_auth", ".exerepair"}:
            continue
        target = destination / child.name
        if child.is_dir():
            shutil.copytree(child, target, symlinks=True)
        elif child.is_file():
            shutil.copy2(child, target)
    executable = destination / source.name
    if not executable.is_file():
        raise RecoveryError("隔离运行目录未复制目标 EXE")
    return executable


def discover_native_runtime(
    source: Path,
    data: bytes,
    static: NativeCallProfile,
    work_dir: Path,
    *,
    timeout: float = 20.0,
    progress=None,
) -> NativeCallProfile:
    """Locate the unpacked outer guard without modifying the original process."""
    report = progress or (lambda _message: None)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    cached, _cache = load_native_cache(static, data, work_dir)
    if cached is not None:
        report("复用与当前样本哈希和 PE 结构绑定的原生调用证据")
        return cached
    if os.name != "nt":
        raise RecoveryError("未知构建需要 Windows 隔离运行时定位")
    try:
        import frida
    except ImportError as error:
        raise RecoveryError(
            "未知构建需要一次隔离运行时定位；缺少可选依赖 frida"
        ) from error

    pe = PEImage.parse(data)
    sections = [
        {
            "rva": section.virtual_address,
            "size": max(section.virtual_size, section.raw_size),
            "characteristics": section.characteristics,
        }
        for section in pe.sections
        if section.virtual_address
    ]
    script_path = Path(__file__).with_suffix(".js")
    if not script_path.is_file():
        raise RecoveryError(f"运行时定位脚本缺失：{script_path}")

    events: list[dict] = []
    evidence: dict | None = None
    errors: list[str] = []
    device = frida.get_local_device()
    pid = None
    session = None
    started = time.monotonic()

    with tempfile.TemporaryDirectory(
        prefix="native-probe-", dir=str(work_dir)
    ) as temporary:
        probe_root = Path(temporary)
        executable = _copy_probe_tree(source, probe_root)
        try:
            pid = device.spawn(
                [str(executable)], cwd=str(probe_root), stdio="pipe"
            )
            report(f"已启动隔离原生调用定位进程 PID={pid}")
            session = device.attach(pid)

            def detached(reason, *_args):
                message = f"隔离定位会话终止：{reason}"
                errors.append(message)
                events.append({"event": "detached", "reason": str(reason)})

            session.on("detached", detached)
            script = session.create_script(
                script_path.read_text(encoding="utf-8")
            )

            def receive(message, _data):
                nonlocal evidence
                if message.get("type") == "error":
                    description = message.get("description", "runtime locator failed")
                    errors.append(description)
                    events.append({"event": "script_error", "description": description})
                    return
                if message.get("type") != "send":
                    return
                payload = message.get("payload")
                if not isinstance(payload, dict):
                    return
                events.append(payload)
                if payload.get("event") == "native_call_evidence":
                    candidate = payload.get("evidence")
                    if isinstance(candidate, dict):
                        evidence = candidate

            script.on("message", receive)
            script.load()
            script.exports_sync.configure(sections)
            device.resume(pid)
            while evidence is None and time.monotonic() - started < timeout:
                if errors:
                    break
                time.sleep(0.05)
            if evidence is None:
                counts = [
                    event.get("candidate_count")
                    for event in events
                    if event.get("event") == "executeAPI_call"
                ]
                detail = f"；候选数量轨迹={counts[-5:]}" if counts else ""
                if errors:
                    detail += f"；{errors[0]}"
                raise RecoveryError(
                    f"运行时未绑定到唯一 executeAPI 原生调用{detail}"
                )
        except RecoveryError:
            raise
        except Exception as error:
            raise RecoveryError(
                f"隔离运行时定位失败：{type(error).__name__}: {error}"
            ) from error
        finally:
            _write_events(work_dir / "native-discovery-events.json", events)
            if pid is not None:
                try:
                    device.kill(pid)
                except Exception:
                    pass
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass

        assert evidence is not None
        bound = bind_runtime_evidence(static, data, evidence)
        save_native_cache(work_dir, bound, source, evidence)
        report(f"已唯一定位并验证外层原生调用 RVA {bound.call_rva:#x}")
        return bound


def _write_events(path: Path, events: list[dict]) -> None:
    path.write_text(
        json.dumps(events, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
