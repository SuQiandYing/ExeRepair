"""Tk-independent state for the recovery console."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Callable

from ..application import (
    ExtractionOptions,
    ExtractionProgress,
    LoadedProgram,
    ContainerService,
)
from ..domain.errors import OperationError
from ..domain.models import PatchMode
from ..application.recovery import RepairService
from ..domain.recovery import DiscCheckProfile, NativeCallProfile, RecoveryError, RepairInspection
from ..formats.enigma import PEImage, decode_enigma_bootstrap


class WorkflowKind(str, Enum):
    UNWRAP = "unwrap"  # executable-container extraction
    REPAIR = "repair"  # Verified target-only runtime-copy repair


class StatusTone(str, Enum):
    NEUTRAL = "neutral"
    INFO = "info"
    SUCCESS = "success"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Row:
    values: tuple[str, ...]
    tag: str = ""


@dataclass(frozen=True, slots=True)
class WorkbenchState:
    phase: str  # empty | loading | ready | busy | error
    tone: StatusTone
    status_title: str
    status_detail: str
    source_path: str = ""
    workflow: WorkflowKind = WorkflowKind.UNWRAP
    rows: tuple[Row, ...] = ()
    details: tuple[tuple[str, str], ...] = ()
    logs: tuple[str, ...] = ()
    action_label: str = "提取"
    can_act: bool = False
    can_choose_resource_dir: bool = False

    @classmethod
    def empty(cls) -> "WorkbenchState":
        return cls(
            phase="empty",
            tone=StatusTone.NEUTRAL,
            status_title="等待文件",
            status_detail="拖入或选择 EXE；自动识别容器或支持的修复流程",
            logs=("",),
        )


StateCallback = Callable[[WorkbenchState], None]


class ConsoleController:
    """Presentation controller with no dependency on tkinter."""

    def __init__(
        self, service: ContainerService | None = None, *,
        repair_service: RepairService | None = None,
        recovery_options: dict | None = None,
    ) -> None:
        self.service = service or ContainerService()
        self.repair_service = repair_service or RepairService()
        self.recovery_options = recovery_options or {}
        self._loaded: LoadedProgram | None = None
        self._repair: RepairInspection | None = None
        self._state = WorkbenchState.empty()
        self._lock = RLock()

    @property
    def state(self) -> WorkbenchState:
        with self._lock:
            return self._state

    def reset(self) -> WorkbenchState:
        with self._lock:
            self._loaded = None
            self._repair = None
            self._state = WorkbenchState.empty()
            return self._state

    def set_disc_resource_dir(self, path: str | Path | None) -> None:
        with self._lock:
            if path is None:
                self.recovery_options.pop("disc_resource_dir", None)
            else:
                self.recovery_options["disc_resource_dir"] = Path(path)

    # -- loading -----------------------------------------------------------

    def begin_load(self, path: str | Path) -> WorkbenchState:
        with self._lock:
            self._loaded = None
            self._repair = None
            self.recovery_options.pop("disc_resource_dir", None)
            self._state = replace(
                WorkbenchState.empty(),
                phase="loading",
                tone=StatusTone.INFO,
                status_title="正在解析",
                status_detail=str(path),
                source_path=str(path),
                logs=(self._line(f"加载 {path}"),),
            )
            return self._state

    def load(self, path: str | Path) -> WorkbenchState:
        path = Path(path)
        with self._lock:
            self._loaded = None
            self._repair = None
        if self.recovery_options.get("disc_profile") is not None:
            return self._load_repair(path)
        try:
            loaded = self.service.load(path)
        except OperationError:
            return self._load_repair(path)
        with self._lock:
            self._loaded = loaded
            self._state = self._unwrap_state(loaded)
            return self._state

    def _load_repair(self, path: Path) -> WorkbenchState:
        try:
            disc_profile = self.recovery_options.get("disc_profile")
            inspection = (
                self.repair_service.inspect(path, disc_profile=disc_profile)
                if disc_profile is not None else self.repair_service.inspect(path)
            )
        except (OSError, ValueError) as error:
            if self.recovery_options.get("disc_profile") is not None:
                return self._fail("外部配置检查失败", str(error))
            try:
                data = path.read_bytes()
                decode_enigma_bootstrap(data, PEImage.parse(data))
            except (OSError, ValueError):
                return self._fail("无法识别文件", "文件不符合支持的容器、修复配置或 PE32 结构")
            return self._fail("此版本尚无单样本修复配置", str(error))
        profile = inspection.profile
        native = isinstance(profile, NativeCallProfile)
        disc = isinstance(profile, DiscCheckProfile)
        pending_native = native and profile.requires_runtime_discovery
        pending_disc = disc and profile.requires_runtime_discovery
        if disc:
            site_name = "光盘检查"
            site = "运行时自动定位" if pending_disc else f"模块 RVA {profile.return_rva:#x}"
        elif native:
            site_name = "原生调用"
            site = "运行时自动定位" if pending_native else f"RVA {profile.call_rva:#x}"
        else:
            site_name, site = "已验证载荷", str(len(profile.payloads))
        rows = (
            Row(("修复配置", profile.name), "ok"),
            Row((site_name, site), "ok"),
            Row(("加载器入口", f"0x{inspection.entry_rva:08X}"), ""),
            Row(("修复方法", "运行时验证、字节保护；.repair + .rstate" if pending_disc else
                 "完整字节保护、单次检查兼容；.repair + .rstate" if disc else
                 "原生调用保护补丁；.repair + .epack" if native else
                 "新增 .repair；保留原始密文与真实 CRC"), "info"),
            Row(("参考 EXE", "不需要；按当前样本结构定位"), "info"),
            Row(("激活值", "不读取、不搜索、不写入" if native or disc else
                 "仅在恢复进程内存中使用，不写入"), "info"),
        )
        if disc and profile.runtime_note:
            rows += (Row(("运行提示", profile.runtime_note), "info"),)
        status_detail = (
            "修复会运行临时副本、复制部分相邻数据并可能取消对话框；"
            "临时目录不是安全沙箱。" if pending_disc else
            "修复会运行临时副本并复制相邻运行文件；仍需验证调用点。"
            "若出现注册窗口，请检查原程序授权状态和完整运行环境；"
            "临时目录不是安全沙箱。" if pending_native else
            "静态生成副本；无需 Frida/GPU 或压缩器。" if disc else
            "静态生成副本；无需 Frida/GPU 或密钥搜索。" if native else
            "首次需捕获/搜索；后续复用校验缓存。不会修改原始 EXE。"
        )
        if disc and profile.runtime_note:
            status_detail += f"\n{profile.runtime_note}"
        with self._lock:
            self._repair = inspection
            self._state = replace(
                self._state,
                phase="ready",
                tone=StatusTone.INFO if pending_disc or pending_native else StatusTone.SUCCESS,
                status_title=(
                    "通用结构待运行时确认" if pending_disc or pending_native else
                    "单样本修复配置已匹配"
                ),
                status_detail=status_detail,
                workflow=WorkflowKind.REPAIR,
                rows=rows,
                details=(
                    ("目标 SHA-256", profile.baseline_sha256),
                ),
                logs=self._state.logs + (
                    self._line(
                        f"{'结构候选' if pending_disc or pending_native else '配置匹配'}："
                        f"{profile.name}"
                    ),
                ),
                action_label="修复副本",
                can_act=True,
                can_choose_resource_dir=disc,
            )
            return self._state

    def _unwrap_state(self, loaded: LoadedProgram) -> WorkbenchState:
        stub = loaded.stub
        active = sum(
            patch.mode is not PatchMode.None_ for patch in stub.patches
        )
        rows = (
            Row(("容器版本", f"V{stub.level}  (配置 0x{stub.size:08X})"), "info"),
            Row(("Overlay 起点", f"0x{loaded.wrapper_size:08X}"), ""),
            Row(("主程序", f"{loaded.executable_version}  0x{loaded.executable_size:08X}"), ""),
            Row(("有效区块", str(active)), "ok" if active else ""),
            Row(("主程序名称", stub.executable_file_name or "（内嵌）"), ""),
            Row(("对齐大小", f"0x{stub.align_size:08X}"), ""),
            Row(("模式标记", str(stub.config.mode)), ""),
        )
        with self._lock:
            self._state = replace(
                self._state,
                phase="ready",
                tone=StatusTone.SUCCESS,
                status_title="容器已验证",
                status_detail=f"{active} 个有效加密区块",
                workflow=WorkflowKind.UNWRAP,
                rows=rows,
                details=(("源文件", str(loaded.source_path)),),
                logs=self._state.logs + (self._line("容器加载成功。"),),
                action_label="提取",
                can_act=True,
            )
            return self._state

    def _fail(self, title: str, detail: str, *, can_retry: bool = False) -> WorkbenchState:
        with self._lock:
            self._state = replace(
                self._state,
                phase="error",
                tone=StatusTone.ERROR,
                status_title=title,
                status_detail=detail,
                can_act=can_retry,
                action_label=self._state.action_label if can_retry else "提取",
                logs=self._state.logs + (self._line(f"{title}：{detail}"),),
            )
            return self._state

    # -- acting ------------------------------------------------------------

    def begin_action(self) -> WorkbenchState:
        with self._lock:
            self._state = replace(
                self._state,
                phase="busy",
                tone=StatusTone.INFO,
                status_title="正在处理",
                status_detail="…",
                can_act=False,
                logs=self._state.logs + (self._line("开始处理。"),),
            )
            return self._state

    def act(self, output: str | Path | None = None) -> tuple[WorkbenchState, str | None]:
        """Run the pending workflow; returns (state, produced-path|None)."""
        with self._lock:
            loaded, repair = self._loaded, self._repair
        if loaded is not None:
            return self._act_unwrap(loaded, output)
        if repair is not None:
            return self._act_repair(repair, output)
        return self._fail("无法开始", "尚未加载有效文件"), None

    def _act_unwrap(
        self, loaded: LoadedProgram, output: str | Path | None
    ) -> tuple[WorkbenchState, str | None]:
        source = loaded.source_path
        target = (
            Path(output)
            if output is not None
            else source.with_name(f"{source.stem}_crack{source.suffix}")
        )

        def report(event: ExtractionProgress) -> None:
            with self._lock:
                self._state = replace(
                    self._state,
                    status_detail=f"区块 {event.processed}/{event.total}",
                )

        result = self.service.extract_loaded(
            loaded, ExtractionOptions(output_exe=target), report
        )
        with self._lock:
            if result.success:
                self._state = replace(
                    self._state,
                    phase="ready",
                    tone=StatusTone.SUCCESS,
                    status_title="提取完成",
                    status_detail=str(target),
                    can_act=True,
                    logs=self._state.logs + (self._line(f"提取完成：{target}"),),
                )
                return self._state, str(target)
            return (
                self._fail("提取未完全成功", result.last_error or "未知错误"),
                None,
            )

    def _act_repair(
        self, inspection: RepairInspection, output: str | Path | None
    ) -> tuple[WorkbenchState, str | None]:
        def report(message: str) -> None:
            with self._lock:
                self._state = replace(
                    self._state, status_detail=message,
                    logs=self._state.logs + (self._line(message),),
                )
        try:
            result = self.repair_service.repair(
                inspection.source_path, output,
                progress=report, **self.recovery_options,
            )
        except (OSError, ValueError, RecoveryError) as error:
            return self._fail("修复失败", str(error), can_retry=True), None
        with self._lock:
            detail = str(result.output_path)
            if isinstance(inspection.profile, DiscCheckProfile):
                note = result.runtime_note or "文件已复验；实际运行效果尚未验证。"
                detail += f"\n{note}"
            self._state = replace(
                self._state,
                phase="ready",
                tone=(StatusTone.INFO if isinstance(inspection.profile, DiscCheckProfile)
                      else StatusTone.SUCCESS),
                status_title="修复副本已生成",
                status_detail=detail,
                can_act=True,
                logs=self._state.logs
                + (self._line(f"已写出并复验：{result.output_path}"),),
            )
            return self._state, str(result.output_path)

    @staticmethod
    def _line(message: str) -> str:
        return f"{datetime.now():%H:%M:%S}  {message}"
