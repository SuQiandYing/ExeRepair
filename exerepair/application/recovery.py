"""Target-only repair orchestration, validated cache and reversible publication."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import tempfile
from typing import Callable

from ..adapters.aplib import AplibCompressor
from ..domain.recovery import (
    NativeCallProfile, RecoveredPayload, RecoveryError, RepairInspection, RepairResult,
)
from ..formats.enigma import PEImage
from ..workflows.native_repair import build_native_repair
from ..workflows.profiles import identify_profile
from ..workflows.repair import build_repair, sha256, validate_payloads

Progress = Callable[[str], None]


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2) + "\n").encode("utf-8")


def load_payload_manifest(path: Path, original: bytes, profile) -> tuple[RecoveredPayload, ...]:
    """Never trust crc_verified/sha fields: recompute and compare with the profile."""
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise RecoveryError("恢复清单根节点必须是对象")
    forbidden = {"key_prefix", "key_tail", "component_value", "matched_values", "component"}
    if forbidden.intersection(manifest):
        raise RecoveryError("恢复清单包含不应持久化的敏感字段")
    if manifest.get("format") not in (
        "seep.recovered-payloads.v1", "exerepair.recovered-payloads.v2",
    ):
        raise RecoveryError("不支持的恢复清单格式")
    if manifest.get("baseline_sha256") != profile.baseline_sha256:
        raise RecoveryError("恢复清单属于其他样本")
    if manifest.get("activation_component_written") is not False:
        raise RecoveryError("恢复清单未满足不持久化激活值的约束")
    rows = manifest.get("payloads", [])
    if not isinstance(rows, list) or len(rows) != len(profile.payloads):
        raise RecoveryError("恢复清单载荷数量不匹配")
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("source_rva"), int):
            raise RecoveryError("恢复清单载荷记录缺少有效 source RVA")
        if not isinstance(row.get("path"), str) or not row["path"]:
            raise RecoveryError("恢复清单载荷路径必须是非空字符串")
        if forbidden.intersection(row):
            raise RecoveryError("恢复清单载荷包含不应持久化的敏感字段")
    by_rva = {row["source_rva"]: row for row in rows}
    if len(by_rva) != len(rows):
        raise RecoveryError("恢复清单包含重复源 RVA")
    payloads = []
    for spec in profile.payloads:
        row = by_rva.get(spec.source_rva)
        if row is None or any(row.get(name) != expected for name, expected in (
            ("source_offset", spec.source_offset), ("payload_size", spec.size),
            ("flags", spec.flags), ("expected_crc", spec.crc32),
            ("sha256", spec.clear_sha256),
        )):
            raise RecoveryError("恢复清单描述符或摘要不匹配")
        source = Path(row["path"])
        if not source.is_absolute():
            source = path.parent / source
        payloads.append(RecoveredPayload(spec, source.read_bytes()))
    # The v1 lab field destination_rva incorrectly held descriptor+0 (enabled).
    # It is intentionally ignored; it is never used for memory writes or packing.
    result = tuple(payloads)
    validate_payloads(original, profile, result)
    return result


def save_payload_manifest(
    directory: Path, original: bytes, profile, payloads: tuple[RecoveredPayload, ...]
) -> Path:
    validate_payloads(original, profile, payloads)
    directory.mkdir(parents=True, exist_ok=True)
    rows = []
    for index, payload in enumerate(payloads):
        spec = payload.spec
        name = f"payload-{index:02d}.bin"
        _atomic_write(directory / name, payload.data)
        rows.append({
            "source_rva": spec.source_rva, "source_offset": spec.source_offset,
            "payload_size": spec.size, "flags": spec.flags, "expected_crc": spec.crc32,
            "sha256": spec.clear_sha256, "path": name,
        })
    path = directory / "recovered-payloads.json"
    _atomic_write(path, _json_bytes({
        "format": "exerepair.recovered-payloads.v2",
        "baseline_sha256": profile.baseline_sha256,
        "activation_component_written": False, "payloads": rows,
    }))
    load_payload_manifest(path, original, profile)
    return path


def _aliases(path: Path, source: Path) -> bool:
    return path == source or (path.exists() and os.path.samefile(path, source))


def rollback_script(baseline_name: str, expected_sha256: str) -> bytes:
    """POSIX sh; only needs cp/cmp and sha256sum or shasum."""
    quoted = shlex.quote(baseline_name)
    return f"""#!/bin/sh
set -eu
[ "$#" -eq 1 ] || {{ echo 'Usage: rollback.sh /absolute/path/to/a/target-copy.exe' >&2; exit 2; }}
here=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
baseline="$here"/{quoted}
target=$1
case "$target" in /*|[A-Za-z]:/*) ;; *) echo 'Use an absolute target-copy path' >&2; exit 3 ;; esac
[ -f "$baseline" ] || {{ echo 'Missing pristine sibling baseline' >&2; exit 4; }}
[ ! "$baseline" -ef "$target" ] || {{ echo 'Refusing to overwrite the baseline' >&2; exit 5; }}
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$baseline" | cut -d ' ' -f 1)
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$baseline" | cut -d ' ' -f 1)
else
  echo 'Need sha256sum or shasum' >&2; exit 6
fi
[ "$actual" = "{expected_sha256}" ] || {{ echo 'Baseline hash mismatch' >&2; exit 7; }}
cp "$baseline" "$target"
cmp "$baseline" "$target"
printf 'ROLLBACK_SHA256=%s\\n' "$actual"
""".encode("utf-8")


class RepairService:
    def __init__(self, compressor: Callable[[bytes], bytes] | None = None) -> None:
        self._compressor = compressor

    def inspect(self, target: str | Path) -> RepairInspection:
        source = Path(target).expanduser().resolve(strict=True)
        data = source.read_bytes()
        profile = identify_profile(data)
        pe = PEImage.parse(data)
        return RepairInspection(source, profile, pe.entry_rva, pe.image_base,
                                pe.size_of_image, len(pe.sections))

    def repair(
        self,
        target: str | Path,
        output: str | Path | None = None,
        *,
        manifest: str | Path | None = None,
        work_dir: str | Path | None = None,
        aplib_dll: str | Path | None = None,
        backend: str = "auto",
        search_start: int = 0,
        search_count: int = 1 << 32,
        overwrite: bool = False,
        progress: Progress | None = None,
    ) -> RepairResult:
        report_progress = progress or (lambda _: None)
        inspection = self.inspect(target)
        source, profile = inspection.source_path, inspection.profile
        original = source.read_bytes()
        destination = (Path(output).expanduser().resolve() if output is not None
                       else source.with_name(f"{source.stem}_crack{source.suffix}"))
        if _aliases(destination, source):
            raise RecoveryError("输出必须是副本，不能覆盖原始样本或其硬链接")
        directory = (Path(work_dir).expanduser().resolve() if work_dir is not None
                     else destination.parent / ".exerepair" / profile.baseline_sha256[:12])
        compressor = self._compressor or AplibCompressor(aplib_dll)
        manifest_path = None
        payloads = ()
        if isinstance(profile, NativeCallProfile):
            if manifest is not None:
                raise RecoveryError("该原生调用配置不使用恢复清单，不能指定 --recovery-manifest")
            report_progress("构建已验证的原生调用补丁；不启动探测进程，不搜索密钥")
            built = build_native_repair(original, profile, compressor)
        else:
            manifest_path = (Path(manifest).expanduser().resolve(strict=True) if manifest else
                             directory / "recovered-payloads.json")
            if manifest_path.is_file():
                report_progress("校验并复用已恢复载荷；不重复捕获或搜索")
                payloads = load_payload_manifest(manifest_path, original, profile)
            elif manifest is not None:
                raise RecoveryError("指定的恢复清单不存在")
            else:
                report_progress("正在隔离副本中捕获载荷描述符；原始样本不变")
                # Optional dependencies are isolated from inspection, Container and replay.
                from ..adapters.runtime_capture import capture_context
                from ..adapters.component_recovery import recover_payloads

                context = capture_context(
                    original, source.parent, profile, compressor, directory,
                    progress=report_progress,
                )
                try:
                    payloads = recover_payloads(
                        original, profile, context, backend=backend, start=search_start,
                        count=search_count, progress=report_progress, work_dir=directory,
                    )
                finally:
                    context.clear()
                manifest_path = save_payload_manifest(directory, original, profile, payloads)
            report_progress("重建运行时复制节，修改 VM 调用并验证引擎往返")
            built = build_repair(original, profile, payloads, compressor)
        paths = {
            "baseline": destination.with_name(destination.name + ".baseline.exe"),
            "diff": destination.with_name(destination.name + ".DIFF.json"),
            "verification": destination.with_name(destination.name + ".VERIFICATION.json"),
            "rollback": destination.with_name(destination.name + ".ROLLBACK.sh"),
        }
        verification = dict(built.report, source=str(source), output=str(destination),
                            recovered_manifest=str(manifest_path) if manifest_path else None,
                            original_unchanged=True)
        files = {
            paths["baseline"]: original, paths["diff"]: _json_bytes(built.patch),
            paths["verification"]: _json_bytes(verification),
            paths["rollback"]: rollback_script(paths["baseline"].name, profile.baseline_sha256),
            destination: built.data,
        }
        for path, content in files.items():
            if _aliases(path, source):
                raise RecoveryError("产物路径指向原始样本")
            if path.exists():
                if not path.is_file():
                    raise RecoveryError(f"产物路径不是文件：{path}")
                if path.read_bytes() != content and not overwrite:
                    raise RecoveryError(f"产物已存在且内容不同；需 --force：{path}")
        if sha256(source.read_bytes()) != profile.baseline_sha256:
            raise RecoveryError("处理过程中原始样本发生变化；未发布")
        for path, content in files.items():
            if not path.exists() or path.read_bytes() != content:
                _atomic_write(path, content)
            if path.read_bytes() != content:
                raise RecoveryError(f"产物重读失败：{path}")
        paths["rollback"].chmod(paths["rollback"].stat().st_mode | 0o111)
        if sha256(source.read_bytes()) != profile.baseline_sha256:
            raise RecoveryError("写出后原始样本身份异常")
        report_progress(f"完成：{destination}；文件校验和补丁重放通过，尚未自动启动游戏")
        return RepairResult(destination, built.patch["modified_sha256"], paths["diff"],
                            paths["verification"], paths["rollback"], len(payloads), True)
