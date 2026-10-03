"""Command-line entry point for inspection, extraction, and repair."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .application import ContainerService, ExtractionOptions
from .application.recovery import RepairService
from .domain.errors import OperationError
from .domain.models import PatchMode
from .domain.recovery import NativeCallProfile


def _path_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("executable", nargs="?", type=Path, help="目标 EXE 路径")
    parser.add_argument("-i", "--inspect", action="store_true", help="仅显示信息，不写出副本")
    parser.add_argument("-o", "--output", type=Path, help="输出路径")
    parser.add_argument("--gui", action="store_true", help="打开图形界面")
    parser.add_argument("--force", action="store_true", help="允许替换不同的现有输出")


def _recovery_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--recovery-manifest",
        type=Path,
        help="复用已经校验的载荷清单",
    )
    parser.add_argument("--work-dir", type=Path, help="恢复缓存与隔离探测目录")
    parser.add_argument("--aplib-dll", type=Path, help="覆盖内置压缩器 DLL")
    parser.add_argument("--backend", choices=("auto", "opencl", "cpu"), default="auto")
    parser.add_argument("--search-start", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--search-count", type=lambda value: int(value, 0), default=1 << 32)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exerepair",
        description="视觉小说 EXE 恢复工具（容器提取 / 单样本修复）",
    )
    _path_options(parser)
    _recovery_options(parser)
    return parser


def _print_program(program) -> None:
    stub = program.stub
    active = sum(patch.mode is not PatchMode.None_ for patch in stub.patches)
    rows = (
        ("版本", str(stub.level)),
        ("壳大小", f"{program.wrapper_size:08X}"),
        ("加密配置大小", f"{stub.size:08X}"),
        ("模式", str(stub.config.mode)),
        ("主程序版本", program.executable_version),
        ("主程序大小", f"{program.executable_size:08X}"),
        ("有效加密区块", str(active)),
    )
    for label, value in rows:
        print(f"{label}: {value}")


def _inspect_or_repair(target: Path, args) -> int:
    inspection = RepairService().inspect(target)
    profile = inspection.profile
    print(f"修复配置: {profile.name}")
    print(f"原始 SHA256: {profile.baseline_sha256}")
    if isinstance(profile, NativeCallProfile):
        print("修复方法: 已验证的原生 executeAPI 调用；不捕获、不搜索密钥")
    else:
        print(f"载荷数量: {len(profile.payloads)}")

    if args.inspect:
        print("单样本修复已识别；未启动进程或读取激活信息")
        return 0

    result = RepairService().repair(
        target,
        args.output,
        manifest=args.recovery_manifest,
        work_dir=args.work_dir,
        aplib_dll=args.aplib_dll,
        backend=args.backend,
        search_start=args.search_start,
        search_count=args.search_count,
        overwrite=args.force,
        progress=lambda message: print(message, flush=True),
    )
    print(f"输出: {result.output_path}")
    print(f"输出 SHA256: {result.output_sha256}")
    print(f"补丁: {result.diff_path}")
    print(f"校验: {result.verification_path}")
    print(f"回滚: {result.rollback_path}")
    return 0



def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.gui or args.executable is None:
        from .ui import main as ui_main

        return ui_main(
            args.executable,
            recovery_options={
                "manifest": args.recovery_manifest,
                "work_dir": args.work_dir,
                "aplib_dll": args.aplib_dll,
                "backend": args.backend,
                "search_start": args.search_start,
                "search_count": args.search_count,
                "overwrite": args.force,
            },
        )

    target = args.executable
    try:
        program = ContainerService().load(target)
    except OperationError as error:
        if not target.exists():
            print(error.message, file=sys.stderr)
            return 2
        try:
            return _inspect_or_repair(target, args)
        except (OSError, ValueError, KeyError, TypeError) as failure:
            print(f"exerepair: {failure}", file=sys.stderr)
            return 2

    _print_program(program)
    if args.inspect:
        return 0

    output = args.output or target.with_name(f"{target.stem}_crack{target.suffix}")
    result = ContainerService().extract_loaded(
        program,
        ExtractionOptions(output_exe=output),
    )
    if not result.success:
        print(f"提取失败: {result.last_error}", file=sys.stderr)
        return 2
    print(f"提取成功: {result.output_directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
