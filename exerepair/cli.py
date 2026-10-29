"""Command-line entry point for inspection, extraction, and repair."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .application import ContainerService, ExtractionOptions
from .application.recovery import RepairService
from .application.enigma import EnigmaService
from .domain.errors import OperationError
from .domain.models import PatchMode
from .domain.recovery import DiscCheckProfile, NativeCallProfile
from .launcher import launch_from_folder


def _path_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("executable", nargs="?", type=Path, help="目标 EXE 路径")
    parser.add_argument("-i", "--inspect", action="store_true", help="仅显示信息，不写出副本")
    parser.add_argument("-o", "--output", type=Path, help="输出路径")
    parser.add_argument("--gui", action="store_true", help="打开图形界面")
    parser.add_argument("--enigma", action="store_true", help="使用静态 Enigma 配置/节/EVB 恢复流程")
    parser.add_argument("--enigma-metadata-rva", type=lambda value: int(value, 0), help="Enigma 元数据 RVA（静态恢复必填）")
    parser.add_argument("--enigma-salt", type=lambda value: int(value, 0), help="已知 Enigma 32 位 section salt")
    parser.add_argument("--force", action="store_true", help="允许替换不同的现有输出")
    parser.add_argument(
        "--run",
        action="store_true",
        help="以 EXE 所在目录为工作目录启动，不修改输入文件",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="与 --run 一起使用，等待目标退出或达到超时",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        help="与 --run --wait 一起使用的等待秒数；超时后目标继续运行",
    )
    parser.add_argument(
        "--launch-arg",
        action="append",
        default=[],
        dest="launch_args",
        help="传给目标程序的参数；可重复指定",
    )


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


def _enigma_command(target: Path, args) -> int:
    if args.run or args.gui or args.recovery_manifest is not None:
        raise ValueError("--enigma 不能与 --run、--gui 或 --recovery-manifest 一起使用")
    service = EnigmaService()
    if args.inspect:
        inspection = service.inspect(target, metadata_rva=args.enigma_metadata_rva)
        print(f"PE 位数: {inspection.bitness}")
        print(f"映像基址: 0x{inspection.image_base:x}")
        print(f"入口 RVA: 0x{inspection.entry_rva:x}")
        print(f"节数量: {inspection.section_count}")
        if inspection.configuration is None:
            print("未解析元数据；提供 --enigma-metadata-rva 可继续配置检查")
        else:
            print(f"描述符数量: {len(inspection.configuration.descriptors)}")
            print(f"Loader 上下文: {'已提供' if inspection.configuration.context is not None else '未提供'}")
        return 0
    if args.enigma_metadata_rva is None:
        raise ValueError("静态 Enigma 恢复需要 --enigma-metadata-rva；RVA 必须来自独立入口分析")
    output = args.output or target.with_name(f"{target.stem}_enigma")
    result = service.recover(
        target,
        metadata_rva=args.enigma_metadata_rva,
        salt=args.enigma_salt,
        backend=args.backend,
        search_start=args.search_start,
        search_count=args.search_count,
        output_directory=output,
        progress=lambda message: print(message, flush=True),
    )
    print(f"section salt: {'已恢复' if result.salt is not None else '未加密'}")
    print(f"恢复节: {len(result.recovered_sections)}")
    print(f"EVB 文件: {len(result.evb_files)}")
    print(f"输出目录: {result.output_directory}")
    return 0


def _inspect_or_repair(target: Path, args) -> int:
    inspection = RepairService().inspect(target)
    profile = inspection.profile
    print(f"修复配置: {profile.name}")
    print(f"原始 SHA256: {profile.baseline_sha256}")
    if isinstance(profile, DiscCheckProfile):
        print("修复类型: 光盘检查兼容；不捕获、不搜索密钥、不依赖压缩器")
    elif isinstance(profile, NativeCallProfile):
        if profile.requires_runtime_discovery:
            print("修复方法: 已通过结构验证；修复时自动隔离定位原生调用")
        else:
            print("修复方法: 已定位的原生 executeAPI 调用；不捕获、不搜索密钥")
    else:
        print(f"载荷数量: {len(profile.payloads)}")

    if args.inspect:
        print("样本结构已识别；未启动进程或读取激活信息")
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
    if args.enigma:
        if args.executable is None:
            parser.error("--enigma 必须提供目标 EXE")
        try:
            return _enigma_command(args.executable, args)
        except (OSError, ValueError, KeyError, TypeError) as failure:
            print(f"exerepair: {failure}", file=sys.stderr)
            return 2
    if args.run:
        if args.executable is None:
            parser.error("--run 必须提供目标 EXE")
        if args.inspect or args.output is not None or args.gui or args.force:
            parser.error("--run 不能与 --inspect、--output、--gui 或 --force 同时使用")
        if args.timeout is not None and not args.wait:
            parser.error("--timeout 必须与 --run --wait 一起使用")
        try:
            launched = launch_from_folder(
                args.executable,
                args.launch_args,
                wait=args.wait,
                timeout=args.timeout,
            )
        except (OSError, ValueError) as error:
            print(f"exerepair: 启动失败：{error}", file=sys.stderr)
            return 2
        print(f"启动文件: {launched.executable}")
        print(f"工作目录: {launched.working_directory}")
        print(f"PID: {launched.process_id}")
        if launched.timed_out:
            print("状态: 等待超时，目标进程仍在运行")
        elif launched.return_code is None:
            print("状态: 已启动")
        else:
            print(f"退出码: {launched.return_code}")
        return launched.return_code if args.wait and launched.return_code is not None else 0
    if args.wait or args.timeout is not None or args.launch_args:
        parser.error("--wait、--timeout 和 --launch-arg 只能与 --run 一起使用")
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
