"""Launch an executable with its own folder as the process working directory."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
from collections.abc import Sequence


@dataclass(frozen=True, slots=True)
class LaunchResult:
    """Observable result of starting one executable."""

    executable: Path
    working_directory: Path
    process_id: int
    return_code: int | None
    timed_out: bool = False


def launch_from_folder(
    executable: str | Path,
    arguments: Sequence[str] = (),
    *,
    wait: bool = False,
    timeout: float | None = None,
) -> LaunchResult:
    """Start *executable* with its parent directory as ``cwd``.

    The source file is only read for existence and is never modified.  The
    default is non-blocking so GUI games remain available after the CLI exits.
    ``wait=True`` is useful for verification and optionally returns after a
    bounded timeout while leaving the child process alive.
    """

    source = Path(executable).expanduser().resolve(strict=True)
    if not source.is_file():
        raise FileNotFoundError(f"目标不是普通文件：{source}")
    if timeout is not None and timeout < 0:
        raise ValueError("timeout 必须是非负数")

    command = [str(source), *(str(argument) for argument in arguments)]
    process = subprocess.Popen(command, cwd=str(source.parent), shell=False)
    return_code: int | None = None
    timed_out = False
    if wait:
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True

    return LaunchResult(
        executable=source,
        working_directory=source.parent,
        process_id=process.pid,
        return_code=return_code,
        timed_out=timed_out,
    )
