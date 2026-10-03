"""ExeRepair desktop console."""

from __future__ import annotations

from typing import Any

from .viewmodel import ConsoleController, WorkbenchState


def main(initial_path: object = None, *, recovery_options: dict | None = None) -> int:
    from .app import main as run

    return run(initial_path, recovery_options=recovery_options)  # type: ignore[arg-type]


def __getattr__(name: str) -> Any:
    if name == "MainWindow":
        from .view import MainWindow

        return MainWindow
    raise AttributeError(name)


__all__ = ["ConsoleController", "MainWindow", "WorkbenchState", "main"]
