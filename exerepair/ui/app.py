"""Desktop composition root."""

from __future__ import annotations

from pathlib import Path
import tkinter as tk

from .view import TkinterDnD, MainWindow
from .viewmodel import ConsoleController


def main(
    initial_path: str | Path | None = None, *, recovery_options: dict | None = None
) -> int:
    root = TkinterDnD.Tk() if TkinterDnD is not None else tk.Tk()
    MainWindow(root, initial_path, ConsoleController(recovery_options=recovery_options))
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
