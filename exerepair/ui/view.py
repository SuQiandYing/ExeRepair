"""Minimal Tk view: one drop target, one info table, one log, one action."""

from __future__ import annotations

from pathlib import Path
from queue import Empty, SimpleQueue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .viewmodel import ConsoleController, StatusTone, WorkbenchState

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    DND_FILES = None
    TkinterDnD = None

BG = "#F5F5F4"
PANEL = "#FFFFFF"
LINE = "#DDDDDA"
TEXT = "#1F1F1D"
MUTED = "#77776F"
OK = "#3B82F6"
GOOD = "#16A34A"
BAD = "#DC2626"
TAG_COLORS = {"info": OK, "ok": GOOD, "bad": BAD, "": TEXT}


class MainWindow:
    def __init__(
        self,
        root: tk.Tk,
        initial_path: str | Path | None = None,
        controller: ConsoleController | None = None,
    ) -> None:
        self.root = root
        self.controller = controller or ConsoleController()
        self._busy = False
        self._events: SimpleQueue[tuple[object, ...]] = SimpleQueue()

        root.title("ExeRepair")
        root.geometry("760x560")
        root.minsize(640, 480)
        root.configure(background=BG)
        self._build()
        self.render(self.controller.state)
        root.after(50, self._poll)

        if initial_path is not None:
            root.after(0, self.load_path, Path(initial_path))

    def _build(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        frame = ttk.Frame(self.root, padding=14, style="Main.TFrame")
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(2, weight=1)
        frame.rowconfigure(3, weight=1)

        top = ttk.Frame(frame, style="Main.TFrame")
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)
        ttk.Button(top, text="选择文件…", command=self.select_file).grid(
            row=0, column=0, padx=(0, 10)
        )
        self.path_label = ttk.Label(
            top, text="拖入 EXE 到窗口，或点击选择", style="Muted.TLabel"
        )
        self.path_label.grid(row=0, column=1, sticky="w")

        status = tk.Frame(
            frame, background=PANEL, highlightbackground=LINE, highlightthickness=1
        )
        status.grid(row=1, column=0, sticky="ew", pady=(12, 12))
        status.columnconfigure(0, weight=1)
        self.status_title = tk.Label(
            status, text="等待文件", background=PANEL, foreground=TEXT,
            font=("Microsoft YaHei UI", 11, "bold"), anchor="w",
        )
        self.status_title.grid(row=0, column=0, sticky="ew", padx=12, pady=(9, 1))
        self.status_detail = tk.Label(
            status, text="", background=PANEL, foreground=MUTED,
            font=("Microsoft YaHei UI", 9), anchor="w", wraplength=680,
            justify="left",
        )
        self.status_detail.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 9))

        columns = ("key", "value")
        self.table = ttk.Treeview(
            frame, columns=columns, show="headings", height=8,
            style="Info.Treeview",
        )
        self.table.heading("key", text="项目")
        self.table.heading("value", text="内容")
        self.table.column("key", width=150, minwidth=120, anchor="w")
        self.table.column("value", width=520, minwidth=300, anchor="w")
        self.table.grid(row=2, column=0, sticky="nsew")
        for tag, color in TAG_COLORS.items():
            self.table.tag_configure(tag, foreground=color)

        self.log = tk.Text(
            frame, height=5, background=PANEL, foreground=MUTED, relief="flat",
            highlightthickness=1, highlightbackground=LINE, font=("Consolas", 8),
            state="disabled", wrap="word",
        )
        self.log.grid(row=3, column=0, sticky="nsew", pady=(12, 0))

        bottom = ttk.Frame(frame, style="Main.TFrame")
        bottom.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        bottom.columnconfigure(0, weight=1)
        self.action = ttk.Button(
            bottom, text="提取", command=self.run_action, state="disabled"
        )
        self.action.grid(row=0, column=0, sticky="e")

        self._register_drop()

    def _register_drop(self) -> None:
        if TkinterDnD is not None and DND_FILES is not None:
            self.root.drop_target_register(DND_FILES)  # type: ignore[attr-defined]
            self.root.dnd_bind("<<Drop>>", self._on_drop)  # type: ignore[attr-defined]

    def _on_drop(self, event: object) -> str:
        if not self._busy:
            files = self.root.tk.splitlist(getattr(event, "data", ""))
            if files:
                self.load_path(files[0])
        return "break"

    def select_file(self) -> None:
        name = filedialog.askopenfilename(
            parent=self.root,
            title="选择目标 EXE",
            filetypes=(("可执行程序", "*.exe"), ("所有文件", "*.*")),
        )
        if name:
            self.load_path(name)

    def load_path(self, path: str | Path) -> None:
        if self._busy:
            return
        self._busy = True
        self.render(self.controller.begin_load(path))
        threading.Thread(
            target=lambda: self._events.put(
                ("load", self.controller.load(path))
            ),
            daemon=True,
        ).start()

    def run_action(self) -> None:
        if self._busy or not self.controller.state.can_act:
            return
        self._busy = True
        self.render(self.controller.begin_action())
        threading.Thread(
            target=lambda: self._events.put(
                ("act", *self.controller.act())
            ),
            daemon=True,
        ).start()

    def _poll(self) -> None:
        try:
            while True:
                event = self._events.get_nowait()
                kind = event[0]
                self._busy = False
                if kind == "load":
                    self.render(event[1])  # type: ignore[arg-type]
                    state = event[1]
                    if state.tone is StatusTone.ERROR:
                        messagebox.showerror(
                            "ExeRepair", state.status_detail, parent=self.root
                        )
                elif kind == "act":
                    self.render(event[1])  # type: ignore[arg-type]
                    if event[2]:
                        messagebox.showinfo(
                            "ExeRepair", f"完成：\n{event[2]}", parent=self.root
                        )
                    else:
                        messagebox.showerror(
                            "ExeRepair",
                            self.controller.state.status_detail,
                            parent=self.root,
                        )
        except Empty:
            pass
        if self._busy and self.controller.state.phase == "busy":
            self.render(self.controller.state)
        if self.root.winfo_exists():
            self.root.after(50, self._poll)

    def render(self, state: WorkbenchState) -> None:
        self.path_label.configure(text=state.source_path or "拖入 EXE 到窗口，或点击选择")
        self.status_title.configure(text=state.status_title)
        self.status_detail.configure(text=state.status_detail)
        color = {
            StatusTone.NEUTRAL: MUTED,
            StatusTone.INFO: OK,
            StatusTone.SUCCESS: GOOD,
            StatusTone.ERROR: BAD,
        }[state.tone]
        self.status_title.configure(foreground=color)
        self.action.configure(
            text=state.action_label, state="normal" if state.can_act and not self._busy else "disabled"
        )
        if any(row.values != ("", "") for row in state.rows) or state.rows != getattr(self, "_rows", state.rows):
            self._rows = state.rows
            self.table.delete(*self.table.get_children())
            for row in state.rows:
                self.table.insert("", "end", values=row.values, tags=(row.tag,))
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.insert("end", "\n".join(line for line in state.logs if line))
        self.log.see("end")
        self.log.configure(state="disabled")
