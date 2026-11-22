"""'Lists and database' window: the threat database on this device, your lists, privacy setting."""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess  # nosec B404 - starts our own updater with fixed arguments
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .. import paths
from .. import settings as settings_mod
from ..textsafe import safe_text
from ..threatdb import ThreatDB, ensure_healthy

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
LISTS = (("allow", "Allowlist", "Domains and links you trust: warnings are switched off for them."),
         ("block", "Blocklist", "Domains and links you never want to open: always shown as dangerous."),
         ("reported", "Reported", "Links you reported as phishing. They stay blocked on this device; nothing is sent anywhere."))


def updater_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [str(Path(sys.executable).with_name("hg-update.exe")), "--now"]
    entry = Path(__file__).resolve().parent.parent / "_entry.py"
    return [sys.executable, "-I", "-B", str(entry), "update", "--quiet"]


def open_db() -> ThreatDB:
    paths.ensure_data_dir()
    ensure_healthy(paths.db_path(), thorough=False)  # a damaged file is rebuilt with your lists
    return ThreatDB(paths.db_path())


def _ago(iso: str | None) -> str:
    if not iso:
        return "never"
    try:
        delta = dt.datetime.now(dt.UTC) - dt.datetime.fromisoformat(iso)
    except ValueError:
        return iso
    hours = delta.total_seconds() / 3600
    return f"{max(1, round(hours * 60))} min ago" if hours < 1 else f"{round(hours)} h ago" if hours < 48 else f"{delta.days} days ago"


class ListsWindow(tk.Toplevel):
    def __init__(self, master: tk.Misc, font_small=None):
        super().__init__(master)
        self.title("Homograph Guard - lists and threat database")
        self.geometry("880x620")
        self.minsize(720, 520)
        self.db = open_db()
        self.updating = False
        self._build(font_small)
        self.refresh()
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _close(self) -> None:
        self.db.close()
        self.destroy()

    def _build(self, font_small) -> None:
        pad = {"padx": 14, "pady": (10, 0)}
        top = ttk.Frame(self, padding=(14, 12, 14, 0))
        top.pack(fill="x")
        self.db_text = tk.StringVar()
        ttk.Label(top, textvariable=self.db_text, wraplength=620, justify="left").pack(side="left", fill="x", expand=True)
        self.btn_update = ttk.Button(top, text="Update now", command=self.update_now)
        self.btn_update.pack(side="right")

        self.feeds = ttk.Treeview(self, columns=("feed", "entries", "status"), show="headings", height=6)
        for col, text, width in (("feed", "Feed", 330), ("entries", "Entries", 110), ("status", "Status", 380)):
            self.feeds.heading(col, text=text, anchor="w")
            self.feeds.column(col, width=width, anchor="w", stretch=(col == "status"))
        self.feeds.pack(fill="x", **pad)

        priv = ttk.LabelFrame(self, text="When the browser extension checks a link", padding=(10, 6))
        priv.pack(fill="x", **pad)
        self.dns_mode = tk.StringVar()
        for mode, label in (("off", "Use only this device (nothing is sent anywhere)"),
                            ("suspicious", "Also ask DNS resolvers about suspicious links"),
                            ("all", "Also ask DNS resolvers about every link")):
            ttk.Radiobutton(priv, text=label, value=mode, variable=self.dns_mode, command=self.set_dns).pack(anchor="w")
        self.locked = ttk.Label(priv, text="", foreground="#B54708")
        self.locked.pack(anchor="w")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=14, pady=10)
        self.trees: dict[str, ttk.Treeview] = {}
        for kind, title, help_text in LISTS:
            tab = ttk.Frame(nb, padding=8)
            nb.add(tab, text=title)
            ttk.Label(tab, text=help_text, foreground="#56626F").pack(anchor="w")
            row = ttk.Frame(tab)
            row.pack(fill="x", pady=6)
            entry = ttk.Entry(row)
            entry.pack(side="left", fill="x", expand=True)
            note = ttk.Entry(row, width=28)
            note.pack(side="left", padx=6)
            ttk.Button(row, text="Report" if kind == "reported" else "Add",
                       command=lambda k=kind, e=entry, n=note: self.add(k, e, n)).pack(side="left")
            tree = ttk.Treeview(tab, columns=("value", "note", "when"), show="headings", selectmode="extended")
            for col, text, width in (("value", "Domain or link", 420), ("note", "Note", 200), ("when", "Added", 140)):
                tree.heading(col, text=text, anchor="w")
                tree.column(col, width=width, anchor="w", stretch=(col == "value"))
            tree.pack(fill="both", expand=True)
            buttons = ttk.Frame(tab)
            buttons.pack(fill="x", pady=(6, 0))
            ttk.Button(buttons, text="Remove selected", command=lambda k=kind: self.remove(k)).pack(side="left")
            ttk.Button(buttons, text="Export lists...", command=self.export).pack(side="right")
            ttk.Button(buttons, text="Import lists...", command=self.import_).pack(side="right", padx=6)
            self.trees[kind] = tree

    # ------------------------------------------------------------------ data
    def refresh(self) -> None:
        st = self.db.status()
        self.db_text.set(f"Threat database on this device: {st['domains']:,} domains and {st['urls']:,} links, updated "
                         f"{_ago(st['updated'])}. It is refreshed every day from public phishing and malware lists; "
                         "looking a link up never sends it anywhere.")
        self.feeds.delete(*self.feeds.get_children())
        for f in st["feeds"]:
            state = f["status"] + (f" - {safe_text(f['error'], 120)}" if f["error"] else "")
            self.feeds.insert("", "end", values=(safe_text(f["title"], 80), f"{(f['domains'] or 0) + (f['urls'] or 0):,}", state))
        s = settings_mod.load()
        self.dns_mode.set(s.dns_mode)
        self.locked.configure(text="Set by your organisation's policy." if "dns_mode" in s.locked else "")
        for kind, tree in self.trees.items():
            tree.delete(*tree.get_children())
            rows = self.db.reports() if kind == "reported" else self.db.entries(kind)
            for r in rows:
                value = r.get("url") or r.get("value")
                when = (r.get("reported") or r.get("added") or "")[:10]
                tree.insert("", "end", iid=value, values=(safe_text(value, 300), safe_text(r.get("note"), 120), when))

    def add(self, kind: str, entry: ttk.Entry, note: ttk.Entry) -> None:
        text = entry.get().strip()
        try:
            if kind == "reported":
                self.db.report(text, note.get().strip())
            else:
                self.db.add_entry(kind, text, note.get().strip())
        except ValueError as exc:
            messagebox.showerror("Not added", str(exc), parent=self)
            return
        entry.delete(0, "end")
        note.delete(0, "end")
        self.refresh()

    def remove(self, kind: str) -> None:
        for iid in self.trees[kind].selection():
            if kind == "reported":
                self.db.unreport(iid)
            else:
                self.db.remove_entry(kind, iid)
        self.refresh()

    def set_dns(self) -> None:
        try:
            settings_mod.set_value("dns_mode", self.dns_mode.get())
        except (ValueError, PermissionError) as exc:
            messagebox.showerror("Not changed", str(exc), parent=self)
        self.refresh()

    def export(self) -> None:
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".json", initialfile="homograph-guard-lists.json",
                                            filetypes=[("Homograph Guard lists", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(self.db.export_lists(), fh, indent=2)

    def import_(self) -> None:
        path = filedialog.askopenfilename(parent=self, filetypes=[("Homograph Guard lists", "*.json"), ("All files", "*")])
        if not path:
            return
        try:
            if os.path.getsize(path) > 16 * 1024 * 1024:
                raise ValueError("the file is too large")
            with open(path, encoding="utf-8-sig") as fh:
                n = self.db.import_lists(json.load(fh))
        except (OSError, ValueError) as exc:
            messagebox.showerror("Not imported", str(exc), parent=self)
            return
        messagebox.showinfo("Imported", f"{n} entries imported.", parent=self)
        self.refresh()

    def update_now(self) -> None:
        if self.updating:
            return
        self.updating = True
        self.btn_update.configure(state="disabled", text="Updating...")

        def work():
            try:
                subprocess.run(updater_command(), creationflags=_NO_WINDOW, timeout=1800, check=False)  # nosec B603
            finally:
                self.after(0, self._updated)

        threading.Thread(target=work, daemon=True).start()

    def _updated(self) -> None:
        self.updating = False
        self.btn_update.configure(state="normal", text="Update now")
        self.refresh()
