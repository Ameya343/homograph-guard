"""Desktop GUI for homograph-guard (Tkinter, no extra dependencies).

The window is a viewer. Links are only ever handled by an isolated worker
(see ``worker.py``); what comes back is a JSON report, displayed as plain
text in Tk widgets - nothing is rendered as HTML and no link is clickable.
"""

from __future__ import annotations

import argparse
import json
import queue
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

from .. import __version__
from ..report import describe_context
from ..textsafe import safe_text
from .worker import DEFAULT_IMAGE, WorkerConfig, WorkerError, docker_status, run_batch

PALETTE = {
    "bench": "#E8ECF0",  # window background, a cool lab-bench grey
    "sheet": "#FFFFFF",  # panels
    "ink": "#17212B",
    "muted": "#56626F",
    "faint": "#6E7A88",
    "rule": "#C6CFD8",
    "marker": "#C8146C",  # highlighter for impostor characters
    "marker_soft": "#FBE3EF",
    "select": "#D7E2EE",
    "button": "#17212B",
    "button_text": "#FFFFFF",
}
VERDICT = {
    "high_risk": ("#B42318", "High risk"),
    "suspicious": ("#B54708", "Suspicious"),
    "caution": ("#7A6400", "Caution"),
    "no_indicators": ("#1F7A4D", "No indicators"),
    "error": ("#6941C6", "Could not check"),
}
SEVERITY = {"critical": "#B42318", "high": "#B42318", "medium": "#B54708", "low": "#56626F", "info": "#6E7A88"}
HINT = ("Paste links, domains or email addresses here, one per line - or open a saved email (.eml),\n"
        "web page or chat export. Nothing is opened: an isolated worker reads it as text and checks DNS.")
MAX_TARGETS = 500
MAX_FILE = 16 * 1024 * 1024
DOC_EXTENSIONS = {".eml": "eml", ".html": "html", ".htm": "html", ".xhtml": "html", ".svg": "html"}
FACTS = ("Found", "Link text", "Rewritten by", "Defanged", "Displays as", "DNS name", "Registrable domain")
ICONS = Path(__file__).resolve().with_name("icons")


def set_app_icon(root: tk.Tk) -> None:
    """The app's shield in the title bar and taskbar of every window, instead of Tk's feather."""
    try:
        if sys.platform == "win32":
            ico = str(ICONS / "app.ico")  # holds every size Windows asks for (16 to 256 pixels)
            root.iconbitmap(default=ico)  # windows opened later (lists, dialogs)
            root.iconbitmap(ico)
        else:
            images = [tk.PhotoImage(master=root, file=str(ICONS / f"app-{s}.png")) for s in (256, 128, 64, 48, 32, 16)]
            root.iconphoto(True, *images)
            root._hg_icons = images  # keep a reference: Tk does not
    except (tk.TclError, OSError):
        pass  # a missing icon must never stop the app


def document_format(name: str, data: bytes) -> str | None:
    """How the worker should read an opened file: eml/html/text, or None for a plain list of links.

    Decided from the name and a cheap look at the first bytes - the GUI never parses the document.
    """
    low = name.lower()
    for ext, fmt in DOC_EXTENSIONS.items():
        if low.endswith(ext):
            return fmt
    head = data[:4096].decode("utf-8", "replace")
    first = head.lstrip()[:200].lower()
    if first.startswith(("<!doctype html", "<html")):
        return "html"
    header_names = [ln.split(":", 1)[0].lower() for ln in head.splitlines()[:30] if ":" in ln]
    if {"from", "subject"} <= set(header_names) or {"received", "message-id"} & set(header_names):
        return "eml"
    lines = [ln.strip() for ln in head.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if lines and sum(" " in ln for ln in lines) > len(lines) / 2:
        return "text"  # sentences (an exported chat), not one link per line
    return None


def _pick(families: set[str], wanted: list[str], fallback: str) -> str:
    return next((f for f in wanted if f in families), fallback)


def _keep_divider(paned: ttk.PanedWindow, first: tk.Misc, share: float, minimum: int):
    """Give the first pane of a vertical divider its natural height, but at most ``share`` of the room.

    Tk's own weights take room from the heaviest pane first, which squeezed the DNS table on small
    windows; placing the divider explicitly keeps the important pane readable. Returns the function
    that places it (call it again when the first pane's content changes size).
    """
    def place(_event=None) -> None:
        total = paned.winfo_height()
        if total > 1:
            paned.sashpos(0, max(minimum, min(first.winfo_reqheight(), int(total * share))))

    paned.bind("<Configure>", place, add="+")
    return place


def _wrap_when_narrow(row: tk.Misc, left: tk.Misc, right: tk.Misc, gap: int = 24) -> None:
    """Show two groups side by side, or the right one under the left one when the window is narrow."""
    state: dict[str, bool | None] = {"wrapped": None}

    def relayout(_event=None) -> None:
        wrapped = left.winfo_reqwidth() + right.winfo_reqwidth() + gap > row.winfo_width()
        if wrapped == state["wrapped"]:
            return  # a height change from the last re-pack: nothing to do
        state["wrapped"] = wrapped
        left.pack_forget()
        right.pack_forget()
        if wrapped:
            left.pack(side="top", anchor="w")
            right.pack(side="top", anchor="w", pady=(6, 0))
        else:
            left.pack(side="left")
            right.pack(side="right")

    row.bind("<Configure>", relayout, add="+")
    relayout()


class App:
    def __init__(self, root: tk.Tk, image: str = DEFAULT_IMAGE, force_local: bool = False):
        self.root = root
        self.image = image
        self.force_local = force_local
        self.events: queue.Queue = queue.Queue()
        self.reports: list[dict] = []
        self.holder: dict = {}
        self.running = False
        self.docker_ok = False
        self.docker_msg = "Checking for Docker…"
        root.title("Homograph Guard")
        set_app_icon(root)
        width = max(960, min(1440, root.winfo_screenwidth() - 80))
        height = max(640, min(940, root.winfo_screenheight() - 90))
        root.geometry(f"{width}x{height}")
        root.minsize(960, 640)
        root.configure(bg=PALETTE["bench"])
        self._fonts()
        self._style()
        self._build()
        self._check_install_state()
        threading.Thread(target=self._detect_docker, daemon=True).start()
        root.after(100, self._poll)

    def _check_install_state(self) -> None:
        """Remind the user when the last installation was cut off (the Windows installer records it)."""
        if sys.platform != "win32":
            return
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\HomographGuard") as key:
                state = winreg.QueryValueEx(key, "InstallState")[0]
        except OSError:
            return
        if state == "incomplete":
            self._set_status("The last installation did not finish. Run Homograph Guard Setup again to complete it.")

    # ------------------------------------------------------------------ look
    def _fonts(self) -> None:
        fams = set(tkfont.families(self.root))
        ui = _pick(fams, ["Segoe UI", "SF Pro Text", "Helvetica Neue", "Noto Sans", "DejaVu Sans", "Liberation Sans"], "Helvetica")
        mono = _pick(fams, ["Cascadia Mono", "Consolas", "SF Mono", "Menlo", "DejaVu Sans Mono", "Noto Sans Mono"], "Courier")
        glyph = _pick(fams, ["Segoe UI", "Noto Sans", "DejaVu Sans", "Arial", "Liberation Sans"], ui)
        self.f_body = tkfont.Font(self.root, family=ui, size=10)
        self.f_small = tkfont.Font(self.root, family=ui, size=9)
        self.f_bold = tkfont.Font(self.root, family=ui, size=10, weight="bold")
        self.f_title = tkfont.Font(self.root, family=ui, size=15, weight="bold")
        self.f_verdict = tkfont.Font(self.root, family=ui, size=17, weight="bold")
        self.f_mono = tkfont.Font(self.root, family=mono, size=9)
        self.f_glyph = tkfont.Font(self.root, family=glyph, size=30)
        self.f_code = tkfont.Font(self.root, family=mono, size=8)
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
            try:
                tkfont.nametofont(name).configure(family=ui, size=10)
            except tk.TclError:
                pass

    def _style(self) -> None:
        s = ttk.Style(self.root)
        s.theme_use("clam")
        p = PALETTE
        s.configure(".", background=p["bench"], foreground=p["ink"], font=self.f_body)
        s.configure("Sheet.TFrame", background=p["sheet"])
        s.configure("TCheckbutton", background=p["bench"])
        s.map("TCheckbutton", background=[("active", p["bench"])])
        s.configure("Muted.TLabel", foreground=p["muted"])
        s.configure("Sheet.TLabel", background=p["sheet"])
        s.configure("SheetMuted.TLabel", background=p["sheet"], foreground=p["muted"])
        s.configure("Primary.TButton", background=p["button"], foreground=p["button_text"],
                    font=self.f_bold, padding=(18, 8), borderwidth=0)
        s.map("Primary.TButton", background=[("disabled", "#8A949E"), ("active", "#2B3A49")])
        s.configure("TButton", padding=(12, 6))
        s.configure("Treeview", background=p["sheet"], fieldbackground=p["sheet"], rowheight=26,
                    bordercolor=p["rule"], font=self.f_body)
        s.configure("Treeview.Heading", background=p["bench"], foreground=p["muted"], font=self.f_small,
                    relief="flat", padding=(6, 4))
        s.map("Treeview", background=[("selected", p["select"])], foreground=[("selected", p["ink"])])
        s.configure("TNotebook", background=p["sheet"], borderwidth=0, tabmargins=(0, 6, 0, 0))
        s.configure("TNotebook.Tab", padding=(14, 6), background=p["bench"], foreground=p["muted"])
        s.map("TNotebook.Tab", background=[("selected", p["sheet"])], foreground=[("selected", p["ink"])])
        s.configure("TCombobox", padding=4)
        s.configure("Horizontal.TProgressbar", background=p["ink"], troughcolor=p["rule"], thickness=4)

    # ------------------------------------------------------------------ layout
    def _build(self) -> None:
        p = PALETTE
        top = ttk.Frame(self.root, padding=(18, 14, 18, 6))
        top.pack(fill="x")
        ttk.Label(top, text="Homograph Guard", font=self.f_title).pack(side="left")
        self.iso_label = ttk.Label(top, text=self.docker_msg, style="Muted.TLabel")
        self.iso_label.pack(side="right")

        entry_row = ttk.Frame(self.root, padding=(18, 4, 18, 4))
        entry_row.pack(fill="x")
        self.input = tk.Text(entry_row, height=3, wrap="none", font=self.f_body, relief="solid", bd=1,
                             highlightthickness=1, highlightbackground=p["rule"], highlightcolor=p["ink"],
                             padx=10, pady=8, undo=True)
        self.input.pack(side="left", fill="x", expand=True)
        self.input.tag_configure("hint", foreground=p["faint"])
        self._show_hint()
        self.input.bind("<FocusIn>", lambda e: self._hide_hint())
        self.input.bind("<FocusOut>", lambda e: self._show_hint())
        self.input.bind("<Control-Return>", lambda e: (self.check(), "break")[1])
        buttons = ttk.Frame(entry_row, padding=(12, 0, 0, 0))
        buttons.pack(side="left", fill="y")
        self.btn_check = ttk.Button(buttons, text="Check links", style="Primary.TButton", command=self.check)
        self.btn_check.pack(fill="x")
        ttk.Button(buttons, text="Open file…", command=self.open_file).pack(fill="x", pady=(6, 0))
        ttk.Button(buttons, text="Lists & database…", command=self.open_lists).pack(fill="x", pady=(6, 0))
        self.btn_stop = ttk.Button(buttons, text="Stop", command=self.stop, state="disabled")
        self.btn_stop.pack(fill="x", pady=(6, 0))

        opts = ttk.Frame(self.root, padding=(18, 4, 18, 10))
        opts.pack(fill="x")
        self.var_dns = tk.BooleanVar(value=True)
        self.var_asn = tk.BooleanVar(value=True)
        self.var_tls = tk.BooleanVar(value=False)
        self.var_expand = tk.BooleanVar(value=True)
        self.var_transport = tk.StringVar(value="DNS over HTTPS")
        self.var_mode = tk.StringVar(value="Automatic")
        checks = ttk.Frame(opts)
        ttk.Checkbutton(checks, text="Compare Google, Cloudflare and AdGuard DNS",
                        variable=self.var_dns, command=self._dns_toggled).pack(side="left")
        self.chk_asn = ttk.Checkbutton(checks, text="Look up network owners", variable=self.var_asn)
        self.chk_asn.pack(side="left", padx=(14, 0))
        self.chk_expand = ttk.Checkbutton(checks, text="Expand short links", variable=self.var_expand)
        self.chk_expand.pack(side="left", padx=(14, 0))
        pickers = ttk.Frame(opts)
        self.chk_tls = ttk.Checkbutton(pickers, text="Read the TLS certificate", variable=self.var_tls,
                                       command=self._confirm_tls)
        self.chk_tls.pack(side="left", padx=(0, 14))
        ttk.Label(pickers, text="Lookups via", style="Muted.TLabel").pack(side="left", padx=(0, 6))
        ttk.Combobox(pickers, textvariable=self.var_transport, state="readonly", width=16,
                     values=["DNS over HTTPS", "DNS over TLS", "Plain UDP"]).pack(side="left")
        ttk.Label(pickers, text="Run in", style="Muted.TLabel").pack(side="left", padx=(14, 6))
        ttk.Combobox(pickers, textvariable=self.var_mode, state="readonly", width=20,
                     values=["Automatic", "Docker sandbox", "Guarded local process"]).pack(side="left")
        _wrap_when_narrow(opts, checks, pickers)

        # The status line is packed before the panes, so the panes can never squeeze it out of view.
        status = ttk.Frame(self.root, padding=(18, 2, 18, 10))
        status.pack(side="bottom", fill="x")
        self.status = ttk.Label(status, text="Ready.", style="Muted.TLabel")
        self.status.pack(side="left")
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=160)
        self.progress.pack(side="right")

        panes = ttk.PanedWindow(self.root, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=18, pady=(0, 6))
        left = ttk.Frame(panes, style="Sheet.TFrame")
        right = ttk.Frame(panes, style="Sheet.TFrame")
        panes.add(left, weight=0)
        panes.add(right, weight=1)

        def place_list(_event=None) -> None:  # the list gets a third of the width, within limits
            total = panes.winfo_width()
            if total > 1:
                panes.sashpos(0, max(220, min(640, int(total * 0.33))))

        panes.bind("<Configure>", place_list, add="+")

        self.results = ttk.Treeview(left, columns=("verdict", "score", "target"), show="headings", selectmode="browse")
        for col, text, width, anchor in (("verdict", "Verdict", 120, "w"), ("score", "Score", 54, "e"),
                                         ("target", "Link", 220, "w")):
            self.results.heading(col, text=text, anchor=anchor)
            self.results.column(col, width=width, anchor=anchor, stretch=(col == "target"))
        for code, (color, _) in VERDICT.items():
            self.results.tag_configure(code, foreground=color)
        self.results.pack(fill="both", expand=True)
        self.results.bind("<<TreeviewSelect>>", lambda e: self._show_selected())

        self._build_detail(right)

    def _build_detail(self, parent: ttk.Frame) -> None:
        p = PALETTE
        # Overview on top, tabs below, with a divider the user can drag. The overview keeps its
        # natural height, at most a little over half: spare room goes to the tabs, and on a small
        # window the overview gives way (its hostname strip shrinks first).
        split = ttk.PanedWindow(parent, orient="vertical")
        split.pack(fill="both", expand=True)
        overview = ttk.Frame(split, style="Sheet.TFrame")
        below = ttk.Frame(split, style="Sheet.TFrame")
        split.add(overview, weight=0)
        split.add(below, weight=1)
        self._place_overview = _keep_divider(split, overview, 0.6, 120)
        parent = overview
        head = ttk.Frame(parent, style="Sheet.TFrame", padding=(18, 14, 18, 4))
        head.pack(fill="x")
        verdict = ttk.Frame(head, style="Sheet.TFrame")
        self.v_verdict = tk.Label(verdict, text="", font=self.f_verdict, bg=p["sheet"], fg=p["ink"], anchor="w")
        self.v_verdict.pack(side="left")
        self.v_score = tk.Label(verdict, text="", font=self.f_bold, bg=p["sheet"], fg=p["muted"])
        self.v_score.pack(side="left", padx=(12, 0), pady=(6, 0))
        actions = ttk.Frame(head, style="Sheet.TFrame")
        ttk.Button(actions, text="Report as phishing", command=self.report_selected).pack(side="left", padx=(0, 6))
        ttk.Button(actions, text="Copy defanged link", command=self.copy_defanged).pack(side="left")
        ttk.Button(actions, text="Export report…", command=self.export).pack(side="left", padx=(6, 0))
        _wrap_when_narrow(head, verdict, actions)

        self.v_summary = tk.Label(parent, text="Paste a link above and choose Check links.", font=self.f_body,
                                  bg=p["sheet"], fg=p["muted"], anchor="w", justify="left", padx=18)
        self.v_summary.pack(fill="x")

        # Two columns: what the link is (long values, may be cut at the edge) | the host names.
        # Rows without a value for the selected link are left out (see _layout_facts).
        facts = ttk.Frame(parent, style="Sheet.TFrame", padding=(18, 8, 18, 0))
        facts.pack(fill="x")
        facts.columnconfigure(1, weight=1)
        self.fact_vars: dict[str, tk.StringVar] = {}
        self.fact_cells: dict[str, tuple[ttk.Label, ttk.Label]] = {}
        for key in FACTS:
            var = tk.StringVar(value="")
            self.fact_vars[key] = var
            self.fact_cells[key] = (ttk.Label(facts, text=key, style="SheetMuted.TLabel", font=self.f_small),
                                    ttk.Label(facts, textvariable=var, style="Sheet.TLabel"))
        self._layout_facts()

        strip = ttk.Frame(parent, style="Sheet.TFrame", padding=(18, 10, 18, 4))
        strip.pack(fill="both", expand=True)
        self.canvas_scroll = ttk.Scrollbar(strip, orient="horizontal")
        self.canvas_scroll.pack(side="bottom", fill="x")
        self.canvas = tk.Canvas(strip, height=80, bg=p["sheet"], highlightthickness=1,
                                highlightbackground=p["rule"], xscrollincrement=20)
        self.canvas.pack(fill="both", expand=True)
        self.canvas_scroll.configure(command=self.canvas.xview)
        self.canvas.configure(xscrollcommand=self.canvas_scroll.set)

        nb = ttk.Notebook(below)
        nb.pack(fill="both", expand=True, padx=18, pady=(6, 14))
        self.t_findings = self._text_tab(nb, "Findings")
        dns_tab = ttk.Frame(nb, style="Sheet.TFrame")
        nb.add(dns_tab, text="DNS comparison")
        # The resolvers' answers first (the table), the explanation under it; the divider moves.
        dns_split = ttk.PanedWindow(dns_tab, orient="vertical")
        dns_split.pack(fill="both", expand=True)
        table = ttk.Frame(dns_split, style="Sheet.TFrame")
        notes = ttk.Frame(dns_split, style="Sheet.TFrame")
        dns_split.add(table, weight=0)
        dns_split.add(notes, weight=1)
        _keep_divider(dns_split, table, 0.7, 60)  # every resolver row if it fits, else 70 %
        self.dns_tree = ttk.Treeview(table, columns=("resolver", "kind", "answer", "status", "network"),
                                     show="headings", height=6)
        for col, text, width in (("resolver", "Resolver", 290), ("kind", "Filters", 64), ("answer", "Answer", 230),
                                 ("status", "Status", 110), ("network", "Network", 220)):
            self.dns_tree.heading(col, text=text, anchor="w")
            self.dns_tree.column(col, width=width, anchor="w", stretch=(col in ("answer", "network")))
        self.dns_tree.tag_configure("blocked", foreground=SEVERITY["high"])
        self.dns_tree.tag_configure("failed", foreground=SEVERITY["info"])
        dns_scroll = ttk.Scrollbar(table, orient="vertical", command=self.dns_tree.yview)
        self.dns_tree.configure(yscrollcommand=dns_scroll.set)
        dns_scroll.pack(side="right", fill="y", pady=(6, 0))
        self.dns_tree.pack(fill="both", expand=True, padx=(2, 0), pady=(6, 0))
        self.t_dns = self._text(notes, height=3)
        chars_tab = ttk.Frame(nb, style="Sheet.TFrame")
        nb.add(chars_tab, text="Characters")
        self.char_tree = ttk.Treeview(chars_tab, columns=("label", "pos", "char", "code", "script", "looks", "name"),
                                      show="headings")
        for col, text, width in (("label", "Label", 120), ("pos", "#", 36), ("char", "Char", 50), ("code", "Code point", 90),
                                 ("script", "Script", 100), ("looks", "Looks like", 80), ("name", "Unicode name", 320)):
            self.char_tree.heading(col, text=text, anchor="w")
            self.char_tree.column(col, width=width, anchor="w", stretch=(col == "name"))
        self.char_tree.tag_configure("impostor", foreground=PALETTE["marker"])
        self.char_tree.pack(fill="both", expand=True, padx=2, pady=6)
        self.t_json = self._text_tab(nb, "Raw report", mono=True)

    def _layout_facts(self) -> None:
        """Left column: the link's facts that have a value; right column: always the three host names."""
        left = [k for k in FACTS[:4] if self.fact_vars[k].get() not in ("", "-", "Typed or pasted")]
        for k in FACTS[:4]:
            if k not in left:
                for w in self.fact_cells[k]:
                    w.grid_remove()
        for row, k in enumerate(left):
            name, value = self.fact_cells[k]
            name.grid(row=row, column=0, sticky="w", padx=(0, 14))
            value.grid(row=row, column=1, sticky="w")
        for row, k in enumerate(FACTS[4:]):
            name, value = self.fact_cells[k]
            name.grid(row=row, column=2, sticky="w", padx=(24, 14))
            value.grid(row=row, column=3, sticky="w")

    def _text(self, parent, mono: bool = False, height: int = 10, expand: bool = True) -> tk.Text:
        p = PALETTE
        frame = ttk.Frame(parent, style="Sheet.TFrame")
        frame.pack(fill="both" if expand else "x", expand=expand, padx=2, pady=6)
        t = tk.Text(frame, wrap="word", font=self.f_mono if mono else self.f_body, relief="flat", bg=p["sheet"],
                    fg=p["ink"], padx=12, pady=10, highlightthickness=0, cursor="arrow", height=height)
        sb = ttk.Scrollbar(frame, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set, state="disabled")
        sb.pack(side="right", fill="y")
        t.pack(side="left", fill="both", expand=True)
        t.tag_configure("title", font=self.f_bold)
        t.tag_configure("muted", foreground=p["muted"], lmargin1=86, lmargin2=86, spacing3=8)
        t.tag_configure("good", foreground=VERDICT["no_indicators"][0], font=self.f_bold)
        t.tag_configure("plain", lmargin1=0)
        t.tag_configure("muted_flat", foreground=p["muted"])
        for sev, color in SEVERITY.items():
            t.tag_configure(sev, foreground=color, font=self.f_bold)
        return t

    def _text_tab(self, nb: ttk.Notebook, title: str, mono: bool = False) -> tk.Text:
        tab = ttk.Frame(nb, style="Sheet.TFrame")
        nb.add(tab, text=title)
        return self._text(tab, mono=mono)

    # ------------------------------------------------------------------ input
    def _show_hint(self) -> None:
        if not self.input.get("1.0", "end-1c").strip():
            self.input.delete("1.0", "end")
            self.input.insert("1.0", HINT, "hint")

    def _hide_hint(self) -> None:
        if self.input.tag_ranges("hint"):
            self.input.delete("1.0", "end")

    def _targets(self) -> list[str]:
        if self.input.tag_ranges("hint"):
            return []
        lines = [ln.strip() for ln in self.input.get("1.0", "end").splitlines()]
        return list(dict.fromkeys(ln for ln in lines if ln and not ln.startswith("#")))

    def _dns_toggled(self) -> None:
        state = "normal" if self.var_dns.get() else "disabled"
        self.chk_asn.configure(state=state)
        self.chk_expand.configure(state=state)
        self.chk_tls.configure(state=state)

    def _confirm_tls(self) -> None:
        if self.var_tls.get():
            ok = messagebox.askyesno(
                "Read the TLS certificate?",
                "This makes one TLS handshake with the suspect server on port 443 to read its certificate. "
                "No web page is requested, but the server will see your IP address.\n\nTurn it on?",
                parent=self.root)
            self.var_tls.set(bool(ok))

    def open_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.root, title="Open an email, web page, chat export or list of links",
            filetypes=[("Emails, pages, chats and link lists", "*.eml *.html *.htm *.svg *.txt *.csv *.log"),
                       ("Email message", "*.eml"), ("Web page", "*.html *.htm"), ("Text", "*.txt *.csv *.log"),
                       ("All files", "*")])
        if not path:
            return
        try:
            with open(path, "rb") as fh:
                data = fh.read(MAX_FILE + 1)
        except OSError as exc:
            messagebox.showerror("Could not open file", str(exc), parent=self.root)
            return
        if len(data) > MAX_FILE:
            messagebox.showerror("File too large", "Choose a file smaller than 16 MB.", parent=self.root)
            return
        name = path.replace("\\", "/").rsplit("/", 1)[-1]
        fmt = document_format(name, data)
        if fmt:
            self.check_document(data, fmt, name)
            return
        self._hide_hint()
        self.input.delete("1.0", "end")
        self.input.insert("1.0", data.decode("utf-8", "replace"))

    # ------------------------------------------------------------------ run
    def _mode(self) -> str:
        choice = self.var_mode.get()
        if choice == "Guarded local process" or self.force_local:
            return "local"
        if choice == "Docker sandbox":
            return "docker"
        return "docker" if self.docker_ok else "local"

    def check(self) -> None:
        if self.running:
            return
        targets = self._targets()
        if not targets:
            self._set_status("Paste at least one link, domain or email address first.")
            return
        if len(targets) > MAX_TARGETS:
            messagebox.showerror("Too many links", f"Check at most {MAX_TARGETS} links at a time.", parent=self.root)
            return
        self._launch(targets, f"{len(targets)} link{'s' if len(targets) != 1 else ''}")

    def check_document(self, data: bytes, fmt: str, name: str) -> None:
        """Let the worker find and check every link in an email, page or chat export."""
        if self.running:
            return
        self._launch([], safe_text(name, 80), payload=data, fmt=fmt)

    def _launch(self, targets: list[str], what: str, payload: bytes | None = None, fmt: str | None = None) -> None:
        mode = self._mode()
        if mode == "docker" and not self.docker_ok:
            messagebox.showerror("Docker sandbox unavailable", self.docker_msg, parent=self.root)
            return
        transport = {"DNS over HTTPS": "doh", "DNS over TLS": "dot", "Plain UDP": "udp"}[self.var_transport.get()]
        cfg = WorkerConfig(mode=mode, image=self.image, dns=self.var_dns.get(), asn=self.var_asn.get(),
                           tls_peek=self.var_tls.get() and self.var_dns.get(), transport=transport,
                           expand=self.var_expand.get())
        self.running = True
        self.btn_check.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.progress.start(12)
        where = "the Docker sandbox" if mode == "docker" else "a guarded local process"
        verb = "Scanning" if payload is not None else "Checking"
        self._set_status(f"{verb} {what} in {where}…")
        self.reports.clear()
        self.results.delete(*self.results.get_children())
        threading.Thread(target=self._work, args=(cfg, targets, where, payload, fmt), daemon=True).start()

    def _work(self, cfg: WorkerConfig, targets: list[str], where: str,
              payload: bytes | None = None, fmt: str | None = None) -> None:
        started = time.monotonic()
        try:
            run_batch(cfg, targets, on_report=lambda r: self.events.put(("report", r)), holder=self.holder,
                      payload=payload, input_format=fmt)
            self.events.put(("done", time.monotonic() - started, where))
        except WorkerError as exc:
            self.events.put(("error", str(exc)))
        except Exception as exc:  # noqa: BLE001 - surface anything to the user
            self.events.put(("error", f"{type(exc).__name__}: {exc}"))

    def stop(self) -> None:
        proc = self.holder.get("proc")
        if proc:
            proc.kill()
            self._set_status("Stopped.")

    def _poll(self) -> None:
        try:
            while True:
                kind, *data = self.events.get_nowait()
                if kind == "report":
                    self._add_report(data[0])
                elif kind == "done":
                    n = len(self.reports)
                    risky = sum(r.get("verdict") in ("high_risk", "suspicious") for r in self.reports)
                    note = f", {risky} risky" if risky else ""
                    msg = (f"Checked {n} link{'s' if n != 1 else ''}{note} in {data[1]} ({data[0]:.1f} s). "
                           "No page was opened." if n else "No links or sender addresses were found.")
                    self._finish(msg)
                elif kind == "error":
                    self._finish(f"Check failed: {safe_text(data[0], 300)}")
                elif kind == "docker":
                    self.docker_ok, self.docker_msg = data
                    self.iso_label.configure(text=("Docker sandbox ready" if self.docker_ok and not self.force_local
                                                   else safe_text(self.docker_msg, 160)))
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _finish(self, message: str) -> None:
        self.running = False
        self.progress.stop()
        self.btn_check.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self._set_status(message)

    def _detect_docker(self) -> None:
        self.events.put(("docker", *docker_status(self.image)))

    def _set_status(self, text: str) -> None:
        self.status.configure(text=text)

    # ------------------------------------------------------------------ results
    def _add_report(self, rep: dict) -> None:
        self.reports.append(rep)
        verdict = rep.get("verdict", "error")
        label = VERDICT.get(verdict, VERDICT["error"])[1]
        target = rep.get("defanged") or rep.get("input") or ""
        ctx = rep.get("context") or {}
        if ctx.get("hidden"):
            target = f"[hidden] {target}"
        elif ctx.get("source") == "header":
            target = f"[{ctx.get('where', 'header').replace(' header', '')}] {rep.get('input', '')}"
        iid = str(len(self.reports) - 1)
        self.results.insert("", "end", iid=iid, values=(label, rep.get("score", 0), safe_text(target, 140)),
                            tags=(verdict,))
        if len(self.reports) == 1:
            self.results.selection_set(iid)

    def _selected(self) -> dict | None:
        sel = self.results.selection()
        return self.reports[int(sel[0])] if sel else None

    def _show_selected(self) -> None:
        rep = self._selected()
        if not rep:
            return
        p = PALETTE
        verdict = rep.get("verdict", "error")
        color, label = VERDICT.get(verdict, VERDICT["error"])
        self.v_verdict.configure(text=label, fg=color)
        self.v_score.configure(text=f"{rep.get('score', 0)} / 100")
        self.v_summary.configure(text=safe_text(rep.get("summary") or rep.get("error") or "", 300), fg=p["ink"])
        url = rep.get("url") or {}
        ctx = rep.get("context") or {}
        hops = (rep.get("wrapped") or {}).get("hops") or []
        self.fact_vars["Found"].set(safe_text(describe_context(ctx), 160) if ctx else "Typed or pasted")
        self.fact_vars["Link text"].set(safe_text(ctx.get("text") or "-", 160))
        short = rep.get("short_link") or {}
        self.fact_vars["Rewritten by"].set(safe_text(" → ".join(
            f"{h['vendor']} ad network (it picks the destination when clicked)" if h.get("kind") == "advert"
            else h["service"] + ("" if h.get("trusted") else f" on {h['host']} (unverified)") for h in hops)
            or (f"{short['service']} short link - where it leads is not known" if short else "-"), 200))
        self.fact_vars["Defanged"].set(safe_text(rep.get("defanged") or "-", 160))
        self.fact_vars["Displays as"].set(safe_text(url.get("host_unicode") or "-", 160))
        self.fact_vars["DNS name"].set(safe_text(url.get("host_ascii") or "-", 160))
        self.fact_vars["Registrable domain"].set(safe_text(url.get("registrable") or "-", 160))
        self._layout_facts()
        self._draw_glyphs(rep)
        self.root.after_idle(self._place_overview)  # the hostname strip may have changed height
        self._fill_findings(rep)
        self._fill_dns(rep)
        self._fill_chars(rep)
        self._fill_text(self.t_json, [(safe_text(json.dumps(rep, indent=2, ensure_ascii=False), 400000), "plain")])

    def _draw_glyphs(self, rep: dict) -> None:
        c, p = self.canvas, PALETTE
        c.delete("all")
        labels = rep.get("labels") or []
        if not labels:
            what = (rep.get("url") or {}).get("host_ascii") or (rep.get("url") or {}).get("scheme") or ""
            msg = (f"No hostname letters to inspect ({safe_text(what, 60)})." if what
                   else "No hostname letters to inspect.")
            c.create_text(18, 40, text=msg, anchor="w", font=self.f_body, fill=p["muted"])
            c.configure(scrollregion=(0, 0, 400, 76), height=80)
            return
        x, base = 18, 44
        for li, lb in enumerate(labels):
            info = {ch["position"]: ch for ch in lb.get("chars") or []}
            for pos, ch in enumerate(lb.get("unicode", ""), 1):
                ci = info.get(pos) or {}
                impostor = bool(ci.get("odd_script") or ci.get("lookalike_kind") == "confusable")
                accent = bool(ci) and not impostor and bool(ci.get("looks_like"))
                shown = safe_text(ch, 12)
                width = max(self.f_glyph.measure(shown), 14)
                cell = width + 10
                captions = []
                if impostor or accent:
                    captions = [ci.get("codepoint", ""), ci.get("script", "")]
                    cell = max(cell, max(self.f_code.measure(t) for t in captions) + 10)
                cx = x + cell / 2
                if impostor:
                    c.create_rectangle(x + 2, 6, x + cell - 2, base + 26, fill=p["marker_soft"], outline="")
                    c.create_rectangle(x + 2, base + 23, x + cell - 2, base + 27, fill=p["marker"], outline="")
                fg = p["marker"] if impostor else p["ink"]
                c.create_text(cx, base, text=shown, font=self.f_glyph, fill=fg)
                for row, cap in enumerate(captions):
                    c.create_text(cx, base + 37 + row * 13, text=cap, font=self.f_code, tags=("caption",),
                                  fill=p["marker"] if impostor else p["muted"])
                x += cell
            if li < len(labels) - 1:
                c.create_text(x + 6, base, text=".", font=self.f_glyph, fill=p["faint"])
                x += 16
        tall = bool(c.find_withtag("caption"))  # code point and script under impostor letters
        c.configure(scrollregion=(0, 0, x + 18, 102 if tall else 76), height=104 if tall else 80)
        c.xview_moveto(0)

    def _fill_text(self, widget: tk.Text, parts: list[tuple[str, str]]) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        for text, tag in parts:
            widget.insert("end", text, tag)
        widget.configure(state="disabled")

    def _fill_findings(self, rep: dict) -> None:
        findings = sorted(rep.get("findings") or [], key=lambda f: -abs(f.get("weight", 0)))
        parts: list[tuple[str, str]] = []
        if rep.get("error"):
            parts.append((safe_text(rep["error"], 300) + "\n", "high"))
        if not findings:
            parts.append(("Nothing deceptive was found in this link's text.\n", "plain"))
        for f in findings:
            w = int(f.get("weight", 0))
            sev = f.get("severity", "info")
            tag = "good" if w < 0 else sev
            label = f"{sev.capitalize():<9}{w:+d} " if w else f"{sev.capitalize():<9}   "
            parts.append((f"{label:<14}", tag))
            parts.append((safe_text(f.get("title"), 200) + "\n", "title"))
            if f.get("detail"):
                parts.append((safe_text(f["detail"], 800) + "\n", "muted"))
        self._fill_text(self.t_findings, parts)

    def _fill_dns(self, rep: dict) -> None:
        self.dns_tree.delete(*self.dns_tree.get_children())
        dns = rep.get("dns")
        lines: list[tuple[str, str]] = []
        if not dns:
            lines.append(("DNS comparison was off for this check, or the link has no hostname.\n", "plain"))
        elif dns.get("resolvers"):
            asn = dns.get("asn") or {}
            for r in dns["resolvers"]:
                a = r.get("a") or {}
                ips = a.get("addresses") or []
                if a.get("error"):
                    answer, status, tag = "-", "No answer", "failed"
                else:
                    answer = ", ".join(ips[:3]) + (f" (+{len(ips) - 3})" if len(ips) > 3 else "") or "-"
                    status, tag = (a.get("rcode") or "?"), ""
                    if r.get("blocked"):
                        status, tag = "Blocked", "blocked"
                first = next((ip for ip in ips if ip in asn), None)
                net = f"AS{asn[first]['asn']} {asn[first].get('as_name', '')}" if first else ""
                self.dns_tree.insert("", "end", values=(safe_text(r.get("name"), 60), "Yes" if r.get("filtering") else "No",
                                                        safe_text(answer, 120), status, safe_text(net, 80)),
                                     tags=(tag,) if tag else ())
            consensus = {
                "identical": "All unfiltered resolvers agree on the same addresses.",
                "overlapping": "The unfiltered resolvers share some addresses.",
                "different-ips-same-network": "Addresses differ but sit on the same network (normal for CDNs).",
                "disagree": "The resolvers disagree about which network hosts this domain.",
                "nxdomain": "The domain does not exist in DNS right now.",
                "single": "Only one unfiltered resolver answered.",
            }.get(dns.get("consensus"), "Not enough answers to compare.")
            lines.append((consensus + "\n", "title"))
            for r in dns["resolvers"]:
                if r.get("blocked"):
                    lines.append((f"{safe_text(r['name'], 60)} blocks it: {safe_text(r.get('block_reason'), 120)}\n", "high"))
            b = dns.get("brand")
            if b:
                relation = {
                    "same-ip": "uses the same IP address as",
                    "same-subnet": "is in the same network block as",
                    "same-prefix": "is inside the announced network of",
                    "same-network": "is on the same network as",
                    "shared-provider": "shares only a public hosting provider with",
                    "different-network": "is hosted on a different network from",
                    "suspect-does-not-resolve": "does not resolve, so it cannot be compared with",
                    "brand-did-not-resolve": "could not be compared with",
                }.get(b.get("relation"), "was compared with")
                regions = f" (compared from {b['regions_checked']} regions)" if b.get("regions_checked") else ""
                lines.append((f"This domain {relation} the real {safe_text(b.get('domain'), 80)}{regions}.\n", "plain"))
            if dns.get("ns"):
                lines.append(("Nameservers: " + safe_text(", ".join(dns["ns"][:4]), 300) + "\n", "plain"))
            if dns.get("mx") is not None:
                lines.append(("Mail servers: " + (safe_text(", ".join(dns["mx"][:3]), 300) or "none") + "\n", "plain"))
            for w in dns.get("warnings") or []:
                lines.append((safe_text(w, 400) + "\n", "medium"))
            errors = sorted({(r.get("a") or {}).get("error") for r in dns["resolvers"]} - {None})
            if errors and not dns.get("warnings"):
                lines.append(("Some resolvers did not answer: " + safe_text("; ".join(errors), 400) + "\n", "muted_flat"))
        elif dns.get("asn"):
            for ip, info in dns["asn"].items():
                lines.append((f"{ip}: AS{info['asn']} {safe_text(info.get('as_name'), 60)} ({info.get('country', '')})\n", "plain"))
        self._fill_text(self.t_dns, lines)

    def _fill_chars(self, rep: dict) -> None:
        self.char_tree.delete(*self.char_tree.get_children())
        for lb in rep.get("labels") or []:
            for ch in lb.get("chars") or []:
                impostor = ch.get("odd_script") or ch.get("lookalike_kind") == "confusable"
                self.char_tree.insert("", "end", values=(
                    safe_text(lb.get("unicode"), 40), ch.get("position"), safe_text(ch.get("char"), 12),
                    ch.get("codepoint"), ch.get("script"), safe_text(ch.get("looks_like") or "", 10),
                    safe_text(ch.get("name"), 80)), tags=("impostor",) if impostor else ())

    # ------------------------------------------------------------------ actions
    def open_lists(self) -> None:
        from .lists import ListsWindow

        try:
            ListsWindow(self.root)
        except Exception as exc:  # noqa: BLE001 - e.g. the database is locked by an update
            messagebox.showerror("Could not open the lists", str(exc), parent=self.root)

    def report_selected(self) -> None:
        rep = self._selected()
        target = ((rep or {}).get("wrapped") or {}).get("destination") or (rep or {}).get("input")
        if not target:
            self._set_status("Select a checked link first.")
            return
        from .lists import open_db

        db = open_db()
        try:
            url = db.report(str(target))
        except ValueError as exc:
            self._set_status(f"Not reported: {safe_text(str(exc), 200)}")
            return
        finally:
            db.close()
        self._set_status(f"Reported {safe_text(url, 160)} as phishing. It stays blocked on this device and in the browser extension.")

    def copy_defanged(self) -> None:
        rep = self._selected()
        if not rep or not rep.get("defanged"):
            self._set_status("Select a checked link first.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(safe_text(rep["defanged"], 2000))
        self._set_status("Copied the defanged link. It will not open if clicked.")

    def export(self) -> None:
        if not self.reports:
            self._set_status("There is nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(parent=self.root, title="Export report", defaultextension=".json",
                                            filetypes=[("JSON report", "*.json")], initialfile="homograph-report.json")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(self.reports, fh, ensure_ascii=True, indent=2)
        except OSError as exc:
            messagebox.showerror("Could not save the report", str(exc), parent=self.root)
            return
        self._set_status(f"Saved {len(self.reports)} report{'s' if len(self.reports) != 1 else ''} to {path}.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="homograph-guard-gui", description="Desktop GUI for homograph-guard")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="Docker image to run checks in")
    parser.add_argument("--local", action="store_true", help="never use Docker; use the guarded local process")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)
            # Its own taskbar entry and icon, even when started through python.exe
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("HomographGuard.App")
        except (AttributeError, OSError):
            pass
    root = tk.Tk()
    App(root, image=args.image, force_local=args.local)
    root.mainloop()
    return 0
