"""Reusable, themed widgets built for legibility."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class ScrollFrame(ttk.Frame):
    """A frame with a hairline border, used to separate panels visually."""

    def __init__(self, master, theme, **kw):
        super().__init__(master, style="Border.TFrame", padding=1, **kw)
        self.theme = theme
        self.inner = ttk.Frame(self, style="Panel.TFrame")
        self.inner.pack(fill="both", expand=True)


class SortableTree(ttk.Frame):
    """Treeview + scrollbars, zebra striping, click-to-sort headings."""

    def __init__(self, master, theme, columns, mono=False, height=12, on_select=None,
                 on_activate=None):
        super().__init__(master, style="Border.TFrame", padding=1)
        self.theme = theme
        self.columns = columns
        self._sort_col = None
        self._sort_desc = False
        self._on_select = on_select

        ids = [c[0] for c in columns]
        self.tree = ttk.Treeview(self, columns=ids, show="headings", height=height,
                                 style="Mono.Treeview" if mono else "Treeview",
                                 selectmode="browse")
        for cid, text, width, anchor, stretch in columns:
            self.tree.heading(cid, text=text, anchor="w",
                              command=lambda c=cid: self.sort_by(c))
            self.tree.column(cid, width=width, anchor=anchor, stretch=stretch,
                             minwidth=max(40, width // 3))
        vs = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        hs = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        if on_select:
            self.tree.bind("<<TreeviewSelect>>", lambda e: on_select(self.selected()))
        if on_activate:
            self.tree.bind("<Double-1>", lambda e: on_activate(self.selected()))
            self.tree.bind("<Return>", lambda e: on_activate(self.selected()))
        self.restyle()

    # -- data ---------------------------------------------------------------

    def clear(self):
        self.tree.delete(*self.tree.get_children())

    def add(self, values, tags=(), iid=None):
        n = len(self.tree.get_children())
        tags = tuple(tags) + ("odd" if n % 2 else "even",)
        return self.tree.insert("", "end", iid=iid, values=values, tags=tags)

    def selected(self):
        sel = self.tree.selection()
        return sel[0] if sel else None

    def select_iid(self, iid):
        if iid and self.tree.exists(iid):
            self.tree.selection_set(iid)
            self.tree.focus(iid)
            self.tree.see(iid)

    def restripe(self):
        for i, iid in enumerate(self.tree.get_children()):
            tags = [t for t in self.tree.item(iid, "tags") if t not in ("odd", "even")]
            tags.append("odd" if i % 2 else "even")
            self.tree.item(iid, tags=tags)

    # -- sorting ------------------------------------------------------------

    def sort_by(self, col):
        desc = not self._sort_desc if self._sort_col == col else False
        self._sort_col, self._sort_desc = col, desc
        rows = [(self.tree.set(iid, col), iid) for iid in self.tree.get_children()]

        def key(item):
            v = item[0]
            try:
                return (0, float(str(v).replace(",", "").replace("%", "")
                                 .replace(" ms", "").replace(" s", "").strip() or 0))
            except ValueError:
                return (1, str(v).lower())
        rows.sort(key=key, reverse=desc)
        for i, (_v, iid) in enumerate(rows):
            self.tree.move(iid, "", i)
        self.restripe()
        for cid, text, *_ in self.columns:
            arrow = "  ▾" if (cid == col and desc) else ("  ▴" if cid == col else "")
            self.tree.heading(cid, text=text + arrow)

    # -- theme --------------------------------------------------------------

    def restyle(self):
        c = self.theme.c
        self.tree.tag_configure("even", background=c["panel"], foreground=c["text"])
        self.tree.tag_configure("odd", background=c["row_alt"], foreground=c["text"])
        for name in ("blue", "green", "amber", "red", "purple", "cyan", "pink", "grey"):
            self.tree.tag_configure("fg_" + name, foreground=c[name])
        self.tree.tag_configure("bold", font=self.theme.font("ui_bold"))
        self.tree.tag_configure("dim", foreground=c["text_dim"])


class TextPane(ttk.Frame):
    """Read-only, monospace text area with tags and a scrollbar."""

    def __init__(self, master, theme, mono=True, wrap="none", padding=14, height=10):
        super().__init__(master, style="Border.TFrame", padding=1)
        self.theme = theme
        self.mono = mono
        c = theme.c
        self.text = tk.Text(self, wrap=wrap, height=height, relief="flat", bd=0,
                            padx=padding, pady=padding - 2,
                            background=c["panel"], foreground=c["text"],
                            insertbackground=c["text"],
                            selectbackground=c["sel"], selectforeground=c["sel_text"],
                            font=theme.font("mono" if mono else "ui"),
                            highlightthickness=0, spacing1=1, spacing3=3,
                            inactiveselectbackground=c["sel"])
        vs = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=vs.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        if wrap == "none":
            hs = ttk.Scrollbar(self, orient="horizontal", command=self.text.xview)
            self.text.configure(xscrollcommand=hs.set)
            hs.grid(row=1, column=0, sticky="ew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.text.bind("<Key>", self._readonly)
        self.restyle()

    @staticmethod
    def _readonly(event):
        allowed = ("c", "a", "Left", "Right", "Up", "Down", "Prior", "Next",
                   "Home", "End")
        if event.state & 0x0008 or event.state & 0x0004:      # Cmd / Ctrl
            return None
        if event.keysym in allowed:
            return None
        return "break"

    def set(self, content, tag=None):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        if content:
            self.text.insert("1.0", content, tag or ())
        self.text.see("1.0")

    def append(self, content, tag=None):
        self.text.insert("end", content, tag or ())

    def clear(self):
        self.text.delete("1.0", "end")

    def restyle(self):
        c = self.theme.c
        self.text.configure(background=c["panel"], foreground=c["text"],
                            selectbackground=c["sel"], selectforeground=c["sel_text"],
                            insertbackground=c["text"],
                            font=self.theme.font("mono" if self.mono else "ui"))
        for name in ("blue", "green", "amber", "red", "purple", "cyan", "pink", "grey"):
            self.text.tag_configure(name, foreground=c[name])
        self.text.tag_configure("dim", foreground=c["text_dim"])
        self.text.tag_configure("faint", foreground=c["text_faint"])
        self.text.tag_configure("bold", font=self.theme.font(
            "mono_bold" if self.mono else "ui_bold"))
        self.text.tag_configure("h2", font=self.theme.font("h2"), spacing1=10, spacing3=8)
        self.text.tag_configure("h3", font=self.theme.font("h3"), spacing1=8, spacing3=4)
        self.text.tag_configure("hl", background=c["sel"], foreground=c["sel_text"])
        self.text.tag_configure("mark", background=c["amber"], foreground="#12151a")
        self.text.tag_configure("client", foreground=c["blue"])
        self.text.tag_configure("server", foreground=c["green"])


class HexView(TextPane):
    """Classic offset / hex / ASCII dump with optional highlighted range."""

    def show(self, data, highlight=None, max_bytes=65536):
        self.text.configure(state="normal")
        self.clear()
        if not data:
            self.text.insert("1.0", "  (no bytes)", ("dim",))
            return
        blob = data[:max_bytes]
        hs, he = highlight if highlight else (-1, -1)
        lines = []
        for off in range(0, len(blob), 16):
            chunk = blob[off:off + 16]
            hexpart = " ".join("%02x" % b for b in chunk[:8])
            hexpart2 = " ".join("%02x" % b for b in chunk[8:])
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "·" for b in chunk)
            lines.append(("%08x" % off, "%-23s  %-23s" % (hexpart, hexpart2), ascii_part))
        for off_s, hex_s, asc_s in lines:
            self.text.insert("end", off_s + "  ", ("faint",))
            self.text.insert("end", hex_s + "  ", ())
            self.text.insert("end", "│" + asc_s + "\n", ("dim",))
        if hs >= 0 and he > hs:
            self._highlight_range(hs, min(he, len(blob)))
        if len(data) > max_bytes:
            self.text.insert("end", "\n  … %d more bytes not shown\n" % (len(data) - max_bytes),
                             ("dim",))

    def _highlight_range(self, start, end):
        for byte in range(start, end):
            row = byte // 16 + 1
            col = byte % 16
            hex_col = 10 + col * 3 + (2 if col >= 8 else 0)
            self.text.tag_add("hl", "%d.%d" % (row, hex_col), "%d.%d" % (row, hex_col + 2))
            asc_col = 10 + 48 + 3 + col
            self.text.tag_add("hl", "%d.%d" % (row, asc_col), "%d.%d" % (row, asc_col + 1))


class StatCard(ttk.Frame):
    """Big number + caption. Value colour carries meaning; caption always present."""

    def __init__(self, master, theme, caption, value="—", accent=None, width=0):
        super().__init__(master, style="Border.TFrame", padding=1)
        self.theme = theme
        self.accent = accent
        box = ttk.Frame(self, style="Panel.TFrame", padding=(16, 13, 16, 14))
        box.pack(fill="both", expand=True)
        self.caption = ttk.Label(box, text=caption.upper(), style="PanelDim.TLabel")
        self.caption.pack(anchor="w")
        self.value = ttk.Label(box, text=value, style="Stat.TLabel")
        self.value.pack(anchor="w", pady=(4, 0))
        if width:
            box.configure(width=width)
        self.restyle()

    def set(self, value, accent=None):
        self.value.configure(text=str(value))
        if accent is not None:
            self.accent = accent
        self.restyle()

    def restyle(self):
        c = self.theme.c
        self.value.configure(foreground=c[self.accent] if self.accent else c["text"],
                             font=self.theme.font("h2"), background=c["panel"])
        self.caption.configure(foreground=c["text_dim"], font=self.theme.font("small_bold"),
                               background=c["panel"])


class BarChart(ttk.Frame):
    """Horizontal labelled bars — readable at a glance, no legend needed."""

    def __init__(self, master, theme, title="", height=200):
        super().__init__(master, style="Border.TFrame", padding=1)
        self.theme = theme
        self.title = title
        self.rows = []
        box = ttk.Frame(self, style="Panel.TFrame", padding=(16, 14))
        box.pack(fill="both", expand=True)
        if title:
            self.heading = ttk.Label(box, text=title.upper(), style="H3.TLabel")
            self.heading.pack(anchor="w", pady=(0, 10))
        else:
            self.heading = None
        self.canvas = tk.Canvas(box, height=height, highlightthickness=0, bd=0,
                                background=theme.c["panel"])
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>", lambda e: self.redraw())

    def set_rows(self, rows):
        """rows: list of (label, value, display_value, accent_key)."""
        self.rows = rows
        self.redraw()

    def redraw(self):
        c = self.theme.c
        cv = self.canvas
        cv.delete("all")
        cv.configure(background=c["panel"])
        if self.heading:
            self.heading.configure(foreground=c["text_dim"], font=self.theme.font("h3"))
        if not self.rows:
            cv.create_text(12, 16, text="no data", anchor="w", fill=c["text_dim"],
                           font=self.theme.font("ui"))
            return
        w = cv.winfo_width() or 400
        fnt = self.theme.font("ui")
        fnt_s = self.theme.font("small")
        label_w = min(190, max(90, max(fnt.measure(r[0]) for r in self.rows) + 16))
        val_w = max(fnt_s.measure(str(r[2])) for r in self.rows) + 14
        bar_x = label_w + 8
        bar_w = max(40, w - bar_x - val_w - 8)
        top = 4
        row_h = self.theme.size(13) + 16
        peak = max((r[1] for r in self.rows), default=1) or 1
        for i, (label, value, disp, accent) in enumerate(self.rows):
            y = top + i * row_h
            cy = y + row_h / 2 - 1
            cv.create_text(4, cy, text=label, anchor="w", fill=c["text"], font=fnt)
            cv.create_rectangle(bar_x, y + 4, bar_x + bar_w, y + row_h - 8,
                                fill=c["raised"], outline="")
            length = max(3, bar_w * (value / peak))
            cv.create_rectangle(bar_x, y + 4, bar_x + length, y + row_h - 8,
                                fill=c[accent], outline="")
            cv.create_text(bar_x + bar_w + 8, cy, text=str(disp), anchor="w",
                           fill=c["text_dim"], font=fnt_s)
        cv.configure(height=int(top * 2 + row_h * len(self.rows)))


class Timeline(ttk.Frame):
    """Packets-over-time column chart with time axis labels."""

    def __init__(self, master, theme, height=150):
        super().__init__(master, style="Border.TFrame", padding=1)
        self.theme = theme
        self.data = []
        self.start = 0.0
        self.duration = 0.0
        box = ttk.Frame(self, style="Panel.TFrame", padding=(16, 14))
        box.pack(fill="both", expand=True)
        self.heading = ttk.Label(box, text="TRAFFIC OVER TIME", style="H3.TLabel")
        self.heading.pack(anchor="w", pady=(0, 10))
        self.canvas = tk.Canvas(box, height=height, highlightthickness=0, bd=0,
                                background=theme.c["panel"])
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>", lambda e: self.redraw())

    def set_data(self, timeline, start, duration):
        self.data = timeline
        self.start = start
        self.duration = duration
        self.redraw()

    def redraw(self):
        c = self.theme.c
        cv = self.canvas
        cv.delete("all")
        cv.configure(background=c["panel"])
        self.heading.configure(foreground=c["text_dim"], font=self.theme.font("h3"))
        if not self.data:
            return
        w = cv.winfo_width() or 600
        h = (cv.winfo_height() or 150) - 22
        peak = max((d[1] for d in self.data), default=1) or 1
        n = len(self.data)
        gap = 2
        bw = max(2.0, (w - gap * (n - 1)) / n)
        # baseline + gridlines
        for frac in (0.5, 1.0):
            y = h - h * frac + 4
            cv.create_line(0, y, w, y, fill=c["border_soft"])
            cv.create_text(2, y - 8, text="%d" % int(peak * frac), anchor="w",
                           fill=c["text_faint"], font=self.theme.font("small"))
        for i, (_ts, count, _b) in enumerate(self.data):
            x = i * (bw + gap)
            bh = (count / peak) * h
            cv.create_rectangle(x, h - bh + 4, x + bw, h + 4,
                                fill=c["blue"] if count else c["border_soft"], outline="")
        cv.create_line(0, h + 4, w, h + 4, fill=c["border"])
        fnt = self.theme.font("small")
        cv.create_text(0, h + 14, text="0 s", anchor="nw", fill=c["text_dim"], font=fnt)
        cv.create_text(w, h + 14, text="%.2f s" % self.duration, anchor="ne",
                       fill=c["text_dim"], font=fnt)


class Banner(ttk.Frame):
    """Loud, colour-coded verdict strip: the headline answer of the analysis."""

    def __init__(self, master, theme):
        super().__init__(master, style="Border.TFrame", padding=1)
        self.theme = theme
        self.accent = "grey"
        self.box = tk.Frame(self, bd=0, highlightthickness=0)
        self.box.pack(fill="both", expand=True)
        self.stripe = tk.Frame(self.box, width=6, bd=0, highlightthickness=0)
        self.stripe.pack(side="left", fill="y")
        inner = tk.Frame(self.box, bd=0, highlightthickness=0)
        inner.pack(side="left", fill="both", expand=True, padx=18, pady=14)
        self.inner = inner
        self.head = tk.Label(inner, text="NO FILE LOADED", anchor="w", bd=0)
        self.head.pack(anchor="w")
        self.body = tk.Label(inner, text="Open a capture to begin.", anchor="w",
                             justify="left", bd=0)
        self.body.pack(anchor="w", pady=(3, 0))
        self.restyle()

    def set(self, head, body, level):
        self.accent = {"critical": "red", "high": "amber", "medium": "blue",
                       "low": "green", "info": "grey"}.get(level, "grey")
        self.head.configure(text=head)
        self.body.configure(text=body)
        self.restyle()

    def restyle(self):
        c = self.theme.c
        acc = c[self.accent]
        self.box.configure(background=c["panel"])
        self.inner.configure(background=c["panel"])
        self.stripe.configure(background=acc)
        self.head.configure(background=c["panel"], foreground=acc,
                            font=self.theme.font("h2"))
        self.body.configure(background=c["panel"], foreground=c["text"],
                            font=self.theme.font("ui"),
                            wraplength=max(400, self.winfo_width() - 80))
