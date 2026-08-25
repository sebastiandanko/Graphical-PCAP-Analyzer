"""PCAP Analyzer — desktop GUI (Tkinter/ttk).

Native window, no browser and no web view anywhere in the stack.
"""

from __future__ import annotations

import datetime as _dt
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import detect, session
from .dissect import PORT_SERVICES
from .reader import CaptureError, linktype_name
from .theme import SEVERITY_LABEL, Theme
from .widgets import (Banner, BarChart, HexView, SortableTree, StatCard, TextPane,
                      Timeline)

APP_NAME = "PCAP Analyzer"
MAX_ROWS = 20000              # packet rows rendered at once


def human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%.0f %s" if unit == "B" else "%.1f %s") % (n, unit)
        n /= 1024.0
    return "%d B" % n


def human_num(n):
    return "{:,}".format(int(n))


def human_rate(bps):
    for unit in ("bit/s", "kbit/s", "Mbit/s", "Gbit/s"):
        if bps < 1000 or unit == "Gbit/s":
            return "%.1f %s" % (bps, unit)
        bps /= 1000.0
    return "%.0f bit/s" % bps


# ===========================================================================
# tabs
# ===========================================================================

class Tab(ttk.Frame):
    def __init__(self, app):
        super().__init__(app.notebook, style="TFrame", padding=(16, 14))
        self.app = app
        self.theme = app.theme
        self.analysis = None
        self.build()

    def build(self):
        pass

    def load(self, analysis):
        self.analysis = analysis

    def restyle(self):
        for child in self.walk():
            if hasattr(child, "restyle"):
                child.restyle()

    def walk(self, node=None):
        node = node or self
        for ch in node.winfo_children():
            yield ch
            yield from self.walk(ch)


# --------------------------------------------------------------------------
# Overview
# --------------------------------------------------------------------------

class OverviewTab(Tab):
    def build(self):
        self.cards = {}
        card_row = ttk.Frame(self, style="TFrame")
        card_row.pack(fill="x", pady=(0, 14))
        specs = [("packets", "Packets", None), ("bytes", "Total bytes", None),
                 ("duration", "Duration", None), ("rate", "Average rate", None),
                 ("hosts", "Hosts", "blue"), ("convs", "Conversations", "blue"),
                 ("findings", "Findings", "amber")]
        for i, (key, cap, accent) in enumerate(specs):
            card = StatCard(card_row, self.theme, cap, "—", accent)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            card_row.grid_columnconfigure(i, weight=1, uniform="cards")
            self.cards[key] = card

        self.timeline = Timeline(self, self.theme, height=140)
        self.timeline.pack(fill="x", pady=(0, 14))

        charts = ttk.Frame(self, style="TFrame")
        charts.pack(fill="both", expand=True)
        self.proto_chart = BarChart(charts, self.theme, "Protocols by packet count")
        self.talker_chart = BarChart(charts, self.theme, "Top talkers by bytes")
        self.port_chart = BarChart(charts, self.theme, "Top destination ports")
        for i, ch in enumerate((self.proto_chart, self.talker_chart, self.port_chart)):
            ch.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            charts.grid_columnconfigure(i, weight=1, uniform="charts")
        charts.grid_rowconfigure(0, weight=1)

        self.meta = TextPane(self, self.theme, mono=True, wrap="word", height=7)
        self.meta.pack(fill="x", pady=(14, 0))

    def load(self, an):
        self.analysis = an
        st = an.stats
        self.cards["packets"].set(human_num(st.packets))
        self.cards["bytes"].set(human_size(st.bytes))
        self.cards["duration"].set("%.2f s" % st.duration if st.duration < 120
                                   else "%.1f min" % (st.duration / 60))
        self.cards["rate"].set(human_rate(st.avg_bps))
        self.cards["hosts"].set(human_num(len(st.endpoints)))
        self.cards["convs"].set(human_num(len(an.conversations)))
        crit = sum(1 for f in an.findings if f.severity in ("critical", "high"))
        self.cards["findings"].set("%d / %d" % (crit, len(an.findings)),
                                   "red" if crit else "green")

        self.timeline.set_data(st.timeline, st.start, st.duration)

        rows = []
        for proto, count in st.protocols.most_common(9):
            rows.append((proto, count, human_num(count), self.theme_key(proto)))
        self.proto_chart.set_rows(rows)

        rows = []
        for (src, dst), byts in st.talkers.most_common(9):
            rows.append(("%s → %s" % (_trim(src), _trim(dst)), byts, human_size(byts), "cyan"))
        self.talker_chart.set_rows(rows)

        rows = []
        for port, count in st.ports.most_common(9):
            svc = PORT_SERVICES.get(port, "")
            label = "%d %s" % (port, ("(%s)" % svc) if svc else "")
            rows.append((label.strip(), count, human_num(count), "purple"))
        self.port_chart.set_rows(rows)

        m = an.meta
        start = _dt.datetime.fromtimestamp(st.start) if st.start else None
        lines = [
            "File            %s" % an.path,
            "Format          %s %s, %s-endian, %s timestamps" % (
                m["format"], m["version"], m["endian"], m["resolution"]),
            "Link layer      %s" % ", ".join(sorted(linktype_name(l) for l in m["linktypes"])),
            "Snapshot length %s" % (human_num(m["snaplen"]) + " bytes" if m["snaplen"] else "unset"),
            "On disk         %s" % human_size(m["filesize"]),
            "First packet    %s" % (start.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if start else "—"),
            "IPv4 / IPv6     %s / %s      TCP %s · UDP %s · other %s" % (
                human_num(st.ipv4), human_num(st.ipv6), human_num(st.tcp),
                human_num(st.udp), human_num(st.other)),
        ]
        self.meta.set("\n".join(lines))
        self.meta.text.tag_add("dim", "1.0", "end")

    @staticmethod
    def theme_key(proto):
        from .theme import PROTO_COLOR
        return PROTO_COLOR.get(proto, "grey")


def _trim(s, n=17):
    return s if len(s) <= n else s[:n - 1] + "…"


# --------------------------------------------------------------------------
# Findings (the "scan" answer)
# --------------------------------------------------------------------------

class FindingsTab(Tab):
    def build(self):
        head = ttk.Frame(self, style="TFrame")
        head.pack(fill="x", pady=(0, 12))
        ttk.Label(head, text="Detected activity", style="H2.TLabel").pack(side="left")
        self.count_lbl = ttk.Label(head, text="", style="Dim.TLabel")
        self.count_lbl.pack(side="left", padx=(12, 0))

        self.filter_var = tk.StringVar(value="All severities")
        box = ttk.Combobox(head, textvariable=self.filter_var, state="readonly", width=18,
                           values=["All severities", "Critical only", "Critical + High",
                                   "Scans only", "Flags only"])
        box.pack(side="right")
        box.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        ttk.Label(head, text="Show:", style="Dim.TLabel").pack(side="right", padx=(0, 8))

        pane = ttk.PanedWindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True)

        self.tree = SortableTree(
            pane, self.theme,
            [("sev", "Severity", 110, "w", False),
             ("cat", "Category", 150, "w", False),
             ("title", "Finding", 520, "w", True),
             ("count", "Packets", 90, "e", False)],
            height=18, on_select=self.on_select)
        pane.add(self.tree, weight=3)

        right = ttk.Frame(pane, style="TFrame", padding=(12, 0, 0, 0))
        pane.add(right, weight=2)
        self.detail = TextPane(right, self.theme, mono=False, wrap="word", height=18)
        self.detail.pack(fill="both", expand=True)
        btns = ttk.Frame(right, style="TFrame")
        btns.pack(fill="x", pady=(10, 0))
        self.btn_pkt = ttk.Button(btns, text="Show packets", command=self.goto_packets,
                                  style="Accent.TButton", state="disabled")
        self.btn_pkt.pack(side="left")
        self.btn_stream = ttk.Button(btns, text="Follow stream", command=self.goto_stream,
                                     state="disabled")
        self.btn_stream.pack(side="left", padx=(8, 0))
        self._rows = []

    def load(self, an):
        self.analysis = an
        self.refresh()

    def refresh(self):
        if not self.analysis:
            return
        mode = self.filter_var.get()
        findings = self.analysis.findings
        if mode == "Critical only":
            findings = [f for f in findings if f.severity == "critical"]
        elif mode == "Critical + High":
            findings = [f for f in findings if f.severity in ("critical", "high")]
        elif mode == "Scans only":
            findings = [f for f in findings
                        if f.category in ("Port scan", "Network sweep", "Recon")]
        elif mode == "Flags only":
            findings = [f for f in findings if f.category == "Flag"]
        self._rows = findings
        self.tree.clear()
        for i, f in enumerate(findings):
            self.tree.add((SEVERITY_LABEL.get(f.severity, f.severity.upper()),
                           f.category, f.title, len(f.packets) or "—"),
                          tags=("fg_" + self._sev_key(f.severity), "bold"), iid=str(i))
        total = len(self.analysis.findings)
        crit = sum(1 for f in self.analysis.findings if f.severity == "critical")
        self.count_lbl.configure(text="%d shown · %d total · %d critical" %
                                      (len(findings), total, crit))
        if findings:
            self.tree.select_iid("0")
            self.on_select("0")
        else:
            self.detail.set("Nothing matched this filter.\n")
            self.btn_pkt.configure(state="disabled")
            self.btn_stream.configure(state="disabled")

    @staticmethod
    def _sev_key(sev):
        from .theme import SEVERITY_COLOR
        return SEVERITY_COLOR.get(sev, "grey")

    def current(self):
        iid = self.tree.selected()
        if iid is None or not self._rows:
            return None
        try:
            return self._rows[int(iid)]
        except (ValueError, IndexError):
            return None

    def on_select(self, iid):
        f = self.current()
        if not f:
            return
        t = self.detail
        t.clear()
        t.append(SEVERITY_LABEL.get(f.severity, "") + "   " + f.category + "\n",
                 (self._sev_key(f.severity), "bold"))
        t.append(f.title + "\n\n", ("h2",))
        t.append(f.detail + "\n", ())
        if f.evidence:
            t.append("\nEvidence\n", ("h3",))
            t.append(f.evidence + "\n", ("amber",))
        if f.packets:
            t.append("\nPackets\n", ("h3",))
            nums = ", ".join(str(n) for n in f.packets[:40])
            if len(f.packets) > 40:
                nums += "  … (+%d more)" % (len(f.packets) - 40)
            t.append(nums + "\n", ("dim",))
        self.btn_pkt.configure(state="normal" if f.packets else "disabled")
        self.btn_stream.configure(state="normal" if f.stream_id >= 0 else "disabled")

    def goto_packets(self):
        f = self.current()
        if f and f.packets:
            self.app.show_packets(f.packets, "finding: " + f.title)

    def goto_stream(self):
        f = self.current()
        if f and f.stream_id >= 0:
            self.app.follow_stream(f.stream_id)


# --------------------------------------------------------------------------
# Packets
# --------------------------------------------------------------------------

class PacketsTab(Tab):
    def build(self):
        bar = ttk.Frame(self, style="TFrame")
        bar.pack(fill="x", pady=(0, 10))
        ttk.Label(bar, text="Filter", style="Dim.TLabel").pack(side="left", padx=(0, 8))
        self.filter_var = tk.StringVar()
        self.entry = ttk.Entry(bar, textvariable=self.filter_var, width=52,
                               font=self.theme.font("mono"))
        self.entry.pack(side="left")
        self.entry.bind("<Return>", lambda e: self.apply_filter())
        ttk.Button(bar, text="Apply", command=self.apply_filter,
                   style="Accent.TButton").pack(side="left", padx=(8, 0))
        ttk.Button(bar, text="Clear", command=self.clear_filter).pack(side="left", padx=(6, 0))
        self.hint = ttk.Label(
            bar, style="Dim.TLabel",
            text="e.g.  tcp   ·   port 80   ·   ip 10.0.0.5   ·   http   ·   flag")
        self.hint.pack(side="left", padx=(14, 0))
        self.status = ttk.Label(bar, text="", style="Dim.TLabel")
        self.status.pack(side="right")

        pane = ttk.PanedWindow(self, orient="vertical")
        pane.pack(fill="both", expand=True)

        self.list = SortableTree(
            pane, self.theme,
            [("no", "No.", 78, "e", False),
             ("time", "Time", 110, "e", False),
             ("src", "Source", 190, "w", False),
             ("dst", "Destination", 190, "w", False),
             ("proto", "Protocol", 96, "w", False),
             ("len", "Length", 78, "e", False),
             ("info", "Info", 700, "w", True)],
            height=14, on_select=self.on_select)
        pane.add(self.list, weight=3)

        lower = ttk.PanedWindow(pane, orient="horizontal")
        pane.add(lower, weight=2)

        left = ttk.Frame(lower, style="Border.TFrame", padding=1)
        lower.add(left, weight=1)
        self.detail = ttk.Treeview(left, show="tree", selectmode="browse",
                                   style="Treeview")
        vs = ttk.Scrollbar(left, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=vs.set)
        self.detail.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.detail.column("#0", width=460, stretch=True)
        self.detail.bind("<<TreeviewSelect>>", self.on_layer)

        right = ttk.Frame(lower, style="TFrame", padding=(10, 0, 0, 0))
        lower.add(right, weight=1)
        self.hex = HexView(right, self.theme, height=10)
        self.hex.pack(fill="both", expand=True)

        self._shown = []          # packets currently listed
        self._layer_spans = {}

    # -- data ---------------------------------------------------------------

    def load(self, an):
        self.analysis = an
        self.filter_var.set("")
        self.populate(an.packets)

    def populate(self, packets, note=""):
        self.list.clear()
        self._shown = packets[:MAX_ROWS]
        start = self.analysis.stats.start if self.analysis else 0
        for p in self._shown:
            self.list.add(
                (p.number, "%.6f" % (p.ts - start), p.src or "—", p.dst or "—",
                 p.proto, p.wirelen or p.caplen, p.info),
                tags=("fg_" + self._proto_key(p.proto),), iid=str(p.index))
        extra = ""
        if len(packets) > MAX_ROWS:
            extra = "  (showing first %s — narrow the filter to see the rest)" % human_num(MAX_ROWS)
        self.status.configure(text="%s of %s packets%s%s" % (
            human_num(len(self._shown)),
            human_num(len(self.analysis.packets)) if self.analysis else "0",
            extra, ("   ·   " + note) if note else ""))
        if self._shown:
            self.list.select_iid(str(self._shown[0].index))
            self.on_select(str(self._shown[0].index))
        else:
            self.detail.delete(*self.detail.get_children())
            self.hex.show(b"")

    @staticmethod
    def _proto_key(proto):
        from .theme import PROTO_COLOR
        return PROTO_COLOR.get(proto, "grey")

    # -- filtering ----------------------------------------------------------

    def clear_filter(self):
        self.filter_var.set("")
        if self.analysis:
            self.populate(self.analysis.packets)

    def apply_filter(self):
        if not self.analysis:
            return
        expr = self.filter_var.get().strip()
        if not expr:
            self.populate(self.analysis.packets)
            return
        try:
            pred = build_filter(expr)
        except ValueError as exc:
            messagebox.showwarning("Filter", str(exc), parent=self)
            return
        matched = [p for p in self.analysis.packets if pred(p)]
        self.populate(matched, note="filter: %s" % expr)

    def show_numbers(self, numbers, note=""):
        if not self.analysis:
            return
        wanted = set(numbers)
        matched = [p for p in self.analysis.packets if p.number in wanted]
        self.filter_var.set("")
        self.populate(matched, note=note)

    # -- detail -------------------------------------------------------------

    def on_select(self, iid):
        if iid is None or not self.analysis:
            return
        try:
            pkt = self.analysis.packets[int(iid)]
        except (ValueError, IndexError):
            return
        self.detail.delete(*self.detail.get_children())
        self._layer_spans = {}
        c = self.theme.c
        self.detail.tag_configure("layer", font=self.theme.font("ui_bold"),
                                  foreground=c["blue"])
        self.detail.tag_configure("field", font=self.theme.font("mono_small"),
                                  foreground=c["text"])
        self.detail.tag_configure("meta", foreground=c["text_dim"],
                                  font=self.theme.font("mono_small"))

        ts = _dt.datetime.fromtimestamp(pkt.ts)
        frame = self.detail.insert("", "end", text="Frame %d — %d bytes on wire, %d captured"
                                   % (pkt.number, pkt.wirelen, pkt.caplen),
                                   open=True, tags=("layer",))
        for label, value in (
                ("Arrival time", ts.strftime("%Y-%m-%d %H:%M:%S.%f")),
                ("Epoch", "%.6f" % pkt.ts),
                ("Link type", linktype_name(pkt.linktype)),
                ("Highest protocol", pkt.proto)):
            self.detail.insert(frame, "end", text="%s:  %s" % (label, value), tags=("meta",))
        self._layer_spans[frame] = (0, 0)

        for layer in pkt.layers:
            node = self.detail.insert("", "end", text=layer.name, open=True, tags=("layer",))
            self._layer_spans[node] = (layer.offset, layer.offset + layer.length)
            for label, value in layer.fields:
                child = self.detail.insert(node, "end", text="%s:  %s" % (label, value),
                                           tags=("field",))
                self._layer_spans[child] = (layer.offset, layer.offset + layer.length)
        if pkt.payload:
            node = self.detail.insert("", "end", open=True, tags=("layer",),
                                      text="Payload — %d bytes" % len(pkt.payload))
            self._layer_spans[node] = (pkt.payload_off, pkt.payload_off + len(pkt.payload))
            preview = pkt.payload[:400].decode("utf-8", "replace")
            preview = "".join(ch if ch.isprintable() or ch in "\n\r\t" else "·" for ch in preview)
            for line in preview.splitlines()[:12]:
                if line.strip():
                    self.detail.insert(node, "end", text=line[:200], tags=("field",))
        if pkt.error:
            self.detail.insert("", "end", text="⚠ " + pkt.error, tags=("layer",))
        self.hex.show(pkt.raw)

    def on_layer(self, _event):
        sel = self.detail.selection()
        if not sel or not self.analysis:
            return
        iid = self.list.selected()
        if iid is None:
            return
        pkt = self.analysis.packets[int(iid)]
        span = self._layer_spans.get(sel[0])
        self.hex.show(pkt.raw, highlight=span if span and span[1] > span[0] else None)


def build_filter(expr):
    """Tiny display-filter language. Every token must match (logical AND)."""
    tokens = expr.split()
    tests = []
    i = 0
    protos = {"tcp", "udp", "icmp", "icmpv6", "arp", "dns", "http", "https", "tls",
              "ftp", "telnet", "ssh", "smtp", "pop3", "imap", "dhcp", "smb", "ntp",
              "tftp", "irc", "syslog", "snmp", "mdns", "redis", "mysql"}
    while i < len(tokens):
        t = tokens[i].lower()
        if t in ("port", "sport", "dport", "ip", "src", "dst", "contains", "len>", "len<"):
            if i + 1 >= len(tokens):
                raise ValueError("`%s` needs a value, e.g. `%s 80`" % (t, t))
            val = tokens[i + 1]
            i += 2
            tests.append(_kv_test(t, val))
            continue
        if t in protos:
            tests.append(lambda p, t=t: p.proto.lower() == t or p.transport.lower() == t)
        elif t == "flag":
            tests.append(lambda p: bool(detect.KNOWN_FLAG_RE.search(p.payload or b"")))
        elif t in ("syn", "ack", "rst", "fin", "psh", "urg"):
            bits = {"fin": 0x01, "syn": 0x02, "rst": 0x04, "psh": 0x08,
                    "ack": 0x10, "urg": 0x20}
            tests.append(lambda p, b=bits[t]: bool(p.tcp_flags & b))
        elif t == "payload":
            tests.append(lambda p: bool(p.payload))
        else:
            tests.append(_free_text(tokens[i]))
        i += 1
    if not tests:
        raise ValueError("Empty filter.")
    return lambda p: all(fn(p) for fn in tests)


def _kv_test(key, val):
    if key in ("port", "sport", "dport"):
        try:
            n = int(val)
        except ValueError:
            raise ValueError("`%s` expects a number, got %r" % (key, val))
        if key == "sport":
            return lambda p: p.sport == n
        if key == "dport":
            return lambda p: p.dport == n
        return lambda p: n in (p.sport, p.dport)
    if key == "ip":
        return lambda p: val in (p.src, p.dst)
    if key == "src":
        return lambda p: p.src == val
    if key == "dst":
        return lambda p: p.dst == val
    if key == "contains":
        needle = val.encode("utf-8", "replace").lower()
        return lambda p: needle in (p.payload or b"").lower() or val.lower() in p.info.lower()
    if key == "len>":
        n = int(val)
        return lambda p: (p.wirelen or p.caplen) > n
    n = int(val)
    return lambda p: (p.wirelen or p.caplen) < n


def _free_text(word):
    low = word.lower()
    b = low.encode("utf-8", "replace")
    return lambda p: (low in p.info.lower() or low in p.src.lower()
                      or low in p.dst.lower() or low in p.proto.lower()
                      or b in (p.payload or b"").lower())


# --------------------------------------------------------------------------
# Conversations
# --------------------------------------------------------------------------

class ConversationsTab(Tab):
    def build(self):
        head = ttk.Frame(self, style="TFrame")
        head.pack(fill="x", pady=(0, 10))
        ttk.Label(head, text="Conversations", style="H2.TLabel").pack(side="left")
        ttk.Label(head, style="Dim.TLabel",
                  text="double-click a row to read the reassembled stream"
                  ).pack(side="left", padx=(12, 0))
        self.count = ttk.Label(head, text="", style="Dim.TLabel")
        self.count.pack(side="right")

        self.tree = SortableTree(
            self, self.theme,
            [("id", "Stream", 80, "e", False),
             ("proto", "Proto", 80, "w", False),
             ("a", "Endpoint A", 210, "w", False),
             ("b", "Endpoint B", 210, "w", False),
             ("svc", "Service", 110, "w", False),
             ("pkts", "Packets", 90, "e", False),
             ("bytes", "Bytes", 100, "e", False),
             ("ab", "A → B", 100, "e", False),
             ("ba", "B → A", 100, "e", False),
             ("dur", "Duration", 100, "e", False),
             ("start", "Start", 100, "e", False)],
            height=22, on_activate=self.open_stream)
        self.tree.pack(fill="both", expand=True)
        ttk.Button(self, text="Follow selected stream", style="Accent.TButton",
                   command=lambda: self.open_stream(self.tree.selected())).pack(
            anchor="w", pady=(10, 0))
        self._map = {}

    def load(self, an):
        self.analysis = an
        self.tree.clear()
        self._map = {}
        start = an.stats.start
        convs = sorted(an.conversations, key=lambda c: -c.total_bytes)
        for c in convs:
            iid = "c%d" % c.stream_id
            self._map[iid] = c
            self.tree.add(
                (c.stream_id, c.proto,
                 "%s:%d" % (c.a_ip, c.a_port) if c.a_port else c.a_ip,
                 "%s:%d" % (c.b_ip, c.b_port) if c.b_port else c.b_ip,
                 c.service or "—", c.total_packets, human_size(c.total_bytes),
                 human_size(c.bytes_ab), human_size(c.bytes_ba),
                 "%.2f s" % c.duration, "%.2f s" % (c.start - start)),
                tags=("fg_" + ("green" if c.service in ("HTTP", "FTP", "TELNET")
                               else "blue" if c.proto == "TCP" else "cyan"),),
                iid=iid)
        self.count.configure(text="%d conversations" % len(convs))

    def open_stream(self, iid):
        conv = self._map.get(iid)
        if conv:
            self.app.follow_stream(conv.stream_id)


# --------------------------------------------------------------------------
# Follow stream
# --------------------------------------------------------------------------

class StreamTab(Tab):
    def build(self):
        head = ttk.Frame(self, style="TFrame")
        head.pack(fill="x", pady=(0, 10))
        ttk.Label(head, text="Stream", style="H2.TLabel").pack(side="left")
        self.picker_var = tk.StringVar()
        self.picker = ttk.Combobox(head, textvariable=self.picker_var, state="readonly",
                                   width=54, font=self.theme.font("mono_small"))
        self.picker.pack(side="left", padx=(12, 0))
        self.picker.bind("<<ComboboxSelected>>", lambda e: self.on_pick())

        self.mode = tk.StringVar(value="ASCII")
        for label in ("ASCII", "Hex", "Client only", "Server only"):
            ttk.Radiobutton(head, text=label, value=label, variable=self.mode,
                            command=self.render).pack(side="left", padx=(12, 0))
        ttk.Button(head, text="Save stream…", command=self.save).pack(side="right")

        legend = ttk.Frame(self, style="TFrame")
        legend.pack(fill="x", pady=(0, 6))
        self.legend_a = ttk.Label(legend, text="■ client → server", style="Dim.TLabel")
        self.legend_a.pack(side="left")
        self.legend_b = ttk.Label(legend, text="■ server → client", style="Dim.TLabel")
        self.legend_b.pack(side="left", padx=(16, 0))
        self.info = ttk.Label(legend, text="", style="Dim.TLabel")
        self.info.pack(side="right")

        self.view = TextPane(self, self.theme, mono=True, wrap="word", height=24)
        self.view.pack(fill="both", expand=True)
        self.conv = None

    def load(self, an):
        self.analysis = an
        self.conv = None
        options = []
        self._by_label = {}
        for c in sorted(an.conversations, key=lambda c: c.stream_id):
            if c.proto not in ("TCP", "UDP") or not c.segments:
                continue
            label = "%-4d %-4s %s  %s" % (c.stream_id, c.proto, c.label(),
                                          human_size(c.total_bytes))
            options.append(label)
            self._by_label[label] = c
        self.picker.configure(values=options)
        if options:
            self.picker_var.set(options[0])
            self.conv = self._by_label[options[0]]
        self.render()

    def on_pick(self):
        self.conv = self._by_label.get(self.picker_var.get())
        self.render()

    def show(self, stream_id):
        for label, conv in getattr(self, "_by_label", {}).items():
            if conv.stream_id == stream_id:
                self.picker_var.set(label)
                self.conv = conv
                break
        self.render()

    def render(self):
        c = self.theme.c
        self.legend_a.configure(foreground=c["blue"])
        self.legend_b.configure(foreground=c["green"])
        self.view.clear()
        conv = self.conv
        if not conv:
            self.view.append("Select a conversation to reassemble it.\n", ("dim",))
            self.info.configure(text="")
            return
        mode = self.mode.get()
        self.info.configure(text="stream %d · %s · %s packets · %s" % (
            conv.stream_id, conv.label(), human_num(conv.total_packets),
            human_size(conv.total_bytes)))
        if mode == "Hex":
            data = conv.data_ab() + conv.data_ba()
            lines = []
            for off in range(0, min(len(data), 65536), 16):
                chunk = data[off:off + 16]
                lines.append("%08x  %-47s  %s" % (
                    off, " ".join("%02x" % b for b in chunk),
                    "".join(chr(b) if 32 <= b < 127 else "·" for b in chunk)))
            self.view.append("\n".join(lines) or "(empty)")
            return
        if mode == "Client only":
            self._dump(conv.data_ab(), "client")
            return
        if mode == "Server only":
            self._dump(conv.data_ba(), "server")
            return
        total = 0
        for direction, blob, _idx in conv.chunks():
            tag = "client" if direction == 0 else "server"
            self.view.append(self._decode(blob), (tag,))
            total += len(blob)
            if total > 400000:
                self.view.append("\n… output truncated at 400 KB\n", ("dim",))
                break
        if total == 0:
            self.view.append("This conversation carries no application payload "
                             "(handshake / control packets only).\n", ("dim",))

    def _dump(self, blob, tag):
        if not blob:
            self.view.append("(no data in this direction)\n", ("dim",))
            return
        self.view.append(self._decode(blob[:400000]), (tag,))

    @staticmethod
    def _decode(blob):
        txt = blob.decode("utf-8", "replace")
        return "".join(ch if (ch.isprintable() or ch in "\n\r\t") else "·" for ch in txt)

    def save(self):
        if not self.conv:
            return
        path = filedialog.asksaveasfilename(
            title="Save stream", defaultextension=".bin",
            initialfile="stream_%d.bin" % self.conv.stream_id, parent=self)
        if not path:
            return
        with open(path, "wb") as fh:
            fh.write(self.conv.data_ab() + self.conv.data_ba())
        self.app.set_status("Saved stream %d to %s" % (self.conv.stream_id, path))


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------

class CredentialsTab(Tab):
    def build(self):
        head = ttk.Frame(self, style="TFrame")
        head.pack(fill="x", pady=(0, 10))
        ttk.Label(head, text="Credentials recovered from cleartext protocols",
                  style="H2.TLabel").pack(side="left")
        self.count = ttk.Label(head, text="", style="Dim.TLabel")
        self.count.pack(side="right")

        self.tree = SortableTree(
            self, self.theme,
            [("proto", "Protocol", 130, "w", False),
             ("client", "Client", 170, "w", False),
             ("server", "Server", 170, "w", False),
             ("user", "Username", 220, "w", False),
             ("pass", "Password / token", 300, "w", True),
             ("note", "How it was recovered", 260, "w", False),
             ("pkt", "Packet", 90, "e", False)],
            mono=True, height=20, on_activate=self.goto)
        self.tree.pack(fill="both", expand=True)
        self.empty = ttk.Label(self, style="Dim.TLabel", text="")
        self.empty.pack(anchor="w", pady=(10, 0))
        self._map = {}

    def load(self, an):
        self.analysis = an
        self.tree.clear()
        self._map = {}
        for i, cr in enumerate(an.credentials):
            iid = "cr%d" % i
            self._map[iid] = cr
            self.tree.add((cr.proto, cr.client, cr.server, cr.username, cr.password,
                           cr.note, cr.packet or "—"),
                          tags=("fg_red", "bold"), iid=iid)
        self.count.configure(text="%d found" % len(an.credentials))
        self.empty.configure(text="" if an.credentials else
                             "No cleartext credentials in this capture — either the traffic is "
                             "encrypted, or no authentication happened.")

    def goto(self, iid):
        cr = self._map.get(iid)
        if cr and cr.packet:
            self.app.show_packets([cr.packet], "credential: %s" % cr.proto)


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------

class FilesTab(Tab):
    def build(self):
        head = ttk.Frame(self, style="TFrame")
        head.pack(fill="x", pady=(0, 10))
        ttk.Label(head, text="Files carried in the capture", style="H2.TLabel").pack(side="left")
        ttk.Button(head, text="Export all…", command=self.export_all).pack(side="right")
        ttk.Button(head, text="Save selected…", style="Accent.TButton",
                   command=self.save_one).pack(side="right", padx=(0, 8))
        self.count = ttk.Label(head, text="", style="Dim.TLabel")
        self.count.pack(side="right", padx=(0, 16))

        pane = ttk.PanedWindow(self, orient="vertical")
        pane.pack(fill="both", expand=True)
        self.tree = SortableTree(
            pane, self.theme,
            [("name", "Name", 240, "w", False),
             ("kind", "Type", 260, "w", True),
             ("size", "Size", 100, "e", False),
             ("src", "Source", 380, "w", False),
             ("stream", "Stream", 90, "e", False)],
            height=11, on_select=self.preview)
        pane.add(self.tree, weight=2)
        self.view = HexView(pane, self.theme, height=12)
        pane.add(self.view, weight=2)
        self._map = {}

    def load(self, an):
        self.analysis = an
        self.tree.clear()
        self._map = {}
        for i, f in enumerate(an.carved):
            iid = "f%d" % i
            self._map[iid] = f
            self.tree.add((f.name, f.kind, human_size(f.size), f.source, f.stream_id),
                          tags=("fg_" + ("amber" if f.ext in ("exe", "elf", "zip", "pem")
                                         else "green"),), iid=iid)
        self.count.configure(text="%d objects" % len(an.carved))
        self.view.show(b"")

    def preview(self, iid):
        f = self._map.get(iid)
        if not f:
            return
        head = f.data[:4096]
        printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
        if head and printable / len(head) > 0.9:
            self.view.set(f.data[:60000].decode("utf-8", "replace"))
        else:
            self.view.show(f.data, max_bytes=16384)

    def save_one(self):
        f = self._map.get(self.tree.selected())
        if not f:
            messagebox.showinfo(APP_NAME, "Select a file first.", parent=self)
            return
        path = filedialog.asksaveasfilename(title="Save file", initialfile=f.name, parent=self)
        if path:
            with open(path, "wb") as fh:
                fh.write(f.data)
            self.app.set_status("Saved %s (%s)" % (os.path.basename(path), human_size(f.size)))

    def export_all(self):
        if not self._map:
            return
        folder = filedialog.askdirectory(title="Export every extracted object to…", parent=self)
        if not folder:
            return
        written = 0
        for i, f in enumerate(self._map.values()):
            name = "%03d_%s" % (i, f.name.replace("/", "_"))
            with open(os.path.join(folder, name), "wb") as fh:
                fh.write(f.data)
            written += 1
        self.app.set_status("Exported %d objects to %s" % (written, folder))


# ===========================================================================
# main window
# ===========================================================================

class App(tk.Tk):
    def __init__(self, path=None):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1500x950")
        self.minsize(1120, 720)
        self.theme = Theme(self, mode="dark")
        self.analysis = None
        self._queue = queue.Queue()

        self._build_menu()
        self._build_chrome()
        self._build_tabs()
        self._bind_keys()
        self.show_welcome()
        if path:
            self.after(120, lambda: self.open_path(path))

    # -- chrome -------------------------------------------------------------

    def _build_menu(self):
        menu = tk.Menu(self)
        filemenu = tk.Menu(menu, tearoff=0)
        filemenu.add_command(label="Open capture…", accelerator="Cmd+O", command=self.open_dialog)
        filemenu.add_command(label="Export report…", accelerator="Cmd+E", command=self.export_report)
        filemenu.add_separator()
        filemenu.add_command(label="Close capture", command=self.close_capture)
        menu.add_cascade(label="File", menu=filemenu)

        view = tk.Menu(menu, tearoff=0)
        view.add_command(label="Zoom in", accelerator="Cmd++", command=lambda: self.zoom(1))
        view.add_command(label="Zoom out", accelerator="Cmd+-", command=lambda: self.zoom(-1))
        view.add_command(label="Reset zoom", command=lambda: self.zoom(0, reset=True))
        view.add_separator()
        view.add_command(label="Toggle light / dark", accelerator="Cmd+L",
                         command=self.toggle_theme)
        menu.add_cascade(label="View", menu=view)

        helpmenu = tk.Menu(menu, tearoff=0)
        helpmenu.add_command(label="Filter syntax", command=self.show_help)
        helpmenu.add_command(label="What the scanner looks for", command=self.show_detectors)
        menu.add_cascade(label="Help", menu=helpmenu)
        self.configure(menu=menu)

    def _build_chrome(self):
        top = ttk.Frame(self, style="TFrame", padding=(18, 14, 18, 8))
        top.pack(fill="x")
        title_box = ttk.Frame(top, style="TFrame")
        title_box.pack(side="left")
        self.title_lbl = ttk.Label(title_box, text=APP_NAME, style="H1.TLabel")
        self.title_lbl.pack(anchor="w")
        self.file_lbl = ttk.Label(title_box, text="no capture loaded", style="Dim.TLabel")
        self.file_lbl.pack(anchor="w", pady=(2, 0))

        buttons = ttk.Frame(top, style="TFrame")
        buttons.pack(side="right")
        ttk.Button(buttons, text="Open capture…", style="Accent.TButton",
                   command=self.open_dialog).pack(side="left")
        ttk.Button(buttons, text="A−", width=4, command=lambda: self.zoom(-1)).pack(
            side="left", padx=(8, 0))
        ttk.Button(buttons, text="A+", width=4, command=lambda: self.zoom(1)).pack(
            side="left", padx=(4, 0))
        ttk.Button(buttons, text="Light / dark", command=self.toggle_theme).pack(
            side="left", padx=(8, 0))

        self.banner = Banner(self, self.theme)
        self.banner.pack(fill="x", padx=18, pady=(6, 8))

        self.status_bar = ttk.Label(self, text="Ready", style="Dim.TLabel",
                                    padding=(20, 8))
        self.status_bar.pack(side="bottom", fill="x")
        self.progress = ttk.Progressbar(self, mode="determinate", maximum=100)

    def _build_tabs(self):
        self.body = ttk.Frame(self, style="TFrame")
        self.body.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        self.notebook = ttk.Notebook(self.body)
        self.tabs = {}
        for key, label, cls in (
                ("overview", "  Overview  ", OverviewTab),
                ("findings", "  Findings  ", FindingsTab),
                ("packets", "  Packets  ", PacketsTab),
                ("convs", "  Conversations  ", ConversationsTab),
                ("stream", "  Follow Stream  ", StreamTab),
                ("creds", "  Credentials  ", CredentialsTab),
                ("files", "  Files  ", FilesTab)):
            tab = cls(self)
            self.notebook.add(tab, text=label)
            self.tabs[key] = tab
        self.welcome = self._build_welcome()

    def _build_welcome(self):
        f = ttk.Frame(self.body, style="TFrame", padding=60)
        inner = ttk.Frame(f, style="Border.TFrame", padding=1)
        inner.pack(expand=True)
        box = ttk.Frame(inner, style="Panel.TFrame", padding=44)
        box.pack()
        ttk.Label(box, text="Open a capture to analyse", style="H1.TLabel",
                  background=self.theme.c["panel"]).pack(anchor="w")
        msg = ("Load a .pcap, .pcapng or .cap file. The analyser reassembles every\n"
               "conversation, then reports what the traffic actually is:\n\n"
               "   ·  port scans, sweeps, brute force and other reconnaissance\n"
               "   ·  flags — plain, base64, hex, ROT13 or single-byte XOR\n"
               "   ·  credentials sent in the clear (FTP, HTTP, Telnet, SMTP, POP3…)\n"
               "   ·  DNS and ICMP tunnelling, beaconing, remote shells\n"
               "   ·  files transferred over HTTP, FTP and raw TCP\n\n"
               "Everything runs locally. No network access, no browser.")
        lbl = ttk.Label(box, text=msg, style="Panel.TLabel", justify="left")
        lbl.configure(font=self.theme.font("ui"), foreground=self.theme.c["text_dim"])
        lbl.pack(anchor="w", pady=(16, 26))
        ttk.Button(box, text="Choose a capture file…", style="Accent.TButton",
                   command=self.open_dialog).pack(anchor="w")
        self._welcome_labels = (lbl, box)
        return f

    def _bind_keys(self):
        self.bind_all("<Command-o>", lambda e: self.open_dialog())
        self.bind_all("<Control-o>", lambda e: self.open_dialog())
        self.bind_all("<Command-e>", lambda e: self.export_report())
        self.bind_all("<Command-l>", lambda e: self.toggle_theme())
        self.bind_all("<Command-plus>", lambda e: self.zoom(1))
        self.bind_all("<Command-equal>", lambda e: self.zoom(1))
        self.bind_all("<Command-minus>", lambda e: self.zoom(-1))
        self.bind_all("<Control-plus>", lambda e: self.zoom(1))
        self.bind_all("<Control-minus>", lambda e: self.zoom(-1))
        self.bind_all("<Command-f>", lambda e: self.focus_filter())
        self.bind_all("<Control-f>", lambda e: self.focus_filter())

    # -- state --------------------------------------------------------------

    def show_welcome(self):
        self.notebook.pack_forget()
        self.welcome.pack(fill="both", expand=True)

    def show_tabs(self):
        self.welcome.pack_forget()
        self.notebook.pack(fill="both", expand=True)

    def set_status(self, text):
        self.status_bar.configure(text=text)

    def focus_filter(self):
        self.show_tab("packets")
        self.tabs["packets"].entry.focus_set()

    def show_tab(self, key):
        self.notebook.select(self.tabs[key])

    def show_packets(self, numbers, note=""):
        self.show_tab("packets")
        self.tabs["packets"].show_numbers(numbers, note)

    def follow_stream(self, stream_id):
        self.show_tab("stream")
        self.tabs["stream"].show(stream_id)

    # -- loading ------------------------------------------------------------

    def open_dialog(self):
        path = filedialog.askopenfilename(
            title="Open capture file",
            filetypes=[("Capture files", "*.pcap *.pcapng *.cap *.dmp"),
                       ("All files", "*.*")])
        if path:
            self.open_path(path)

    def open_path(self, path):
        if not os.path.exists(path):
            messagebox.showerror(APP_NAME, "File not found:\n%s" % path)
            return
        self.file_lbl.configure(text="loading %s…" % os.path.basename(path))
        self.banner.set("ANALYSING", "Reading %s…" % os.path.basename(path), "info")
        self.progress.pack(side="bottom", fill="x", before=self.status_bar)
        self.progress["value"] = 0
        self.set_status("Loading…")

        def work():
            try:
                an = session.load(path, progress=lambda f, m: self._queue.put(("p", f, m)))
                self._queue.put(("done", an, ""))
            except CaptureError as exc:
                self._queue.put(("err", str(exc), ""))
            except Exception as exc:                     # noqa: BLE001 - surfaced in UI
                import traceback
                traceback.print_exc()
                self._queue.put(("err", "%s: %s" % (type(exc).__name__, exc), ""))

        threading.Thread(target=work, daemon=True).start()
        self.after(40, self._drain)

    def _drain(self):
        busy = True
        try:
            while True:
                kind, a, b = self._queue.get_nowait()
                if kind == "p":
                    self.progress["value"] = a * 100
                    self.set_status(b)
                elif kind == "done":
                    self._finish(a)
                    busy = False
                elif kind == "err":
                    self.progress.pack_forget()
                    self.banner.set("COULD NOT READ FILE", a, "critical")
                    self.set_status("Failed to load capture")
                    messagebox.showerror(APP_NAME, a)
                    busy = False
        except queue.Empty:
            pass
        if busy:
            self.after(40, self._drain)

    def _finish(self, an):
        self.analysis = an
        self.progress.pack_forget()
        self.show_tabs()
        for tab in self.tabs.values():
            tab.load(an)
        head, body, level = an.verdict
        self.banner.set(head, body, level)
        self.file_lbl.configure(text="%s   ·   %s   ·   %s packets   ·   %s" % (
            an.path, human_size(an.meta["filesize"]), human_num(an.stats.packets),
            ", ".join(sorted(linktype_name(l) for l in an.meta["linktypes"]))))
        crit = sum(1 for f in an.findings if f.severity == "critical")
        self.set_status("Loaded %s — %s packets, %d conversations, %d findings (%d critical)"
                        % (an.name, human_num(an.stats.packets), len(an.conversations),
                           len(an.findings), crit))
        self.show_tab("overview" if not an.findings else "findings")

    def close_capture(self):
        self.analysis = None
        self.show_welcome()
        self.banner.set("NO FILE LOADED", "Open a capture to begin.", "info")
        self.file_lbl.configure(text="no capture loaded")
        self.set_status("Ready")

    # -- report -------------------------------------------------------------

    def export_report(self):
        if not self.analysis:
            messagebox.showinfo(APP_NAME, "Load a capture first.")
            return
        path = filedialog.asksaveasfilename(
            title="Export analysis report", defaultextension=".md",
            initialfile=os.path.splitext(self.analysis.name)[0] + "_report.md",
            filetypes=[("Markdown", "*.md"), ("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(build_report(self.analysis))
        self.set_status("Report written to %s" % path)

    # -- appearance ---------------------------------------------------------

    def zoom(self, delta, reset=False):
        if reset:
            self.theme.scale = 0
            self.theme.apply()
        else:
            self.theme.zoom(delta)
        self._restyle_all()
        self.set_status("Text scale %+d" % self.theme.scale)

    def toggle_theme(self):
        self.theme.toggle_mode()
        self._restyle_all()

    def _restyle_all(self):
        c = self.theme.c
        self.configure(bg=c["bg"])
        self.banner.restyle()
        for tab in self.tabs.values():
            tab.restyle()
        for w in (getattr(self, "_welcome_labels", ()) or ()):
            try:
                w.configure(background=c["panel"])
            except tk.TclError:
                pass
        try:
            self._welcome_labels[0].configure(foreground=c["text_dim"],
                                              font=self.theme.font("ui"))
        except (AttributeError, IndexError, tk.TclError):
            pass
        pk = self.tabs["packets"]
        pk.entry.configure(font=self.theme.font("mono"))
        if self.analysis:
            self.tabs["overview"].load(self.analysis)

    # -- help ---------------------------------------------------------------

    def show_help(self):
        messagebox.showinfo(
            "Filter syntax",
            "Tokens are combined with AND.\n\n"
            "  tcp  udp  icmp  arp  dns  http  tls  ftp  telnet  ssh …\n"
            "        keep packets of that protocol\n"
            "  port 80 / sport 1234 / dport 53\n"
            "  ip 10.0.0.5 / src 10.0.0.5 / dst 8.8.8.8\n"
            "  contains password        substring in payload or info\n"
            "  syn ack rst fin psh urg  TCP flags\n"
            "  flag                     packets containing a CTF flag pattern\n"
            "  payload                  packets that carry application data\n"
            "  anything else            free-text search across all columns\n\n"
            "Example:   tcp port 21 contains PASS")

    def show_detectors(self):
        messagebox.showinfo(
            "What the scanner looks for",
            "Reconnaissance\n"
            "  TCP SYN / connect / NULL / FIN / XMAS scans, UDP scans,\n"
            "  horizontal sweeps, ARP scans, ICMP ping sweeps, traceroute,\n"
            "  DNS zone transfers, directory brute forcing.\n\n"
            "Credentials & secrets\n"
            "  FTP, Telnet, HTTP Basic/Bearer/forms, POP3, IMAP, SMTP AUTH,\n"
            "  Redis AUTH, SNMP communities, private keys, AWS keys, JWTs.\n\n"
            "CTF patterns\n"
            "  flag{…} style tokens in cleartext, base64, hex, ROT13 and\n"
            "  single-byte XOR; DNS and ICMP tunnelling; files carved out of\n"
            "  HTTP/FTP/raw TCP; remote shell sessions; C2 beaconing;\n"
            "  SQLi, LFI, command injection, web shells and scanner user agents.")


# ---------------------------------------------------------------------------

def build_report(an):
    st = an.stats
    head, body, _lvl = an.verdict
    out = []
    w = out.append
    w("# PCAP analysis — %s\n" % an.name)
    w("*Generated %s*\n" % _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    w("## Verdict\n")
    w("**%s** — %s\n" % (head, body))
    w("## Capture\n")
    w("| Property | Value |\n|---|---|")
    w("| File | `%s` |" % an.path)
    w("| Format | %s %s |" % (an.meta["format"], an.meta["version"]))
    w("| Size on disk | %s |" % human_size(an.meta["filesize"]))
    w("| Packets | %s |" % human_num(st.packets))
    w("| Bytes | %s |" % human_size(st.bytes))
    w("| Duration | %.3f s |" % st.duration)
    w("| Hosts | %d |" % len(st.endpoints))
    w("| Conversations | %d |" % len(an.conversations))
    w("")
    w("## Findings (%d)\n" % len(an.findings))
    for f in an.findings:
        w("### [%s] %s" % (SEVERITY_LABEL.get(f.severity, f.severity), f.title))
        w("*Category: %s*\n" % f.category)
        w(f.detail)
        if f.evidence:
            w("\n> Evidence: `%s`" % f.evidence.replace("`", "'"))
        if f.packets:
            w("\nPackets: %s%s" % (", ".join(str(n) for n in f.packets[:30]),
                                   " …" if len(f.packets) > 30 else ""))
        w("")
    if an.credentials:
        w("## Credentials (%d)\n" % len(an.credentials))
        w("| Protocol | Client | Server | Username | Password | Source |\n|---|---|---|---|---|---|")
        for c in an.credentials:
            w("| %s | %s | %s | `%s` | `%s` | %s |" % (
                c.proto, c.client, c.server, c.username, c.password, c.note))
        w("")
    if an.carved:
        w("## Extracted objects (%d)\n" % len(an.carved))
        w("| Name | Type | Size | Stream |\n|---|---|---|---|")
        for f in an.carved[:60]:
            w("| %s | %s | %s | %d |" % (f.name, f.kind, human_size(f.size), f.stream_id))
        w("")
    w("## Top conversations\n")
    w("| Stream | Proto | A | B | Packets | Bytes |\n|---|---|---|---|---|---|")
    for c in sorted(an.conversations, key=lambda c: -c.total_bytes)[:20]:
        w("| %d | %s | %s:%d | %s:%d | %d | %s |" % (
            c.stream_id, c.proto, c.a_ip, c.a_port, c.b_ip, c.b_port,
            c.total_packets, human_size(c.total_bytes)))
    w("")
    w("## Protocol breakdown\n")
    w("| Protocol | Packets | Bytes |\n|---|---|---|")
    for proto, count in st.protocols.most_common(20):
        w("| %s | %s | %s |" % (proto, human_num(count), human_size(st.proto_bytes[proto])))
    return "\n".join(out) + "\n"


def main(argv=None):
    import sys
    argv = argv if argv is not None else sys.argv[1:]
    path = argv[0] if argv else None
    app = App(path)
    app.mainloop()
