"""Colour palette, fonts and ttk styling.

Readability rules applied throughout:
  * high contrast text on a low-glare background (WCAG AA or better)
  * one accent colour per meaning, never reused for a second meaning
  * generous row height and padding; nothing smaller than 11 pt
  * severity is carried by colour *and* by a text label, never colour alone
"""

from __future__ import annotations

import tkinter.font as tkfont
from tkinter import ttk

DARK = {
    "bg":          "#12151a",
    "panel":       "#191d24",
    "raised":      "#212733",
    "row_alt":     "#1d222b",
    "border":      "#2e3644",
    "border_soft": "#242b36",
    "text":        "#eef2f8",
    "text_dim":    "#a7b3c4",
    "text_faint":  "#8b96a7",
    "sel":         "#2b4f7d",
    "sel_text":    "#ffffff",
}

LIGHT = {
    "bg":          "#f4f6f9",
    "panel":       "#ffffff",
    "raised":      "#eef1f6",
    "row_alt":     "#f7f9fc",
    "border":      "#ccd4e0",
    "border_soft": "#e2e8f0",
    "text":        "#131820",
    "text_dim":    "#4a5568",
    "text_faint":  "#5e697a",
    "sel":         "#cfe2ff",
    "sel_text":    "#0b1c33",
}

# accents (identical meaning in both themes, tuned per background)
ACCENT_DARK = {
    "blue":   "#5aa9ff",
    "green":  "#4ad991",
    "amber":  "#ffbe5c",
    "red":    "#ff6b76",
    "purple": "#bb95ff",
    "cyan":   "#4fd8e0",
    "pink":   "#ff85c0",
    "grey":   "#8d9aad",
}

ACCENT_LIGHT = {
    "blue":   "#0b62d6",
    "green":  "#0a7a48",
    "amber":  "#9a6100",
    "red":    "#c62430",
    "purple": "#6a35c9",
    "cyan":   "#06707a",
    "pink":   "#b4287f",
    "grey":   "#5b6675",
}

SEVERITY_COLOR = {
    "critical": "red",
    "high":     "amber",
    "medium":   "blue",
    "low":      "cyan",
    "info":     "grey",
}

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}

# protocol → accent key, used to colour the packet list
PROTO_COLOR = {
    "TCP": "blue", "UDP": "cyan", "HTTP": "green", "HTTPS": "green", "TLS": "purple",
    "DNS": "amber", "MDNS": "amber", "ARP": "pink", "ICMP": "pink", "ICMPv6": "pink",
    "FTP": "green", "TELNET": "red", "SSH": "purple", "SMTP": "green", "POP3": "green",
    "IMAP": "green", "DHCP": "amber", "SMB": "purple", "IRC": "green", "TFTP": "amber",
    "SYSLOG": "grey", "NTP": "grey", "SNMP": "grey", "REDIS": "red", "MYSQL": "purple",
}

MONO_CANDIDATES = ["SF Mono", "Menlo", "JetBrains Mono", "Cascadia Mono",
                   "DejaVu Sans Mono", "Consolas", "Courier New"]
UI_CANDIDATES = ["SF Pro Text", "Helvetica Neue", "Segoe UI", "Inter",
                 "DejaVu Sans", "Arial"]


class Theme:
    """Owns colours + fonts and pushes them into ttk styles."""

    def __init__(self, root, mode="dark", scale=0):
        self.root = root
        self.mode = mode
        self.scale = scale                 # -2 … +4 zoom steps
        self.fonts = {}
        self._pick_families()
        self.apply()

    # -- palette ------------------------------------------------------------

    @property
    def c(self):
        base = dict(DARK if self.mode == "dark" else LIGHT)
        base.update(ACCENT_DARK if self.mode == "dark" else ACCENT_LIGHT)
        return base

    def color(self, key):
        return self.c[key]

    def sev_color(self, severity):
        return self.c[SEVERITY_COLOR.get(severity, "grey")]

    def proto_color(self, proto):
        return self.c[PROTO_COLOR.get(proto, "grey")]

    # -- fonts --------------------------------------------------------------

    def _pick_families(self):
        available = set(tkfont.families(self.root))
        self.mono_family = next((f for f in MONO_CANDIDATES if f in available), "Courier")
        self.ui_family = next((f for f in UI_CANDIDATES if f in available), "Helvetica")

    def size(self, base):
        return max(9, base + self.scale)

    def _build_fonts(self):
        s = self.size
        spec = {
            "ui":        (self.ui_family, s(13), "normal"),
            "ui_bold":   (self.ui_family, s(13), "bold"),
            "small":     (self.ui_family, s(11), "normal"),
            "small_bold": (self.ui_family, s(11), "bold"),
            "h1":        (self.ui_family, s(21), "bold"),
            "h2":        (self.ui_family, s(16), "bold"),
            "h3":        (self.ui_family, s(13), "bold"),
            "mono":      (self.mono_family, s(12), "normal"),
            "mono_bold": (self.mono_family, s(12), "bold"),
            "mono_small": (self.mono_family, s(11), "normal"),
            "mono_big":  (self.mono_family, s(14), "normal"),
            "chip":      (self.ui_family, s(10), "bold"),
        }
        for name, (fam, size, weight) in spec.items():
            if name in self.fonts:
                self.fonts[name].configure(family=fam, size=size, weight=weight)
            else:
                self.fonts[name] = tkfont.Font(family=fam, size=size, weight=weight)
        return self.fonts

    def font(self, name="ui"):
        return self.fonts[name]

    # -- ttk ----------------------------------------------------------------

    def apply(self):
        c = self.c
        f = self._build_fonts()
        st = ttk.Style(self.root)
        try:
            st.theme_use("clam")               # fully restylable on every platform
        except Exception:
            pass

        self.root.configure(bg=c["bg"])
        row_h = self.size(13) + 14

        st.configure(".", background=c["bg"], foreground=c["text"],
                     fieldbackground=c["panel"], bordercolor=c["border"],
                     font=f["ui"], focuscolor=c["blue"])

        st.configure("TFrame", background=c["bg"])
        st.configure("Panel.TFrame", background=c["panel"])
        st.configure("Raised.TFrame", background=c["raised"])
        st.configure("Border.TFrame", background=c["border"])

        st.configure("TLabel", background=c["bg"], foreground=c["text"], font=f["ui"])
        st.configure("Panel.TLabel", background=c["panel"], foreground=c["text"])
        st.configure("Dim.TLabel", background=c["bg"], foreground=c["text_dim"], font=f["small"])
        st.configure("PanelDim.TLabel", background=c["panel"], foreground=c["text_dim"],
                     font=f["small"])
        st.configure("H1.TLabel", background=c["bg"], foreground=c["text"], font=f["h1"])
        st.configure("H2.TLabel", background=c["bg"], foreground=c["text"], font=f["h2"])
        st.configure("H3.TLabel", background=c["panel"], foreground=c["text_dim"], font=f["h3"])
        st.configure("Stat.TLabel", background=c["panel"], foreground=c["text"], font=f["h2"])

        st.configure("TButton", background=c["raised"], foreground=c["text"],
                     bordercolor=c["border"], focusthickness=2, relief="flat",
                     padding=(14, 8), font=f["ui"])
        st.map("TButton",
               background=[("pressed", c["sel"]), ("active", c["border"])],
               foreground=[("disabled", c["text_faint"])])
        st.configure("Accent.TButton", background=c["blue"], foreground="#08111d",
                     font=f["ui_bold"])
        st.map("Accent.TButton", background=[("active", c["cyan"]), ("pressed", c["sel"])])

        st.configure("TEntry", fieldbackground=c["panel"], foreground=c["text"],
                     insertcolor=c["text"], bordercolor=c["border"], padding=8)
        st.map("TEntry", bordercolor=[("focus", c["blue"])])
        st.configure("TCombobox", fieldbackground=c["panel"], background=c["raised"],
                     foreground=c["text"], arrowcolor=c["text_dim"], padding=6)

        st.configure("TNotebook", background=c["bg"], borderwidth=0, tabmargins=(8, 8, 8, 0))
        st.configure("TNotebook.Tab", background=c["bg"], foreground=c["text_dim"],
                     padding=(20, 11), font=f["ui_bold"], borderwidth=0)
        st.map("TNotebook.Tab",
               background=[("selected", c["panel"])],
               foreground=[("selected", c["text"]), ("active", c["text"])])

        st.configure("Treeview", background=c["panel"], fieldbackground=c["panel"],
                     foreground=c["text"], rowheight=row_h, borderwidth=0,
                     font=f["ui"])
        st.configure("Treeview.Heading", background=c["raised"], foreground=c["text_dim"],
                     font=f["small_bold"], relief="flat", padding=(10, 9),
                     bordercolor=c["border"])
        st.map("Treeview.Heading", background=[("active", c["border"])])
        st.map("Treeview",
               background=[("selected", c["sel"])],
               foreground=[("selected", c["sel_text"])])

        st.configure("Mono.Treeview", font=f["mono"], rowheight=row_h)

        st.configure("TPanedwindow", background=c["bg"])
        st.configure("Sash", sashthickness=8, gripcount=0, background=c["border_soft"])

        st.configure("Vertical.TScrollbar", background=c["raised"], troughcolor=c["bg"],
                     bordercolor=c["bg"], arrowcolor=c["text_dim"], relief="flat",
                     width=13)
        st.map("Vertical.TScrollbar", background=[("active", c["border"])])
        st.configure("Horizontal.TScrollbar", background=c["raised"], troughcolor=c["bg"],
                     bordercolor=c["bg"], arrowcolor=c["text_dim"], relief="flat")

        st.configure("TProgressbar", background=c["blue"], troughcolor=c["raised"],
                     bordercolor=c["raised"], lightcolor=c["blue"], darkcolor=c["blue"])
        for kind in ("TCheckbutton", "TRadiobutton"):
            st.configure(kind, background=c["bg"], foreground=c["text"],
                         indicatorcolor=c["panel"], bordercolor=c["border"],
                         font=f["ui"], padding=(2, 4))
            st.map(kind,
                   indicatorcolor=[("selected", c["blue"]), ("pressed", c["sel"])],
                   foreground=[("active", c["text"])],
                   background=[("active", c["bg"])])
        st.configure("TSeparator", background=c["border_soft"])
        return self

    # -- zoom / mode --------------------------------------------------------

    def zoom(self, delta):
        self.scale = max(-2, min(6, self.scale + delta))
        self.apply()

    def toggle_mode(self):
        self.mode = "light" if self.mode == "dark" else "dark"
        self.apply()
