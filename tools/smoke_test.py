#!/usr/bin/env python3
"""Headless-ish UI smoke test: builds the real window, loads captures, drives
every tab, filter, theme and export path, then exits.

    python3 tools/smoke_test.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapx import session          # noqa: E402
from pcapx.app import App, build_report   # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = [os.path.join(ROOT, "samples", n)
           for n in ("recon_scan.pcap", "ctf_challenge.pcap")]

ok = 0
fail = []


def check(label, fn):
    global ok
    try:
        fn()
        ok += 1
        print("  ok    %s" % label)
    except Exception as exc:                      # noqa: BLE001
        import traceback
        fail.append((label, exc))
        print("  FAIL  %s -> %s: %s" % (label, type(exc).__name__, exc))
        traceback.print_exc()


def main():
    app = App()
    app.geometry("1500x950")
    app.update()

    for path in SAMPLES:
        print("\n%s" % os.path.basename(path))
        an = session.load(path)
        check("load into every tab", lambda: app._finish(an))
        check("render window", app.update)

        for key in ("overview", "findings", "packets", "convs", "stream", "creds", "files"):
            check("show tab %s" % key, lambda k=key: (app.show_tab(k), app.update))

        pk = app.tabs["packets"]
        for expr in ("tcp", "udp port 53", "http contains flag", "ip 10.10.14.7",
                     "flag", "arp", "syn", "icmp payload", "nonsense-token"):
            check("filter %r" % expr,
                  lambda e=expr: (pk.filter_var.set(e), pk.apply_filter(), app.update()))
        check("clear filter", lambda: (pk.clear_filter(), app.update()))

        check("select every 40th packet", lambda: [
            (pk.list.select_iid(str(p.index)), pk.on_select(str(p.index)))
            for p in an.packets[::40]] and app.update())

        fd = app.tabs["findings"]
        for mode in ("All severities", "Critical only", "Critical + High",
                     "Scans only", "Flags only"):
            check("findings filter %r" % mode,
                  lambda m=mode: (fd.filter_var.set(m), fd.refresh(), app.update()))
        check("walk every finding", lambda: [
            (fd.tree.select_iid(str(i)), fd.on_select(str(i)))
            for i in range(len(fd._rows))] and app.update())
        check("finding → packets", lambda: (fd.filter_var.set("All severities"), fd.refresh(),
                                            fd.goto_packets(), app.update()))

        check("conversations tab", lambda: (app.show_tab("convs"), app.update()))
        for conv in an.conversations[:25]:
            check("follow stream %d" % conv.stream_id,
                  lambda c=conv: (app.follow_stream(c.stream_id), app.update()))
        st = app.tabs["stream"]
        for mode in ("Hex", "Client only", "Server only", "ASCII"):
            check("stream view %s" % mode,
                  lambda m=mode: (st.mode.set(m), st.render(), app.update()))

        fl = app.tabs["files"]
        check("preview every carved file", lambda: [
            fl.preview(iid) for iid in list(fl._map)] and app.update())

        cr = app.tabs["creds"]
        check("credential jump", lambda: (
            cr.goto(next(iter(cr._map), None)) if cr._map else None, app.update()))

        check("zoom in/out/reset", lambda: (app.zoom(1), app.update(), app.zoom(2),
                                            app.update(), app.zoom(-1), app.update(),
                                            app.zoom(0, reset=True), app.update()))
        check("light theme", lambda: (app.toggle_theme(), app.update()))
        check("dark theme", lambda: (app.toggle_theme(), app.update()))

        out = os.path.join(tempfile.gettempdir(), os.path.basename(path) + ".md")
        check("markdown report", lambda: open(out, "w").write(build_report(an)))
        print("  report: %s (%d bytes)" % (out, os.path.getsize(out)))

    check("close capture", lambda: (app.close_capture(), app.update()))
    app.destroy()

    print("\n%d checks passed, %d failed" % (ok, len(fail)))
    for label, exc in fail:
        print("  FAILED: %s (%s)" % (label, exc))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
