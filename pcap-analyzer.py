#!/usr/bin/env python3
"""Launcher for the PCAP Analyzer desktop application.

    python3 pcap-analyzer.py [capture.pcap]

Requires only the Python standard library (Tkinter for the GUI).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import tkinter  # noqa: F401
except ImportError:
    sys.exit(
        "Tkinter is not available for this Python build.\n"
        "  macOS (Homebrew):  brew install python-tk\n"
        "  Debian/Ubuntu:     sudo apt install python3-tk\n"
        "  Fedora:            sudo dnf install python3-tkinter"
    )

from pcapx.app import main  # noqa: E402

if __name__ == "__main__":
    main()
