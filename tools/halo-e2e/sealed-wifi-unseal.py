#!/usr/bin/env python3
"""Sealed-OS-only entrypoint for the reviewed sealed Wi-Fi helper."""
from pathlib import Path
import runpy
import sys

runpy.run_path(str(Path(__file__).with_name("sealed-wifi.py")))["main"](["unseal", *sys.argv[1:]])
