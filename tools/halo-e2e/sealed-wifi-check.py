#!/usr/bin/env python3
"""Factory-side negative PCR check; only exit 3 means expected mismatch."""
from pathlib import Path
import runpy
import sys

runpy.run_path(str(Path(__file__).with_name("sealed-wifi.py")))["main"](["check-denied", *sys.argv[1:]])
