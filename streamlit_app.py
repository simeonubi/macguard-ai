"""MacGuard AI - Streamlit Application Launcher.

Provides a clean root-level entrypoint for Streamlit execution,
preventing Python module namespace collision with the 'app' package.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is in sys.path
_project_root = str(Path(__file__).resolve().parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from app.ui.app import main

if __name__ == "__main__":
    main()
