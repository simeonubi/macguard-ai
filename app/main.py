from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is in sys.path when running file directly
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from app.cli import main

if __name__ == "__main__":
    main()
