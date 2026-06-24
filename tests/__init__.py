from __future__ import annotations

import sys
from pathlib import Path

PYTHON_SOURCE_DIR = Path(__file__).resolve().parents[1] / "src" / "vrchat_net_capture"
if str(PYTHON_SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_SOURCE_DIR))
