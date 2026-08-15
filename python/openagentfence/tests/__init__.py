"""Test package for the openagentfence interoperability package.

Kept as a package so ``python -m unittest discover`` finds these modules from
the package root. Each test module also bootstraps ``sys.path`` itself, so
discovery started directly at this directory works too, with or without an
editable install.
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
