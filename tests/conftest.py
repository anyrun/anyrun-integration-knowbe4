import os
import sys
from pathlib import Path

# src/*.py use flat imports (e.g. `from const import ...`), so src itself must
# be on sys.path. `pythonpath` in pyproject.toml already does this, but that
# relies on the pytest plugin running before conftest is imported - insert it
# here too so tests are correct even if collection order ever changes.
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# const.py raises at import time if these are missing, and half the test
# suite imports modules that import const. Set harmless defaults before any
# test module (or its imports) can run.
os.environ.setdefault("PHISHER_API_TOKEN", "test-phisher-token")
os.environ.setdefault("ANYRUN_API_KEY", "test-anyrun-key")
