
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = Path(__file__).resolve().parent / "fixture"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT

@pytest.fixture(scope="session")
def fixture_dir() -> Path:
    return FIXTURE_DIR
