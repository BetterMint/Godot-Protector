
from __future__ import annotations

import fnmatch
from pathlib import Path

SKIP_DIRS = {".git", ".godot", ".import", "export_presets.cfg.bak", "__pycache__"}
EDITOR_FILES = {"export_presets.cfg"}

def iter_project_files(root: str | Path) -> list[Path]:
    root = Path(root)
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.name in EDITOR_FILES:
            continue
        out.append(p)
    return out

def to_res_path(root: str | Path, p: str | Path) -> str:
    rel = Path(p).relative_to(root).as_posix()
    return "res://" + rel

def matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pat) for pat in patterns)

class ProtectionError(Exception):
    pass
