
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).resolve().parent / "fixture"

def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "gdprotect.cli", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )

def test_scan_fixture_lists_counts():
    r = run_cli("scan", str(FIXTURE))
    assert r.returncode == 0, r.stderr
    assert "5 files" in r.stdout
    assert "gdscript_source=2" in r.stdout
    assert "config=2" in r.stdout
    assert "data=1" in r.stdout

def test_build_then_verify_roundtrip(tmp_path):
    out = tmp_path / "game.gdpk"
    key_header = tmp_path / "key_shard.h"

    r = run_cli("--seed", "1", "build", str(FIXTURE),
                "-o", str(out),
                "--no-obfuscate",
                "--emit-key", str(key_header))
    assert r.returncode == 0, r.stderr

    assert out.is_file() and out.stat().st_size > 96
    assert out.read_bytes()[:4] == b"GDPK"

    assert key_header.is_file()
    header = key_header.read_text()
    assert "BUILD_SALT" in header
    assert "KEY_SHARD_0" in header
    assert "KEY_SHARD_3" in header

    m = re.search(r"build key \(keep secret\): ([0-9a-f]{64})", r.stdout)
    assert m, f"no build key printed:\n{r.stdout}"
    key_hex = m.group(1)

    v = run_cli("verify", str(out), "--key", key_hex)
    assert v.returncode == 0, v.stderr + v.stdout
    assert '"integrity": "ok"' in v.stdout
    assert '"files": 5' in v.stdout

def test_keygen_prints_64_hex():
    r = run_cli("keygen")
    assert r.returncode == 0, r.stderr
    assert re.fullmatch(r"[0-9a-f]{64}", r.stdout.strip())
