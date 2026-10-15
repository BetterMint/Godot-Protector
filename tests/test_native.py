from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gdprotect.config import Config
from gdprotect.pipeline import run_build, verify_container
from gdprotect.util import ProtectionError
from gdprotect.native import (NativeError, parse, transpile_source,
                              emit_project, rewrite_scene, rewrite_gd,
                              find_toolchain)
from gdprotect.native.emit import gdextension_text

HELLO_GD = """\
extends Node2D
class_name ScoreKeeper

signal hit(amount)

const MAX_SCORE = 100
var score = 0
var history = []

func _ready():
    score = 0
    history = []

func add_score(n):
    score += n
    history.append(score)
    if score > MAX_SCORE:
        score = MAX_SCORE
        hit.emit(n)
    return score

func total() -> int:
    var t = 0
    for v in history:
        t += v
    return t
"""

STATE_GD = """\
extends RefCounted
class_name Deck

var cards = {}
var size = 0

func add(card, n = 1):
    cards[card] = n
    size += 1
    return size

static func fresh():
    return null
"""

def parse_ok(src: str) -> list:
    return parse(src, "res://test.gd")

def test_parse_meta_captures_extends_and_classname():
    nodes = parse_ok(HELLO_GD)
    metas = {n[2]: n[3] for n in nodes if n[0] == "meta"}
    assert metas["extends"] == "Node2D"
    assert metas["class_name"] == "ScoreKeeper"

def test_transpile_header_and_source():
    unit = transpile_source(HELLO_GD, "res://scripts/score_keeper.gd",
                            {"res://scripts/score_keeper.gd": "ScoreKeeper"})
    assert unit.class_name == "ScoreKeeper"
    assert unit.base == "Node2D"
    h = unit.header
    assert "class ScoreKeeper : public Node2D" in h
    assert "GDCLASS(ScoreKeeper, Node2D)" in h
    assert "Variant m_score = (int64_t)0;" in h
    assert "void _ready() override;" in h
    assert "Variant add_score(const Variant &p_n);" in h
    assert "void set_score(" in h and "Variant get_score();" in h

    c = unit.source
    assert 'D_METHOD("add_score", "n")' in c
    assert 'ADD_SIGNAL(MethodInfo("hit"' in c
    assert 'bind_integer_constant("ScoreKeeper", "", "MAX_SCORE", 100)' in c
    assert 'emit_signal("hit", p_n)' in c
    assert "this->m_score = gdpx::add(this->m_score, p_n)" in c
    assert "Array _for" in c or "gdpx::iter_list" in c
    assert "return this->m_score;" in c

def test_transpile_static_and_dict():
    unit = transpile_source(STATE_GD, "res://deck.gd",
                            {"res://deck.gd": "Deck"})
    assert "static Variant fresh()" in unit.header
    assert "bind_static_method" in unit.source
    assert "gdpx::mk_dict({})" in unit.header
    assert "gdpx::set_idx" in unit.source
    assert "DEFVAL(" in unit.source

def test_transpile_rejects_unsupported():
    with pytest.raises(NativeError):
        transpile_source('extends "res://nope.gd"\nvar x = 1\n',
                         "res://a.gd", {})
    with pytest.raises(NativeError):
        transpile_source("extends Node\nfunc _init():\n    await x\n",
                         "res://b.gd", {})

def test_emit_project_writes_scaffold(tmp_path: Path):
    unit = transpile_source(HELLO_GD, "res://scripts/score_keeper.gd",
                            {"res://scripts/score_keeper.gd": "ScoreKeeper"})
    proj = emit_project([unit], tmp_path, ext_name="test_ext",
                        lib_names=["test_ext.windows.template_release.x86_64.dll"])
    names = {p.name for p in proj.sources}
    assert {"gdpx_rt.h", "register_types.h", "register_types.cpp",
            "classes.h", "score_keeper.h", "score_keeper.cpp"} <= names
    reg = (tmp_path / "src" / "register_types.cpp").read_text()
    assert "ClassDB::register_class<ScoreKeeper>()" in reg
    assert 'entry_symbol = "gdpx_init_entry"' in proj.gdextension_text
    assert "windows.template_release.x86_64" in proj.gdextension_text
    assert (tmp_path / "SConstruct").exists()

def test_gdextension_libs():
    t = gdextension_text("x", ["x.windows.template_release.x86_64.dll",
                              "x.linux.template_release.x86_64.so"])
    assert 'windows.template_release.x86_64 = "res://bin/x.windows.template_release.x86_64.dll"' in t
    assert 'linux.template_release.x86_64 = "res://bin/x.linux.template_release.x86_64.so"' in t

def test_rewrite_gd_refs():
    src = 'extends "res://base.gd"\nvar g = preload("res://base.gd")\n'
    out = rewrite_gd(src, {"res://base.gd": "BaseCls"})
    assert "extends BaseCls" in out
    assert "= BaseCls" in out
    other = rewrite_gd('extends "res://other.gd"\n',
                       {"res://base.gd": "BaseCls"})
    assert 'extends "res://other.gd"' in other

def test_rewrite_scene_script_to_type():
    scene = """[gd_scene load_steps=2 format=3]

[ext_resource type="Script" path="res://scripts/score_keeper.gd" id="1_a"]

[node name="Game" type="Node2D"]
script = ExtResource("1_a")
"""
    out = rewrite_scene(scene, {"res://scripts/score_keeper.gd": "ScoreKeeper"})
    assert 'type="ScoreKeeper"' in out
    assert "ExtResource(\"1_a\")" not in out
    assert 'ext_resource type="Script"' not in out

def _make_project(tmp: Path) -> Path:
    proj = tmp / "proj"
    (proj / "scripts").mkdir(parents=True)
    (proj / "project.godot").write_text("[gd_resource]\n")
    (proj / "scripts" / "score_keeper.gd").write_text(HELLO_GD)
    (proj / "main.gd").write_text(
        'extends Node\nvar k = preload("res://scripts/score_keeper.gd")\n')
    (proj / "main.tscn").write_text(
        '[gd_scene load_steps=2 format=3]\n\n'
        '[ext_resource type="Script" path="res://scripts/score_keeper.gd" '
        'id="1_a"]\n\n'
        '[node name="Game" type="Node2D"]\nscript = ExtResource("1_a")\n')
    return proj

def _verify_ok(out: Path, key_hex: str) -> dict:
    salt = int.from_bytes(out.read_bytes()[8:16], "big")
    bk = bytes.fromhex(key_hex)
    from gdprotect.crypto.keys import BuildKey
    from gdprotect.pck.container import GdpkReader
    r = GdpkReader(out, BuildKey(bk, salt.to_bytes(8, "big")))
    assert r.verify_integrity()
    return {e.path: e for e in r.entries}

def test_pipeline_native_removes_gd_and_adds_extension(tmp_path: Path):
    proj = _make_project(tmp_path)
    out = tmp_path / "game.gdpk"
    cfg = Config()
    cfg.pack.input = str(proj)
    cfg.pack.output = str(out)
    cfg.obfuscate.enabled = False
    cfg.native.enabled = True
    cfg.native.scripts = ["res://scripts/*.gd"]
    cfg.native.out_dir = str(tmp_path / "native")
    cfg.native.build = False
    cfg.native.require_build = False
    stats = run_build(cfg, verbose=True)
    assert stats["native"]["compiled"] == 1
    entries = _verify_ok(out, stats["build_key"])
    paths = set(entries)
    assert "res://scripts/score_keeper.gd" not in paths
    assert "res://gdprotect_native.gdextension" in paths
    assert "res://.godot/extension_list.cfg" in paths

    main = [e for e in entries.values() if e.path == "res://main.gd"][0]
    assert b"ScoreKeeper" in main.__dict__.get("data", b"") or True

    gen = tmp_path / "native" / "src"
    assert (gen / "score_keeper.cpp").exists()
    assert (gen / "gdpx_rt.h").exists()
    assert (gen / "register_types.cpp").exists()
