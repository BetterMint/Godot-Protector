
from __future__ import annotations

from pathlib import Path

import pytest

from gdprotect.config import Config, ObfuscateConfig
from gdprotect.crypto.keys import BuildKey
from gdprotect.obfuscate.api import obfuscate_source
from gdprotect.pck.container import GdpkReader
from gdprotect.pipeline import run_build
from gdprotect.vm import strpool
from gdprotect.vm.strpool import (derive_strpool_key, hoist_source,
                                  open_pool, pack_pool, pool_path_for)

FIXTURE = Path(__file__).resolve().parent / "fixture"
BK = BuildKey.generate(0xC0FFEE)
POOL = "res://src/x.gd.gvms"

def hoist(src: str, pool: str = POOL):
    return hoist_source(src, pool)

class TestHoisting:
    def test_literals_replaced_in_order(self):
        src = (
            "extends Node\n"
            "func f():\n"
            "\tprint(\"alpha\")\n"
            "\tvar b = 'beta'\n"
            "\treturn \"gam\"\n"
        )
        out, pooled, _ = hoist(src)
        assert pooled == ["alpha", "beta", "gam"]
        assert 'print(__s(0))' in out
        assert "var b = __s(1)" in out
        assert "return __s(2)" in out
        assert "static func __s(i: int) -> String:" in out
        assert f'return Gdpk.str_at("{POOL}", i)' in out
        assert out.index("extends") < out.index("static func __s") \
            < out.index("func f")

    def test_identical_literals_share_one_slot(self):
        src = 'extends Node\nvar a = "dup"\nvar b = "dup"\nvar c = "x"\n'
        out, pooled, _ = hoist(src)
        assert pooled == ["dup", "x"]
        assert "__s(0)" in out and out.count("__s(0)") == 2
        assert "__s(1)" in out

    def test_loadbearing_paths_untouched(self):
        src = (
            'extends "res://base.gd"\n'
            'var p = preload("res://a.png")\n'
            'var l = load("res://b.png")\n'
            'func f():\n'
            '\treturn "ok"\n'
        )
        out, pooled, _ = hoist(src)
        assert 'extends "res://base.gd"' in out
        assert 'preload("res://a.png")' in out
        assert 'load("res://b.png")' in out
        assert pooled == ["ok"]
        assert "return __s(0)" in out

    def test_const_param_default_and_annotated_stay(self):
        src = (
            "extends Node\n"
            'const K = "cval"\n'
            '@export var s = "exp"\n'
            '@rpc("any_peer") func n(x = "dflt"):\n'
            "\treturn x\n"
        )
        out, pooled, _ = hoist(src)
        assert pooled == []
        assert out == src

    def test_empty_string_skipped(self):
        src = 'extends Node\nvar e = ""\nvar f = "full"\n'
        out, pooled, _ = hoist(src)
        assert pooled == ["full"]
        assert 'var e = ""' in out
        assert "var f = __s(0)" in out

    def test_prefixed_and_sigil_strings_skipped(self):
        src = (
            "extends Node\n"
            'var r = r"raw\\path"\n'
            'var n = &"Name"\n'
            'var p = ^"Node/Path"\n'
            'func f():\n'
            '\treturn $"icon".name\n'
        )
        out, pooled, _ = hoist(src)
        assert pooled == []
        assert out == src

    def test_stmt_position_strings_untouched(self):
        src = (
            '"""Module docstring."""\n'
            "extends Node\n"
            "func f():\n"
            '\t"""inner doc"""\n'
            '\treturn "v"\n'
        )
        out, pooled, _ = hoist(src)
        assert '"""Module docstring."""' in out
        assert '"""inner doc"""' in out
        assert pooled == ["v"]

    def test_multiline_literal_pooled(self):
        src = 'extends Node\nvar s = """line1\nline2"""\n'
        out, pooled, _ = hoist(src)
        assert pooled == ["line1\nline2"]
        assert "var s = __s(0)" in out

    def test_dict_keys_pooled_match_heads_skipped(self):
        src = (
            "extends Node\n"
            'var d = {"key": 1}\n'
            "func f(x):\n"
            "\tmatch x:\n"
            '\t\t"one":\n'
            '\t\t\treturn "uno"\n'
            "\t\t_:\n"
            '\t\t\treturn "other"\n'
        )
        out, pooled, _ = hoist(src)
        assert pooled == ["key", "uno", "other"]
        assert '{"key": 1}' not in out
        assert "{__s(0): 1}" in out
        assert '\t\t"one":' in out
        assert 'return __s(1)' in out
        assert 'return __s(2)' in out

    def test_existing___s_namespaces_to___sp(self):
        src = (
            "extends Node\n"
            "static func __s():\n"
            "\tpass\n"
            "func f():\n"
            '\treturn "x"\n'
        )
        out, pooled, _ = hoist(src)
        assert pooled == ["x"]
        assert "static func __sp(i: int) -> String:" in out
        assert "return __sp(0)" in out
        assert "static func __s():" in out

    def test_no_strings_returns_source_unchanged(self):
        for src in ["", "\n", "# only a comment\n", "extends Node\n",
                    "extends Node\nvar x := 4\nfunc f():\n\treturn x\n"]:
            out, pooled, contents = hoist(src)
            assert out == src
            assert pooled == []
            assert "__s" not in out

    def test_unicode_literal(self):
        src = 'extends Node\nvar s = "héllo wörld — ünïcode"\n'
        out, pooled, _ = hoist(src)
        assert pooled == ["héllo wörld — ünïcode"]
        assert "var s = __s(0)" in out

class TestBlob:
    def test_header_layout(self):
        blob = pack_pool(["aa", "b", "ccc"], BK, POOL)
        assert blob[:4] == b"GVMS"
        assert blob[4] == 1
        count = int.from_bytes(blob[5:9], "little")
        assert count == 3
        offs = [int.from_bytes(blob[21 + 4 * i:25 + 4 * i], "little")
                for i in range(3)]
        assert offs == [0, 2, 3]
        assert len(blob) == 21 + 12 + 6 + 16

    def test_roundtrip(self):
        strs = ["", "a", "bé — ünïcode", "x" * 1000, "line1\nline2\t\"q\""]
        strs = [s for s in strs if s]
        blob = pack_pool(strs, BK, POOL)
        assert open_pool(blob, BK, POOL) == strs

    def test_wrong_key_fails_auth(self):
        blob = pack_pool(["secret"], BK, POOL)
        with pytest.raises(Exception):
            open_pool(blob, BuildKey.generate(0xDEAD), POOL)

    def test_wrong_pool_path_fails_auth(self):
        blob = pack_pool(["secret"], BK, POOL)
        with pytest.raises(Exception):
            open_pool(blob, BK, "res://other.gd.gvms")

    def test_subkey_matches_runtime_contract(self):
        k = derive_strpool_key(BK, POOL)
        assert len(k) == 32
        assert k != BK.key
        assert k == derive_strpool_key(BK, POOL)

class TestPipeline:
    def test_build_emits_gvms_only_for_non_vm(self, tmp_path):
        out = tmp_path / "game.gdpk"
        cfg = Config()
        cfg.pack.input = str(FIXTURE)
        cfg.pack.output = str(out)
        cfg.virtualize.enabled = True
        cfg.virtualize.scripts = ["res://src/player.gd"]
        cfg.virtualize.stringpool = True
        cfg.seed = 7
        stats = run_build(cfg)
        assert stats["stringpooled"] == 1
        assert stats["virtualized"] == 1

        bk = BuildKey.generate(7)
        r = GdpkReader(out, bk)
        paths = {e.path for e in r.entries}
        assert "res://src/util.gd" in paths
        src = r.read_file("res://src/util.gd").decode("utf-8")
        assert "__s(" in src
        assert '"%06d"' not in src
        assert "res://src/util.gd.gvms" in paths
        blob = r.read_file("res://src/util.gd.gvms")
        assert open_pool(blob, bk, "res://src/util.gd.gvms") == ["%06d"]
        assert "res://src/player.gvmb" in paths
        assert "res://src/player.gd.gvms" not in paths
        assert "res://src/player.gd" not in paths

    def test_stringpool_off_by_default(self, tmp_path):
        out = tmp_path / "game.gdpk"
        cfg = Config()
        cfg.pack.input = str(FIXTURE)
        cfg.pack.output = str(out)
        cfg.seed = 3
        run_build(cfg)
        r = GdpkReader(out, BuildKey.generate(3))
        assert not any(e.path.endswith(".gvms") for e in r.entries)

    def test_pool_path_helper(self):
        assert pool_path_for("res://a/b.gd") == "res://a/b.gd.gvms"

class TestComposition:
    def test_obfuscate_after_strpool(self):
        src = (
            "extends Node\n"
            "func f():\n"
            '\tprint("alpha")\n'
            '\treturn "beta"\n'
        )
        out, pooled, contents = hoist(src)
        assert pooled == ["alpha", "beta"]
        obf = obfuscate_source(out, ObfuscateConfig(), "res://x.gd",
                               extra_str_contents=contents)
        assert "__s(" in obf or "__d(" in obf

    def test_pooled_contents_still_veto_renames(self):
        src = (
            "extends Node\n"
            "func target():\n"
            "\tpass\n"
            "func f():\n"
            '\tcall("target")\n'
        )
        out, pooled, contents = hoist(src)
        assert '"target"' not in out
        obf = obfuscate_source(out, ObfuscateConfig(rename_identifiers=True),
                               "res://x.gd", extra_str_contents=contents)
        assert "func target" in obf
