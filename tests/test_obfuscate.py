from gdprotect.config import ObfuscateConfig
from gdprotect.obfuscate.api import obfuscate_source

def test_decoder_comes_after_extends_and_docstring_kept():
    src = '''"""Player controller docstring."""
extends CharacterBody2D
class_name PlayerController

var speed := 5.0

func go():
	var msg = "go"
	print(msg)
'''
    out = obfuscate_source(src, ObfuscateConfig(), "res://a.gd")
    assert out.index("extends") < out.index("static func __d")
    assert '"""Player controller docstring."""' in out

def test_inner_class_setget_and_for_else_survive():
    src = '''extends Node

class Inner:
	var value := 0
	func bump():
		value += 1

var items = [
	"a", "b",
	"c",
]

var health = 10 setget set_health, get_health

func set_health(v):
	health = v

func get_health():
	return health

func count(n):
	var total := 0
	for k in range(n):
		total += k
	else:
		total += 0
	return total
'''
    out = obfuscate_source(src, ObfuscateConfig(), "res://b.gd")
    assert "class Inner" in out
    assert "set_health" in out and "get_health" in out
    assert "for" in out and "else:" in out

def test_preserve_list_keeps_names():
    cfg = ObfuscateConfig(preserve=["speed"])
    src = 'extends Node\nvar speed := 1\nfunc f():\n\tvar x = speed\n\treturn x\n'
    out = obfuscate_source(src, cfg, "res://c.gd")
    assert "var speed" in out

def test_empty_and_trivial_sources_dont_crash():
    cfg = ObfuscateConfig()
    for s in ["", "\n", "# only a comment\n", "extends Node\n"]:
        obfuscate_source(s, cfg, "res://d.gd")

def test_continuation_and_semicolons():
    src = '''extends Node
func f():
	var a = 1 + \\
		2
	var b = 3; var c = 4
	if a > 0: b = 2
	return a
'''
    out = obfuscate_source(src, ObfuscateConfig(), "res://e.gd")
    assert "return" in out

def test_reflective_string_veto_keeps_spelled_names():
    src = '''extends Node
var energy := 5
func f():
	self.set("energy", 6)
	call("f")
'''
    out = obfuscate_source(src, ObfuscateConfig(), "res://g.gd")
    assert "var energy" in out
    assert "func f" in out

def test_one_liner_funcs_and_lambdas():
    src = '''extends Node
func f(): return 1
var cb = func(x): return x * 2
func g():
	var y = cb.call(3)
	return y
'''
    out = obfuscate_source(src, ObfuscateConfig(), "res://h.gd")
    assert "call" in out

def test_output_is_deterministic():
    src = 'extends Node\nvar hp := 10\nfunc hurt():\n\thp -= 1\n'
    cfg = ObfuscateConfig()
    a = obfuscate_source(src, cfg, "res://i.gd")
    b = obfuscate_source(src, cfg, "res://i.gd")
    assert a == b
