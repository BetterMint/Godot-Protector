from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .ast import NativeError, parse
from ..vm.compiler import HOST_SLOTS

_BUILTIN_BASES = {
    "Object", "RefCounted", "Resource", "Node", "CanvasItem", "Node2D",
    "Control", "Node3D", "Sprite2D", "Sprite3D", "Area2D", "Area3D",
    "RigidBody2D", "RigidBody3D", "CharacterBody2D", "CharacterBody3D",
    "StaticBody2D", "StaticBody3D", "Timer", "Label", "Button", "Panel",
    "Camera2D", "Camera3D", "AudioStreamPlayer", "AudioStreamPlayer2D",
    "HTTPRequest", "SceneTree", "Window", "SubViewport", "AnimationPlayer",
    "TileMap", "TileMapLayer", "Line2D", "Polygon2D", "Path2D", "Marker2D",
    "TextureRect", "HBoxContainer", "VBoxContainer", "CenterContainer",
    "MarginContainer", "ScrollContainer", "GridContainer", "ItemList",
    "TabContainer", "RichTextLabel", "ProgressBar", "TextureProgressBar",
    "OptionButton", "LineEdit", "TextEdit", "CheckBox", "CheckButton",
    "HSlider", "VSlider", "SpinBox", "CanvasLayer", "ParallaxBackground",
    "AnimatedSprite2D", "AnimatedSprite3D", "GPUParticles2D",
    "GPUParticles3D", "CPUParticles2D", "CPUParticles3D", "RayCast2D",
    "RayCast3D", "CollisionShape2D", "CollisionShape3D", "NinePatchRect",
    "ShaderMaterial", "ResourceFormatLoader", "MainLoop", "EditorPlugin",
}

_SINGLETONS = {
    "Input", "Engine", "OS", "Time", "ProjectSettings", "DisplayServer",
    "RenderingServer", "PhysicsServer2D", "PhysicsServer2DManager",
    "PhysicsServer3D", "PhysicsServer3DManager", "AudioServer",
    "TranslationServer", "ResourceLoader", "ResourceSaver", "Performance",
    "ClassDB", "InputMap", "NavigationServer2D", "NavigationServer3D",
    "TextServerManager", "WorkerThreadPool", "JavaClassWrapper",
}

_CTOR_TYPES = {
    "Vector2", "Vector2i", "Vector3", "Vector3i", "Vector4", "Vector4i",
    "Color", "Rect2", "Rect2i", "Transform2D", "Transform3D", "Basis",
    "Quaternion", "AABB", "Plane", "Projection", "StringName", "NodePath",
    "Array", "Dictionary", "Callable", "Signal", "PackedByteArray",
    "PackedInt32Array", "PackedInt64Array", "PackedFloat32Array",
    "PackedFloat64Array", "PackedStringArray", "PackedVector2Array",
    "PackedVector3Array", "PackedVector4Array", "PackedColorArray",
    "RID",
}

_NUM_CONSTS = {
    "PI": "3.14159265358979323846", "TAU": "6.28318530717958647692",
    "INF": "INFINITY", "NAN": "NAN",
}

_VOID_VIRTUALS = {"_ready", "_enter_tree", "_exit_tree", "_draw",
                  "_tree_entered", "_tree_exited", "_tree_exiting"}
_DELTA_VIRTUALS = {"_process", "_physics_process", "_frame_pre_draw"}
_INPUT_VIRTUALS = {"_input", "_unhandled_input", "_unhandled_key_input",
                   "_shortcut_input"}
_INT_VIRTUALS = {"_notification"}
_FLOAT_INPUT = {"_gui_input", "_input_event", "_drag_data"}

_GDS_KEYWORDS = {"and", "or", "not", "in", "is", "as", "if", "elif",
                 "else", "for", "while", "return", "var", "const", "func",
                 "pass", "break", "continue", "self", "super", "signal",
                 "extends", "class_name", "static", "await", "yield",
                 "match", "enum", "class", "assert", "breakpoint",
                 "preload", "load", "void", "true", "false", "null",
                 "set", "get", "export", "onready", "tool", "remote",
                 "master", "puppet", "sync", "remotesync", "mastersync",
                 "puppetsync", "rpc", "rpc_id", "namespace", "trait",
                 "setget", "when", "PI", "TAU", "INF", "NAN"}

def _snake(name: str) -> str:
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    s = re.sub(r"([a-z])([A-Z])", r"\1_\2", s)
    return s.lower()

def _pascal(stem: str) -> str:
    return "".join(p[:1].upper() + p[1:] for p in re.split(r"[_\-\s]+", stem) if p)

def _cstr(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 32 or o == 127:
            out.append(f"\\x{o:02x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


@dataclass
class NativeUnit:
    res_path: str
    class_name: str
    base: str
    file_stem: str
    header: str
    source: str
    script_symbols: dict = field(default_factory=dict)
    all_names: list = field(default_factory=list)


class _Fn:
    def __init__(self, node):
        _, ln, name, params, body, static = node
        self.ln = ln
        self.name = name
        self.params = params
        self.body = body
        self.static = static


class _CG:
    def __init__(self, fn_name: str, res_path: str, class_map: dict,
                 script_classes: dict | None = None):
        self.fn = fn_name
        self.res_path = res_path
        self.class_map = class_map            # res://path.gd -> native class
        self.script_classes = script_classes or {}  # class name -> res://path
        self.base = "RefCounted"
        self.class_name = ""
        self.explicit_class_name = None
        self.funcs: list[_Fn] = []
        self.members: dict[str, tuple | None] = {}
        self.static_members: set[str] = set()
        self.consts: dict[str, tuple] = {}
        self.signals: dict[str, list[str]] = {}
        self.props: dict[str, tuple] = {}  # name -> (sparam, set_body, get_body)
        self.enums: dict[str, dict] = {}   # enum name -> {member: int}
        self.lambdas: list[tuple] = []     # (params, body, captures)
        self.lambda_ids: dict[int, int] = {}
        self.inners: dict[str, "_CG"] = {}  # inner class name -> sub _CG
        self._inner_nodes: list = []
        self.locals: set[str] = set()
        self.params: set[str] = set()
        self.caps: set[str] = set()
        self.tmp = 0
        self.ret_void = False
        self.in_prop = None

    # ---------------- lambda pre-pass ----------------
    def _bound_names(self, stmts) -> set:
        out = set()
        for s in stmts:
            if not isinstance(s, tuple):
                continue
            if s[0] in ("var", "lconst"):
                out.add(s[2])
            elif s[0] == "for":
                out.add(s[2])
                out |= self._bound_names(s[4])
            elif s[0] == "assign" and s[2][0] == "name":
                out.add(s[2][2])
            elif s[0] == "if":
                for c, b in s[2]:
                    out |= self._bound_names(b)
                if s[3]:
                    out |= self._bound_names(s[3])
            elif s[0] in ("while",):
                out |= self._bound_names(s[3])
            elif s[0] == "match":
                for _, _, b in s[3]:
                    out |= self._bound_names(b)
        return out

    def _uses(self, node, acc: list, skip_lambdas=True):
        if isinstance(node, tuple) and node and isinstance(node[0], str):
            if node[0] == "name":
                acc.append(node[2])
            if node[0] == "lambda" and skip_lambdas:
                return
            for x in node[1:]:
                self._uses(x, acc, skip_lambdas)
        elif isinstance(node, (list, tuple)):
            for x in node:
                self._uses(x, acc, skip_lambdas)

    def collect_lambdas(self):
        for f in self.funcs:
            bound = {p[0] for p in f.params} | self._bound_names(f.body)
            self._scan_body(f.body, bound)
        for name, init in self.members.items():
            if init is not None:
                self._scan_expr(init, set())
        for _sp, sb, gb in self.props.values():
            for b in (sb, gb):
                if b:
                    self._scan_body(b, set(self.members) | set(self.consts))

    def _scan_body(self, stmts, scope: set):
        for s in stmts:
            self._scan_expr(s, scope)

    def _scan_expr(self, e, scope: set):
        if not isinstance(e, (tuple, list)):
            return
        if isinstance(e, tuple) and e and e[0] == "lambda":
            idx = len(self.lambdas)
            self.lambda_ids[id(e)] = idx
            params, body = e[2], e[3]
            lbound = {p[0] for p in params} | self._bound_names(body)
            uses: list = []
            self._uses(body, uses)
            caps = []
            for u in uses:
                if u in scope and u not in lbound and u not in caps:
                    caps.append(u)
            self.lambdas.append((params, body, caps))
            self._scan_body(body, scope | lbound)
            return
        if isinstance(e, (tuple, list)):
            for x in e:
                self._scan_expr(x, scope)

    def err(self, msg, ln=0):
        raise NativeError(f"{self.res_path}:{ln}: {msg}")

    def analyze(self, nodes):
        for nd in nodes:
            tag = nd[0]
            if tag == "meta":
                if len(nd) > 3 and nd[3]:
                    if nd[2] == "extends":
                        if isinstance(nd[3], str) and nd[3].startswith("res://"):
                            target = self.class_map.get(nd[3])
                            if target is None:
                                self.err(f"native class cannot extend "
                                         f"non-native script {nd[3]!r} — "
                                         f"add it to native.scripts", nd[1])
                            self.base = target
                        else:
                            base = nd[3].split(".")[-1]
                            if base in self.class_map.values():
                                self.base = base
                            elif base in self.script_classes:
                                p = self.script_classes[base]
                                if p in self.class_map:
                                    self.base = self.class_map[p]
                                else:
                                    self.err(
                                        f"extends {base!r} (script {p}) — "
                                        f"the base script must also be "
                                        f"native-compiled", nd[1])
                            else:
                                # assume an engine class — the C++ compile
                                # verifies it
                                self.base = base
                    elif nd[2] == "class_name":
                        self.explicit_class_name = nd[3].split(".")[-1]
            elif tag == "func":
                self.funcs.append(_Fn(nd))
            elif tag == "member":
                name, init = nd[2], nd[3]
                self.members[name] = init
                if len(nd) > 6 and (nd[5] is not None or nd[6] is not None):
                    self.props[name] = (nd[4], nd[5], nd[6])
            elif tag == "enum":
                vals = self._enum_vals(nd[3], nd[1])
                if nd[2]:
                    self.enums[nd[2]] = vals
                for n, v in vals.items():
                    self.consts[n] = ("lit", nd[1], v)
            elif tag == "const":
                self.consts[nd[2]] = nd[3]
            elif tag == "var" or tag == "lconst":
                # inner-class bodies emit these tags for members/consts
                if tag == "var":
                    self.members[nd[2]] = nd[3]
                    if len(nd) > 6 and (nd[5] is not None
                                        or nd[6] is not None):
                        self.props[nd[2]] = (nd[4], nd[5], nd[6])
                else:
                    self.consts[nd[2]] = nd[3]
            elif tag == "innerclass":
                self._inner_nodes.append(nd)
            elif tag == "signal":
                self.signals[nd[2]] = nd[3]
        stem = Path(self.res_path).stem
        self.class_name = self.explicit_class_name or _pascal("gd_" + stem) or "GdScript"
        if self.class_name in _BUILTIN_BASES or self.class_name in _SINGLETONS:
            self.err(f"class_name {self.class_name!r} collides with an engine class", 0)
        for name in list(self.members) + list(self.consts) + [f.name for f in self.funcs] + list(self.signals):
            if re.match(r"^[A-Za-z_]\w*$", name) is None:
                self.err(f"identifier {name!r} cannot be emitted as C++", 0)
        for nd in self._inner_nodes:
            sub = _CG(self.fn, self.res_path + "#" + nd[2],
                      self.class_map, self.script_classes)
            sub.class_name = f"{self.class_name}_{nd[2]}"
            if nd[3] is not None:
                sub.base = self._inner_base(nd[3], nd[1])
            sub.analyze(nd[4])
            self.inners[nd[2]] = sub

    def _inner_base(self, expr, ln) -> str:
        if expr[0] == "name":
            b = expr[2]
            if b in self.class_map.values():
                return b
            if b in self.script_classes:
                p = self.script_classes[b]
                if p in self.class_map:
                    return self.class_map[p]
                self.err(f"inner class extends non-native script {b!r}", ln)
            if b in self.inners:
                return self.inners[b].class_name
            return b  # assume engine class
        if expr[0] == "attr":
            return expr[3].split(".")[-1]
        if expr[0] == "call" and expr[2][0] == "name" \
                and expr[2][2] in ("load", "preload") \
                and expr[3] and expr[3][0][0] == "lit" \
                and isinstance(expr[3][0][2], str):
            p = expr[3][0][2]
            if p in self.class_map:
                return self.class_map[p]
            self.err(f"inner class extends non-native script {p!r}", ln)
        self.err("unsupported inner-class base", ln)

    # ---------------- expression emitter ----------------
    def E(self, e) -> str:
        tag = e[0]
        if tag == "lit":
            return self._lit(e[2])
        if tag == "name":
            return self._name(e[2], e[1])
        if tag == "self":
            return "Variant(this)"
        if tag == "lambda":
            idx = self.lambda_ids.get(id(e))
            if idx is None:
                self.err("lambda not registered", e[1])
            params, body, caps = self.lambdas[idx]
            lam = f"callable_mp(this, &{self.class_name}::_l{idx})"
            if caps:
                inner = ", ".join(self._name(w, e[1]) for w in caps)
                lam = f"{lam}.bind({inner})"
            return f"Variant(Callable({lam}))"
        if tag == "attr":
            base = e[2]
            if base[0] == "self":
                return self._member_ref(e[3], e[1])
            if base[0] == "name" and base[2] in self.enums \
                    and e[3] in self.enums[base[2]]:
                return f"Variant((int64_t){self.enums[base[2]][e[3]]})"
            if base[0] == "name" and base[2] in self.inners:
                sub = self.inners[base[2]]
                if e[3] in sub.consts:
                    return f"Variant({sub.class_name}::c_{e[3]})"
                self.err(f"inner class {base[2]} has no member {e[3]!r}",
                         e[1])
            return f"gdpx::get_attr({self.E(base)}, {_cstr(e[3])})"
        if tag == "index":
            return f"gdpx::idx({self.E(e[2])}, {self.E(e[3])})"
        if tag == "call":
            return self._call(e)
        if tag == "bin":
            return self._bin(e)
        if tag == "unary":
            return self._unary(e)
        if tag == "tern":
            return (f"(gdpx::truth({self.E(e[2])}) ? Variant({self.E(e[3])})"
                    f" : Variant({self.E(e[4])}))")
        if tag == "array":
            return "gdpx::mk_array({" + ", ".join(self.E(x) for x in e[2]) + "})"
        if tag == "dict":
            inner = ", ".join(
                "{" + self.E(k) + ", " + self.E(v) + "}" for k, v in e[2])
            return "gdpx::mk_dict({" + inner + "})"
        if tag == "getnode":
            return f"gdpx::get_node(this, String({_cstr(e[2])}))"
        if tag == "istype":
            tn = e[3].split(".")[-1]
            tn = self.inners[tn].class_name if tn in self.inners else tn
            return f"(Variant)gdpx::is_class({self.E(e[2])}, {_cstr(tn)})"
        if tag == "astype":
            tn = e[3].split(".")[-1]
            tn = self.inners[tn].class_name if tn in self.inners else tn
            return f"gdpx::as_class({self.E(e[2])}, {_cstr(tn)})"
        self.err(f"unsupported expression tag {tag!r}", e[1] if len(e) > 1 else 0)

    def _lit(self, v) -> str:
        if v is None:
            return "Variant()"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, int):
            if abs(v) > 0x7FFFFFFFFFFFFFFF:
                self.err("int literal out of range")
            return f"(int64_t){v}LL" if v < 0 else f"(int64_t){v}"
        if isinstance(v, float):
            if v != v:
                return "NAN"
            if v == float("inf"):
                return "INFINITY"
            if v == float("-inf"):
                return "-INFINITY"
            r = repr(v)
            return r if ("." in r or "e" in r or "E" in r) else r + ".0"
        if isinstance(v, str):
            return f"String({_cstr(v)})"
        if isinstance(v, (list, tuple)):
            return "gdpx::mk_array({" + ", ".join(self._lit(x) for x in v) + "})"
        if isinstance(v, dict):
            inner = ", ".join(
                "{" + self._lit(k) + ", " + self._lit(x) + "}" for k, x in v.items())
            return "gdpx::mk_dict({" + inner + "})"
        self.err(f"unsupported literal {type(v)}")

    def _member_ref(self, name: str, ln=0) -> str:
        if name in self.members:
            if name in self.props and self.in_prop != name:
                return f"this->get_{name}()"
            return f"this->m_{name}"
        if name in self.consts:
            return self._const_ref(name)
        if name in self.signals:
            return f"Signal(this, {_cstr(name)})"
        if name in {f.name for f in self.funcs}:
            return f"Callable(this, {_cstr(name)})"
        return f"gdpx::get_attr(Variant(this), {_cstr(name)})"

    def _const_ref(self, name: str) -> str:
        return f"c_{name}"

    def _name(self, w: str, ln=0) -> str:
        if w in self.locals:
            return f"v_{w}"
        if w in self.params:
            return f"p_{w}"
        if w in self.caps:
            return f"c_{w}"
        if w in self.members:
            if w in self.props and self.in_prop != w:
                return f"this->get_{w}()"
            return f"this->m_{w}"
        if w in self.consts:
            return self._const_ref(w)
        if w in self.signals:
            return f"Signal(this, {_cstr(w)})"
        if w in {f.name for f in self.funcs}:
            return f"Callable(this, {_cstr(w)})"
        if w in _SINGLETONS:
            return f"Variant({w}::get_singleton())"
        if w in _NUM_CONSTS:
            return _NUM_CONSTS[w]
        if w in _CTOR_TYPES:
            return f"Variant() /* bare type {w} */"
        if w in self.class_map.values():
            return f"Variant() /* class {w} */"
        if w in self.script_classes:
            return f"gdpx::load_res({_cstr(self.script_classes[w])})"
        if w in self.enums:
            return f"/* enum {w} */ Variant()"
        if w in self.inners:
            return f"/* inner {w} */ Variant()"
        # inherited engine property or script-class name resolved at runtime
        return f"gdpx::get_attr(Variant(this), {_cstr(w)})"

    def _enum_vals(self, items, ln) -> dict:
        out = {}
        nxt = 0
        for n, e in items:
            if e is not None:
                v = self._const_eval(e)
                if not isinstance(v, int):
                    self.err(f"enum value {n!r} is not a constant int", ln)
                nxt = v
            out[n] = nxt
            nxt += 1
        return out

    def _const_eval(self, e):
        tag = e[0]
        if tag == "lit":
            return e[2]
        if tag == "name" and e[2] in self.consts:
            return self._const_eval(self.consts[e[2]])
        if tag == "name" and e[2] in _NUM_CONSTS:
            import math
            return {"PI": math.pi, "TAU": math.tau, "INF": math.inf,
                    "NAN": math.nan}[e[2]]
        if tag == "unary":
            v = self._const_eval(e[3])
            return {"-": -v, "+": +v, "~": ~v if isinstance(v, int) else None,
                    "not": not v, "!": not v}.get(e[2])
        if tag == "bin":
            a, b = self._const_eval(e[3]), self._const_eval(e[4])
            try:
                return {"+": a + b, "-": a - b, "*": a * b,
                        "/": a // b if isinstance(a, int) and isinstance(b, int)
                        else a / b, "%": a % b, "**": a ** b,
                        "<<": a << b, ">>": a >> b, "&": a & b,
                        "|": a | b, "^": a ^ b}[e[2]]
            except Exception:
                pass
        self.err("non-constant expression in enum", e[1] if len(e) > 1 else 0)

    def _call(self, e) -> str:
        ln = e[1]
        callee = e[2]
        args = e[3]
        if callee[0] == "name":
            w = callee[2]
            if w == "range":
                vals = [self.E(a) for a in args]
                if not (1 <= len(vals) <= 3):
                    self.err("range() takes 1-3 args", ln)
                a = vals[0] if len(vals) > 1 else "(int64_t)0"
                b = vals[1] if len(vals) > 1 else vals[0]
                s = vals[2] if len(vals) > 2 else "(int64_t)1"
                return (f"gdpx::range_arr((int64_t)gdpx::to_int({a}), "
                        f"(int64_t)gdpx::to_int({b}), (int64_t)gdpx::to_int({s}))")
            if w in ("load", "preload"):
                if args and args[0][0] == "lit" and isinstance(args[0][2], str) \
                        and args[0][2] in self.class_map:
                    return (f"Variant(ClassDB::instantiate("
                            f"{_cstr(self.class_map[args[0][2]])}))")
                return "gdpx::load_res(" + self.E(args[0]) + ")"
            if w in ("int", "float", "bool"):
                return f"(Variant)gdpx::to_{w}({self.E(args[0])})"
            if w == "str":
                return f"(Variant)gdpx::to_str({self.E(args[0])})"
            if w == "len":
                return f"(Variant)gdpx::len({self.E(args[0])})"
            if w in ("print", "printerr", "print_debug", "prints",
                     "push_error", "push_warning"):
                inner = ", ".join(self.E(a) for a in args)
                return f"UtilityFunctions::{w}({inner})"
            if w in _CTOR_TYPES:
                inner = ", ".join(self.E(a) for a in args)
                return f"Variant({w}({inner}))"
            if w in _NUM_CONSTS:
                self.err(f"'{w}' is a constant, not callable", ln)
            if w in self.class_map.values():
                if len(args) == 0:
                    return f"Variant(ClassDB::instantiate({_cstr(w)}))"
                self.err(f"class {w} constructor takes no args", ln)
            if w in {f.name for f in self.funcs}:
                fn = next(f for f in self.funcs if f.name == w)
                flat = [self.E(a) for a in args]
                if len(flat) < len(fn.params):
                    for pname, dflt in fn.params[len(flat):]:
                        if dflt is None:
                            self.err(f"call to '{w}' missing required arg "
                                     f"'{pname}'", ln)
                        flat.append(self.E(dflt))
                inner = ", ".join(flat)
                return f"this->{w}({inner})"
            if w in self.locals or w in self.members or w in self.params:
                tgt = (f"v_{w}" if w in self.locals
                       else f"p_{w}" if w in self.params else f"this->m_{w}")
                inner = ", ".join(self.E(a) for a in args)
                return f"gdpx::callv({tgt}, {{{inner}}})"
            inner = ", ".join(self.E(a) for a in args)
            return f"this->call({_cstr(w)}{', ' if inner else ''}{inner})"
        if callee[0] == "attr":
            obj, m = callee[2], callee[3]
            if m == "emit" and obj[0] in ("name",) and obj[2] in self.signals:
                inner = ", ".join(self.E(a) for a in args)
                return f"this->emit_signal({_cstr(obj[2])}{', ' if inner else ''}{inner})"
            if m in ("connect", "disconnect") and obj[0] == "name" \
                    and obj[2] in self.signals:
                inner = ", ".join(self.E(a) for a in args)
                return f"this->{m}({_cstr(obj[2])}, {inner})"
            if m == "new":
                if obj[0] == "call" and obj[2][0] == "name" \
                        and obj[2][2] in ("load", "preload") \
                        and obj[3] and obj[3][0][0] == "lit" \
                        and isinstance(obj[3][0][2], str) \
                        and obj[3][0][2] in self.class_map:
                    return (f"Variant(ClassDB::instantiate("
                            f"{_cstr(self.class_map[obj[3][0][2]])}))")
                if obj[0] == "name" and obj[2] in self.class_map.values():
                    return f"Variant(ClassDB::instantiate({_cstr(obj[2])}))"
                if obj[0] == "name" and obj[2] in self.script_classes:
                    return (f"gdpx::instantiate_script("
                            f"{_cstr(self.script_classes[obj[2]])})")
                if obj[0] == "name" and obj[2] in self.inners:
                    return (f"Variant(ClassDB::instantiate("
                            f"{_cstr(self.inners[obj[2]].class_name)}))")
            inner = ", ".join(self.E(a) for a in args)
            return f"gdpx::call_m({self.E(obj)}, {_cstr(m)}, {{{inner}}})"
        if callee[0] == "self":
            self.err("'self()' call", ln)
        inner = ", ".join(self.E(a) for a in args)
        return f"gdpx::callv({self.E(callee)}, {{{inner}}})"

    _BIN = {"+": "add", "-": "sub", "*": "mul", "/": "div", "%": "mod",
            "**": "pow_", "&": "band", "|": "bor", "^": "bxor",
            "<<": "shl", ">>": "shr"}

    def _bin(self, e) -> str:
        ln, op, a, b = e[1], e[2], e[3], e[4]
        if op == "and":
            return f"(Variant)(gdpx::truth({self.E(a)}) && gdpx::truth({self.E(b)}))"
        if op == "or":
            return f"(Variant)(gdpx::truth({self.E(a)}) || gdpx::truth({self.E(b)}))"
        if op in ("in", "notin"):
            r = f"gdpx::in_({self.E(a)}, {self.E(b)})"
            return f"(Variant)(!({r}))" if op == "notin" else f"(Variant)({r})"
        if op in self._BIN:
            return f"gdpx::{self._BIN[op]}({self.E(a)}, {self.E(b)})"
        cmpf = {"==": "eq", "!=": "ne", "<": "lt", "<=": "le",
                ">": "gt", ">=": "ge"}.get(op)
        if cmpf:
            return f"(Variant)gdpx::{cmpf}({self.E(a)}, {self.E(b)})"
        self.err(f"unsupported operator {op!r}", ln)

    def _unary(self, e) -> str:
        ln, op, x = e[1], e[2], e[3]
        if op in ("not", "!"):
            return f"(Variant)(!gdpx::truth({self.E(x)}))"
        if op == "-":
            return f"gdpx::neg({self.E(x)})"
        if op == "~":
            return f"gdpx::bnot({self.E(x)})"
        if op == "+":
            return self.E(x)
        self.err(f"unsupported unary {op!r}", ln)

    # ---------------- statement emitter ----------------
    def S(self, stmt, ind: str, out: list[str]):
        tag = stmt[0]
        ln = stmt[1]
        if tag == "var" or tag == "lconst":
            name, init = stmt[2], stmt[3]
            self.locals.add(name)
            pre = "const Variant" if tag == "lconst" else "Variant"
            if init is None:
                out.append(f"{ind}{pre} v_{name};")
            else:
                out.append(f"{ind}{pre} v_{name} = {self.E(init)};")
            return
        if tag == "assign":
            tgt, op, val = stmt[2], stmt[3], stmt[4]
            self._assign(tgt, op, val, ind, out)
            return
        if tag == "expr":
            out.append(f"{ind}{self.E(stmt[2])};")
            return
        if tag == "return":
            if self.ret_void:
                if stmt[2] is not None:
                    out.append(f"{ind}gdpx::ignore({self.E(stmt[2])});")
                out.append(f"{ind}return;")
            elif stmt[2] is None:
                out.append(f"{ind}return Variant();")
            else:
                out.append(f"{ind}return {self.E(stmt[2])};")
            return
        if tag == "if":
            cases, els = stmt[2], stmt[3]
            for i, (cond, suite) in enumerate(cases):
                kw = "if" if i == 0 else "else if"
                out.append(f"{ind}{kw} (gdpx::truth({self.E(cond)})) {{")
                self._suite(suite, ind + "    ", out)
                out.append(f"{ind}}}")
            if els is not None:
                out.append(f"{ind}else {{")
                self._suite(els, ind + "    ", out)
                out.append(f"{ind}}}")
            return
        if tag == "while":
            out.append(f"{ind}while (gdpx::truth({self.E(stmt[2])})) {{")
            self._suite(stmt[3], ind + "    ", out)
            out.append(f"{ind}}}")
            return
        if tag == "for":
            var, it = stmt[2], stmt[3]
            self.locals.add(var)
            self._for(var, it, stmt[4], ind, out)
            return
        if tag == "match":
            self.tmp += 1
            mv = f"_m{self.tmp}"
            out.append(f"{ind}{{")
            out.append(f"{ind}    Variant {mv} = {self.E(stmt[2])};")
            first = True
            for pats, guard, body in stmt[3]:
                conds = [f"gdpx::eq({mv}, {self.E(p)})"
                         for p in pats if p[0] != "wild"]
                cond = " || ".join(conds)
                if guard is not None:
                    cond = (f"({cond}) && gdpx::truth({self.E(guard)})"
                            if cond else f"gdpx::truth({self.E(guard)})")
                if cond:
                    kw = "if" if first else "else if"
                    out.append(f"{ind}    {kw} ({cond}) {{")
                else:
                    out.append(f"{ind}    else {{" if not first
                               else f"{ind}    {{")
                self._suite(body, ind + "        ", out)
                out.append(f"{ind}    }}")
                first = False
            out.append(f"{ind}}}")
            return
        if tag == "enum":
            for n, v in self._enum_vals(stmt[3], ln).items():
                self.locals.add(n)
                out.append(f"{ind}const int64_t v_{n} = {v};")
            return
        if tag == "pass":
            out.append(f"{ind};")
            return
        if tag in ("break", "continue"):
            out.append(f"{ind}{tag};")
            return
        self.err(f"unsupported statement {tag!r}", ln)

    def _for(self, var, it, body, ind, out):
        if it[0] == "call" and it[2][0] == "name" and it[2][2] == "range":
            args = [self.E(a) for a in it[3]]
            if len(args) == 1:
                lo, hi, st = "0", args[0], "1"
            elif len(args) == 2:
                lo, hi, st = args[0], args[1], "1"
            else:
                lo, hi, st = args[0], args[1], args[2]
            self.tmp += 1
            stv = f"_st{self.tmp}"
            out.append(f"{ind}for (int64_t v_{var} = gdpx::to_int({lo}), "
                       f"{stv} = gdpx::to_int({st}); "
                       f"({stv} > 0) ? (v_{var} < gdpx::to_int({hi})) "
                       f": (v_{var} > gdpx::to_int({hi})); "
                       f"v_{var} += {stv}) {{")
            self._suite(body, ind + "    ", out)
            out.append(f"{ind}}}")
            return
        self.tmp += 1
        t = f"_for{self.tmp}"
        out.append(f"{ind}{{ Array {t} = gdpx::iter_list({self.E(it)});")
        out.append(f"{ind}  for (int64_t {t}_i = 0; {t}_i < {t}.size(); "
                   f"++{t}_i) {{")
        out.append(f"{ind}      Variant v_{var} = {t}[{t}_i];")
        self._suite(body, ind + "        ", out)
        out.append(f"{ind}  }} }}")
        return

    def _assign(self, tgt, op, val, ind, out):
        v = self.E(val)
        if op == "=":
            rhs = v
        elif op in _CMPND:
            rhs = f"gdpx::{_CMPND[op]}(<t>, {v})"
        else:
            self.err(f"unsupported assignment op {op!r}")
        if tgt[0] == "name":
            w = tgt[2]
            if w in self.locals:
                ref = f"v_{w}"
            elif w in self.params:
                ref = f"p_{w}"
            elif w in self.members:
                if w in self.props and self.in_prop != w:
                    cur = f"this->get_{w}()"
                    out.append(f"{ind}this->set_{w}("
                               f"{rhs.replace('<t>', cur)});")
                    return
                ref = f"this->m_{w}"
            elif w in self.consts:
                self.err(f"cannot assign to const {w!r}", tgt[1])
            else:
                self.locals.add(w)
                ref = f"v_{w}"
            out.append(f"{ind}{ref} = {rhs.replace('<t>', ref)};")
            return
        if tgt[0] == "attr":
            base = tgt[2]
            if base[0] == "self" and tgt[3] in self.members:
                w = tgt[3]
                if w in self.props and self.in_prop != w:
                    cur = f"this->get_{w}()"
                    out.append(f"{ind}this->set_{w}("
                               f"{rhs.replace('<t>', cur)});")
                    return
                ref = f"this->m_{w}"
                out.append(f"{ind}{ref} = {rhs.replace('<t>', ref)};")
                return
            b = self.E(base)
            if op == "=":
                out.append(f"{ind}gdpx::set_attr({b}, {_cstr(tgt[3])}, {v});")
            else:
                out.append(f"{ind}gdpx::set_attr({b}, {_cstr(tgt[3])}, "
                           f"{rhs.replace('<t>', 'gdpx::get_attr(' + b + ', ' + _cstr(tgt[3]) + ')')});")
            return
        if tgt[0] == "index":
            b = self.E(tgt[2])
            k = self.E(tgt[3])
            if op == "=":
                out.append(f"{ind}gdpx::set_idx({b}, {k}, {v});")
            else:
                out.append(f"{ind}gdpx::set_idx({b}, {k}, "
                           f"{rhs.replace('<t>', 'gdpx::idx(' + b + ', ' + k + ')')});")
            return
        self.err("invalid assignment target", tgt[1])

    _CMPND = {"+=": "add", "-=": "sub", "*=": "mul", "/=": "div",
              "%=": "mod", "**=": "pow_", "&=": "band", "|=": "bor",
              "^=": "bxor", "<<=": "shl", ">>=": "shr"}

    def _suite(self, stmts, ind, out):
        if not stmts:
            out.append(ind + ";")
            return
        for s in stmts:
            self.S(s, ind, out)

    # ---------------- member init ----------------
    def _member_init_expr(self, name, init, ln):
        if init is None:
            return ""
        return " = " + self.E(init)

    def _const_init(self, name, e, ln):
        return " = " + self.E(e)


_CMPND = _CG._CMPND

def _sig(fn: _Fn, owner: _CG) -> tuple[str, str]:
    name = fn.name
    params = ", ".join(f"const Variant &p_{p[0]}" for p in fn.params)
    if name == "_init":
        return None, None
    if name in _VOID_VIRTUALS:
        return f"void {name}() override", "void"
    if name in _DELTA_VIRTUALS:
        p = params or "const Variant &p_delta"
        return f"void {name}(double p_delta) override", "void"
    if name in _INPUT_VIRTUALS:
        return f"void {name}(const Ref<InputEvent> &p_event) override", "void"
    if name in _INT_VIRTUALS:
        return f"void {name}(int p_what) override", "void"
    static = "static " if fn.static else ""
    return f"{static}Variant {name}({params})", "variant"


def transpile_source(source: str, res_path: str,
                     class_map: dict | None = None,
                     script_classes: dict | None = None) -> NativeUnit:
    nodes = parse(source, res_path)
    cg = _CG(res_path, res_path, class_map or {}, script_classes)
    cg.analyze(nodes)
    cg.collect_lambdas()

    cls = cg.class_name
    fn_stem = Path(res_path).stem
    cgs = [cg] + list(cg.inners.values())
    for sub in cgs[1:]:
        sub.collect_lambdas()

    # ---------- header ----------
    h = []
    h.append("#pragma once")
    native_names = set(cg.class_map.values()) | {x.class_name for x in cgs}
    seen_inc = set()
    for sub in cgs:
        if sub.base not in native_names:
            inc = f"#include <godot_cpp/classes/{_snake(sub.base)}.hpp>"
            if inc not in seen_inc:
                h.append(inc); seen_inc.add(inc)
        if _INPUT_VIRTUALS & {f.name for f in sub.funcs}:
            for inc in ("#include <godot_cpp/classes/input_event.hpp>",
                        "#include <godot_cpp/classes/ref.hpp>"):
                if inc not in seen_inc:
                    h.append(inc); seen_inc.add(inc)
        if sub.lambdas:
            for inc in ("#include <godot_cpp/variant/callable.hpp>",
                        "#include <godot_cpp/variant/callable_method_pointer.hpp>"):
                if inc not in seen_inc:
                    h.append(inc); seen_inc.add(inc)
    h.append("#include <godot_cpp/variant/variant.hpp>")
    h.append("#include <godot_cpp/variant/string.hpp>")
    h.append("#include <godot_cpp/variant/string_name.hpp>")
    h.append('#include "gdpx_rt.h"')
    h.append("")
    h.append("using namespace godot;")
    h.append("")
    for sub in cgs:
        h += _emit_decl(sub)

    # ---------- source ----------
    c = []
    c.append(f'#include "{fn_stem}.h"')
    c.append("#include <godot_cpp/core/class_db.hpp>")
    c.append("#include <godot_cpp/variant/utility_functions.hpp>")
    c.append("")
    c.append("using namespace godot;")
    c.append("")
    for sub in cgs:
        c += _emit_impl(sub)

    return NativeUnit(res_path=res_path, class_name=cls, base=cg.base,
                      file_stem=fn_stem, header="\n".join(h),
                      source="\n".join(c),
                      all_names=[x.class_name for x in cgs])


def _emit_decl(cg: _CG) -> list[str]:
    cls = cg.class_name
    h = []
    h.append(f"class {cls} : public {cg.base} {{")
    h.append(f"    GDCLASS({cls}, {cg.base})")
    h.append("")
    for name, init in cg.members.items():
        expr = ""
        if init is not None:
            cg.locals = set()
            expr = " = " + cg.E(init)
        h.append(f"    Variant m_{name}{expr};")
    for cname in cg.consts:
        h.append(f"    static const Variant c_{cname};")
    h.append("    static void _bind_methods();")
    h.append("public:")
    h.append(f"    {cls}();")
    for m in cg.members:
        if m in cg.props:
            sparam = cg.props[m][0]
            h.append(f"    void set_{m}(const Variant &p_{sparam});")
            h.append(f"    Variant get_{m}();")
        else:
            h.append(f"    void set_{m}(const Variant &p_v);")
            h.append(f"    Variant get_{m}() const;")
    for f in cg.funcs:
        proto, kind = _sig(f, cg)
        if proto:
            h.append(f"    {proto};")
    for i, (params, _body, caps) in enumerate(cg.lambdas):
        args = ", ".join([f"Variant p_{p[0]}" for p in params]
                         + [f"Variant c_{w}" for w in caps])
        h.append(f"    Variant _l{i}({args});")
    h.append("};")
    h.append("")
    return h


def _emit_impl(cg: _CG) -> list[str]:
    cls = cg.class_name
    c = []
    for cname, ce in cg.consts.items():
        c.append(f"const Variant {cls}::c_{cname}{cg._const_init(cname, ce, 0)};")
    c.append("")
    c.append(f"void {cls}::_bind_methods() {{")
    for f in cg.funcs:
        proto, kind = _sig(f, cg)
        if not proto or f.name == "_init":
            continue
        argnames = ", ".join(_cstr(p[0]) for p in f.params)
        dm = f'D_METHOD({_cstr(f.name)}{", " if argnames else ""}{argnames})'
        defvals = "".join(
            f", DEFVAL({cg.E(p[1])})" for p in f.params if p[1] is not None)
        if f.static:
            c.append(f"    ClassDB::bind_static_method({_cstr(cls)}, {dm}, "
                     f"&{cls}::{f.name}{defvals});")
        elif kind == "variant":
            c.append(f"    ClassDB::bind_method({dm}, &{cls}::{f.name}{defvals});")
    for m in cg.members:
        c.append(f"    ClassDB::bind_method(D_METHOD(\"set_{m}\", \"v\"), "
                 f"&{cls}::set_{m});")
        c.append(f"    ClassDB::bind_method(D_METHOD(\"get_{m}\"), "
                 f"&{cls}::get_{m});")
        c.append(f'    ADD_PROPERTY(PropertyInfo(Variant::NIL, "{m}"), '
                 f'"set_{m}", "get_{m}");')
    for sname, params in cg.signals.items():
        plist = ", ".join(
            f'PropertyInfo(Variant::NIL, "{p}")' for p in params)
        c.append(f'    ADD_SIGNAL(MethodInfo("{sname}"{", " if plist else ""}'
                 f"{plist}));")
    for cname, ce in cg.consts.items():
        if ce[0] == "lit" and isinstance(ce[2], int):
            c.append(f'    ClassDB::bind_integer_constant("{cls}", "", '
                     f'"{cname}", {ce[2]});')
    c.append("}")
    c.append("")

    c.append(f"{cls}::{cls}() {{")
    init_fn = next((f for f in cg.funcs if f.name == "_init"), None)
    if init_fn:
        cg.locals = set()
        cg.params = set()
        body: list[str] = []
        cg._suite(init_fn.body, "    ", body)
        c.extend(body or ["    ;"])
    c.append("}")
    c.append("")

    for m in cg.members:
        prop = cg.props.get(m)
        if prop is None:
            c.append(f"void {cls}::set_{m}(const Variant &p_v) {{ m_{m} = p_v; }}")
            c.append(f"Variant {cls}::get_{m}() const {{ return m_{m}; }}")
            continue
        sparam, set_body, get_body = prop
        if set_body is not None:
            c.append(f"void {cls}::set_{m}(const Variant &p_{sparam}) {{")
            cg.locals, cg.params = set(), {sparam}
            cg.in_prop, cg.ret_void = m, True
            body: list[str] = []
            cg._suite(set_body, "    ", body)
            c.extend(body or ["    ;"])
            c.append("}")
            cg.in_prop = None
        else:
            c.append(f"void {cls}::set_{m}(const Variant &p_{sparam}) "
                     f"{{ m_{m} = p_{sparam}; }}")
        c.append(f"Variant {cls}::get_{m}() {{")
        if get_body is not None:
            cg.locals, cg.params = set(), set()
            cg.in_prop, cg.ret_void = m, False
            body = []
            cg._suite(get_body, "    ", body)
            c.extend(body or ["    ;"])
        else:
            c.append(f"    return m_{m};")
        c.append("}")
        cg.in_prop = None
    if cg.members:
        c.append("")

    for f in cg.funcs:
        proto, kind = _sig(f, cg)
        if not proto or f.name == "_init":
            continue
        bind = None
        sig = None
        if kind == "variant":
            cg.params = {p[0] for p in f.params}
            cg.locals = set()
        else:
            cg.params = set()
            cg.locals = set()
        cg.caps = set()
        if kind != "variant":
            name = f.name
            orig = f.params[0][0] if f.params else None
            if name in _VOID_VIRTUALS:
                sig = f"void {cls}::{name}()"
            elif name in _DELTA_VIRTUALS:
                sig = f"void {cls}::{name}(double p_delta)"
                if orig:
                    cg.locals = {orig}
                    bind = f"    Variant v_{orig} = p_delta;"
            elif name in _INPUT_VIRTUALS:
                sig = f"void {cls}::{name}(const Ref<InputEvent> &p_event)"
                if orig:
                    cg.locals = {orig}
                    bind = f"    Variant v_{orig} = Variant(p_event.ptr());"
            elif name in _INT_VIRTUALS:
                sig = f"void {cls}::{name}(int p_what)"
                if orig:
                    cg.locals = {orig}
                    bind = f"    Variant v_{orig} = (int64_t)p_what;"
        cg.tmp = 0
        cg.ret_void = kind == "void"
        body: list[str] = []
        cg._suite(f.body, "    ", body)
        if kind == "variant":
            sig = proto.replace("static ", "")
            sig = "Variant " + cls + "::" + f.name + sig[sig.index("("):]
            c.append(sig + " {")
            c.extend(body or ["    ;"])
            c.append("    return Variant();")
            c.append("}")
        else:
            c.append(sig + " {")
            if bind:
                c.append(bind)
            c.extend(body or ["    ;"])
            c.append("}")
        c.append("")

    for i, (params, body, caps) in enumerate(cg.lambdas):
        args = ", ".join([f"Variant p_{p[0]}" for p in params]
                         + [f"Variant c_{w}" for w in caps])
        c.append(f"Variant {cls}::_l{i}({args}) {{")
        cg.locals = set()
        cg.params = {p[0] for p in params}
        cg.caps = set(caps)
        cg.ret_void = False
        cg.tmp = 0
        lbody: list[str] = []
        cg._suite(body, "    ", lbody)
        c.extend(lbody or ["    ;"])
        c.append("    return Variant();")
        c.append("}")
        c.append("")
    cg.caps = set()
    return c
