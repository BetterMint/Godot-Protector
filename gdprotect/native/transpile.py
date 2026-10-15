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


_GLOBALS = {
    "abs", "absf", "absi", "acos", "asin", "atan", "atan2",
    "angle_difference", "bezier_derivative", "bezier_interpolate",
    "bytes_to_var", "bytes_to_var_with_objects", "ceil", "ceilf", "ceili",
    "clamp", "clampf", "clampi", "cos", "cosh", "cubic_interpolate",
    "cubic_interpolate_angle", "cubic_interpolate_angle_in_time",
    "cubic_interpolate_in_time", "db_to_linear", "deg_to_rad", "ease",
    "error_string", "exp", "floor", "floorf", "floori", "fmod", "fposmod",
    "hash", "instance_from_id", "inverse_lerp", "is_equal_approx",
    "is_finite", "is_inf", "is_instance_id_valid", "is_instance_valid",
    "is_nan", "is_same", "is_zero_approx", "lerp", "lerp_angle", "lerpf",
    "linear_to_db", "log", "max", "maxf", "maxi", "min", "minf", "mini",
    "move_toward", "nearest_po2", "pingpong", "posmod", "print_rich",
    "print_verbose", "rad_to_deg", "rand_from_seed", "randf",
    "randf_range", "randfn", "randi", "randi_range", "randomize", "remap",
    "rid_allocate_id", "rid_from_int64", "rotate_toward", "round",
    "roundf", "roundi", "seed", "sign", "signf", "signi", "sin", "sinh",
    "smoothstep", "snapped", "snappedf", "snappedi", "sqrt",
    "step_decimals", "str_to_var", "tan", "tanh", "type_convert",
    "typeof", "var_to_bytes", "var_to_bytes_with_objects", "var_to_str",
    "var_to_str_with_objects", "weakref", "wrap", "wrapf", "wrapi",
}

_VOID_VIRTUALS = {"_ready", "_enter_tree", "_exit_tree", "_draw",
                  "_tree_entered", "_tree_exited", "_tree_exiting"}
_DELTA_VIRTUALS = {"_process", "_physics_process", "_frame_pre_draw"}
_INPUT_VIRTUALS = {"_input", "_unhandled_input", "_unhandled_key_input",
                   "_shortcut_input"}
_INT_VIRTUALS = {"_notification"}
_FLOAT_INPUT = {"_gui_input", "_input_event", "_drag_data"}


_NON_NODE_BASES = {
    "Object", "RefCounted", "Resource", "MainLoop", "SceneTree",
    "ResourceFormatLoader", "ResourceFormatSaver", "Script",
    "ScriptLanguage", "ConfigFile", "XMLParser", "Tween", "PacketPeer",
}

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

def _resolve_path(res_path: str, p: str) -> str:
    import posixpath
    if p.startswith("res://"):
        return p
    base = posixpath.dirname(res_path)
    return posixpath.normpath(posixpath.join(base, p))

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
            out.append(f"\\{o:03o}")
        elif o > 127:


            for b in ch.encode("utf-8"):
                out.append(f"\\{b:03o}")
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
    tool: bool = False
    co_classes: list = field(default_factory=list)
    script_symbols: dict = field(default_factory=dict)
    all_names: list = field(default_factory=list)

class _Fn:
    def __init__(self, node):
        _, ln, name, params, body, static = node[:6]
        self.ln = ln
        self.name = name
        self.params = params
        self.body = body
        self.static = static
        self.anns = node[6] if len(node) > 6 else []
        self.co = None
        self.co_fields: list = []

class _CG:
    def __init__(self, fn_name: str, res_path: str, class_map: dict,
                 script_classes: dict | None = None,
                 autoloads: dict | None = None):
        self.fn = fn_name
        self.res_path = res_path
        self.class_map = class_map
        self.script_classes = script_classes or {}
        self.autoloads = autoloads or {}
        self.base = "RefCounted"
        self.class_name = ""
        self.explicit_class_name = None
        self.tool = False
        self.funcs: list[_Fn] = []
        self.members: dict[str, tuple | None] = {}
        self.static_members: set[str] = set()
        self.onready: set[str] = set()
        self.consts: dict[str, tuple] = {}
        self.signals: dict[str, list[str]] = {}
        self.props: dict[str, tuple] = {}
        self.enums: dict[str, dict] = {}
        self.lambdas: list[tuple] = []
        self.lambda_ids: dict[int, int] = {}
        self.lambda_cos: dict[int, dict] = {}
        self.inners: dict[str, "_CG"] = {}
        self._inner_nodes: list = []
        self.locals: set[str] = set()
        self.params: set[str] = set()
        self.caps: set[str] = set()
        self.tmp = 0
        self.ret_void = False
        self.in_prop = None
        self.this_ = "this"
        self.co = None
        self._loop_stack: list = []
        self._co_tmp = 0
        self._co_fields: list = []
        self._late: list = []


    def _bound_names(self, stmts) -> set:
        out = set()
        for s in stmts:
            if not isinstance(s, tuple):
                continue
            if s[0] in ("var", "lconst"):
                out.add(s[2])
            elif s[0] == "enum":
                for n, _e in s[3]:
                    out.add(n)
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


    def _find_await(self, node):
        if isinstance(node, tuple) and node and isinstance(node[0], str):
            if node[0] == "await":
                return True
            if node[0] == "lambda":
                return False
            return any(self._find_await(x) for x in node[1:])
        if isinstance(node, (list, tuple)):
            return any(self._find_await(x) for x in node)
        return False

    def _has_coawait(self, node):
        if isinstance(node, tuple) and node and isinstance(node[0], str):
            if node[0] == "coawait":
                return True
            return any(self._has_coawait(x) for x in node[1:])
        if isinstance(node, (list, tuple)):
            return any(self._has_coawait(x) for x in node)
        return False

    def prepare(self):

        inits = [("assign", 0, ("name", 0, n), "=", init)
                 for n, init in self.members.items()
                 if n in self.onready and init is not None]
        if inits:
            ready = next((f for f in self.funcs if f.name == "_ready"),
                         None)
            if ready is not None:
                ready.body = inits + ready.body
            elif self._nodeish():
                self.funcs.append(
                    _Fn(("func", 0, "_ready", [], inits, False)))
            else:
                initf = next((f for f in self.funcs if f.name == "_init"),
                             None)
                if initf is None:
                    initf = _Fn(("func", 0, "_init", [], inits, False))
                    self.funcs.append(initf)
                else:
                    initf.body = inits + initf.body
        for f in self.funcs:
            if not self._find_await(f.body):
                continue
            if f.name == "_init":
                self.err("'await' in _init is not supported", f.ln)
            self._co_tmp = 0
            self._co_fields = []
            bound = self._bound_names(f.body)
            body = self._xform_stmts(f.body)
            f.body = body
            fields = ([f"p_{p[0]}" for p in f.params]
                      + [f"v_{w}" for w in sorted(bound)]
                      + [f"v_{w}" for w in self._co_fields])
            need = self._co_temps_needed(body)
            fields += [f"_fs{k}" for k in range(need["for"])]
            fields += [f"_fi{k}" for k in range(need["for"])]
            fields += [f"_mv{k}" for k in range(need["match"])]
            f.co = {"fields": fields,
                    "awaits": self._count_awaits(body),
                    "locals": bound | set(self._co_fields)}
        for i, (params, body, caps) in enumerate(self.lambdas):
            if not self._find_await(body):
                continue
            self._co_tmp = 0
            self._co_fields = []
            bound = self._bound_names(body)
            body = self._xform_stmts(body)
            self.lambdas[i] = (params, body, caps)
            fields = ([f"p_{p[0]}" for p in params]
                      + [f"c_{w}" for w in caps]
                      + [f"v_{w}" for w in sorted(bound)]
                      + [f"v_{w}" for w in self._co_fields])
            need = self._co_temps_needed(body)
            fields += [f"_fs{k}" for k in range(need["for"])]
            fields += [f"_fi{k}" for k in range(need["for"])]
            fields += [f"_mv{k}" for k in range(need["match"])]
            self.lambda_cos[i] = {
                "fields": fields,
                "awaits": self._count_awaits(body),
                "locals": bound | set(self._co_fields)}
        for name, (sp, sb, gb) in self.props.items():
            if (isinstance(sb, list) and self._find_await(sb)) \
                    or (isinstance(gb, list) and self._find_await(gb)):
                self.err(f"'await' in property accessor '{name}'", 0)
        for name, init in self.members.items():
            if init is not None and self._find_await(init):
                self.err(f"'await' in initializer of '{name}'", 0)

    def _co_temps_needed(self, stmts):
        n_for = n_match = 0
        def walk(ss):
            nonlocal n_for, n_match
            for s in ss:
                if not isinstance(s, tuple):
                    continue
                if s[0] == "for" and self._has_coawait(s[4]):
                    n_for += 1
                    walk(s[4])
                elif s[0] == "while":
                    walk(s[3])
                elif s[0] == "if":
                    for _, b in s[2]:
                        walk(b)
                    if s[3]:
                        walk(s[3])
                elif s[0] == "match":
                    hit = any(self._has_coawait(b) for _, _, b in s[3])
                    if hit:
                        n_match += 1
                    for _, _, b in s[3]:
                        walk(b)
        walk(stmts)
        return {"for": n_for, "match": n_match}

    def _count_awaits(self, node, n=0):
        if isinstance(node, tuple) and node and isinstance(node[0], str):
            if node[0] == "coawait":
                n += 1
            for x in node[1:]:
                n = self._count_awaits(x, n)
            return n
        if isinstance(node, (list, tuple)):
            for x in node:
                n = self._count_awaits(x, n)
        return n

    def _hoist_expr(self, e, pre):
        if not isinstance(e, (tuple, list)) or not e:
            return e
        if isinstance(e, tuple) and isinstance(e[0], str):
            if e[0] == "await":
                sub = self._hoist_expr(e[2], pre)
                t = f"_aw{self._co_tmp}"
                self._co_tmp += 1
                self._co_fields.append(t)
                pre.append(("coawait", e[1], sub, t))
                return ("name", e[1], t)
            if e[0] == "lambda":
                return e
            return tuple([e[0], e[1]]
                         + [self._hoist_expr(x, pre) for x in e[2:]])
        return [self._hoist_expr(x, pre) for x in e]

    def _hoist_stmt(self, s, pre):
        tag = s[0]
        if tag in ("var", "lconst"):
            return tuple([s[0], s[1], s[2],
                          self._hoist_expr(s[3], pre)] + list(s[4:]))
        if tag == "assign":
            val = self._hoist_expr(s[4], pre)
            tgt = s[2]
            if tgt[0] == "attr":
                tgt = ("attr", tgt[1], self._hoist_expr(tgt[2], pre), tgt[3])
            elif tgt[0] == "index":
                tgt = ("index", tgt[1], self._hoist_expr(tgt[2], pre),
                       self._hoist_expr(tgt[3], pre))
            return ("assign", s[1], tgt, s[3], val)
        if tag == "expr":
            return ("expr", s[1], self._hoist_expr(s[2], pre))
        if tag == "return":
            return ("return", s[1],
                    self._hoist_expr(s[2], pre) if s[2] is not None else None)
        if tag == "assert":
            return ("assert", s[1], self._hoist_expr(s[2], pre),
                    self._hoist_expr(s[3], pre) if s[3] is not None else None)
        return s

    def _xform_stmts(self, stmts):
        out = []
        for s in stmts:
            if not isinstance(s, tuple):
                out.append(s)
                continue
            tag = s[0]
            if tag in ("var", "lconst", "assign", "expr", "return", "assert"):
                pre = []
                s2 = self._hoist_stmt(s, pre)
                out += pre
                out.append(s2)
            elif tag == "if":
                out += self._xform_if(s[2], s[3], s[1])
            elif tag == "while":
                if self._find_await(s[2]):
                    pre = []
                    cond = self._hoist_expr(s[2], pre)
                    chk = ("if", s[1],
                           [(("unary", s[1], "not", cond),
                             [("break", s[1])])], None)
                    body = pre + [chk] + self._xform_stmts(s[3])
                    out.append(("while", s[1], ("lit", s[1], True), body))
                else:
                    out.append(("while", s[1], s[2],
                                self._xform_stmts(s[3])))
            elif tag == "for":
                pre = []
                it = self._hoist_expr(s[3], pre)
                out += pre
                out.append(("for", s[1], s[2], it,
                            self._xform_stmts(s[4])))
            elif tag == "match":
                pre = []
                subj = self._hoist_expr(s[2], pre)
                arms = []
                for pats, guard, body in s[3]:
                    if guard is not None and self._find_await(guard):
                        self.err("'await' in a match guard is not "
                                 "supported", s[1])
                    arms.append((pats, guard, self._xform_stmts(body)))
                out += pre
                out.append(("match", s[1], subj, arms))
            else:
                out.append(s)
        return out

    def _xform_if(self, cases, els, ln):


        if not cases:
            return self._xform_stmts(els) if els else []
        cond, body = cases[0]
        pre = []
        c2 = self._hoist_expr(cond, pre)
        inner = self._xform_if(cases[1:], els, ln)
        node = ("if", ln, [(c2, self._xform_stmts(body))],
                inner if inner else None)
        return pre + [node]

    def err(self, msg, ln=0):
        raise NativeError(f"{self.res_path}:{ln}: {msg}")

    def analyze(self, nodes):
        for nd in nodes:
            tag = nd[0]
            if tag == "meta":
                anns = nd[4] if len(nd) > 4 else []
                if "tool" in anns or nd[2] == "tool":
                    self.tool = True
                if len(nd) > 3 and nd[3]:
                    if nd[2] == "extends":
                        if isinstance(nd[3], str) and ".gd" in nd[3]:
                            p = nd[3]
                            if not p.startswith("res://"):
                                p = _resolve_path(self.res_path, p)
                            target = self.class_map.get(p)
                            if target is None:
                                self.err(f"native class cannot extend "
                                         f"non-native script {p!r} — "
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
                if len(nd) > 7 and nd[7]:
                    self.static_members.add(name)
                anns = nd[8] if len(nd) > 8 else []
                if "onready" in anns:
                    self.onready.add(name)
            elif tag == "enum":
                vals = self._enum_vals(nd[3], nd[1])
                if nd[2]:
                    self.enums[nd[2]] = vals
                for n, v in vals.items():
                    self.consts[n] = ("lit", nd[1], v)
            elif tag == "const":
                self.consts[nd[2]] = nd[3]
            elif tag == "var" or tag == "lconst":

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
        if not self.class_name:


            self.class_name = (self.class_map.get(self.res_path)
                               or self.explicit_class_name
                               or _pascal("gd_" + stem) or "GdScript")
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
            return b
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


    def E(self, e) -> str:
        tag = e[0]
        if tag == "lit":
            return self._lit(e[2])
        if tag == "name":
            return self._name(e[2], e[1])
        if tag == "self":
            return f"Variant({self.this_})"
        if tag == "super":
            return f"Variant({self.this_})"
        if tag == "await":
            self.err("internal: unhoisted await", e[1])
        if tag == "lambda":
            idx = self.lambda_ids.get(id(e))
            if idx is None:
                self.err("lambda not registered", e[1])
            params, body, caps = self.lambdas[idx]
            lam = f"callable_mp({self.this_}, &{self.class_name}::_l{idx})"
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
            return f"gdpx::get_node({self.this_}, String({_cstr(e[2])}))"
        if tag == "istype":
            return self._istype(e[2], e[3], as_=False)
        if tag == "astype":
            return self._istype(e[2], e[3], as_=True)
        self.err(f"unsupported expression tag {tag!r}", e[1] if len(e) > 1 else 0)

    def _istype(self, obj_e, tn, as_):
        v = self.E(obj_e)
        base = tn.split(".")[-1]
        if base in self.inners:
            tn = self.inners[base].class_name
        elif base in self.class_map.values():
            tn = base
        elif base in self.script_classes:
            chk = f"gdpx::is_script({v}, {_cstr(self.script_classes[base])})"
            return (f"({chk} ? {v} : Variant())" if as_
                    else f"(Variant)({chk})")
        elif base in (self.locals | self.params | set(self.members)):
            dyn = f"gdpx::is_dyn({v}, {self._name(base)})"
            return (f"({dyn} ? {v} : Variant())" if as_
                    else f"(Variant)({dyn})")
        chk = f"gdpx::is_class({v}, {_cstr(tn)})"
        return (f"({chk} ? {v} : Variant())" if as_ else f"(Variant)({chk})")

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
        th = self.this_
        if name in self.members:
            if name in self.props and self.in_prop != name:
                return f"{th}->get_{name}()"
            return f"{th}->m_{name}"
        if name in self.consts:
            return self._const_ref(name)
        if name in self.signals:
            return f"Signal({th}, {_cstr(name)})"
        if name in {f.name for f in self.funcs}:
            return f"Callable({th}, {_cstr(name)})"
        return f"gdpx::get_attr(Variant({th}), {_cstr(name)})"

    def _const_ref(self, name: str) -> str:
        return f"c_{name}"

    def _name(self, w: str, ln=0) -> str:
        th = self.this_
        if w in self.locals:
            return f"v_{w}"
        if w in self.params:
            return f"p_{w}"
        if w in self.caps:
            return f"c_{w}"
        if w in self.members:
            if w in self.props and self.in_prop != w:
                return f"{th}->get_{w}()"
            return f"{th}->m_{w}"
        if w in self.consts:
            return self._const_ref(w)
        if w in self.signals:
            return f"Signal({th}, {_cstr(w)})"
        if w in {f.name for f in self.funcs}:
            return f"Callable({th}, {_cstr(w)})"
        if w in _SINGLETONS:
            return f"Variant({w}::get_singleton())"
        if w in _NUM_CONSTS:
            return _NUM_CONSTS[w]
        if w in _CTOR_TYPES:
            return f"Variant() /* bare type {w} */"
        if w in self.class_map.values():
            return f"gdpx::script_ref({_cstr(w)})"
        if w in self.script_classes:
            return f"gdpx::load_res({_cstr(self.script_classes[w])})"
        if w in self.autoloads:
            return f"gdpx::autoload({_cstr(w)})"
        if w in self.enums:
            return f"/* enum {w} */ Variant()"
        if w in self.inners:
            return f"/* inner {w} */ Variant()"

        return f"gdpx::get_attr(Variant({th}), {_cstr(w)})"

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
                        "/": a // b if isinstance(a, int)
                        and isinstance(b, int)
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
                return f"{self.this_}->{w}({inner})"
            if w in _GLOBALS:
                inner = ", ".join(self.E(a) for a in args)
                return f"UtilityFunctions::{w}({inner})"
            if w in self.locals or w in self.members or w in self.params:
                tgt = (f"v_{w}" if w in self.locals
                       else f"p_{w}" if w in self.params
                       else f"{self.this_}->m_{w}")
                inner = ", ".join(self.E(a) for a in args)
                return f"gdpx::callv({tgt}, {{{inner}}})"
            inner = ", ".join(self.E(a) for a in args)
            return (f"{self.this_}->call({_cstr(w)}"
                    f"{', ' if inner else ''}{inner})")
        if callee[0] == "attr":
            obj, m = callee[2], callee[3]
            if obj[0] == "super":
                inner = ", ".join(self.E(a) for a in args)
                return f"{self.this_}->{self.base}::{m}({inner})"
            if m == "emit" and obj[0] in ("name",) and obj[2] in self.signals:
                inner = ", ".join(self.E(a) for a in args)
                return (f"{self.this_}->emit_signal({_cstr(obj[2])}"
                        f"{', ' if inner else ''}{inner})")
            if m in ("connect", "disconnect") and obj[0] == "name" \
                    and obj[2] in self.signals:
                inner = ", ".join(self.E(a) for a in args)
                return f"{self.this_}->{m}({_cstr(obj[2])}, {inner})"
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
        if callee[0] == "super":

            return "Variant() /* super() */"
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


    def _awaitable(self, e) -> str:


        if e[0] == "attr":
            return (f"Variant(Signal(gdpx::to_obj({self.E(e[2])}), "
                    f"StringName({_cstr(e[3])})))")
        if e[0] == "name" and e[2] in self.signals:
            return f"Variant(Signal({self.this_}, {_cstr(e[2])}))"
        return self.E(e)

    def _coS(self, stmt, ind, out):


        tag, ln = stmt[0], stmt[1]
        if tag == "coawait":
            n = self.co["next"]
            self.co["next"] += 1
            aw = self._awaitable(stmt[2])
            out.append(f"{ind}{{ Variant _aw = {aw};")
            out.append(f"{ind}  Object *_ao = nullptr; StringName _as; "
                       f"Variant _av;")
            out.append(f"{ind}  if (gdpx::await_split(_aw, _ao, _as, _av)) {{")
            out.append(f"{ind}      _st = {n};")
            out.append(f"{ind}      _ao->connect(_as, Callable(this, \"_r\"), "
                       f"Object::CONNECT_ONE_SHOT);")
            out.append(f"{ind}      return Variant(); }}")
            out.append(f"{ind}  a0 = _av; }}")
            out.append(f"{ind}_L{n}: ;")
            if stmt[3]:
                out.append(f"{ind}v_{stmt[3]} = a0;")
            return
        if tag in ("var", "lconst"):
            name, init = stmt[2], stmt[3]
            self.locals.add(name)
            rhs = self.E(init) if init is not None else "Variant()"
            out.append(f"{ind}v_{name} = {rhs};")
            return
        if tag == "return":
            e = self.E(stmt[2]) if stmt[2] is not None else "Variant()"
            out.append(f"{ind}{{ Variant _rv = {e}; gx_finish(_rv); "
                       f"return _rv; }}")
            return
        if tag in ("break", "continue"):
            top = self._loop_stack[-1] if self._loop_stack else None
            if top is None or top == "native":
                out.append(f"{ind}{tag};")
            else:
                out.append(f"{ind}goto {top[0 if tag == 'continue' else 1]};")
            return
        if tag == "while" and self._has_coawait(stmt[3]):
            k = self._next_lbl()
            out.append(f"{ind}_Lb{k}: ;")
            out.append(f"{ind}if (!gdpx::truth({self.E(stmt[2])})) "
                       f"goto _Le{k};")
            self._loop_stack.append((f"_Lc{k}", f"_Le{k}"))
            self._suite(stmt[3], ind, out)
            self._loop_stack.pop()
            out.append(f"{ind}_Lc{k}: ;")
            out.append(f"{ind}goto _Lb{k};")
            out.append(f"{ind}_Le{k}: ;")
            return
        if tag == "for" and self._has_coawait(stmt[4]):
            k = self._next_lbl()
            fk = self.co["fi"]
            self.co["fi"] += 1
            var = stmt[2]
            self.locals.add(var)
            out.append(f"{ind}_fs{fk} = gdpx::iter_list({self.E(stmt[3])});")
            out.append(f"{ind}_fi{fk} = (int64_t)0;")
            out.append(f"{ind}_Lb{k}: ;")
            out.append(f"{ind}if (gdpx::to_int(_fi{fk}) >= "
                       f"gdpx::len(_fs{fk})) goto _Le{k};")
            out.append(f"{ind}v_{var} = gdpx::idx(_fs{fk}, _fi{fk});")
            self._loop_stack.append((f"_Lc{k}", f"_Le{k}"))
            self._suite(stmt[4], ind, out)
            self._loop_stack.pop()
            out.append(f"{ind}_Lc{k}: ;")
            out.append(f"{ind}_fi{fk} = gdpx::add(_fi{fk}, (int64_t)1);")
            out.append(f"{ind}goto _Lb{k};")
            out.append(f"{ind}_Le{k}: ;")
            return
        if tag == "match" and any(self._has_coawait(b)
                                  for _, _, b in stmt[3]):
            mk = self.co["mv"]
            self.co["mv"] += 1
            mv = f"_mv{mk}"
            out.append(f"{ind}{mv} = {self.E(stmt[2])};")
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
                    out.append(f"{ind}{kw} ({cond}) {{")
                else:
                    out.append(f"{ind}else {{" if not first
                               else f"{ind}{{")
                self._suite(body, ind + "    ", out)
                out.append(f"{ind}}}")
                first = False
            return
        if tag in ("for", "while"):

            self._loop_stack.append("native")
            if tag == "while":
                out.append(f"{ind}while (gdpx::truth({self.E(stmt[2])})) {{")
                self._suite(stmt[3], ind + "    ", out)
                out.append(f"{ind}}}")
            else:
                self._for(stmt[2], stmt[3], stmt[4], ind, out)
            self._loop_stack.pop()
            return
        if tag == "enum":
            for n, v in self._enum_vals(stmt[3], ln).items():
                self.locals.add(n)
                out.append(f"{ind}v_{n} = (int64_t){v};")
            return

        return self._plainS(stmt, ind, out)

    def _next_lbl(self):
        n = self.co["lbl"]
        self.co["lbl"] += 1
        return n

    def _nodeish(self) -> bool:
        return self.base not in _NON_NODE_BASES

    def _plainS(self, stmt, ind, out):

        tag = stmt[0]
        if tag == "assign":
            self._assign(stmt[2], stmt[3], stmt[4], ind, out)
            return
        if tag == "expr":
            out.append(f"{ind}{self.E(stmt[2])};")
            return
        if tag == "assert":
            msg = self.E(stmt[3]) if stmt[3] is not None else "Variant()"
            out.append(f"{ind}gdpx::expect({self.E(stmt[2])}, {msg}, "
                       f"{_cstr(self.res_path + ':' + str(stmt[1]))});")
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
        if tag == "pass":
            out.append(f"{ind};")
            return
        if tag == "return":

            e = self.E(stmt[2]) if stmt[2] is not None else "Variant()"
            out.append(f"{ind}return {e};")
            return
        self.err(f"unsupported statement {tag!r}", stmt[1])

    def S(self, stmt, ind: str, out: list[str]):
        tag = stmt[0]
        ln = stmt[1]
        if self.co is not None:
            return self._coS(stmt, ind, out)
        if tag == "var" or tag == "lconst":
            name, init = stmt[2], stmt[3]
            self.locals.add(name)
            pre = "const Variant" if tag == "lconst" else "Variant"
            if init is None:
                out.append(f"{ind}{pre} v_{name};")
            else:
                out.append(f"{ind}{pre} v_{name} = {self.E(init)};")
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
        if tag == "enum":
            for n, v in self._enum_vals(stmt[3], ln).items():
                self.locals.add(n)
                out.append(f"{ind}const int64_t v_{n} = {v};")
            return
        if tag in ("break", "continue"):
            out.append(f"{ind}{tag};")
            return
        return self._plainS(stmt, ind, out)

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
                    cur = f"{self.this_}->get_{w}()"
                    out.append(f"{ind}{self.this_}->set_{w}("
                               f"{rhs.replace('<t>', cur)});")
                    return
                ref = f"{self.this_}->m_{w}"
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
                    cur = f"{self.this_}->get_{w}()"
                    out.append(f"{ind}{self.this_}->set_{w}("
                               f"{rhs.replace('<t>', cur)});")
                    return
                ref = f"{self.this_}->m_{w}"
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
                     script_classes: dict | None = None,
                     autoloads: dict | None = None) -> NativeUnit:
    nodes = parse(source, res_path)
    cg = _CG(res_path, res_path, class_map or {}, script_classes, autoloads)
    cg.analyze(nodes)

    cls = cg.class_name
    fn_stem = Path(res_path).stem
    cgs = [cg] + list(cg.inners.values())
    for sub in cgs:
        sub.collect_lambdas()
        sub.prepare()


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
        if sub.lambdas or any(f.co for f in sub.funcs):
            for inc in ("#include <godot_cpp/variant/callable.hpp>",
                        "#include <godot_cpp/variant/callable_method_pointer.hpp>",
                        "#include <godot_cpp/classes/ref.hpp>"):
                if inc not in seen_inc:
                    h.append(inc); seen_inc.add(inc)
    h.append("#include <godot_cpp/variant/variant.hpp>")
    h.append("#include <godot_cpp/variant/string.hpp>")
    h.append("#include <godot_cpp/variant/string_name.hpp>")
    h.append('#include "gdpx_rt.h"')
    h.append("")
    h.append("using namespace godot;")
    h.append("")
    co_classes = []
    for sub in cgs:
        h += _emit_decl(sub)
        co_classes += [f"{sub.class_name}_Co{f.name}"
                       for f in sub.funcs if f.co]
        co_classes += [f"{sub.class_name}_Co_l{i}"
                       for i in sub.lambda_cos]


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
                      source="\n".join(c), tool=cg.tool,
                      co_classes=co_classes,
                      all_names=[x.class_name for x in cgs])

def _co_name(cls: str, fname: str) -> str:
    return f"{cls}_Co{fname}"

def _emit_decl(cg: _CG) -> list[str]:
    cls = cg.class_name
    h = []
    h.append(f"class {cls} : public {cg.base} {{")
    h.append(f"    GDCLASS({cls}, {cg.base})")
    h.append("public:")
    for name, init in cg.members.items():
        expr = ""
        if init is not None and name not in cg.onready:
            cg.locals = set()
            expr = " = " + cg.E(init)
        if name in cg.static_members:
            if init is not None and init[0] != "lit":
                cg._late.append((f"m_{name}", init))
                expr = ""
            h.append(f"    static inline Variant m_{name}{expr};")
        else:
            h.append(f"    Variant m_{name}{expr};")
    for cname, ce in cg.consts.items():
        if ce[0] == "lit" and isinstance(ce[2], (int, float, str, bool,
                                               type(None))):
            h.append(f"    static const Variant c_{cname};")
        else:
            h.append(f"    static Variant c_{cname};")
    h.append("protected:")
    h.append("    static void _bind_methods();")
    h.append("public:")
    h.append(f"    {cls}();")
    for m in cg.members:
        sparam = cg.props[m][0] if m in cg.props else "v"
        h.append(f"    void set_{m}(const Variant &p_{sparam});")
        h.append(f"    Variant get_{m}();")
    init_fn = next((f for f in cg.funcs if f.name == "_init"), None)
    if init_fn is not None:
        ps = ", ".join(f"Variant p_{p[0]} = Variant()"
                       for p in init_fn.params)
        h.append(f"    Variant _gx_init({ps});")
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
    for f in cg.funcs:
        if not f.co:
            continue
        _co_decl(h, cls, _co_name(cls, f.name), f.co["fields"])
    for i, lco in cg.lambda_cos.items():
        _co_decl(h, cls, _co_name(cls, f"_l{i}"), lco["fields"])
    return h

def _co_decl(h: list[str], cls: str, cof: str, fields: list[str]):
    h.append(f"class {cof} : public GxCo {{")
    h.append(f"    GDCLASS({cof}, GxCo)")
    h.append("protected:")
    h.append("    static void _bind_methods() {")
    h.append(f'        ClassDB::bind_method(D_METHOD("_r", "a0", '
             f'"a1", "a2", "a3", "a4", "a5"), &{cof}::_r, '
             + ", ".join(["DEFVAL(Variant())"] * 6) + ");")
    h.append("    }")
    h.append("public:")
    h.append(f"    {cls} *self = nullptr;")
    for fld in fields:
        h.append(f"    Variant {fld};")
    h.append("    int _st = 0;")
    h.append("    Variant _r(Variant a0 = Variant(), "
             "Variant a1 = Variant(), Variant a2 = Variant(), "
             "Variant a3 = Variant(), Variant a4 = Variant(), "
             "Variant a5 = Variant());")
    h.append("};")
    h.append("")

def _emit_impl(cg: _CG) -> list[str]:
    cls = cg.class_name
    c = []
    for cname, ce in cg.consts.items():
        if ce[0] == "lit" and isinstance(ce[2], (int, float, str, bool,
                                               type(None))):
            c.append(f"const Variant {cls}::c_{cname}"
                     f"{cg._const_init(cname, ce, 0)};")
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
    init_fn = next((f for f in cg.funcs if f.name == "_init"), None)
    if init_fn is not None:
        an = ", ".join(_cstr(p[0]) for p in init_fn.params)
        dvs = ", ".join(["DEFVAL(Variant())"] * len(init_fn.params))
        c.append(f'    ClassDB::bind_method(D_METHOD("_gx_init"'
                 f'{", " if an else ""}{an}), &{cls}::_gx_init'
                 f'{", " if dvs else ""}{dvs});')
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
    cg.locals = set()
    for fld, e in cg._late:
        c.append(f"    {cls}::{fld} = {cg.E(e)};")
    for cname, ce in cg.consts.items():
        if not (ce[0] == "lit" and isinstance(ce[2], (int, float, str, bool,
                                                    type(None)))):
            c.append(f"    {cls}::c_{cname} = {cg.E(ce)};")
    c.append("}")
    c.append("")

    c.append(f"{cls}::{cls}() {{")
    if init_fn is not None:
        c.append("    this->_gx_init();")
    c.append("}")
    c.append("")

    if init_fn is not None:
        ps = ", ".join(f"Variant p_{p[0]}" for p in init_fn.params)
        c.append(f"Variant {cls}::_gx_init({ps}) {{")
        cg.locals, cg.params = set(), {p[0] for p in init_fn.params}
        cg.caps, cg.ret_void, cg.tmp = set(), False, 0
        body: list[str] = []
        cg._suite(init_fn.body, "    ", body)
        c.extend(body or ["    ;"])
        c.append("    return Variant();")
        c.append("}")
        c.append("")

    for m in cg.members:
        prop = cg.props.get(m)
        if prop is None:
            c.append(f"void {cls}::set_{m}(const Variant &p_v) {{ m_{m} = p_v; }}")
            c.append(f"Variant {cls}::get_{m}() {{ return m_{m}; }}")
            continue
        sparam, set_body, get_body = prop
        if isinstance(set_body, tuple) and set_body[0] == "sg":
            c.append(f"void {cls}::set_{m}(const Variant &p_{sparam}) "
                     f"{{ this->{set_body[1]}(p_{sparam}); }}")
        elif set_body is not None:
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
        if isinstance(get_body, tuple) and get_body[0] == "sg":
            c.append(f"Variant {cls}::get_{m}() "
                     f"{{ return this->{get_body[1]}(); }}")
        else:
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
                    bind = (f"{orig}",
                            f"Variant({0 if False else 'p_delta'})")
            elif name in _INPUT_VIRTUALS:
                sig = f"void {cls}::{name}(const Ref<InputEvent> &p_event)"
                if orig:
                    bind = (orig, "Variant(p_event.ptr())")
            elif name in _INT_VIRTUALS:
                sig = f"void {cls}::{name}(int p_what)"
                if orig:
                    bind = (orig, "(int64_t)p_what")
        cg.tmp = 0
        cg._loop_stack = []
        cg.ret_void = kind == "void"
        if kind == "variant":
            sig = proto.replace("static ", "")
            sig = "Variant " + cls + "::" + f.name + sig[sig.index("("):]
        if f.co:
            cof = _co_name(cls, f.name)
            c.append(sig + " {")
            c.append(f"    Ref<{cof}> c;")
            c.append("    c.instantiate();")
            if not f.static:
                c.append("    c->self = this;")
            for p in f.params:
                c.append(f"    c->p_{p[0]} = p_{p[0]};")
            if bind:
                c.append(f"    c->v_{bind[0]} = {bind[1]};")
            c.append("    c->_r();")
            c.append("    return Variant(c.ptr());"
                     if kind == "variant" else "")
            c.append("}")
            c.append("")

            cg.locals = set(f.co["locals"])
            cg.params = {p[0] for p in f.params}
            cg.this_ = "self"
            cg.co = {"next": 1, "lbl": 0, "fi": 0, "mv": 0}
            cg.ret_void = False
            rbody: list[str] = []
            cases = [f"    case {i}: goto _L{i};"
                     for i in range(1, f.co["awaits"] + 1)]
            c.append(f"Variant {cof}::_r(Variant a0, Variant a1, "
                     "Variant a2, Variant a3, Variant a4, Variant a5) {")
            c.append("    switch (_st) {")
            c.append("    case 0: goto _L0;")
            c.extend(cases)
            c.append("    default: return Variant();")
            c.append("    }")
            c.append("_L0: ;")
            cg._suite(f.body, "    ", rbody)
            c.extend(rbody or ["    ;"])
            c.append("    { gx_finish(Variant()); return Variant(); }")
            c.append("}")
            c.append("")
            cg.co = None
            cg.this_ = "this"
            continue
        body: list[str] = []
        cg._suite(f.body, "    ", body)
        if kind == "variant":
            c.append(sig + " {")
            c.extend(body or ["    ;"])
            c.append("    return Variant();")
            c.append("}")
        else:
            c.append(sig + " {")
            if bind:
                c.append(f"    Variant v_{bind[0]} = {bind[1]};")
            c.extend(body or ["    ;"])
            c.append("}")
        c.append("")

    for i, (params, body, caps) in enumerate(cg.lambdas):
        args = ", ".join([f"Variant p_{p[0]}" for p in params]
                         + [f"Variant c_{w}" for w in caps])
        lco = cg.lambda_cos.get(i)
        if lco is not None:
            cof = _co_name(cls, f"_l{i}")
            c.append(f"Variant {cls}::_l{i}({args}) {{")
            c.append(f"    Ref<{cof}> c;")
            c.append("    c.instantiate();")
            c.append("    c->self = this;")
            for p in params:
                c.append(f"    c->p_{p[0]} = p_{p[0]};")
            for w in caps:
                c.append(f"    c->c_{w} = c_{w};")
            c.append("    c->_r();")
            c.append("    return Variant(c.ptr());")
            c.append("}")
            c.append("")
            cg.locals = set(lco["locals"])
            cg.params = {p[0] for p in params}
            cg.caps = set(caps)
            cg.this_ = "self"
            cg.co = {"next": 1, "lbl": 0, "fi": 0, "mv": 0}
            cg.ret_void = False
            cg.tmp = 0
            cg._loop_stack = []
            rbody: list[str] = []
            cases = [f"    case {k}: goto _L{k};"
                     for k in range(1, lco["awaits"] + 1)]
            c.append(f"Variant {cof}::_r(Variant a0, Variant a1, "
                     "Variant a2, Variant a3, Variant a4, Variant a5) {")
            c.append("    switch (_st) {")
            c.append("    case 0: goto _L0;")
            c.extend(cases)
            c.append("    default: return Variant();")
            c.append("    }")
            c.append("_L0: ;")
            cg._suite(body, "    ", rbody)
            c.extend(rbody or ["    ;"])
            c.append("    { gx_finish(Variant()); return Variant(); }")
            c.append("}")
            c.append("")
            cg.co = None
            cg.this_ = "this"
            cg.caps = set()
            continue
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
