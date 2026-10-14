
from __future__ import annotations

from .lexer import (KEYWORDS, SIG_KINDS, Token, detokenize, find_suite,
                    is_stmt_start, sig_indices, tokenize)

BUILTINS = frozenset({
    "print", "prints", "print_debug", "printerr", "printraw", "print_rich",
    "push_error", "push_warning", "preload", "load", "range", "len", "str",
    "int", "float", "bool", "abs", "min", "max", "clamp", "sign", "floor",
    "ceil", "round", "sqrt", "pow", "exp", "log", "sin", "cos", "tan",
    "asin", "acos", "atan", "atan2", "fmod", "fposmod", "posmod", "lerp",
    "inverse_lerp", "remap", "smoothstep", "step_decimals", "snapped",
    "wrap", "wrapi", "wrapf", "randf", "randi", "randomize", "randi_range",
    "randf_range", "randfn", "seed", "rand_from_seed", "deg_to_rad",
    "rad_to_deg", "is_zero_approx", "is_equal_approx", "is_finite",
    "is_inf", "is_nan", "nearest_po2", "db_to_linear", "linear_to_db",
    "ease", "move_toward", "rotate_toward", "type_convert", "typeof",
    "is_instance_valid", "is_instance_id_valid", "instance_from_id",
    "weakref", "bytes_to_var", "var_to_bytes", "str_to_var", "var_to_str",
    "hash", "ord", "char", "hex", "Color8", "print_stack",
    "get_stack", "rid_from_int64", "is_same",
    "PI", "TAU", "INF", "NAN",
    "String", "StringName", "NodePath", "Array", "Dictionary",
    "PackedByteArray", "PackedInt32Array", "PackedInt64Array",
    "PackedFloat32Array", "PackedFloat64Array", "PackedStringArray",
    "PackedVector2Array", "PackedVector3Array", "PackedColorArray",
    "Vector2", "Vector2i", "Vector3", "Vector3i", "Vector4", "Vector4i",
    "Rect2", "Rect2i", "Transform2D", "Transform3D", "Basis", "Quaternion",
    "Plane", "AABB", "Color", "RID", "Callable", "Signal", "Object",
    "Node", "Node2D", "Node3D", "Control", "Resource", "RefCounted",
    "SceneTree", "Input", "InputEvent", "Engine", "OS", "ProjectSettings",
    "ResourceLoader", "ResourceSaver", "DisplayServer", "Time",
    "Variant", "PackedScene", "Texture2D",
    "Sprite2D", "AnimatedSprite2D", "AnimationPlayer", "Timer", "Tween",
    "AudioStreamPlayer", "Label", "Button", "CanvasItem", "Viewport",
})

NEVER_EXTRA = frozenset({"get", "set"})

_PROTECT_ANNOTS = frozenset({"onready", "rpc", "icon"})

_QUALI_KW = frozenset({
    "export", "onready", "remote", "master", "puppet", "sync",
    "remotesync", "mastersync", "puppetsync", "tool",
})

_NAME_LETTERS = "abcdefghjkmnpqrstuvwxyz"
_NAME_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz"

def _gen_name(rng, taken: set) -> str:
    while True:
        s = "_" + rng.choice(_NAME_LETTERS) + "".join(
            rng.choice(_NAME_CHARS) for _ in range(rng.randint(2, 3)))
        if s not in taken:
            taken.add(s)
            return s

def _func_regions(toks: list[Token], sig: list[int]) -> list[tuple[int, int]]:
    regs = []
    for pos, ti in enumerate(sig):
        if toks[ti].kind == "kw" and toks[ti].value == "func":
            r = find_suite(toks, sig, pos)
            if r:
                regs.append(r)
    return regs

def _in_regions(regions, ti: int) -> bool:
    return any(a < ti < b for a, b in regions)

def rename_source(src: str, cfg, rng, str_contents: set | None = None) -> str:
    toks = tokenize(src)
    sig = sig_indices(toks)
    L = len(sig)
    regions = _func_regions(toks, sig)

    preserve = set(getattr(cfg, "preserve", None) or [])
    never = KEYWORDS | BUILTINS | NEVER_EXTRA | preserve
    str_contents = set(str_contents or ())
    for t in toks:
        if t.kind == "str" and isinstance(t.sval, str):
            str_contents.add(t.sval)

    protected: set[int] = set()
    defs: list[tuple[int, bool]] = []
    maybe_self: set[int] = set()
    pending_protect = False

    def eligible(name: str) -> bool:
        return (not name.startswith("_")
                and name not in never
                and name not in str_contents)

    def define(ti: int, member: bool, force_protect: bool) -> None:
        t = toks[ti]
        if force_protect or not eligible(t.value):
            protected.add(ti)
        else:
            defs.append((ti, member))

    def protect_type_run(j: int) -> int:
        while j < L:
            tt = toks[sig[j]]
            if tt.kind == "id":
                protected.add(sig[j])
            elif tt.kind == "op" and tt.value in (".", "[", "]"):
                pass
            else:
                break
            j += 1
        return j

    def skip_parens(j: int, protect_ids: bool = True) -> int:
        d = 0
        while j < L:
            tt = toks[sig[j]]
            if tt.kind == "op":
                if tt.value == "(":
                    d += 1
                elif tt.value == ")":
                    d -= 1
                    if d == 0:
                        return j + 1
            elif protect_ids and tt.kind == "id":
                protected.add(sig[j])
            j += 1
        return j

    def stmt_end(i: int) -> int:
        j = i + 1
        while j < L and not is_stmt_start(toks, sig[j]):
            j += 1
        return j

    def collect_params(j: int) -> int:
        d = 0
        expect = True
        while j < L:
            tt = toks[sig[j]]
            if tt.kind == "op":
                v = tt.value
                if v == "(":
                    d += 1
                elif v == ")":
                    d -= 1
                    if d == 0:
                        return j + 1
                elif v == "," and d == 1:
                    expect = True
                elif v == ":" and d == 1:
                    j = protect_type_run(j + 1)
                    continue
                j += 1
                continue
            if tt.kind == "id" and d == 1 and expect:
                define(sig[j], False, False)
                expect = False
            j += 1
        return j

    def collect_for_targets(i: int) -> None:
        d = 0
        j = i + 1
        while j < L:
            tt = toks[sig[j]]
            if tt.kind == "op":
                if tt.value in "([{":
                    d += 1
                elif tt.value in ")]}":
                    d -= 1
            elif tt.kind == "kw" and tt.value == "in" and d == 0:
                return
            elif tt.kind == "id" and d == 0:
                define(sig[j], False, False)
            j += 1

    openers: list[str] = []
    i = 0
    while i < L:
        ti = sig[i]
        t = toks[ti]
        stmt_start = is_stmt_start(toks, ti)

        if t.kind == "op":
            if t.value in "([{":
                openers.append(t.value)
            elif t.value in ")]}" and openers:
                openers.pop()

        if stmt_start and t.kind == "op" and t.value == "@":
            while i < L and toks[sig[i]].kind == "op" \
                    and toks[sig[i]].value == "@":
                i += 1
                if i < L and toks[sig[i]].kind in ("id", "kw"):
                    an = toks[sig[i]].value
                    if an.startswith("export") or an in _PROTECT_ANNOTS:
                        pending_protect = True
                    i += 1
                if i < L and toks[sig[i]].kind == "op" \
                        and toks[sig[i]].value == "(":
                    d = 0
                    while i < L:
                        tt = toks[sig[i]]
                        if tt.kind == "op":
                            if tt.value == "(":
                                d += 1
                            elif tt.value == ")":
                                d -= 1
                                if d == 0:
                                    i += 1
                                    break
                        elif tt.kind == "id":
                            protected.add(sig[i])
                        i += 1
            if i >= L:
                break
            ti = sig[i]
            t = toks[ti]

        if t.kind == "kw":
            v = t.value
            if v in _QUALI_KW:
                pending_protect = True
            elif v == "extends":
                pending_protect = False
                j = i + 1
                end = stmt_end(i)
                while j < end:
                    if toks[sig[j]].kind == "id":
                        protected.add(sig[j])
                    j += 1
            elif v in ("class_name", "class"):
                pending_protect = False
                if i + 1 < L and toks[sig[i + 1]].kind == "id":
                    protected.add(sig[i + 1])
            elif v == "signal":
                pending_protect = False
                j = i + 1
                if j < L and toks[sig[j]].kind == "id":
                    protected.add(sig[j])
                    j += 1
                if j < L and toks[sig[j]].kind == "op" \
                        and toks[sig[j]].value == "(":
                    skip_parens(j)
            elif v == "const":
                pending_protect = False
                if i + 1 < L and toks[sig[i + 1]].kind == "id":
                    protected.add(sig[i + 1])
            elif v == "enum":
                pending_protect = False
                j = i + 1
                if j < L and toks[sig[j]].kind == "id":
                    protected.add(sig[j])
                    j += 1
                if j < L and toks[sig[j]].kind == "op" \
                        and toks[sig[j]].value == "{":
                    d = 0
                    while j < L:
                        tt = toks[sig[j]]
                        if tt.kind == "op":
                            if tt.value == "{":
                                d += 1
                            elif tt.value == "}":
                                d -= 1
                                if d == 0:
                                    break
                        elif tt.kind == "id":
                            protected.add(sig[j])
                        j += 1
            elif v in ("is", "as"):
                protect_type_run(i + 1)
            elif v == "var":
                j = i + 1
                if j < L and toks[sig[j]].kind == "id":
                    define(sig[j], not _in_regions(regions, sig[j]),
                           pending_protect)
                    pending_protect = False
                    j += 1
                    if j < L and toks[sig[j]].kind == "op" \
                            and toks[sig[j]].value == ":" \
                            and toks[sig[j] + 1].kind not in ("nl", "ind"):
                        protect_type_run(j + 1)
            elif v == "func":
                j = i + 1
                if j < L and toks[sig[j]].kind == "id":
                    define(sig[j], False, pending_protect)
                    pending_protect = False
                    j += 1
                if j < L and toks[sig[j]].kind == "op" \
                        and toks[sig[j]].value == "(":
                    j = collect_params(j)
                if j < L and toks[sig[j]].kind == "op" \
                        and toks[sig[j]].value == "->":
                    protect_type_run(j + 1)
            elif v == "for":
                collect_for_targets(i)
            elif v == "setget":
                j = i + 1
                end = stmt_end(i)
                while j < end:
                    if toks[sig[j]].kind == "id":
                        protected.add(sig[j])
                    j += 1
            elif v not in ("static", "if", "elif", "else", "while", "match",
                           "return", "pass", "break", "continue", "await",
                           "assert", "yield", "breakpoint", "in", "not",
                           "and", "or", "self", "super", "true", "false",
                           "null", "void", "func", "var"):
                pending_protect = False
            i += 1
            continue

        if t.kind == "id":
            prev = toks[sig[i - 1]] if i > 0 else None
            nxt = toks[sig[i + 1]] if i + 1 < L else None

            if prev is not None and prev.kind == "op" and prev.value == ".":
                base = toks[sig[i - 2]] if i >= 2 else None
                if base is not None and base.kind == "kw" \
                        and base.value == "self":
                    maybe_self.add(ti)
                else:
                    protected.add(ti)
                i += 1
                continue

            if (prev is not None and prev.kind == "op"
                    and prev.value in ("{", ",")
                    and openers and openers[-1] == "{"
                    and nxt is not None and nxt.kind == "op"
                    and nxt.value in ("=", ":")):
                protected.add(ti)
                i += 1
                continue

            if (stmt_start and nxt is not None and nxt.kind == "op"
                    and nxt.value == ":="):
                define(ti, not _in_regions(regions, ti), False)
                i += 1
                continue

        if t.kind == "op" and t.value == "$":
            j = i + 1
            while j < L:
                tt = toks[sig[j]]
                if tt.kind == "id":
                    protected.add(sig[j])
                elif tt.kind == "op" and tt.value in ("/", "."):
                    pass
                else:
                    break
                j += 1
        elif t.kind == "op" and t.value == "%":
            prev = toks[sig[i - 1]] if i > 0 else None
            primary = (prev is None or prev.kind == "kw"
                       or (prev.kind == "op"
                           and prev.value not in (")", "]", "}")))
            if primary and i + 1 < L and toks[sig[i + 1]].kind == "id":
                protected.add(sig[i + 1])

        if stmt_start and pending_protect and t.kind not in ("kw", "op"):
            pending_protect = False
        i += 1

    member_defs = {toks[ti].value for ti, m in defs if m}

    for ti in maybe_self:
        if toks[ti].value not in member_defs:
            protected.add(ti)

    protected_names = {toks[ti].value for ti in protected
                       if toks[ti].kind == "id"}

    taken = {t.value for t in toks if t.kind == "id"} | never
    mapping: dict[str, str] = {}
    seen: set[str] = set()
    for ti, _member in defs:
        name = toks[ti].value
        if name in seen:
            continue
        seen.add(name)
        if name in protected_names or not eligible(name):
            continue
        mapping[name] = _gen_name(rng, taken)

    for i in sig:
        t = toks[i]
        if t.kind == "id" and i not in protected and t.value in mapping:
            t.value = mapping[t.value]

    return detokenize(toks)
