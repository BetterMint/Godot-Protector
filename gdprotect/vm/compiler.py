
from __future__ import annotations

import random
import struct

from .isa import (Dialect, GVMB_MAGIC, GVMB_VERSION, Insn, Op, encode_insn,
                  write_const)

class CompileError(Exception):
    pass

class VirtualizeUnsupported(CompileError):
    pass

HOST_SLOTS = {
    "print", "printerr", "print_debug", "prints",
    "str", "len", "range", "load", "preload",
    "pow", "abs", "min", "max", "clamp",
    "floor", "ceil", "round", "sign", "sqrt",
    "sin", "cos", "tan", "asin", "acos",
    "atan", "atan2", "fmod", "fposmod",
    "lerp", "snapped", "move_toward", "wrapf",
    "randf", "randi", "randf_range", "randi_range",
    "seed", "randomize",
    "int", "float", "bool", "type_string",
    "is_instance_valid", "push_error", "push_warning",
    "str_to_var", "var_to_str", "type_convert",
    "bnot", "band", "bor", "bxor", "bshl", "bshr",
    "Vector2", "Vector2i", "Vector3", "Vector3i",
    "Color", "Rect2", "Rect2i", "Transform2D",
    "StringName", "NodePath", "Vector4", "Vector4i",
    "Plane", "Quaternion", "AABB", "Basis",
    "Transform3D", "Projection",
    "Callable",
}

_TYPE_CONSTS = {
    "Vector2": {
        "ZERO": (0, 0), "ONE": (1, 1), "INF": ("INF", "INF"),
        "LEFT": (-1, 0), "RIGHT": (1, 0), "UP": (0, -1), "DOWN": (0, 1),
    },
    "Vector3": {
        "ZERO": (0, 0, 0), "ONE": (1, 1, 1), "INF": ("INF", "INF", "INF"),
        "LEFT": (-1, 0, 0), "RIGHT": (1, 0, 0),
        "UP": (0, 1, 0), "DOWN": (0, -1, 0),
        "FORWARD": (0, 0, -1), "BACK": (0, 0, 1),
    },
    "Vector4": {
        "ZERO": (0, 0, 0, 0), "ONE": (1, 1, 1, 1),
        "INF": ("INF", "INF", "INF", "INF"),
    },
}
_NUM_CONSTS = {"PI": 3.141592653589793, "TAU": 6.283185307179586,
               "INF": float("inf"), "NAN": float("nan")}

class _T:
    __slots__ = ("kind", "val", "line")

    def __init__(self, kind, val, line):
        self.kind = kind
        self.val = val
        self.line = line

    def __repr__(self):
        return f"<{self.kind}:{self.val!r}@{self.line}>"

_OPS = sorted([
    "**=", "<<=", ">>=", "==", "!=", "<=", ">=", "+=", "-=", "*=", "/=",
    "%=", "&=", "|=", "^=", ":=", "->", "**", "<<", ">>", "&&", "||",
    "+", "-", "*", "/", "%", "<", ">", "=", "!", "~", "?", ":", ";",
    ",", ".", "(", ")", "[", "]", "{", "}", "$", "@", "&", "|", "^",
], key=len, reverse=True)

_STR_ESC = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f",
            "v": "\v", "0": "\0", "\\": "\\", '"': '"', "'": "'",
            "/": "/", "a": "\a"}

def _lex_str(src, i, fn, line):
    n = len(src)
    nl = 0
    if src[i] in "&^":
        i += 1
    q = src[i]
    triple = src.startswith(q * 3, i)
    i += 3 if triple else 1
    out = []
    while i < n:
        c = src[i]
        if triple and src.startswith(q * 3, i):
            return "".join(out), i + 3, nl
        if not triple and c == q:
            return "".join(out), i + 1, nl
        if c == "\n" or c == "\r":
            if not triple:
                raise CompileError(f"{fn}:{line}: newline in string")
            if c == "\r" and i + 1 < n and src[i + 1] == "\n":
                i += 1
            nl += 1
            out.append("\n")
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            d = src[i + 1]
            if d in _STR_ESC:
                out.append(_STR_ESC[d])
                i += 2
                continue
            if d in "\r\n":
                if d == "\r" and i + 2 < n and src[i + 2] == "\n":
                    i += 1
                nl += 1
                i += 2
                continue
            if d in "xuU":
                w = {"x": 2, "u": 4, "U": 8}[d]
                try:
                    out.append(chr(int(src[i + 2:i + 2 + w], 16)))
                    i += 2 + w
                    continue
                except ValueError:
                    pass
            out.append("\\")
            out.append(d)
            i += 2
            continue
        out.append(c)
        i += 1
    raise CompileError(f"{fn}:{line}: unterminated string")

def _lex_num(src, i, fn, line):
    n = len(src)
    if src[i] == "0" and i + 2 < n and src[i + 1] in "xXbBoO":
        base = {"x": 16, "b": 2, "o": 8}[src[i + 1].lower()]
        j = i + 2
        digs = "0123456789abcdefABCDEF" if base == 16 else "0123456787"
        while j < n and (src[j] in digs or src[j] == "_"):
            j += 1
        try:
            return int(src[i + 2:j].replace("_", ""), base), j
        except ValueError:
            raise CompileError(f"{fn}:{line}: malformed number {src[i:j]!r}")
    j = i
    isf = False
    while j < n and (src[j].isdigit() or src[j] == "_"):
        j += 1
    if j < n and src[j] == "." and j + 1 < n and src[j + 1].isdigit():
        isf = True
        j += 1
        while j < n and (src[j].isdigit() or src[j] == "_"):
            j += 1
    if j < n and src[j] in "eE":
        k = j + 1
        if k < n and src[k] in "+-":
            k += 1
        if k < n and src[k].isdigit():
            isf = True
            j = k
            while j < n and (src[j].isdigit() or src[j] == "_"):
                j += 1
    s = src[i:j]
    if not s or s == "_":
        raise CompileError(f"{fn}:{line}: malformed number")
    try:
        return (float(s) if isf else int(s)), j
    except ValueError:
        raise CompileError(f"{fn}:{line}: malformed number {s!r}")

def _lex(src, fn):
    toks = []
    indents = [0]
    i, n = 0, len(src)
    line = 1
    start = True
    depth = 0
    while i < n:
        c = src[i]
        if start:
            w = 0
            while i < n and src[i] in " \t":
                w += (8 - w % 8) if src[i] == "\t" else 1
                i += 1
            if i >= n:
                break
            c = src[i]
            if c == "#":
                while i < n and src[i] != "\n":
                    i += 1
                continue
            if c in "\r\n":
                if c == "\r" and i + 1 < n and src[i + 1] == "\n":
                    i += 1
                i += 1
                line += 1
                continue
            if depth > 0:
                start = False
                continue
            start = False
            if w > indents[-1]:
                indents.append(w)
                toks.append(_T("indent", w, line))
            elif w < indents[-1]:
                while w < indents[-1]:
                    indents.pop()
                    toks.append(_T("dedent", 0, line))
                if w != indents[-1]:
                    raise CompileError(f"{fn}:{line}: inconsistent indentation")
            continue
        if c in " \t":
            i += 1
            continue
        if c == "#":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "\\":
            j = i + 1
            if j < n and src[j] == "\r" and j + 1 < n and src[j + 1] == "\n":
                j += 1
            if j < n and src[j] in "\r\n":
                i = j + 1
                line += 1
                continue
            raise CompileError(f"{fn}:{line}: unexpected '\\'")
        if c in "\r\n":
            if c == "\r" and i + 1 < n and src[i + 1] == "\n":
                i += 1
            i += 1
            line += 1
            if depth == 0:
                toks.append(_T("nl", None, line))
                start = True
            continue
        if c in "\"'" or (c in "&^" and i + 1 < n and src[i + 1] in "\"'"):
            v, i, add = _lex_str(src, i, fn, line)
            toks.append(_T("str", v, line))
            line += add
            continue
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            v, i = _lex_num(src, i, fn, line)
            toks.append(_T("num", v, line))
            continue
        if c == "_" or c.isalpha():
            j = i + 1
            while j < n and (src[j] == "_" or src[j].isalnum()):
                j += 1
            toks.append(_T("name", src[i:j], line))
            i = j
            continue
        for op in _OPS:
            if src.startswith(op, i):
                i += len(op)
                if op in "([{":
                    depth += 1
                elif op in ")]}":
                    depth -= 1
                    if depth < 0:
                        raise CompileError(f"{fn}:{line}: unbalanced '{op}'")
                toks.append(_T("op", op, line))
                break
        else:
            raise CompileError(f"{fn}:{line}: unexpected character {c!r}")
    if depth != 0:
        raise CompileError(f"{fn}:{line}: unclosed bracket")
    if toks and toks[-1].kind not in ("nl", "dedent"):
        toks.append(_T("nl", None, line))
    while len(indents) > 1:
        indents.pop()
        toks.append(_T("dedent", 0, line))
    toks.append(_T("eof", None, line))
    return toks

class _Parser:
    def __init__(self, toks, fn):
        self.t = toks
        self.i = 0
        self.fn = fn or "<script>"

    @property
    def cur(self):
        return self.t[self.i]

    def peek(self, k=1):
        return self.t[min(self.i + k, len(self.t) - 1)]

    def take(self):
        tk = self.cur
        if tk.kind != "eof":
            self.i += 1
        return tk

    def at_op(self, v):
        t = self.cur
        return t.kind == "op" and t.val == v

    def at_kw(self, w):
        t = self.cur
        return t.kind == "name" and t.val == w

    def accept_op(self, v):
        if self.at_op(v):
            return self.take()
        return None

    def accept_kw(self, w):
        if self.at_kw(w):
            return self.take()
        return None

    def expect_op(self, v):
        if not self.at_op(v):
            self.err(f"expected '{v}', got {self.cur.val!r}")
        return self.take()

    def expect_name(self):
        if self.cur.kind != "name":
            self.err(f"expected name, got {self.cur.val!r}")
        return self.take().val

    def err(self, msg, tok=None):
        ln = (tok or self.cur).line
        raise CompileError(f"{self.fn}:{ln}: {msg}")

    def unsup(self, msg, tok=None):
        ln = (tok or self.cur).line
        raise VirtualizeUnsupported(f"{self.fn}:{ln}: {msg}")

    def parse_module(self):
        nodes = []
        while True:
            while self.cur.kind == "nl" or self.at_op(";"):
                self.take()
            t = self.cur
            if t.kind == "eof":
                return nodes
            if self.at_op("@"):
                anns = []
                while self.at_op("@"):
                    anns += self.read_annotations()
                    while self.cur.kind == "nl" or self.at_op(";"):
                        self.take()
                t = self.cur
                if t.kind == "eof":
                    return nodes
                if t.kind == "indent":
                    self.unsup("unexpected indentation at top level", t)
                if t.kind != "name":
                    self.unsup(f"unexpected top-level token {t.val!r}", t)
                nodes.append(self.parse_module_stmt(t) + (anns,))
                continue
            if t.kind == "indent":
                self.unsup("unexpected indentation at top level (get/set "
                           "blocks and inner classes are unsupported)", t)
            if t.kind != "name":
                self.unsup(f"unexpected top-level token {t.val!r}", t)
            nodes.append(self.parse_module_stmt(t))

    def parse_module_stmt(self, t):
        w = t.val
        if w == "func":
            return self.parse_func(False)
        if w == "static":
            self.take()
            if self.at_kw("func"):
                return self.parse_func(True)
            if self.at_kw("var"):
                return self.parse_member(True)
            self.unsup("'static' outside a function/var")
        if w == "var":
            return self.parse_member(False)
        if w == "const":
            return self.parse_const()
        if w == "signal":
            return self.parse_signal()
        if w in ("extends", "class_name", "tool"):
            ln = self.take().line
            arg = None
            if self.cur.kind == "str":
                arg = self.take().val
            elif self.cur.kind == "name":
                arg = self.take().val
                while self.accept_op("."):
                    arg += "." + self.expect_name()
            while self.cur.kind not in ("nl", "eof"):
                self.take()
            return ("meta", ln, w, arg)
        if w == "enum" and getattr(self, "native", False):
            return self.parse_enum()
        if w == "class" and getattr(self, "native", False):
            return self.parse_inner_class()
        if w in ("enum", "class", "match", "await", "yield", "assert",
                 "setget", "export", "onready", "remote", "master",
                 "puppet", "sync", "remotesync", "mastersync",
                 "puppetsync", "breakpoint", "namespace"):
            self.unsup(f"top-level '{w}' is not virtualizable", t)
        self.unsup(f"unsupported top-level statement '{w}'", t)

    def read_annotations(self):

        out = []
        while self.accept_op("@"):
            n = self.expect_name()
            while self.accept_op("."):
                n += "." + self.expect_name()
            if self.at_op("("):
                d = 0
                while True:
                    t = self.take()
                    if t.kind == "eof":
                        self.err("unterminated annotation", t)
                    if t.kind == "op" and t.val == "(":
                        d += 1
                    elif t.kind == "op" and t.val == ")":
                        d -= 1
                        if d == 0:
                            break
            out.append(n)
        return out

    def skip_annotations(self):
        self.read_annotations()

    def parse_signal(self):
        ln = self.take().line
        name = self.expect_name()
        params = []
        if self.accept_op("("):
            if not self.accept_op(")"):
                while True:
                    params.append(self.expect_name())
                    if self.accept_op(":") and not self.at_op("="):
                        self.skip_type()
                    if not self.accept_op(","):
                        break
                    if self.at_op(")"):
                        break
                self.expect_op(")")
        return ("signal", ln, name, params)

    def parse_const(self):
        ln = self.take().line
        name = self.expect_name()
        if self.accept_op(":") and not self.at_op("="):
            self.skip_type()
        if not self.accept_op("=") and not self.accept_op(":="):
            self.err("expected '=' in const declaration")
        e = self.parse_expr()
        return ("const", ln, name, e)

    def parse_member(self, static=False):
        t = self.take()
        name = self.expect_name()
        if self.accept_op(":") and not self.at_op("="):
            if self.cur.kind == "nl" and not getattr(self, "native", False):
                self.unsup("property get/set blocks", t)
            if self.at_kw("get") or self.at_kw("set") or self.at_kw("setget"):
                self.unsup("property accessors (setget/get/set)", t)
            self.skip_type()
        init = None
        if self.accept_op("=") or self.accept_op(":="):
            init = self.parse_expr()
        sparam, setter, getter = "value", None, None
        if getattr(self, "native", False) and self.at_op(":"):
            self.take()
            sparam, setter, getter = self.parse_accessors()
        elif getattr(self, "native", False) and self.at_kw("setget"):
            self.take()
            setter, getter = self.parse_setget_args(name)
        elif self.at_kw("setget") or self.at_kw("get") or self.at_kw("set"):
            self.unsup("property accessors (setget/get/set)")
        return ("member", t.line, name, init, sparam, setter, getter,
                static)

    def parse_setget_args(self, name):

        sn = gn = None
        if self.cur.kind == "name" and self.cur.val != "_":
            sn = self.take().val
        if self.accept_op(","):
            if self.cur.kind == "name" and self.cur.val != "_":
                gn = self.take().val
        setter = ("sg", sn or f"set_{name}")
        getter = ("sg", gn or f"get_{name}") \
            if (gn is not None or sn is None) else None
        return setter, getter

    def parse_accessors(self):

        sparam, setter, getter = "value", None, None
        def one():
            nonlocal sparam, setter, getter
            if self.at_kw("set"):
                self.take()
                if self.accept_op("("):
                    if not self.at_op(")"):
                        sparam = self.expect_name()
                        if self.accept_op(":") and not self.at_op("="):
                            self.skip_type()
                    self.expect_op(")")
                setter = self.parse_suite()
                return True
            if self.at_kw("get"):
                self.take()
                getter = self.parse_suite()
                return True
            return False
        if self.cur.kind == "nl":
            self.take()
            if self.cur.kind == "indent":
                self.take()
                while True:
                    while self.cur.kind == "nl":
                        self.take()
                    if not one():
                        break
                while self.cur.kind == "nl":
                    self.take()
                if self.cur.kind == "dedent":
                    self.take()
        else:
            while one():
                if not self.accept_op(";"):
                    break
        return sparam, setter, getter

    def parse_enum(self):
        ln = self.take().line
        name = None
        if self.cur.kind == "name":
            name = self.take().val
        self.expect_op("{")
        items = []
        while not self.at_op("}"):
            n = self.expect_name()
            e = None
            if self.accept_op("="):
                e = self.parse_expr()
            items.append((n, e))
            self.accept_op(",")
        self.expect_op("}")
        return ("enum", ln, name, items)

    def parse_match(self):
        ln = self.take().line
        subj = self.parse_expr()
        self.expect_op(":")
        if self.cur.kind == "nl":
            self.take()
        if self.cur.kind == "indent":
            self.take()
        arms = []
        while self.cur.kind not in ("dedent", "eof"):
            pats = []
            while True:
                if self.cur.kind == "name" and self.cur.val == "_":
                    self.take()
                    pats.append(("wild", ln))
                elif self.at_kw("var"):
                    self.unsup("binding patterns in match", self.cur)
                else:
                    pats.append(self.parse_expr())
                if not self.accept_op(","):
                    break
            guard = None
            if self.at_kw("when"):
                self.take()
                guard = self.parse_expr()
            arms.append((pats, guard, self.parse_suite()))
            while self.cur.kind == "nl":
                self.take()
        if self.cur.kind == "dedent":
            self.take()
        return ("match", ln, subj, arms)

    def parse_func(self, static):
        ln = self.take().line
        name = self.expect_name()
        self.expect_op("(")
        params = []
        if not self.accept_op(")"):
            while True:
                if self.at_op(")"):
                    break
                pname = self.expect_name()
                if self.accept_op(":") and not self.at_op("="):
                    self.skip_type()
                dflt = None
                if self.accept_op("="):
                    dflt = self.parse_expr()
                params.append((pname, dflt))
                if not self.accept_op(","):
                    break
            self.expect_op(")")
        if self.accept_op("->"):
            self.skip_type()
        body = self.parse_suite()
        return ("func", ln, name, params, body, static)

    def skip_type(self):
        if self.cur.kind != "name":
            self.err("expected a type name")
        self.take()
        while self.accept_op("."):
            self.expect_name()
        if self.at_op("["):
            d = 0
            while True:
                t = self.take()
                if t.kind == "eof":
                    self.err("unterminated type", t)
                if t.kind == "op" and t.val == "[":
                    d += 1
                elif t.kind == "op" and t.val == "]":
                    d -= 1
                    if d == 0:
                        return

    def parse_suite(self, in_expr=False):
        in_expr = in_expr or getattr(self, "expr_depth", 0) > 0
        ln = self.expect_op(":").line
        if self.cur.kind == "nl":
            self.take()
            if self.cur.kind == "indent":
                self.take()
                return self.parse_block()
            return []
        if self.cur.kind == "eof":
            self.err("expected a suite after ':'")
        out = self.parse_inline(in_expr)
        if out and out[-1][0] in ("if", "while", "for"):
            return out
        t = self.cur
        if t.kind == "nl":
            self.take()
        elif in_expr and (t.kind == "op" and t.val in (")", "]", "}", ",")
                          or t.kind in ("eof", "dedent")):
            pass
        elif t.kind in ("eof", "dedent"):
            pass
        elif self.at_kw("elif") or self.at_kw("else"):
            pass
        else:
            self.err(f"expected end of line, got {t.val!r}", t)
        return out

    def parse_inline(self, in_expr=False):
        in_expr = in_expr or getattr(self, "expr_depth", 0) > 0
        out = []
        while True:
            out.append(self.parse_stmt())
            if self.accept_op(";"):
                t = self.cur
                if in_expr and t.kind == "op" and t.val in (")", "]", "}", ","):
                    break
                if t.kind in ("nl", "eof") or self.at_kw("elif") \
                        or self.at_kw("else"):
                    break
                continue
            if in_expr:
                t = self.cur
                if t.kind == "op" and t.val in (")", "]", "}", ",") \
                        or t.kind in ("nl", "eof", "dedent") \
                        or self.at_kw("elif") or self.at_kw("else"):
                    break
                continue
            break
        return out

    def parse_block(self):
        out = []
        while True:
            while self.cur.kind == "nl":
                self.take()
            t = self.cur
            if t.kind == "dedent" or t.kind == "eof":
                if t.kind == "dedent":
                    self.take()
                return out
            s = self.parse_stmt()
            out.append(s)
            while self.accept_op(";"):
                t = self.cur
                if t.kind in ("nl", "dedent", "eof"):
                    break
                s = self.parse_stmt()
                out.append(s)
            if s[0] not in ("if", "while", "for", "match"):
                t = self.cur
                if t.kind not in ("nl", "dedent", "eof") \
                        and not self.at_kw("elif") and not self.at_kw("else") \
                        and not (s[0] in ("var", "lconst")
                                 and isinstance(s[3], tuple)
                                 and s[3][0] == "lambda") \
                        and not (s[0] == "assign"
                                 and isinstance(s[4], tuple)
                                 and s[4][0] == "lambda") \
                        and not (s[0] == "return"
                                 and isinstance(s[2], tuple)
                                 and s[2][0] == "lambda"):
                    self.err(f"expected end of statement, got {t.val!r}", t)

    def parse_stmt(self):
        t = self.cur
        if t.kind == "op" and t.val == "@":
            self.skip_annotations()
            while self.cur.kind == "nl":
                self.take()
            if self.cur.kind in ("dedent", "eof"):
                return ("pass", t.line)
            return self.parse_stmt()
        if t.kind == "name":
            w = t.val
            if w == "if":
                return self.parse_if()
            if w == "while":
                return self.parse_while()
            if w == "for":
                return self.parse_for()
            if w == "return":
                ln = self.take().line
                if self.cur.kind in ("nl", "dedent", "eof") \
                        or self.at_op(";"):
                    return ("return", ln, None)
                if getattr(self, "expr_depth", 0) and self._stmtish_ahead():
                    return ("return", ln, None)
                return ("return", ln, self.parse_expr())
            if w in ("pass", "break", "continue"):
                return (self.take().val, t.line)
            if w == "var":
                return self.parse_local_var()
            if w == "const":
                ln = self.take().line
                name = self.expect_name()
                if self.accept_op(":") and not self.at_op("="):
                    self.skip_type()
                if not self.accept_op("=") and not self.accept_op(":="):
                    self.err("expected '=' in const declaration")
                return ("lconst", ln, name, self.parse_expr())
            if w in ("elif", "else"):
                self.err(f"'{w}' without matching 'if'", t)
            if w == "match" and getattr(self, "native", False):
                return self.parse_match()
            if w == "enum" and getattr(self, "native", False):
                return self.parse_enum()
            if w == "signal" and getattr(self, "native", False):
                return self.parse_signal()
            if w == "static" and getattr(self, "native", False):
                self.take()
                if self.at_kw("func"):
                    return self.parse_func(True)
                if self.at_kw("var"):
                    return self.parse_member()
                self.unsup("'static' outside a function/var", t)
            if getattr(self, "native", False) and w == "assert":
                self.take()
                if self.at_op("("):
                    a = self.parse_call_args()
                else:
                    a = [self.parse_expr()]
                    if self.accept_op(","):
                        a.append(self.parse_expr())
                if not (1 <= len(a) <= 2):
                    self.err("assert takes 1-2 args", t)
                return ("assert", t.line, a[0],
                        a[1] if len(a) > 1 else None)
            if getattr(self, "native", False) and w == "breakpoint":
                self.take()
                return ("pass", t.line)
            if w in ("match", "await", "yield", "assert", "breakpoint",
                     "enum", "class", "func", "signal", "extends",
                     "class_name", "setget", "static", "remote", "master",
                     "puppet", "sync") and not (
                    getattr(self, "native", False)
                    and w in ("await", "yield", "match", "enum")):
                self.unsup(f"'{w}' is not virtualizable", t)
        e = self.parse_expr()
        if e[0] == "name" and self.at_op(":="):
            ln = self.take().line
            return ("var", ln, e[2], self.parse_expr())
        if self.at_op(","):
            if getattr(self, "expr_depth", 0):
                return ("expr", t.line, e)
            self.unsup("tuple assignment / destructuring", t)
        if self.cur.kind == "op" and self.cur.val in _ASSIGN_OPS:
            op = self.take().val
            if e[0] not in ("name", "attr", "index"):
                self.err("invalid assignment target", t)
            return ("assign", t.line, e, op, self.parse_expr())
        return ("expr", t.line, e)

    def parse_local_var(self):
        t = self.take()
        name = self.expect_name()
        if self.accept_op(":") and not self.at_op("="):
            if self.cur.kind == "nl" and not getattr(self, "native", False):
                self.unsup("property get/set blocks", t)
            if self.at_kw("get") or self.at_kw("set") or self.at_kw("setget"):
                self.unsup("property accessors (setget/get/set)", t)
            self.skip_type()
        init = None
        if self.accept_op("=") or self.accept_op(":="):
            init = self.parse_expr()
        if getattr(self, "native", False) and self.at_op(":"):
            self.take()
            sparam, setter, getter = self.parse_accessors()
            return ("var", t.line, name, init, sparam, setter, getter)
        if getattr(self, "native", False) and self.at_kw("setget"):
            self.take()
            setter, getter = self.parse_setget_args(name)
            return ("var", t.line, name, init, "value", setter, getter)
        return ("var", t.line, name, init)

    def parse_if(self):
        ln = self.take().line
        cases = [(self.parse_expr(), self.parse_suite())]
        els = None
        while self.at_kw("elif"):
            self.take()
            cases.append((self.parse_expr(), self.parse_suite()))
        if self.at_kw("else"):
            self.take()
            els = self.parse_suite()
        return ("if", ln, cases, els)

    def parse_while(self):
        ln = self.take().line
        cond = self.parse_expr()
        return ("while", ln, cond, self.parse_suite())

    def parse_for(self):
        ln = self.take().line
        var = self.expect_name()
        if getattr(self, "native", False) \
                and self.accept_op(":") and not self.at_op("="):
            self.skip_type()
        if self.at_op(","):
            self.unsup("multi-target for loops")
        if not self.accept_kw("in"):
            self.err("expected 'in' in for loop")
        it = self.parse_expr()
        return ("for", ln, var, it, self.parse_suite())

    def parse_expr(self):
        return self.parse_tern()

    def parse_tern(self):
        e = self.parse_or()
        if self.at_kw("if"):
            if getattr(self, "expr_depth", 0) and self._if_is_stmt():
                return e
            ln = self.take().line
            c = self.parse_or()
            if not self.accept_kw("else"):
                self.err("expected 'else' in ternary expression")
            return ("tern", ln, c, e, self.parse_tern())
        return e

    def _if_is_stmt(self):



        d = 0
        i = self.i + 1
        while i < len(self.t):
            t = self.t[i]
            if t.kind == "op":
                if t.val in ("(", "[", "{"):
                    d += 1
                elif t.val in (")", "]", "}"):
                    if d == 0:
                        return True
                    d -= 1
                elif t.val in (":", ",") and d == 0:
                    return True
            elif t.kind == "name" and t.val == "else" and d == 0:
                return False
            elif t.kind in ("eof", "dedent"):
                return True
            i += 1
        return True

    def _stmtish_ahead(self):


        t = self.cur
        if t.kind == "name" and t.val in ("if", "for", "while", "match",
                "var", "const", "return", "pass", "break", "continue",
                "elif", "else", "enum"):
            return True
        d = 0
        i = self.i
        while i < len(self.t):
            t = self.t[i]
            if t.kind == "op":
                if t.val in ("(", "[", "{"):
                    d += 1
                elif t.val in (")", "]", "}"):
                    if d == 0:
                        return False
                    d -= 1
                elif d == 0 and t.val in _ASSIGN_OPS:
                    return True
                elif d == 0 and t.val in (",", ";", ":"):
                    return False
            elif t.kind in ("nl", "dedent", "eof"):
                return False
            i += 1
        return False

    def parse_or(self):
        e = self.parse_and()
        while True:
            if self.at_kw("or") or self.at_op("||"):
                ln = self.take().line
                e = ("bin", ln, "or", e, self.parse_and())
            else:
                return e

    def parse_and(self):
        e = self.parse_not()
        while True:
            if self.at_kw("and") or self.at_op("&&"):
                ln = self.take().line
                e = ("bin", ln, "and", e, self.parse_not())
            else:
                return e

    def parse_not(self):
        if self.at_kw("not"):
            ln = self.take().line
            return ("unary", ln, "not", self.parse_not())
        return self.parse_cmp()

    def parse_cmp(self):
        e = self.parse_bitor()
        seen_cmp = False
        while True:
            t = self.cur
            if t.kind == "op" and t.val in _CMP_OPS:
                if seen_cmp:
                    self.unsup("chained comparisons", t)
                seen_cmp = True
                self.take()
                e = ("bin", t.line, t.val, e, self.parse_bitor())
            elif self.at_kw("in"):
                self.take()
                e = ("bin", t.line, "in", e, self.parse_bitor())
            elif self.at_kw("not") and self.peek().val == "in":
                self.take()
                self.take()
                e = ("bin", t.line, "notin", e, self.parse_bitor())
            elif self.at_kw("is") or self.at_kw("as"):
                if getattr(self, "native", False):
                    op = self.take().val
                    tn = self.expect_name()
                    while self.accept_op("."):
                        tn += "." + self.expect_name()
                    e = ("istype" if op == "is" else "astype",
                         t.line, e, tn)
                else:
                    self.unsup(f"'{t.val}' operator", t)
            else:
                return e

    def parse_bitor(self):
        e = self.parse_bitxor()
        while self.at_op("|"):
            ln = self.take().line
            e = ("bin", ln, "|", e, self.parse_bitxor())
        return e

    def parse_bitxor(self):
        e = self.parse_bitand()
        while self.at_op("^"):
            ln = self.take().line
            e = ("bin", ln, "^", e, self.parse_bitand())
        return e

    def parse_bitand(self):
        e = self.parse_shift()
        while self.at_op("&"):
            ln = self.take().line
            e = ("bin", ln, "&", e, self.parse_shift())
        return e

    def parse_shift(self):
        e = self.parse_add()
        while self.at_op("<<") or self.at_op(">>"):
            ln = self.take()
            e = ("bin", ln.line, ln.val, e, self.parse_add())
        return e

    def parse_add(self):
        e = self.parse_mul()
        while self.at_op("+") or self.at_op("-"):
            ln = self.take()
            e = ("bin", ln.line, ln.val, e, self.parse_mul())
        return e

    def parse_mul(self):
        e = self.parse_unary()
        while self.at_op("*") or self.at_op("/") or self.at_op("%"):
            ln = self.take()
            e = ("bin", ln.line, ln.val, e, self.parse_unary())
        return e

    def parse_unary(self):
        t = self.cur
        if getattr(self, "native", False) and self.at_kw("await"):
            ln = self.take().line
            return ("await", ln, self.parse_unary())
        if t.kind == "op" and t.val in ("-", "+", "!", "~"):
            self.take()
            e = self.parse_unary()
            if t.val == "+" and e[0] == "lit":
                return e
            if t.val == "-" and e[0] == "lit" and isinstance(e[2], (int, float)):
                return ("lit", t.line, -e[2])
            return ("unary", t.line, t.val, e)
        return self.parse_pow()

    def parse_pow(self):
        e = self.parse_postfix()
        if self.at_op("**"):
            ln = self.take().line
            e = ("bin", ln, "**", e, self.parse_unary())
        return e

    def parse_postfix(self):
        e = self.parse_primary()
        while True:
            t = self.cur
            if self.at_op("."):
                ln = self.take().line
                e = ("attr", ln, e, self.expect_name())
            elif self.at_op("("):
                e = ("call", t.line, e, self.parse_call_args())
            elif self.at_op("["):
                ln = self.take().line
                ix = self.parse_expr()
                if self.at_op(":"):
                    self.unsup("slices")
                if self.at_op(","):
                    self.unsup("multi-dimensional indexing")
                self.expect_op("]")
                e = ("index", ln, e, ix)
            else:
                return e

    def parse_call_args(self):
        self.expect_op("(")
        args = []
        if not self.accept_op(")"):
            while True:
                if self.at_op(")"):
                    break
                args.append(self.parse_expr())
                if self.at_op("="):
                    self.unsup("named call arguments")
                if not self.accept_op(","):
                    break
            self.expect_op(")")
        return args

    def parse_primary(self):
        t = self.cur
        if t.kind == "num":
            self.take()
            if isinstance(t.val, int) and not -(1 << 63) <= t.val < (1 << 63):
                self.unsup("integer literal outside i64 range", t)
            return ("lit", t.line, t.val)
        if t.kind == "str":
            self.take()
            return ("lit", t.line, t.val)
        if self.at_op("("):
            ln = self.take().line
            e = self.parse_expr()
            if self.at_op(","):
                self.unsup("tuples")
            self.expect_op(")")
            return e
        if self.at_op("["):
            ln = self.take().line
            elems = []
            if not self.accept_op("]"):
                while True:
                    if self.at_op("]"):
                        break
                    elems.append(self.parse_expr())
                    if self.at_kw("for"):
                        self.unsup("comprehensions")
                    if not self.accept_op(","):
                        break
                self.expect_op("]")
            return ("array", ln, elems)
        if self.at_op("{"):
            ln = self.take().line
            pairs = []
            if not self.accept_op("}"):
                while True:
                    if self.at_op("}"):
                        break
                    k = self.parse_expr()
                    self.expect_op(":")
                    pairs.append((k, self.parse_expr()))
                    if not self.accept_op(","):
                        break
                self.expect_op("}")
            return ("dict", ln, pairs)
        if self.at_op("$"):
            ln = self.take().line
            return ("getnode", ln, self.parse_node_path())
        if self.at_op("%"):
            ln = self.take().line
            return ("getnode", ln, "%" + self.expect_name())
        if t.kind == "name":
            self.take()
            w = t.val
            if w == "true":
                return ("lit", t.line, True)
            if w == "false":
                return ("lit", t.line, False)
            if w == "null":
                return ("lit", t.line, None)
            if w == "self":
                return ("self", t.line)
            if w == "func" and getattr(self, "native", False):
                return self.parse_lambda(t.line)
            if w == "super" and getattr(self, "native", False):
                return ("super", t.line)
            if w == "yield" and getattr(self, "native", False):
                return self.parse_yield(t.line)
            if w in ("super", "func", "await", "yield", "match", "enum",
                     "class", "signal", "assert", "breakpoint"):
                self.unsup(f"'{w}' is not virtualizable", t)
            if w in ("if", "else", "elif", "for", "while", "return", "var",
                     "const", "pass", "break", "continue", "and", "or",
                     "not", "in", "is", "as", "extends", "class_name"):
                self.err(f"unexpected keyword '{w}'", t)
            return ("name", t.line, w)
        self.err(f"unexpected token {t.val!r}", t)

    def parse_yield(self, ln):


        if not self.at_op("("):
            return ("await", ln, ("attr", ln,
                                  ("call", ln, ("name", ln, "get_tree"), []),
                                  "process_frame"))
        args = self.parse_call_args()
        if not args:
            return ("await", ln, ("attr", ln,
                                  ("call", ln, ("name", ln, "get_tree"), []),
                                  "process_frame"))
        if len(args) == 1:
            return ("await", ln, args[0])
        if len(args) == 2 and args[1][0] == "lit" \
                and isinstance(args[1][2], str):
            return ("await", ln, ("attr", ln, args[0], args[1][2]))
        self.unsup("yield with unsupported arguments", None)

    def parse_inner_class(self):
        ln = self.take().line
        name = self.expect_name()
        base = None
        if self.accept_kw("extends"):
            base = self.parse_expr()
        self.expect_op(":")
        body = []
        if self.cur.kind == "nl":
            self.take()
            if self.cur.kind == "indent":
                self.take()
                while self.cur.kind not in ("dedent", "eof"):
                    while self.cur.kind == "nl":
                        self.take()
                    if self.cur.kind in ("dedent", "eof"):
                        break
                    if self.at_op("@"):
                        anns = []
                        while self.at_op("@"):
                            anns += self.read_annotations()
                            while self.cur.kind == "nl":
                                self.take()
                        t = self.cur
                        if t.kind != "name":
                            self.unsup(f"unexpected inner-class token {t.val!r}",
                                       t)
                        body.append(self.parse_module_stmt(t) + (anns,))
                        continue
                    t = self.cur
                    if t.kind != "name":
                        self.unsup(f"unexpected inner-class token {t.val!r}", t)
                    body.append(self.parse_module_stmt(t))
                if self.cur.kind == "dedent":
                    self.take()
        else:
            body.append(self.parse_module_stmt(self.cur))
        return ("innerclass", ln, name, base, body)

    def parse_lambda(self, ln):
        self.expect_op("(")
        params = []
        if not self.accept_op(")"):
            while True:
                pname = self.expect_name()
                if self.accept_op(":") and not self.at_op("="):
                    self.skip_type()
                dflt = None
                if self.accept_op("="):
                    dflt = self.parse_expr()
                params.append((pname, dflt))
                if not self.accept_op(","):
                    break
            self.expect_op(")")
        if self.accept_op("->"):
            self.skip_type()
        self.expr_depth = getattr(self, "expr_depth", 0) + 1
        try:
            body = self.parse_suite(in_expr=True)
        finally:
            self.expr_depth -= 1
        return ("lambda", ln, params, body)

    def parse_node_path(self):
        if self.cur.kind == "str":
            return self.take().val
        parts = [self.expect_name()]
        while self.accept_op("/"):
            parts.append(self.expect_name())
        return "/".join(parts)

_CMP_OPS = {"==", "!=", "<", "<=", ">", ">="}
_ASSIGN_OPS = {"=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=",
               "&=", "|=", "^="}

_BIN_OP = {"+": Op.ADD, "-": Op.SUB, "*": Op.MUL, "/": Op.DIV, "%": Op.MOD,
           "==": Op.CMPEQ, "!=": Op.CMPNE, "<": Op.CMPLT, "<=": Op.CMPLE,
           ">": Op.CMPGT, ">=": Op.CMPGE}
_HOST_BIN = {"**": "pow", "&": "band", "|": "bor", "^": "bxor",
             "<<": "bshl", ">>": "bshr"}
_CMPND_OP = {"+=": Op.ADD, "-=": Op.SUB, "*=": Op.MUL, "/=": Op.DIV,
             "%=": Op.MOD}
_CMPND_HOST = {"**=": "pow", "&=": "band", "|=": "bor", "^=": "bxor",
               "<<=": "bshl", ">>=": "bshr"}
_INIT_FN = "__gvm_member_init"
_MAX_INJECT = 12

class _CG:
    def __init__(self, dialect, hardening, fn):
        self.d = dialect
        self.h = hardening
        self.fn = fn or "<script>"
        self.consts = []
        self.cix = {}
        self.code = []
        self.funcs = []
        self.fnames = set()
        self.members = set()
        self.signals = set()
        self.gconst = {}
        self.lmap = {}
        self.lconst = {}
        self.temps = set()
        self.free = set()
        self.loops = []
        self.inj = 0

    def unsup(self, msg, ln=0):
        raise VirtualizeUnsupported(f"{self.fn}:{ln}: {msg}")

    def kx(self, v):
        if v is None:
            k = ("n", None)
        elif isinstance(v, bool):
            k = ("b", v)
        elif isinstance(v, int):
            k = ("i", v)
        elif isinstance(v, float):
            k = ("f", "nan") if v != v else ("f", v)
        elif isinstance(v, str):
            k = ("s", v)
        elif isinstance(v, (bytes, bytearray)):
            k = ("y", bytes(v))
        else:
            raise CompileError(f"{self.fn}: unsupported const {type(v)}")
        ix = self.cix.get(k)
        if ix is None:
            ix = len(self.consts)
            if ix > 0xFFFF:
                self.unsup("constant pool overflow (>65535 entries)")
            self.consts.append(v)
            self.cix[k] = ix
        return ix

    def emit(self, op, a=0, b=0, c=0, bk="R"):
        self.code.append(Insn(op, a=a, b=b, c=c, has_c=True, b_kind=bk))
        return len(self.code) - 1

    def alloc(self, exclude=None):
        if not self.free:
            self.unsup("register pressure — too few scratch registers")
        if exclude is None:
            r = min(self.free)
            self.free.discard(r)
            return r
        cand = min((r for r in self.free if r != exclude), default=None)
        if cand is None:
            self.unsup("register pressure — too few scratch registers")
        self.free.discard(cand)
        return cand

    def rel(self, r):
        if r is not None and r in self.temps:
            self.free.add(r)

    def is_tmp(self, r):
        return r in self.temps

    def kx_setm(self, v, ln):
        k = self.kx(v)
        if k > 0xFF:
            self.unsup("member-name const index >255 (SETM operand is u8)", ln)
        return k

    def build(self, nodes):
        self.fnames = {n[2] for n in nodes if n[0] == "func"}
        inits = []
        for nd in nodes:
            if nd[0] == "const":
                self.gconst[nd[2]] = self._cval(nd[3], nd[1])
            elif nd[0] == "member":
                self.members.add(nd[2])
                inits.append(nd)
            elif nd[0] == "signal":
                self.members.add(nd[2])
                self.signals.add(nd[2])
        init_body = [("assign", nd[1], ("name", nd[1], nd[2]), "=", nd[3])
                     for nd in inits if nd[3] is not None]
        self._func(("func", 0, _INIT_FN, [], init_body, True))
        for nd in nodes:
            if nd[0] == "func":
                self._func(nd)
        return self._image()

    def _cval(self, e, ln):
        t = e[0]
        if t == "lit":
            return e[2]
        if t == "unary":
            v = self._cval(e[3], ln)
            op = e[2]
            if op == "-":
                return self._int64(-v, ln)
            if op == "+":
                return v
            if op == "~":
                return ~v
            if op in ("!", "not"):
                return not v
        if t == "bin":
            op = e[2]
            l = self._cval(e[3], ln)
            r = self._cval(e[4], ln)
            try:
                if op == "+":
                    return self._int64(l + r, ln)
                if op == "-":
                    return self._int64(l - r, ln)
                if op == "*":
                    return self._int64(l * r, ln)
                if op == "/":
                    return self._int64(l // r, ln) \
                        if isinstance(l, int) and isinstance(r, int) else l / r
                if op == "%":
                    return l % r
                if op == "**":
                    return self._int64(l ** r, ln)
                if op == "<<":
                    return self._int64(l << r, ln)
                if op == ">>":
                    return self._int64(l >> r, ln)
                if op == "&":
                    return l & r
                if op == "|":
                    return l | r
                if op == "^":
                    return l ^ r
                if op == "==":
                    return l == r
                if op == "!=":
                    return l != r
                if op == "<":
                    return l < r
                if op == "<=":
                    return l <= r
                if op == ">":
                    return l > r
                if op == ">=":
                    return l >= r
                if op == "and":
                    return l and r
                if op == "or":
                    return l or r
            except Exception:
                self.unsup(f"bad constant expression '{op}'", ln)
        if t == "tern":
            return self._cval(e[3], ln) if self._cval(e[2], ln) \
                else self._cval(e[4], ln)
        self.unsup("non-constant expression in const", ln)

    def _int64(self, v, ln):
        if isinstance(v, int) and not -(1 << 63) <= v < (1 << 63):
            self.unsup("constant outside i64 range", ln)
        return v

    def _func(self, nd):
        _, ln, name, params, body, _static = nd
        entry = len(self.code)
        self.inj = 0
        self.lconst = {}
        locs = []

        def walk(ss):
            for s in ss:
                if s[0] == "var":
                    locs.append(s[2])
                elif s[0] == "for":
                    locs.append(s[2])
                    walk(s[4])
                elif s[0] == "if":
                    for _c, b in s[2]:
                        walk(b)
                    if s[3]:
                        walk(s[3])
                elif s[0] == "while":
                    walk(s[3])
        walk(body)

        self.lmap = {}
        r = 1
        for pn, _d in params:
            if pn in self.lmap:
                self.unsup(f"duplicate parameter '{pn}'", ln)
            self.lmap[pn] = r
            r += 1
        for v in locs:
            if v not in self.lmap:
                self.lmap[v] = r
                r += 1
        if r > 16:
            self.unsup(f"func '{name}' needs >15 registers "
                       f"(params+locals={r - 1})", ln)
        self.temps = {0} | set(range(r, 16))
        self.free = set(self.temps)
        if not self.free:
            self.unsup(f"func '{name}': no scratch registers left", ln)
        self.loops = []

        for pn, dflt in params:
            if dflt is None:
                continue
            rp = self.lmap[pn]
            rt = self.alloc()
            self.emit(Op.LOADK, a=rt, b=self.kx(None), bk="K")
            self.emit(Op.CMPEQ, a=rt, b=rt, c=rp)
            jf = self.emit(Op.JF, a=rt, b=0, bk="J")
            self.rel(rt)
            rv = self.ev(dflt)
            if rv != rp:
                self.emit(Op.MOVE, a=rp, b=rv)
            self.rel(rv)
            self.code[jf].b = len(self.code)

        self._opaque()
        self.blk(body)
        rt = self.alloc()
        self.emit(Op.LOADK, a=rt, b=self.kx(None), bk="K")
        self.emit(Op.RET, a=rt)
        self.funcs.append((entry, len(params), self.kx(name)))

    def blk(self, ss):
        for s in ss:
            self.st(s)

    def _opaque(self):
        if self.h <= 0 or self.inj >= _MAX_INJECT or len(self.free) < 2:
            return
        self.inj += 1
        r1 = self.alloc()
        r2 = self.alloc()
        rng = random.Random(
            (self.d.salt ^ 0x9E3779B9 ^ (len(self.code) * 0x85EBCA77))
            & 0xFFFFFFFF)
        x = rng.randrange(2, 0x8000)
        truth = rng.randrange(2) == 0
        v = rng.randrange(3)
        if v == 0:
            self.emit(Op.LOADK, a=r1, b=self.kx(x), bk="K")
            self.emit(Op.LOADK, a=r2, b=self.kx(x * 2 if truth else x * 2 + 1),
                      bk="K")
            self.emit(Op.ADD, a=r1, b=r1, c=r1)
        elif v == 1:
            self.emit(Op.LOADK, a=r1, b=self.kx(x), bk="K")
            self.emit(Op.LOADK, a=r2, b=self.kx(3), bk="K")
            self.emit(Op.MUL, a=r1, b=r1, c=r2)
            self.emit(Op.LOADK, a=r2,
                      b=self.kx(x * 3 if truth else x * 3 + 1), bk="K")
        else:
            self.emit(Op.LOADK, a=r1, b=self.kx(x), bk="K")
            self.emit(Op.LOADK, a=r2, b=self.kx(x + 1), bk="K")
            self.emit(Op.MUL, a=r1, b=r1, c=r2)
            v2 = x * x + x
            self.emit(Op.LOADK, a=r2,
                      b=self.kx(v2 if truth else v2 + 1), bk="K")
        self.emit(Op.CMPEQ, a=r1, b=r1, c=r2)
        jmp = self.emit(Op.JT if truth else Op.JF, a=r1, b=0, bk="J")
        for _ in range(rng.randrange(2, 6)):
            k = rng.randrange(6)
            if k == 0:
                self.emit(Op.LOADK, a=rng.choice((r1, r2)),
                          b=self.kx(rng.randrange(-0x10000, 0x10000)), bk="K")
            elif k == 1:
                self.emit(Op.MOVE, a=r1, b=r2)
            elif k == 2:
                self.emit(Op.ADD, a=r1, b=r1, c=r2)
            elif k == 3:
                self.emit(Op.MUL, a=r2, b=r2, c=r1)
            elif k == 4:
                self.emit(Op.NOT, a=r1, b=r2)
            else:
                self.emit(Op.PUSH, a=r1)
                self.emit(Op.POP, a=r2)
        self.code[jmp].b = len(self.code)
        self.rel(r1)
        self.rel(r2)

    def st(self, s):
        t = s[0]
        if t == "var":
            rx = self.lmap[s[2]]
            if s[3] is None:
                self.emit(Op.LOADK, a=rx, b=self.kx(None), bk="K")
            else:
                e = s[3]
                if e[0] == "lit":
                    self.emit(Op.LOADK, a=rx, b=self.kx(e[2]), bk="K")
                else:
                    re = self.ev(e)
                    if re != rx:
                        self.emit(Op.MOVE, a=rx, b=re)
                    self.rel(re)
        elif t == "lconst":
            self.lconst[s[2]] = self._cval(s[3], s[1])
        elif t == "assign":
            self._assign(s[2], s[3], s[4], s[1])
        elif t == "expr":
            if not self._pure(s[2]):
                self.rel(self.ev(s[2]))
        elif t == "return":
            if self.h >= 2:
                self._opaque()
            if s[2] is None:
                r = self.alloc()
                self.emit(Op.LOADK, a=r, b=self.kx(None), bk="K")
            else:
                r = self.ev(s[2])
            self.emit(Op.RET, a=r)
            self.rel(r)
        elif t == "if":
            ends = []
            cases, els = s[2], s[3]
            for i, (cond, body) in enumerate(cases):
                rc = self.ev(cond)
                jf = self.emit(Op.JF, a=rc, b=0, bk="J")
                self.rel(rc)
                self._opaque()
                self.blk(body)
                if i + 1 < len(cases) or els is not None:
                    ends.append(self.emit(Op.JMP, b=0, bk="J"))
                self.code[jf].b = len(self.code)
            if els is not None:
                self._opaque()
                self.blk(els)
            for j in ends:
                self.code[j].b = len(self.code)
        elif t == "while":
            ltop = len(self.code)
            rc = self.ev(s[2])
            jf = self.emit(Op.JF, a=rc, b=0, bk="J")
            self.rel(rc)
            brk = []
            self.loops.append((brk, ltop))
            self._opaque()
            self.blk(s[3])
            self.emit(Op.JMP, b=ltop, bk="J")
            end = len(self.code)
            self.code[jf].b = end
            for j in brk:
                self.code[j].b = end
            self.loops.pop()
        elif t == "for":
            ri = self.ev(s[3])
            rv = self.lmap[s[2]]
            if not self.is_tmp(ri) or ri == rv:
                ri2 = self.alloc()
                self.emit(Op.MOVE, a=ri2, b=ri)
                ri = ri2
            ltop = len(self.code)
            it = self.emit(Op.ITER, a=rv, b=ri, c=0)
            brk = []
            self.loops.append((brk, ltop))
            self._opaque()
            self.blk(s[4])
            self.emit(Op.JMP, b=ltop, bk="J")
            end = len(self.code)
            if end > 0xFFFF:
                self.unsup("for-loop exit past cell 65535 (ITER u16)", s[1])
            self.code[it].c = end
            for j in brk:
                self.code[j].b = end
            self.loops.pop()
            self.rel(ri)
        elif t == "break":
            if not self.loops:
                self.unsup("'break' outside a loop", s[1])
            self.loops[-1][0].append(self.emit(Op.JMP, b=0, bk="J"))
        elif t == "continue":
            if not self.loops:
                self.unsup("'continue' outside a loop", s[1])
            self.emit(Op.JMP, b=self.loops[-1][1], bk="J")
        elif t == "pass":
            self.emit(Op.NOP)
        else:
            self.unsup(f"unhandled statement {t!r}", s[1])

    def _assign(self, tgt, op, rhs, ln):
        if tgt[0] == "name":
            self._assign_name(tgt[2], op, rhs, ln)
            return
        steps = []
        node = tgt
        while node[0] in ("attr", "index"):
            steps.append(("getm" if node[0] == "attr" else "aget", node[3]))
            node = node[2]
        steps.reverse()
        if node[0] == "self" and steps and steps[0][0] == "getm" \
                and steps[0][1] in self.members:
            self._assign(("name", ln, steps[0][1]) if len(steps) == 1 else
                         self._rechain(("name", ln, steps[0][1]), steps[1:]),
                         op, rhs, ln)
            return
        rroot = self.ev(node)
        chain = []
        cur = rroot
        for kind, key in steps[:-1]:
            nxt = self.alloc()
            if kind == "getm":
                k = self.kx_setm(key, ln)
                self.emit(Op.GETM, a=nxt, b=cur, c=k)
                chain.append((cur, kind, k, nxt))
            else:
                ri = self.ev(key)
                self.emit(Op.AGET, a=nxt, b=cur, c=ri)
                chain.append((cur, kind, ri, nxt))
            cur = nxt
        lk, lkey = steps[-1]
        lk_kx = rk = None
        if lk == "getm":
            lk_kx = self.kx_setm(lkey, ln)
        else:
            rk = self.ev(lkey)
        if op == "=":
            re = self.ev(rhs)
            self._store_at(cur, lk, lk_kx, rk, re)
            self.rel(re)
        else:
            rt = self.alloc()
            if lk == "getm":
                self.emit(Op.GETM, a=rt, b=cur, c=self.kx(lkey))
            else:
                self.emit(Op.AGET, a=rt, b=cur, c=rk)
            re = self.ev(rhs)
            self._compound(rt, rt, re, op, ln)
            self._store_at(cur, lk, lk_kx, rk, rt)
            self.rel(re)
            self.rel(rt)
        for preg, kind, key, creg in reversed(chain):
            if kind == "getm":
                self.emit(Op.SETM, a=creg, b=preg, c=key)
            else:
                self.emit(Op.ASET, a=creg, b=preg, c=key)
        if node[0] == "name":
            n = node[2]
            if n in self.members:
                self.emit(Op.SETG, a=rroot, b=self.kx(n), bk="K")
            elif n not in self.lmap:
                if n in self.lconst or n in self.gconst:
                    self.unsup(f"assigning to const '{n}'", ln)
                self._store_unknown(n, rroot, ln)
        if rk is not None:
            self.rel(rk)
        for preg, kind, key, creg in chain:
            self.rel(creg)
            if kind == "aget":
                self.rel(key)
        self.rel(rroot)

    def _rechain(self, root, steps):
        ln = root[1]
        e = root
        for kind, key in steps:
            e = ("attr", ln, e, key) if kind == "getm" else ("index", ln, e, key)
        return e

    def _store_at(self, cur, kind, kx_, rk, rv):
        if kind == "getm":
            self.emit(Op.SETM, a=rv, b=cur, c=kx_)
        else:
            self.emit(Op.ASET, a=rv, b=cur, c=rk)

    def _assign_name(self, n, op, rhs, ln):
        if n in self.lmap:
            rx = self.lmap[n]
            if op == "=":
                re = self.ev(rhs)
                if re != rx:
                    self.emit(Op.MOVE, a=rx, b=re)
                self.rel(re)
            else:
                re = self.ev(rhs)
                self._compound(rx, rx, re, op, ln)
                self.rel(re)
        elif n in self.members:
            k = self.kx(n)
            if op == "=":
                re = self.ev(rhs)
                self.emit(Op.SETG, a=re, b=k, bk="K")
                self.rel(re)
            else:
                rt = self.alloc()
                self.emit(Op.GETG, a=rt, b=k, bk="K")
                re = self.ev(rhs)
                self._compound(rt, rt, re, op, ln)
                self.emit(Op.SETG, a=rt, b=k, bk="K")
                self.rel(re)
                self.rel(rt)
        elif n in self.lconst or n in self.gconst:
            self.unsup(f"assigning to const '{n}'", ln)
        else:
            if op == "=":
                re = self.ev(rhs)
                self._store_unknown(n, re, ln)
                self.rel(re)
            else:
                rt = self._load_unknown(n)
                re = self.ev(rhs)
                self._compound(rt, rt, re, op, ln)
                self._store_unknown(n, rt, ln)
                self.rel(re)
                self.rel(rt)

    def _load_unknown(self, n):
        k = self.kx(n)
        r = self.alloc()
        self.emit(Op.GETG, a=r, b=k, bk="K")
        rc = self.alloc()
        rn = self.alloc()
        self.emit(Op.LOADK, a=rn, b=self.kx(None), bk="K")
        self.emit(Op.CMPEQ, a=rc, b=r, c=rn)
        jf = self.emit(Op.JF, a=rc, b=0, bk="J")
        rs = self.alloc()
        self.emit(Op.SELF, a=rs)
        self.emit(Op.GETM, a=r, b=rs, c=k)
        self.rel(rs)
        self.code[jf].b = len(self.code)
        self.rel(rc)
        self.rel(rn)
        return r

    def _store_unknown(self, n, rv, ln):
        k = self.kx(n)
        rg = self.alloc()
        self.emit(Op.GETG, a=rg, b=k, bk="K")
        rn = self.alloc()
        self.emit(Op.LOADK, a=rn, b=self.kx(None), bk="K")
        self.emit(Op.CMPNE, a=rg, b=rg, c=rn)
        jf = self.emit(Op.JF, a=rg, b=0, bk="J")
        self.emit(Op.SETG, a=rv, b=k, bk="K")
        jm = self.emit(Op.JMP, b=0, bk="J")
        self.code[jf].b = len(self.code)
        rs = self.alloc()
        self.emit(Op.SELF, a=rs)
        self.emit(Op.SETM, a=rv, b=rs, c=self.kx_setm(n, ln))
        self.rel(rs)
        self.code[jm].b = len(self.code)
        self.rel(rg)
        self.rel(rn)

    def _compound(self, rd, rl, rr, op, ln):
        if op in _CMPND_OP:
            self.emit(_CMPND_OP[op], a=rd, b=rl, c=rr)
        elif op in _CMPND_HOST:
            self.emit(Op.PUSH, a=rl)
            self.emit(Op.PUSH, a=rr)
            self._push_argc(2)
            self.emit(Op.CALL, a=rd,
                      b=self.kx(_CMPND_HOST[op]), bk="K")
        else:
            self.unsup(f"unsupported assignment operator '{op}'", ln)

    def ev(self, e):
        t = e[0]
        if t == "lit":
            r = self.alloc()
            self.emit(Op.LOADK, a=r, b=self.kx(e[2]), bk="K")
            return r
        if t == "name":
            n = e[2]
            if n in self.lmap:
                return self.lmap[n]
            if n in _NUM_CONSTS:
                r = self.alloc()
                self.emit(Op.LOADK, a=r, b=self.kx(_NUM_CONSTS[n]), bk="K")
                return r
            if n in self.lconst:
                r = self.alloc()
                self.emit(Op.LOADK, a=r, b=self.kx(self.lconst[n]), bk="K")
                return r
            if n in self.gconst:
                r = self.alloc()
                self.emit(Op.LOADK, a=r, b=self.kx(self.gconst[n]), bk="K")
                return r
            if n in self.fnames:
                self.unsup(f"function '{n}' used as a value — first-class "
                           "function refs are unsupported", e[1])
            if n in self.members:
                r = self.alloc()
                self.emit(Op.GETG, a=r, b=self.kx(n), bk="K")
                return r
            return self._load_unknown(n)
        if t == "self":
            r = self.alloc()
            self.emit(Op.SELF, a=r)
            return r
        if t == "array":
            rd = self.alloc()
            self.emit(Op.NEWARR, a=rd)
            if len(self.free) < 2 and e[2]:
                self.unsup("register pressure in array literal", e[1])
            for el in e[2]:
                rv = self.ev(el)
                self.emit(Op.PUSH, a=rv)
                self._push_argc(1)
                ru = self.alloc()
                self.emit(Op.CALLM, a=ru, b=rd, c=self.kx("append"))
                self.rel(ru)
                self.rel(rv)
            return rd
        if t == "dict":
            rd = self.alloc()
            self.emit(Op.NEWDICT, a=rd)
            if len(self.free) < 2 and e[2]:
                self.unsup("register pressure in dict literal", e[1])
            for k, v in e[2]:
                rk = self.ev(k)
                rv = self.ev(v)
                self.emit(Op.ASET, a=rv, b=rd, c=rk)
                self.rel(rv)
                self.rel(rk)
            return rd
        if t == "index":
            ro = self.ev(e[2])
            ri = self.ev(e[3])
            rd = ro if self.is_tmp(ro) else self.alloc()
            self.emit(Op.AGET, a=rd, b=ro, c=ri)
            self.rel(ri)
            return rd
        if t == "attr":
            o = e[2]
            if o[0] == "name" and o[2] in _TYPE_CONSTS \
                    and e[3] in _TYPE_CONSTS[o[2]]:
                ctor = _TYPE_CONSTS[o[2]][e[3]]
                args = [("lit", e[1],
                         float("inf") if c == "INF" else c) for c in ctor]
                return self._ev_call(e[1], ("name", e[1], o[2]), args)
            if o[0] == "self" and e[3] in self.members:
                r = self.alloc()
                self.emit(Op.GETG, a=r, b=self.kx(e[3]), bk="K")
                return r
            ro = self.ev(o)
            rd = ro if self.is_tmp(ro) else self.alloc()
            self.emit(Op.GETM, a=rd, b=ro, c=self.kx(e[3]))
            return rd
        if t == "call":
            return self._ev_call(e[1], e[2], e[3])
        if t == "getnode":
            ln = e[1]
            return self._ev_call(ln,
                                 ("attr", ln, ("self", ln), "get_node"),
                                 [("lit", ln, e[2])])
        if t == "unary":
            op, sub = e[2], e[3]
            if op == "+":
                return self.ev(sub)
            if op == "-":
                ro = self.ev(sub)
                if self.is_tmp(ro):
                    self.emit(Op.NEG, a=ro)
                    return ro
                rd = self.alloc()
                self.emit(Op.MOVE, a=rd, b=ro)
                self.emit(Op.NEG, a=rd)
                return rd
            if op in ("!", "not"):
                ro = self.ev(sub)
                rd = ro if self.is_tmp(ro) else self.alloc()
                self.emit(Op.NOT, a=rd, b=ro)
                return rd
            if op == "~":
                return self._ev_call(e[1], ("name", e[1], "bnot"), [sub])
        if t == "bin":
            return self._ev_bin(e)
        if t == "tern":
            rc = self.ev(e[2])
            jf = self.emit(Op.JF, a=rc, b=0, bk="J")
            self.rel(rc)
            rd = self.alloc()
            rt = self.ev(e[3])
            if rt != rd:
                self.emit(Op.MOVE, a=rd, b=rt)
            self.rel(rt)
            jm = self.emit(Op.JMP, b=0, bk="J")
            self.code[jf].b = len(self.code)
            rf = self.ev(e[4])
            if rf != rd:
                self.emit(Op.MOVE, a=rd, b=rf)
            self.rel(rf)
            self.code[jm].b = len(self.code)
            return rd
        self.unsup(f"unhandled expression {t!r}", e[1])

    def _ev_bin(self, e):
        _, ln, op, l, r = e
        if op == "and" or op == "or":
            rd = self.alloc()
            rl = self.ev(l)
            if rl != rd:
                self.emit(Op.MOVE, a=rd, b=rl)
            self.rel(rl)
            j = self.emit(Op.JF if op == "and" else Op.JT, a=rd, b=0, bk="J")
            rr = self.ev(r)
            if rr != rd:
                self.emit(Op.MOVE, a=rd, b=rr)
            self.rel(rr)
            self.code[j].b = len(self.code)
            return rd
        if op in ("in", "notin"):
            ra = self.ev(l)
            ro = self.ev(r)
            self.emit(Op.PUSH, a=ra)
            self._push_argc(1)
            rd = self.alloc()
            self.emit(Op.CALLM, a=rd, b=ro, c=self.kx("has"))
            self.rel(ra)
            self.rel(ro)
            if op == "notin":
                self.emit(Op.NOT, a=rd, b=rd)
            return rd
        if op in _HOST_BIN:
            return self._ev_call(ln, ("name", ln, _HOST_BIN[op]), [l, r])
        if op in _BIN_OP:
            iop = _BIN_OP[op]
            rl = self.ev(l)
            if not self.free:
                if not self.is_tmp(rl):
                    self.unsup("register pressure in binary op", ln)
                self.emit(Op.PUSH, a=rl)
                self.rel(rl)
                rr = self.ev(r)
                rd = self.alloc(exclude=rr)
                self.emit(Op.POP, a=rd)
                self.emit(iop, a=rd, b=rd, c=rr)
                self.rel(rr)
                return rd
            rr = self.ev(r)
            rd = rl if self.is_tmp(rl) else self.alloc()
            self.emit(iop, a=rd, b=rl, c=rr)
            self.rel(rr)
            return rd
        self.unsup(f"unsupported operator '{op}'", ln)

    def _push_args(self, args):
        for a in args:
            r = self.ev(a)
            self.emit(Op.PUSH, a=r)
            self.rel(r)

    def _push_argc(self, n):
        rc = self.alloc()
        self.emit(Op.LOADK, a=rc, b=self.kx(n), bk="K")
        self.emit(Op.PUSH, a=rc)
        self.rel(rc)

    def _ev_call(self, ln, f, args):
        if f[0] == "name":
            n = f[2]
            if n == "self":
                self.unsup("calling 'self'", ln)
            if n in self.lmap:
                self.unsup(f"calling local variable '{n}'", ln)
            if n in self.lconst or n in self.gconst:
                self.unsup(f"calling const '{n}'", ln)
            if n == "preload":
                if len(args) != 1 or args[0][0] != "lit" \
                        or not isinstance(args[0][2], str):
                    self.unsup("preload() requires a string literal path", ln)
            if n in self.members:
                self.unsup(f"calling member variable '{n}'", ln)
            if n not in self.fnames and n in HOST_SLOTS:
                self._push_args(args)
                self._push_argc(len(args))
                rd = self.alloc()
                self.emit(Op.CALL, a=rd, b=self.kx(n), bk="K")
                return rd
            ro = self.alloc()
            self.emit(Op.SELF, a=ro)
            name_kx = self.kx(n)
        elif f[0] == "attr":
            sig = None
            if f[2][0] == "name" and f[2][2] in self.signals:
                sig = f[2][2]
            elif f[2][0] == "attr" and f[2][2][0] == "self" \
                    and f[2][3] in self.signals:
                sig = f[2][3]
            if sig is not None and f[3] in ("emit", "connect", "disconnect"):
                if f[3] == "emit":
                    return self._sig_call(ln, "emit_signal", sig, args)
                if len(args) != 1 or args[0][0] != "name" \
                        or args[0][2] not in self.fnames:
                    self.unsup(f"signal {f[3]}() needs a module-function "
                               "callback", ln)
                cb = self._ev_call(ln, ("name", ln, "Callable"),
                                   [("self", ln), ("lit", ln, args[0][2])])
                return self._sig_call(ln, f[3], sig, args=[cb])
            if f[2][0] == "self" and f[3] in self.members:
                self.unsup(f"calling member variable '{f[3]}'", ln)
            ro = self.ev(f[2])
            name_kx = self.kx(f[3])
        else:
            self.unsup("indirect call expression", ln)
        return self._callm_tail(ln, ro, name_kx, args)

    def _callm_tail(self, ln, ro, name_kx, args):
        if not self.free:
            self.unsup("register pressure in call", ln)
        self._push_args(args)
        self._push_argc(len(args))
        rd = self.alloc()
        self.emit(Op.CALLM, a=rd, b=ro, c=name_kx)
        self.rel(ro)
        return rd

    def _sig_call(self, ln, method, sig, args):
        ro = self.alloc()
        self.emit(Op.SELF, a=ro)
        rs = self.alloc()
        self.emit(Op.LOADK, a=rs, b=self.kx(sig), bk="K")
        self.emit(Op.PUSH, a=rs)
        self.rel(rs)
        for a in args:
            r = a if isinstance(a, int) else self.ev(a)
            self.emit(Op.PUSH, a=r)
            self.rel(r)
        self._push_argc(1 + len(args))
        rd = self.alloc()
        self.emit(Op.CALLM, a=rd, b=ro, c=self.kx(method))
        self.rel(ro)
        return rd

    def _pure(self, e):
        t = e[0]
        if t in ("lit", "name", "self"):
            return True
        if t == "array":
            return all(self._pure(x) for x in e[2])
        if t == "dict":
            return all(self._pure(k) and self._pure(v) for k, v in e[2])
        if t == "unary":
            return self._pure(e[3])
        if t == "bin":
            return self._pure(e[3]) and self._pure(e[4])
        if t == "tern":
            return self._pure(e[2]) and self._pure(e[3]) and self._pure(e[4])
        return False

    def _image(self):
        code_blob = bytearray()
        for i, insn in enumerate(self.code):
            code_blob += encode_insn(self.d, insn, i)
        out = bytearray()
        out += GVMB_MAGIC
        out += struct.pack("<I", GVMB_VERSION)
        out += struct.pack("<Q", self.d.salt & 0xFFFFFFFFFFFFFFFF)
        out += struct.pack("<III", len(self.consts), len(code_blob),
                           len(self.funcs))
        cp = bytearray()
        for v in self.consts:
            write_const(cp, v)
        out += cp
        for entry, argc, name_kx in self.funcs:
            out += struct.pack("<IHH", entry, argc, name_kx)
        out += code_blob
        return bytes(out)

def compile_source(src: str, dialect: Dialect, filename: str = "",
                   hardening: int = 1) -> bytes:
    toks = _lex(src, filename)
    mod = _Parser(toks, filename).parse_module()
    return _CG(dialect, hardening, filename).build(mod)

__all__ = ["compile_source", "CompileError", "VirtualizeUnsupported",
           "HOST_SLOTS"]
