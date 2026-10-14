
from __future__ import annotations

from dataclasses import dataclass

KEYWORDS = frozenset({
    "if", "elif", "else", "for", "while", "match", "break", "continue",
    "pass", "return", "class", "class_name", "extends", "is", "as",
    "self", "super", "signal", "func", "static", "const", "enum", "var",
    "breakpoint", "await", "assert", "in", "not", "and", "or", "void",
    "true", "false", "null", "trait", "namespace",
    "yield", "setget", "remote", "master", "puppet", "sync", "remotesync",
    "mastersync", "puppetsync", "onready", "export", "tool",
})

OPERATORS = sorted([
    "<<=", ">>=", "**=", "->", ":=", "==", "!=", "<=", ">=", "&&", "||",
    "<<", ">>", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "..",
    "+", "-", "*", "/", "%", "=", "<", ">", "!", "&", "|", "^", "~",
    "(", ")", "[", "]", "{", "}", ",", ":", ";", ".", "@", "$", "?",
], key=len, reverse=True)

OPENERS = frozenset("([{")
CLOSERS = frozenset(")]}")

SIG_KINDS = frozenset({"id", "kw", "num", "str", "op", "raw"})

@dataclass
class Token:
    kind: str
    value: str
    ws: str = ""
    pos: int = 0
    sval: object = None
    sprefix: str = ""

    def copy(self) -> "Token":
        return Token(self.kind, self.value, self.ws, self.pos,
                     self.sval, self.sprefix)

def _is_id_start(c: str) -> bool:
    return c == "_" or c.isalpha()

def _is_id_part(c: str) -> bool:
    return c == "_" or c.isalnum()

_ESCAPES = {
    "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t",
    "v": "\v", "0": "\0", "\\": "\\", "'": "'", '"': '"', "/": "/",
    "?": "?", " ": " ",
}

def unescape(s: str) -> str:
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            e = s[i + 1]
            if e in _ESCAPES:
                out.append(_ESCAPES[e])
                i += 2
                continue
            if e == "u" and i + 5 < n + 1:
                chunk = s[i + 2:i + 6]
                try:
                    out.append(chr(int(chunk, 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            if e == "U" and i + 9 < n + 1:
                chunk = s[i + 2:i + 10]
                try:
                    out.append(chr(int(chunk, 16)))
                    i += 10
                    continue
                except ValueError:
                    pass
            if e == "x" and i + 3 < n + 1:
                chunk = s[i + 2:i + 4]
                try:
                    out.append(chr(int(chunk, 16)))
                    i += 4
                    continue
                except ValueError:
                    pass
            out.append("\\")
            out.append(e)
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)

def _scan_string(src: str, qpos: int, raw: bool) -> tuple[int, object]:
    n = len(src)
    q = src[qpos]
    triple = src.startswith(q * 3, qpos)
    body = qpos + (3 if triple else 1)
    i = body
    while i < n:
        ch = src[i]
        if not raw and ch == "\\":
            i += 2
            continue
        if ch == q:
            if triple:
                if src.startswith(q * 3, i):
                    inner = src[body:i]
                    return i + 3, (inner if raw else unescape(inner))
                i += 1
                continue
            inner = src[body:i]
            return i + 1, (inner if raw else unescape(inner))
        if ch == "\n" and not triple:
            return i, None
        i += 1
    return n, None

def _scan_number(src: str, i: int) -> int:
    n = len(src)
    if src.startswith(("0x", "0X"), i):
        j = i + 2
        while j < n and (src[j] in "0123456789abcdefABCDEF" or src[j] == "_"):
            j += 1
        return j
    if src.startswith(("0b", "0B"), i):
        j = i + 2
        while j < n and (src[j] in "01" or src[j] == "_"):
            j += 1
        return j
    j = i
    while j < n and (src[j].isdigit() or src[j] == "_"):
        j += 1
    if j < n and src[j] == "." and not src.startswith("..", j):
        j += 1
        while j < n and (src[j].isdigit() or src[j] == "_"):
            j += 1
    if j < n and src[j] in "eE":
        k = j + 1
        if k < n and src[k] in "+-":
            k += 1
        m = k
        while m < n and (src[m].isdigit() or src[m] == "_"):
            m += 1
        if m > k:
            j = m
    return j

def tokenize(src: str) -> list[Token]:
    toks: list[Token] = []
    n = len(src)
    i = 0
    ws_parts: list[str] = []
    ws_cont = False
    depth = 0
    line_has_code = False
    indent_stack = [""]

    def emit(kind: str, value: str, pos: int,
             sval: object = None, sprefix: str = "") -> None:
        toks.append(Token(kind, value, "".join(ws_parts), pos, sval, sprefix))
        ws_parts.clear()

    def flush_indent(pos: int) -> None:
        if depth or ws_cont:
            return
        text = "".join(ws_parts)
        nl = text.rfind("\n")
        if nl < 0:
            return
        ind = text[nl + 1:]
        top = indent_stack[-1]
        if ind == top:
            return
        if ind.startswith(top):
            indent_stack.append(ind)
            toks.append(Token("ind", "", "", pos))
            return
        while len(indent_stack) > 1 and not ind.startswith(indent_stack[-1]):
            indent_stack.pop()
            toks.append(Token("ded", "", "", pos))
        if ind != indent_stack[-1] and ind.startswith(indent_stack[-1]):
            indent_stack.append(ind)
            toks.append(Token("ind", "", "", pos))

    def pre_token(pos: int) -> None:
        nonlocal ws_cont
        if ws_cont:
            ws_cont = False
            return
        flush_indent(pos)

    while i < n:
        c = src[i]

        if c in " \t\x0b\x0c":
            ws_parts.append(c)
            i += 1
            continue
        if c == "\r":
            if i + 1 < n and src[i + 1] == "\n":
                ws_parts.append("\r")
                i += 1
                continue
            c = "\n"
        if c == "\n":
            ws_parts.append("\n")
            if depth == 0 and line_has_code and not ws_cont:
                toks.append(Token("nl", "", "", i))
            line_has_code = False
            i += 1
            continue
        if c == "\\":
            j = i + 1
            while j < n and src[j] in " \t":
                j += 1
            k = j + 1 if j < n and src[j] == "\r" else j
            if k < n and src[k] == "\n":
                ws_parts.append(src[i:k + 1])
                i = k + 1
                ws_cont = True
                continue
            pre_token(i)
            emit("op", "\\", i)
            line_has_code = True
            i += 1
            continue

        if c == "#":
            j = src.find("\n", i)
            j = n if j < 0 else j
            toks.append(Token("com", src[i:j], "".join(ws_parts), i))
            ws_parts.clear()
            i = j
            continue

        if c in "&^" and i + 1 < n and src[i + 1] in "\"'":
            pre_token(i)
            end, sval = _scan_string(src, i + 1, raw=False)
            emit("str", src[i:end], i, sval=sval, sprefix=c)
            line_has_code = True
            i = end
            continue
        if c in "\"'":
            pre_token(i)
            end, sval = _scan_string(src, i, raw=False)
            emit("str", src[i:end], i, sval=sval)
            line_has_code = True
            i = end
            continue

        if _is_id_start(c):
            j = i + 1
            while j < n and _is_id_part(src[j]):
                j += 1
            word = src[i:j]
            if word in ("r", "R") and j < n and src[j] in "\"'":
                pre_token(i)
                end, sval = _scan_string(src, j, raw=True)
                emit("str", src[i:end], i, sval=sval, sprefix="r")
                line_has_code = True
                i = end
                continue
            pre_token(i)
            emit("kw" if word in KEYWORDS else "id", word, i)
            line_has_code = True
            i = j
            continue

        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            pre_token(i)
            end = _scan_number(src, i)
            emit("num", src[i:end], i)
            line_has_code = True
            i = end
            continue

        pre_token(i)
        for op in OPERATORS:
            if src.startswith(op, i):
                if op in OPENERS:
                    depth += 1
                elif op in CLOSERS:
                    depth = max(0, depth - 1)
                emit("op", op, i)
                i += len(op)
                break
        else:
            emit("op", c, i)
            i += 1
        line_has_code = True

    if line_has_code:
        toks.append(Token("nl", "", "", n))
    while len(indent_stack) > 1:
        indent_stack.pop()
        toks.append(Token("ded", "", "", n))
    toks.append(Token("eof", "", "".join(ws_parts), n))
    return toks

def detokenize(toks: list[Token]) -> str:
    return "".join(t.ws + t.value for t in toks)

def sig_indices(toks: list[Token]) -> list[int]:
    return [i for i, t in enumerate(toks) if t.kind in SIG_KINDS]

def is_stmt_start(toks: list[Token], ti: int) -> bool:
    return ti == 0 or toks[ti - 1].kind in ("nl", "ind", "ded")

def strip_comments(src: str) -> str:
    return detokenize([t for t in tokenize(src) if t.kind != "com"])

def find_suite(toks: list[Token], sig: list[int], i: int) -> tuple[int, int] | None:
    L = len(sig)
    j, d, colon = i + 1, 0, -1
    while j < L:
        tt = toks[sig[j]]
        if tt.kind == "op":
            if tt.value in OPENERS:
                d += 1
            elif tt.value in CLOSERS:
                d -= 1
            elif tt.value == ":" and d == 0:
                colon = j
                break
        if j > i + 1 and is_stmt_start(toks, sig[j]):
            return None
        j += 1
    if colon < 0 or colon + 1 >= L:
        return None
    a, b = sig[colon], sig[colon + 1]
    ind = -1
    for k in range(a + 1, b):
        if toks[k].kind == "ind":
            ind = k
            break
        if toks[k].kind == "nl":
            continue
    if ind < 0:
        return None
    level = 1
    for k in range(ind + 1, len(toks)):
        if toks[k].kind == "ind":
            level += 1
        elif toks[k].kind == "ded":
            level -= 1
            if level == 0:
                return ind, k
    return ind, len(toks) - 1
