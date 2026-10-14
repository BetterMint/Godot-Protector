
from __future__ import annotations

from .lexer import (Token, detokenize, find_suite, is_stmt_start,
                    sig_indices, tokenize)

_LITERAL_CALLS = frozenset({"preload", "load", "export", "setget"})
_PROTECT_ANNOTS = frozenset({"onready", "rpc"})

_DECODER_NAME = "__d"

def _detect_unit(toks: list[Token]) -> str:
    for t in toks:
        nl = t.ws.rfind("\n")
        if nl >= 0:
            ind = t.ws[nl + 1:]
            if ind:
                return ind
    return "\t"

def _decoder_source(unit: str, name: str) -> str:
    return (
        f"static func {name}(b: Array, k: int) -> String:\n"
        f"{unit}var _b := PackedByteArray(b)\n"
        f"{unit}for _i in _b.size():\n"
        f"{unit}{unit}_b[_i] = _b[_i] ^ ((k + _i * 7) & 0xFF)\n"
        f"{unit}return _b.get_string_from_utf8()")

def _stmt_end_sig(toks, sig, i) -> int:
    j = i + 1
    while j < len(sig) and not is_stmt_start(toks, sig[j]):
        j += 1
    return j

def _paren_range_skip(toks, sig, i, skip: set) -> int:
    d = 0
    j = i
    while j < len(sig):
        tt = toks[sig[j]]
        if tt.kind == "str":
            skip.add(sig[j])
        elif tt.kind == "op":
            if tt.value == "(":
                d += 1
            elif tt.value == ")":
                d -= 1
                if d == 0:
                    return j + 1
        j += 1
    return j

def _header_end(toks, sig) -> int:
    i = 0
    L = len(sig)
    first = True
    while i < L:
        t = toks[sig[i]]
        if t.kind == "op" and t.value == "@" and is_stmt_start(toks, sig[i]):
            i = _stmt_end_sig(toks, sig, i)
            continue
        if t.kind == "kw" and t.value in ("extends", "class_name", "tool"):
            i = _stmt_end_sig(toks, sig, i)
            first = False
            continue
        if t.kind == "str" and first:
            i = _stmt_end_sig(toks, sig, i)
            first = False
            continue
        break
    return i

def encrypt_source(src: str, rng) -> tuple[str, set]:
    toks = tokenize(src)
    sig = sig_indices(toks)
    L = len(sig)
    key = rng.randrange(1, 256)
    skip: set[int] = set()
    contents: set[str] = set()

    for t in toks:
        if t.kind == "str" and isinstance(t.sval, str):
            contents.add(t.sval)

    for i in range(L):
        t = toks[sig[i]]
        if t.kind == "op" and t.value == "(" and i > 0:
            prev = toks[sig[i - 1]]
            if prev.kind == "id" and prev.value in _LITERAL_CALLS:
                _paren_range_skip(toks, sig, i, skip)
            elif prev.kind == "id" and i > 1 \
                    and toks[sig[i - 2]].kind == "op" \
                    and toks[sig[i - 2]].value == "@":
                _paren_range_skip(toks, sig, i, skip)

    for i in range(L):
        if toks[sig[i]].kind == "kw" and toks[sig[i]].value == "func":
            j = i + 1
            if j < L and toks[sig[j]].kind == "id":
                j += 1
            if j < L and toks[sig[j]].kind == "op" \
                    and toks[sig[j]].value == "(":
                _paren_range_skip(toks, sig, j, skip)

    for i in range(L):
        if toks[sig[i]].kind == "kw" and toks[sig[i]].value == "const":
            j = i + 1
            end = _stmt_end_sig(toks, sig, i)
            while j < end:
                if toks[sig[j]].kind == "str":
                    skip.add(sig[j])
                j += 1

    i = 0
    while i < L:
        t = toks[sig[i]]
        if t.kind == "op" and t.value == "@" and is_stmt_start(toks, sig[i]):
            prot = False
            j = i
            while j < L and toks[sig[j]].kind == "op" \
                    and toks[sig[j]].value == "@":
                j += 1
                if j < L and toks[sig[j]].kind in ("id", "kw"):
                    an = toks[sig[j]].value
                    if an.startswith("export") or an in _PROTECT_ANNOTS:
                        prot = True
                    j += 1
                if j < L and toks[sig[j]].kind == "op" \
                        and toks[sig[j]].value == "(":
                    d = 0
                    while j < L:
                        if toks[sig[j]].kind == "op":
                            if toks[sig[j]].value == "(":
                                d += 1
                            elif toks[sig[j]].value == ")":
                                d -= 1
                                if d == 0:
                                    j += 1
                                    break
                        j += 1
            if prot:
                end = _stmt_end_sig(toks, sig, i)
                while j < end:
                    if toks[sig[j]].kind == "str":
                        skip.add(sig[j])
                    j += 1
            i = j
        else:
            i += 1

    for i in range(L):
        t = toks[sig[i]]
        if t.kind == "kw" and t.value == "match":
            suite = find_suite(toks, sig, i)
            if not suite:
                continue
            ind, ded = suite
            s = ind + 1
            while s < ded:
                if toks[s].kind in ("str", "id", "kw", "num", "op") \
                        and is_stmt_start(toks, s):
                    e = s
                    while e < ded and toks[e].kind != "nl":
                        e += 1
                    last = e - 1
                    while last > s and toks[last].kind in ("com",):
                        last -= 1
                    if toks[last].kind == "op" and toks[last].value == ":":
                        for k in range(s, e):
                            if toks[k].kind == "str":
                                skip.add(k)
                    s = e
                else:
                    s += 1

    name = _DECODER_NAME
    while any(t.kind == "id" and t.value == name for t in toks):
        name = "_" + name

    innermost: dict[int, str] = {}
    stack: list[str] = []
    for i in range(L):
        t = toks[sig[i]]
        if t.kind == "op":
            if t.value in "([{":
                stack.append(t.value)
            elif t.value in ")]}" and stack:
                stack.pop()
        innermost[sig[i]] = stack[-1] if stack else ""

    encrypted = 0
    for i in range(L):
        ti = sig[i]
        t = toks[ti]
        if t.kind != "str" or ti in skip or t.sval is None:
            continue
        if t.sprefix:
            continue
        prev = toks[sig[i - 1]] if i > 0 else None
        nxt = toks[sig[i + 1]] if i + 1 < L else None
        if prev is not None and prev.kind == "op" and prev.value == "$":
            continue
        if prev is not None and prev.kind == "kw" \
                and prev.value == "extends":
            continue
        if nxt is not None and nxt.kind == "op" and nxt.value == ":" \
                and innermost.get(ti) == "{":
            continue
        if is_stmt_start(toks, ti):
            continue
        data = t.sval.encode("utf-8")
        enc = [b ^ ((key + k * 7) & 0xFF) for k, b in enumerate(data)]
        t.value = f"{name}([{', '.join(map(str, enc))}], {key})"
        encrypted += 1

    if encrypted:
        unit = _detect_unit(toks)
        hdr = _header_end(toks, sig)
        at = sig[hdr] if hdr < L else len(toks) - 1
        anchor = toks[at]
        dec_ws = anchor.ws
        nl = anchor.ws.rfind("\n")
        ind = anchor.ws[nl + 1:] if nl >= 0 else anchor.ws
        anchor.ws = "\n\n" + ind
        toks.insert(at, Token("raw", _decoder_source(unit, name), dec_ws, at))

    return detokenize(toks), contents
