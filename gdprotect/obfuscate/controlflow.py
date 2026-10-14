
from __future__ import annotations

from .lexer import (SIG_KINDS, Token, detokenize, find_suite, is_stmt_start,
                    sig_indices, tokenize)

_EXCLUDE_KW = frozenset({
    "if", "elif", "else", "for", "while", "match", "func", "class",
    "class_name", "extends", "signal", "enum", "var", "const", "static",
    "breakpoint", "setget", "export", "onready", "remote", "master",
    "puppet", "sync", "remotesync", "mastersync", "puppetsync", "tool",
    "trait", "namespace",
})

_CONDS = (
    "(0x2a ^ 0x15) == 0x3f",
    "(0x1c | 0x22) == 0x3e",
    "(7 * 6) - 42 == 0",
    "(0b1011 & 0b0011) == 0b0011",
    "3 * (4 + 1) == 15",
    "0x10 + 0x20 == 0x30",
    "13 % 5 == 3",
    "not (1 == 2)",
    "(9 >> 1) == 4",
    "(-4) * (-4) == 16",
    "(0x55 ^ 0x2a) == 0x7f",
    "(1 << 3) + 1 == 9",
    "17 - 9 == 8",
    "(0x30 & 0x10) | 4 == 0x14",
    "2 * 3 * 7 == 42",
)

def _file_unit(toks: list[Token]) -> str:
    for t in toks:
        nl = t.ws.rfind("\n")
        if nl >= 0 and t.ws[nl + 1:]:
            return t.ws[nl + 1:]
    return "\t"

def _indent_of(tok: Token) -> str:
    nl = tok.ws.rfind("\n")
    return tok.ws[nl + 1:] if nl >= 0 else tok.ws

def mangle_source(src: str, rng, prob: float = 0.15) -> str:
    toks = tokenize(src)
    sig = sig_indices(toks)
    L = len(sig)
    regions: list[tuple[int, int]] = []

    for pos, ti in enumerate(sig):
        t = toks[ti]
        if t.kind == "kw" and t.value == "func":
            r = find_suite(toks, sig, pos)
            if r:
                regions.append(r)

    if not regions:
        return src

    wraps = []
    s = 0
    while s < len(toks):
        t = toks[s]
        if t.kind not in SIG_KINDS or not is_stmt_start(toks, s):
            s += 1
            continue
        if not any(a < s < b for a, b in regions):
            s += 1
            continue
        e = s
        while e < len(toks) and toks[e].kind != "nl":
            e += 1
        if e >= len(toks):
            break
        ok = t.kind != "op" or t.value not in ("@",)
        if ok and t.kind == "kw" and t.value in _EXCLUDE_KW:
            ok = False
        if ok:
            depth = 0
            for k in range(s, e):
                tt = toks[k]
                if tt.kind == "op":
                    if tt.value in "([{":
                        depth += 1
                    elif tt.value in ")]}":
                        depth -= 1
                    elif depth == 0 and tt.value in (":", ";"):
                        ok = False
                        break
        if ok and rng.random() < prob:
            wraps.append((s, e, _indent_of(t)))
        s = e + 1

    if not wraps:
        return src

    unit = _file_unit(toks)
    out = list(toks)
    junk_i = 0
    for s, e, ind in sorted(wraps, reverse=True):
        orig_ws = out[s].ws
        nl = orig_ws.rfind("\n")
        head = orig_ws[:nl + 1] if nl >= 0 else ""
        cond = rng.choice(_CONDS)
        junk_i += 1
        a, b, c = (rng.randrange(2, 64) for _ in range(3))
        junk = f"var _cj{junk_i} := ({a} ^ {b}) * {c}"
        out[e + 1:e + 1] = [
            Token("raw", "else:", "\n" + ind),
            Token("raw", junk, "\n" + ind + unit),
        ]
        out[s].ws = head + ind + unit
        out.insert(s, Token("raw", f"if {cond}:", orig_ws))

    return detokenize(out)
