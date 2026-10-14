
from __future__ import annotations

import json
import os
import struct

from ..crypto.cipher import NONCE_LEN, aead_decrypt, aead_encrypt
from ..crypto.keys import BuildKey, _kdf
from ..obfuscate.lexer import (Token, detokenize, find_suite, is_stmt_start,
                               sig_indices, tokenize)
from ..obfuscate.strings import (_LITERAL_CALLS, _PROTECT_ANNOTS,
                                 _detect_unit, _header_end,
                                 _paren_range_skip, _stmt_end_sig)
from ..util import ProtectionError

MAGIC = b"GVMS"
VERSION = 1
POOL_SUFFIX = ".gvms"
_HEADER_LEN = 4 + 1 + 4 + NONCE_LEN

def pool_path_for(res_path: str) -> str:
    return res_path + POOL_SUFFIX

def derive_strpool_key(bk: BuildKey, pool_path: str) -> bytes:
    return _kdf(bk.key, bk.salt, pool_path.encode("utf-8"), label=b"strp")

def pack_pool(strings: list[str], bk: BuildKey, pool_path: str) -> bytes:
    joined = bytearray()
    offsets: list[int] = []
    for s in strings:
        offsets.append(len(joined))
        joined += s.encode("utf-8")
    nonce = os.urandom(NONCE_LEN)
    head = bytearray(MAGIC)
    head.append(VERSION)
    head += struct.pack("<I", len(strings))
    head += nonce
    for o in offsets:
        head += struct.pack("<I", o)
    _, ct = aead_encrypt(derive_strpool_key(bk, pool_path),
                         bytes(joined), aad=bytes(head), nonce=nonce)
    return bytes(head) + ct

def open_pool(blob: bytes, bk: BuildKey, pool_path: str) -> list[str]:
    if len(blob) < _HEADER_LEN or blob[:4] != MAGIC:
        raise ProtectionError("not a GVMS pool")
    if blob[4] != VERSION:
        raise ProtectionError(f"unsupported GVMS version {blob[4]}")
    (count,) = struct.unpack_from("<I", blob, 5)
    off_end = _HEADER_LEN + 4 * count
    if len(blob) < off_end:
        raise ProtectionError("truncated GVMS offset table")
    nonce = blob[9:_HEADER_LEN]
    pt = aead_decrypt(derive_strpool_key(bk, pool_path), nonce,
                      blob[off_end:], aad=blob[:off_end])
    offs = [struct.unpack_from("<I", blob, _HEADER_LEN + 4 * i)[0]
            for i in range(count)]
    out: list[str] = []
    for i, o in enumerate(offs):
        e = offs[i + 1] if i + 1 < count else len(pt)
        if o > e or e > len(pt):
            raise ProtectionError("GVMS offsets out of range")
        out.append(pt[o:e].decode("utf-8"))
    return out

def _decoder_source(unit: str, name: str, pool_path: str) -> str:
    return (f"static func {name}(i: int) -> String:\n"
            f"{unit}return Gdpk.str_at({json.dumps(pool_path)}, i)")

def hoist_source(src: str, pool_path: str) -> tuple[str, list[str], set[str]]:
    toks = tokenize(src)
    sig = sig_indices(toks)
    L = len(sig)
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

    taken = {t.value for t in toks if t.kind == "id"}
    name = "__s" if "__s" not in taken else "__sp"
    while name in taken:
        name = "_" + name

    index: dict[str, int] = {}
    pooled: list[str] = []
    for i in range(L):
        ti = sig[i]
        t = toks[ti]
        if t.kind != "str" or ti in skip or t.sval is None:
            continue
        if t.sprefix or not t.sval:
            continue
        prev = toks[sig[i - 1]] if i > 0 else None
        if prev is not None and prev.kind == "op" and prev.value == "$":
            continue
        if prev is not None and prev.kind == "kw" \
                and prev.value == "extends":
            continue
        if is_stmt_start(toks, ti):
            continue
        ix = index.get(t.sval)
        if ix is None:
            ix = len(pooled)
            index[t.sval] = ix
            pooled.append(t.sval)
        t.value = f"{name}({ix})"

    if not pooled:
        return src, [], contents

    unit = _detect_unit(toks)
    hdr = _header_end(toks, sig)
    at = sig[hdr] if hdr < L else len(toks) - 1
    anchor = toks[at]
    dec_ws = anchor.ws
    nl = anchor.ws.rfind("\n")
    ind = anchor.ws[nl + 1:] if nl >= 0 else anchor.ws
    anchor.ws = "\n\n" + ind
    toks.insert(at, Token("raw", _decoder_source(unit, name, pool_path),
                          dec_ws, at))

    return detokenize(toks), pooled, contents

__all__ = ["MAGIC", "VERSION", "POOL_SUFFIX", "pool_path_for",
           "derive_strpool_key", "pack_pool", "open_pool", "hoist_source"]
