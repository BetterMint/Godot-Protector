
from __future__ import annotations

import random

from ..util import ProtectionError
from . import controlflow, lexer, renamer, strings

def _rng(filename: str, stage: str, src: str) -> random.Random:
    return random.Random(f"gdprotect|{filename}|{stage}|{len(src)}")

def obfuscate_source(src: str, cfg, filename: str = "",
                     extra_str_contents: set | None = None) -> str:
    if not getattr(cfg, "enabled", True):
        return src

    out = src
    try:
        if getattr(cfg, "strip_comments", False):
            out = lexer.strip_comments(out)

        str_contents: set = set(extra_str_contents or ())
        if getattr(cfg, "encrypt_strings", False):
            out, enc_contents = strings.encrypt_source(
                out, _rng(filename, "strings", out))
            str_contents |= enc_contents

        if getattr(cfg, "rename_identifiers", False):
            out = renamer.rename_source(
                out, cfg, _rng(filename, "rename", out), str_contents)

        if getattr(cfg, "control_flow", False):
            out = controlflow.mangle_source(
                out, _rng(filename, "cf", out))
    except Exception as e:
        raise ProtectionError(
            f"obfuscate {filename or '<string>'}: {e}") from e
    return out
