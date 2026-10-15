from __future__ import annotations

from ..vm.compiler import CompileError, _Parser, _lex


class NativeError(Exception):
    pass


def parse(source: str, filename: str = "<script>") -> list[tuple]:
    try:
        p = _Parser(_lex(source, filename), filename)
        p.native = True
        return p.parse_module()
    except (CompileError, Exception) as e:
        raise NativeError(str(e)) from e
