
from __future__ import annotations

import random
import struct
from dataclasses import dataclass
from enum import IntEnum, auto

class Op(IntEnum):
    NOP = 0
    LOADK = auto()
    LOADI = auto()
    MOVE = auto()
    ADD = auto()
    SUB = auto()
    MUL = auto()
    DIV = auto()
    MOD = auto()
    NEG = auto()
    NOT = auto()
    AND = auto()
    OR = auto()
    CMPEQ = auto()
    CMPNE = auto()
    CMPLT = auto()
    CMPLE = auto()
    CMPGT = auto()
    CMPGE = auto()
    JMP = auto()
    JT = auto()
    JF = auto()
    PUSH = auto()
    POP = auto()
    CALL = auto()
    CALLM = auto()
    GETG = auto()
    SETG = auto()
    GETM = auto()
    SETM = auto()
    NEWARR = auto()
    NEWDICT = auto()
    AGET = auto()
    ASET = auto()
    ITER = auto()
    RET = auto()
    YIELD = auto()
    SELF = auto()
    _COUNT = auto()

OP_COUNT = int(Op._COUNT)

@dataclass
class Insn:
    op: Op
    a: int = 0
    b: int = 0
    c: int = 0
    has_c: bool = False
    b_kind: str = "R"

def _feistel(v: int, key: int, rounds: int = 4) -> int:
    l, r = (v >> 16) & 0xFFFF, v & 0xFFFF
    for i in range(rounds):
        f = ((r * 0x9E37 + key + i * 0x85EB) & 0xFFFFFFFF) >> 8 | \
            ((r * 0x9E37 + key + i * 0x85EB) & 0xFF) << 24
        l, r = r, l ^ (f & 0xFFFF)
    return ((l & 0xFFFF) << 16) | (r & 0xFFFF)

def _unfeistel(v: int, key: int, rounds: int = 4) -> int:
    l, r = (v >> 16) & 0xFFFF, v & 0xFFFF
    for i in reversed(range(rounds)):
        f = ((l * 0x9E37 + key + i * 0x85EB) & 0xFFFFFFFF) >> 8 | \
            ((l * 0x9E37 + key + i * 0x85EB) & 0xFF) << 24
        l, r = r ^ (f & 0xFFFF), l
    return ((l & 0xFFFF) << 16) | (r & 0xFFFF)

class Dialect:

    def __init__(self, salt: int):
        rng = random.Random(salt ^ 0x47564D31)
        self.encode_map = list(range(OP_COUNT))
        rng.shuffle(self.encode_map)
        self.decode_map = [0] * OP_COUNT
        for sem, enc in enumerate(self.encode_map):
            self.decode_map[enc] = sem
        self.salt = salt

    def cell_key(self, cell_index: int) -> int:
        x = (self.salt + cell_index * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        x ^= x >> 30
        x = (x * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        x ^= x >> 27
        return (x * 0x94D049BB133111EB) & 0xFFFFFFFF

    def encode_op(self, op: Op) -> int:
        return self.encode_map[int(op)]

    def decode_op(self, byte: int) -> Op:
        return Op(self.decode_map[byte])

    def encode_imm(self, v: int, cell: int) -> int:
        return _feistel(v & 0xFFFFFFFF, self.cell_key(cell))

    def decode_imm(self, v: int, cell: int) -> int:
        u = _unfeistel(v, self.cell_key(cell))
        return u - 0x100000000 if u & 0x80000000 else u

GVMB_MAGIC = b"GVMB"
GVMB_VERSION = 1

def encode_insn(d: Dialect, insn: Insn, cell: int) -> bytes:
    out = bytearray([d.encode_op(insn.op)])
    if insn.op in (Op.ADD, Op.SUB, Op.MUL, Op.DIV, Op.MOD, Op.AND, Op.OR,
                   Op.CMPEQ, Op.CMPNE, Op.CMPLT, Op.CMPLE, Op.CMPGT, Op.CMPGE,
                   Op.AGET, Op.ASET, Op.SETM):
        out.append((insn.a << 4) | insn.b)
        out.append(insn.c)
    elif insn.op in (Op.MOVE, Op.NOT, Op.GETM, Op.CALLM, Op.ITER):
        out.append((insn.a << 4) | insn.b)
        out += struct.pack("<H", insn.c)
    elif insn.b_kind == "K":
        out.append(insn.a)
        out += struct.pack("<H", insn.b)
    elif insn.b_kind == "I":
        out.append(insn.a)
        out += struct.pack("<I", d.encode_imm(insn.b, cell) & 0xFFFFFFFF)
    elif insn.b_kind == "J":
        out.append(insn.a)
        out += struct.pack("<I", insn.b ^ (d.cell_key(cell) & 0xFFFFFFFF))
    else:
        out.append(insn.a)
    return bytes(out)

def write_const(cp: bytearray, v) -> None:
    if v is None:
        cp += b"\x00"
    elif isinstance(v, bool):
        cp += b"\x01" + bytes([v])
    elif isinstance(v, int):
        cp += b"\x02" + struct.pack("<q", v)
    elif isinstance(v, float):
        cp += b"\x03" + struct.pack("<d", v)
    elif isinstance(v, str):
        b = v.encode()
        cp += b"\x04" + struct.pack("<I", len(b)) + b
    elif isinstance(v, (bytes, bytearray)):
        cp += b"\x05" + struct.pack("<I", len(v)) + bytes(v)
    else:
        raise TypeError(f"unsupported const {type(v)}")
