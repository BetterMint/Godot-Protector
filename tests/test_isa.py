
from __future__ import annotations

from gdprotect.vm.isa import (
    OP_COUNT,
    Dialect,
    Insn,
    Op,
    _feistel,
    _unfeistel,
    encode_insn,
)

REAL_OPS = [Op(i) for i in range(OP_COUNT)]

def test_opcode_encode_decode_roundtrip():
    d = Dialect(0xC0FFEE)
    for op in REAL_OPS:
        enc = d.encode_op(op)
        assert 0 <= enc < OP_COUNT
        assert d.decode_op(enc) == op

def test_encode_map_is_a_permutation():
    d = Dialect(7)
    assert sorted(d.encode_map) == list(range(OP_COUNT))
    assert sorted(d.decode_map) == list(range(OP_COUNT))

def test_different_salts_different_permutations():
    d1, d2 = Dialect(1), Dialect(2)
    assert d1.encode_map != d2.encode_map
    assert Dialect(1).encode_map == d1.encode_map
    assert Dialect(1).decode_map == d1.decode_map

def test_cell_key_position_dependent():
    d = Dialect(5)
    keys = {d.cell_key(c) for c in range(64)}
    assert len(keys) > 1
    assert d.cell_key(0) == Dialect(5).cell_key(0)
    assert d.cell_key(0) != Dialect(6).cell_key(0)

def test_feistel_unfeistel_roundtrip():
    for key in (0, 1, 0xDEADBEEF, 0xFFFFFFFF):
        for v in (0, 1, -1, 0x7FFFFFFF, -0x80000000, 123456789, -123456789):
            enc = _feistel(v & 0xFFFFFFFF, key)
            assert 0 <= enc <= 0xFFFFFFFF
            assert _unfeistel(enc, key) == v & 0xFFFFFFFF

def test_immediate_roundtrip_signed_int32():
    d = Dialect(77)
    for cell in (0, 1, 17, 4096):
        for v in (0, 1, -1, 2**31 - 1, -(2**31), 424242, -424242):
            assert d.decode_imm(d.encode_imm(v, cell), cell) == v
    assert d.encode_imm(42, 0) != d.encode_imm(42, 1)

def test_encode_insn_produces_bytes():
    d = Dialect(3)
    nop = encode_insn(d, Insn(Op.NOP), cell=0)
    assert isinstance(nop, bytes)
    assert nop[0] == d.encode_op(Op.NOP)
    add = encode_insn(d, Insn(Op.ADD, a=1, b=2, c=3), cell=0)
    assert len(add) == 3
    assert add[0] == d.encode_op(Op.ADD)
    assert add[1] == 0x12 and add[2] == 3
    assert len(encode_insn(d, Insn(Op.LOADK, a=1, b=5, b_kind="K"), 0)) == 4
    assert len(encode_insn(d, Insn(Op.LOADI, a=0, b=-7, b_kind="I"), 0)) == 6
    jmp = encode_insn(d, Insn(Op.JMP, b=10, b_kind="J"), cell=0)
    assert len(jmp) == 6
    assert jmp[1] == 0
    assert int.from_bytes(jmp[2:], "little") == 10 ^ (d.cell_key(0) & 0xFFFFFFFF)
