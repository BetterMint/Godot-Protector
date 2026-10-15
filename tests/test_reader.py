import struct

import pytest

from gdprotect.pck.reader import PCK_MAGIC, PckReader

def _entry(path: bytes, off: int, data: bytes, flags: int = 0) -> bytes:
    plen = len(path)
    pad = (4 - plen % 4) % 4
    return (struct.pack("<I", plen) + path + b"\0" * pad
            + struct.pack("<QQ", off, len(data)) + b"\0" * 16
            + struct.pack("<I", flags))

def _pck_v2(fmt: int = 2) -> bytes:
    body = b"hello v2"
    head = (struct.pack("<IIIII", PCK_MAGIC, fmt, 4, 2, 0)
            + struct.pack("<IQ", 0, 0x200) + b"\0" * 64)
    head += struct.pack("<I", 1) + _entry(b"res://a.txt", 0, body)
    return head.ljust(0x200, b"\0") + body

def _pck_v3(fmt: int = 3, rel: bool = False) -> bytes:
    body = b"hello v3+"
    data_base = 0x200
    dir_off = 0x300
    flags = 2 if rel else 0
    head = (struct.pack("<IIIII", PCK_MAGIC, fmt, 4, 4, 0)
            + struct.pack("<IQ", flags, 0 if rel else data_base)
            + struct.pack("<Q", 0 if rel else dir_off) + b"\0" * 56)
    out = head.ljust(data_base, b"\0") + body
    out = out.ljust(dir_off, b"\0") + struct.pack("<I", 1) + _entry(b"res://b.txt", 0, body)
    return out

def test_pck_v2_roundtrip(tmp_path):
    p = tmp_path / "game.pck"
    p.write_bytes(_pck_v2())
    r = PckReader(p)
    assert r.version == 2
    assert [f.path for f in r.files] == ["res://a.txt"]
    assert r.read_file(r.files[0]) == b"hello v2"

@pytest.mark.parametrize("fmt", [3, 4])
def test_pck_v3_v4_roundtrip(tmp_path, fmt):
    p = tmp_path / "game.pck"
    p.write_bytes(_pck_v3(fmt))
    r = PckReader(p)
    assert r.version == fmt
    assert r.read_file(r.files[0]) == b"hello v3+"

@pytest.mark.parametrize("fmt", [5, 9])
def test_future_pck_format_parsed_as_v3_layout(tmp_path, fmt):
    p = tmp_path / "game.pck"
    p.write_bytes(_pck_v3(fmt))
    r = PckReader(p)
    assert r.version == fmt
    assert [f.path for f in r.files] == ["res://b.txt"]
    assert r.read_file(r.files[0]) == b"hello v3+"

def test_pck_v1_rejected(tmp_path):
    p = tmp_path / "old.pck"
    p.write_bytes(_pck_v3(1))
    with pytest.raises(ValueError, match="unsupported"):
        PckReader(p)

def test_no_pck_raises(tmp_path):
    p = tmp_path / "nope.bin"
    p.write_bytes(b"\0" * 256)
    with pytest.raises(ValueError, match="no pck"):
        PckReader(p)
