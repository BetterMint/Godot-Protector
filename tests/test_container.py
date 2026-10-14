
from __future__ import annotations

import random
import struct
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from gdprotect.crypto.keys import BuildKey
from gdprotect.pck.container import (
    FLAG_CHUNKED,
    FLAG_TABLE_ENC,
    FLAG_TREE,
    FileKind,
    GdpkReader,
    GdpkWriter,
)

BK = BuildKey(key=b"gdprotect-test-key-material-32b!"[:32].ljust(32, b"!"),
              salt=b"\x01\x02\x03\x04\x05\x06\x07\x08")

CHUNK = 64 * 1024

FILES: list[tuple[str, bytes]] = [
    ("src/player.gd", b"extends Node2D\nvar speed := 120.0\n"),
    ("data/config.json", b'{"game": "FixtureGame"}\n'),
    ("assets/icon.png", b"\x89PNG\r\n\x1a\n" + bytes(range(64))),
    ("assets/blob.bin", random.Random(0xC0FFEE).randbytes(150_000)),
    ("empty.txt", b""),
]

def _build(tmp_path: Path, bk: BuildKey = BK) -> Path:
    out = tmp_path / "game.gdpk"
    w = GdpkWriter(bk)
    for path, data in FILES:
        w.add_file(path, data)
    w.finalize(out)
    return out

def _fields(blob: bytes) -> dict:
    (magic, vmaj, vmin, flags, salt, t_off, t_len, t_nonce,
     d_off, d_len, tr_off, tr_len, _res) = struct.unpack_from(
        "<4sBBH8sQQ12sQQQQ20s", blob, 0)
    return dict(magic=magic, flags=flags, salt=salt, t_off=t_off, t_len=t_len,
                d_off=d_off, d_len=d_len, tr_off=tr_off, tr_len=tr_len)

def _with_byte_flip(path: Path, offset: int, tmp_path: Path, name: str) -> Path:
    blob = bytearray(path.read_bytes())
    blob[offset] ^= 0x01
    bad = tmp_path / name
    bad.write_bytes(bytes(blob))
    return bad

def test_roundtrip(tmp_path):
    gdpk = _build(tmp_path)
    head = _fields(gdpk.read_bytes())
    assert head["magic"] == b"GDPK"
    assert head["salt"] == BK.salt
    assert head["flags"] & FLAG_TABLE_ENC
    assert head["flags"] & FLAG_CHUNKED
    assert head["flags"] & FLAG_TREE

    r = GdpkReader(gdpk, BK)
    assert len(r.entries) == len(FILES)
    paths = [e.path for e in r.entries]
    for path, _ in FILES:
        assert f"res://{path}" in paths
    by_path = {e.path: e for e in r.entries}
    assert by_path["res://src/player.gd"].kind == FileKind.GDSCRIPT_SOURCE
    assert by_path["res://data/config.json"].kind == FileKind.CONFIG
    assert by_path["res://assets/blob.bin"].kind == FileKind.DATA

def test_read_file_returns_exact_bytes(tmp_path):
    gdpk = _build(tmp_path)
    r = GdpkReader(gdpk, BK)
    for path, data in FILES:
        got = r.read_file(f"res://{path}")
        assert got == data, f"byte mismatch for {path}"
    for e in r.entries:
        assert r.read_file(e) == dict(FILES)[e.path[6:]]

def test_large_file_is_multi_chunk(tmp_path):
    gdpk = _build(tmp_path)
    r = GdpkReader(gdpk, BK)
    e = next(x for x in r.entries if x.path == "res://assets/blob.bin")
    n_chunks = -(-e.orig_size // CHUNK)
    assert n_chunks >= 3
    assert e.stored_size == e.orig_size + n_chunks * 16

def test_tampered_data_chunk_fails_read(tmp_path):
    gdpk = _build(tmp_path)
    r0 = GdpkReader(gdpk, BK)
    e0 = r0.entries[0]
    bad = _with_byte_flip(gdpk, e0.data_offset + 1, tmp_path, "bad_data.gdpk")
    r = GdpkReader(bad, BK)
    with pytest.raises((InvalidTag, ValueError)):
        r.read_file(e0.path)

def test_tampered_table_fails_constructor(tmp_path):
    gdpk = _build(tmp_path)
    head = _fields(gdpk.read_bytes())
    bad = _with_byte_flip(gdpk, head["t_off"] + head["t_len"] - 1,
                          tmp_path, "bad_table.gdpk")
    with pytest.raises(InvalidTag):
        GdpkReader(bad, BK)

def test_wrong_key_rejected(tmp_path):
    gdpk = _build(tmp_path)
    with pytest.raises(InvalidTag):
        GdpkReader(gdpk, BuildKey(b"\x00" * 32, BK.salt))
    with pytest.raises(ValueError, match="salt"):
        GdpkReader(gdpk, BuildKey(BK.key, b"\xff" * 8))

def test_verify_integrity(tmp_path):
    gdpk = _build(tmp_path)
    r = GdpkReader(gdpk, BK)
    assert r.verify_integrity() is True

    head = _fields(gdpk.read_bytes())
    assert head["tr_len"] > 0
    bad = _with_byte_flip(gdpk, head["tr_off"] + 4, tmp_path, "bad_tree.gdpk")
    r_bad = GdpkReader(bad, BK)
    assert r_bad.verify_integrity() is False
