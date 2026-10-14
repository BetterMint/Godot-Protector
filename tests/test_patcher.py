
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from gdprotect import patcher
from gdprotect.cli import main as cli_main
from gdprotect.crypto.keys import BuildKey
from gdprotect.pipeline import emit_key_header, verify_container
from gdprotect.util import ProtectionError

FIXTURE = Path(__file__).resolve().parent / "fixture"

KEY = bytes.fromhex("00112233445566778899aabbccddeeff"
                    "ffeeddccbbaa99887766554433221100")
KEY2 = bytes(range(32))
SALT = 0x0102030405060708

def _make_fake_pe(path: Path, tail: bytes = b"") -> bytes:
    e_lfanew = 0x80
    raw_ptr, raw_size = 0x200, 0x40

    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = e_lfanew.to_bytes(4, "little")

    coff = ((0x8664).to_bytes(2, "little")
            + (1).to_bytes(2, "little")
            + b"\0" * 12
            + (0xF0).to_bytes(2, "little")
            + (0x22).to_bytes(2, "little"))

    opt = bytearray(0xF0)
    opt[0:2] = (0x20B).to_bytes(2, "little")
    opt[108:112] = (0).to_bytes(4, "little")

    section = (b".text\0\0\0"
               + raw_size.to_bytes(4, "little")
               + (0x1000).to_bytes(4, "little")
               + raw_size.to_bytes(4, "little")
               + raw_ptr.to_bytes(4, "little")
               + b"\0" * 16)

    data = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + section
    data = data.ljust(raw_ptr, b"\0") + b"\xaa" * raw_size + tail
    path.write_bytes(data)
    return data

def test_embed_probe_roundtrip(tmp_path):
    exe = tmp_path / "game.exe"
    _make_fake_pe(exe)
    res = patcher.embed_key(exe, KEY, SALT)

    got = patcher.probe_key(exe)
    assert got == (SALT, KEY)
    assert res.offset + res.size == exe.stat().st_size
    assert res.size == (10 + 4 * 32 + 4) + patcher.FOOTER_LEN

    info = patcher.overlay_info(exe)
    assert info is not None
    assert (info.offset, info.size) == (res.offset, res.size)
    assert info.salt == SALT and info.shards == 4 and info.crc == res.crc

def test_probe_clean_exe_returns_none(tmp_path):
    exe = tmp_path / "game.exe"
    _make_fake_pe(exe)
    assert patcher.probe_key(exe) is None
    assert patcher.overlay_info(exe) is None

@pytest.mark.parametrize("where", ["ver", "salt", "shard", "crc"])
def test_probe_rejects_tampered_blob(tmp_path, where):
    exe = tmp_path / "game.exe"
    _make_fake_pe(exe)
    res = patcher.embed_key(exe, KEY, SALT)
    blob_len = res.size - patcher.FOOTER_LEN
    pos = {"ver": 0, "salt": 4, "shard": 20, "crc": blob_len - 2}[where]

    data = bytearray(exe.read_bytes())
    data[res.offset + pos] ^= 0xFF
    exe.write_bytes(data)

    with pytest.raises(ProtectionError):
        patcher.probe_key(exe)

def test_corrupt_footer_len_rejected(tmp_path):
    exe = tmp_path / "game.exe"
    _make_fake_pe(exe)
    res = patcher.embed_key(exe, KEY, SALT)
    data = bytearray(exe.read_bytes())
    data[res.offset + res.size - patcher.FOOTER_LEN:
         res.offset + res.size - patcher.FOOTER_LEN + 4] = \
        (10**6).to_bytes(4, "little")
    exe.write_bytes(data)
    with pytest.raises(ProtectionError):
        patcher.probe_key(exe)

def test_strip_restores_byte_identical(tmp_path):
    exe = tmp_path / "game.exe"
    original = _make_fake_pe(exe)
    patcher.embed_key(exe, KEY, SALT)
    assert patcher.strip_key(exe) is True
    assert exe.read_bytes() == original
    assert patcher.probe_key(exe) is None
    assert patcher.strip_key(exe) is False

def test_strip_preserves_preexisting_overlay(tmp_path):
    exe = tmp_path / "game.exe"
    tail = b"FAKE-PCK-DATA" + b"\0" * 51
    original = _make_fake_pe(exe, tail=tail)
    patcher.embed_key(exe, KEY, SALT)
    assert patcher.strip_key(exe) is True
    assert exe.read_bytes() == original

def test_reembed_requires_force(tmp_path):
    exe = tmp_path / "game.exe"
    _make_fake_pe(exe)
    patcher.embed_key(exe, KEY, SALT)
    with pytest.raises(ProtectionError):
        patcher.embed_key(exe, KEY2, SALT)
    patcher.embed_key(exe, KEY2, SALT, force=True)
    assert patcher.probe_key(exe) == (SALT, KEY2)

def test_non_pe_rejected(tmp_path):
    exe = tmp_path / "not.exe"
    exe.write_bytes(b"definitely not a pe " * 32)
    with pytest.raises(ProtectionError):
        patcher.embed_key(exe, KEY, SALT)
    with pytest.raises(ProtectionError):
        patcher.pe_end(exe)

    mz_only = tmp_path / "mz.exe"
    mz_only.write_bytes(b"MZ" + b"\0" * 254)
    with pytest.raises(ProtectionError):
        patcher.embed_key(mz_only, KEY, SALT)

def test_missing_file_raises_protection_error(tmp_path):
    ghost = tmp_path / "ghost.exe"
    with pytest.raises(ProtectionError):
        patcher.embed_key(ghost, KEY, SALT)
    with pytest.raises(ProtectionError):
        patcher.probe_key(ghost)
    with pytest.raises(ProtectionError):
        patcher.strip_key(ghost)
    with pytest.raises(ProtectionError):
        patcher.pe_end(ghost)

def test_bad_key_and_shard_args(tmp_path):
    exe = tmp_path / "game.exe"
    _make_fake_pe(exe)
    with pytest.raises(ProtectionError):
        patcher.embed_key(exe, b"short", SALT)
    with pytest.raises(ProtectionError):
        patcher.embed_key(exe, KEY, SALT, shards=1)
    with pytest.raises(ProtectionError):
        patcher.embed_key(exe, KEY, SALT, shards=17)

def test_pe_header_still_parses(tmp_path):
    exe = tmp_path / "game.exe"
    _make_fake_pe(exe)
    before = patcher.pe_end(exe)
    res = patcher.embed_key(exe, KEY, SALT)
    assert patcher.pe_end(exe) == before
    assert res.offset >= before

def test_real_python_exe_roundtrip(tmp_path):
    src = Path(sys.executable)
    if not src.is_file():
        pytest.skip("sys.executable missing")
    exe = tmp_path / "python_copy.exe"
    shutil.copy2(src, exe)
    try:
        end = patcher.pe_end(exe)
    except ProtectionError:
        pytest.skip("sys.executable is not a PE on this platform")

    original = exe.read_bytes()
    res = patcher.embed_key(exe, KEY, SALT)
    assert patcher.probe_key(exe) == (SALT, KEY)
    assert patcher.pe_end(exe) == end and res.offset >= end
    assert patcher.strip_key(exe) is True
    assert exe.read_bytes() == original

def test_cli_embed_verify_strip(tmp_path):
    exe = tmp_path / "game.exe"
    _make_fake_pe(exe)
    rc = cli_main(["patch", "embed", str(exe),
                   "--key-hex", KEY.hex(), "--salt-hex", f"{SALT:016x}"])
    assert rc == 0
    assert cli_main(["patch", "verify", str(exe)]) == 0
    assert cli_main(["patch", "strip", str(exe)]) == 0
    assert cli_main(["patch", "verify", str(exe)]) == 1

def test_cli_embed_from_key_shard_header(tmp_path):
    bk = BuildKey.generate(seed=7)
    header = tmp_path / "key_shard.h"
    emit_key_header(bk, header)

    exe = tmp_path / "game.exe"
    _make_fake_pe(exe)
    rc = cli_main(["patch", "embed", str(exe), "--emit-key", str(header)])
    assert rc == 0
    assert patcher.probe_key(exe) == (int.from_bytes(bk.salt, "big"), bk.key)

def test_cli_embed_bad_args(tmp_path):
    exe = tmp_path / "game.exe"
    _make_fake_pe(exe)
    assert cli_main(["patch", "embed", str(exe),
                     "--key-hex", KEY.hex()]) == 2
    assert cli_main(["patch", "embed", str(exe),
                     "--key-hex", "zz", "--salt-hex", "00"]) == 2

def test_cli_build_patch(tmp_path):
    out = tmp_path / "game.gdpk"
    exe = tmp_path / "game.exe"
    _make_fake_pe(exe)

    rc = cli_main(["--seed", "1", "build", str(FIXTURE), "-o", str(out),
                   "--no-obfuscate", "--patch", str(exe)])
    assert rc == 0

    got = patcher.probe_key(exe)
    assert got is not None
    salt, key = got
    assert salt.to_bytes(8, "big") == out.read_bytes()[8:16]
    assert verify_container(out, key.hex())["integrity"] == "ok"
