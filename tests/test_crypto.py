
from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from gdprotect.crypto.cipher import (
    NONCE_LEN,
    aead_decrypt,
    aead_encrypt,
    derive_chunk_nonce,
)
from gdprotect.crypto.keys import (
    BuildKey,
    derive_file_key,
    derive_table_key,
    split_key_shards,
)

KEY = bytes(range(32))
SALT = b"\x5a\xc3\x11\x22\x88\x44\xaa\x99"

def _xor_all(parts: list[bytes]) -> bytes:
    acc = bytearray(len(parts[0]))
    for p in parts:
        for i, b in enumerate(p):
            acc[i] ^= b
    return bytes(acc)

def test_same_build_material_same_keys():
    bk1 = BuildKey(KEY, SALT)
    bk2 = BuildKey(KEY, SALT)
    assert derive_table_key(bk1) == derive_table_key(bk2)
    for i in range(8):
        assert derive_file_key(bk1, i) == derive_file_key(bk2, i)

def test_different_files_different_keys():
    bk = BuildKey(KEY, SALT)
    file_keys = {derive_file_key(bk, i) for i in range(8)}
    assert len(file_keys) == 8
    assert derive_table_key(bk) not in file_keys
    bk_other = BuildKey(KEY, b"\x00" * 8)
    assert derive_table_key(bk_other) != derive_table_key(bk)
    assert derive_file_key(bk_other, 0) != derive_file_key(bk, 0)

def test_key_and_salt_lengths():
    bk = BuildKey(KEY, SALT)
    assert len(derive_table_key(bk)) == 32
    assert len(derive_file_key(bk, 0)) == 32

def test_shards_xor_rebuild_key():
    key = b"\x11" * 32
    for n in (2, 4, 7, 16):
        shards = split_key_shards(key, n)
        assert len(shards) == n
        assert all(len(s) == len(key) for s in shards)
        assert _xor_all(shards) == key
        for drop in range(n):
            assert _xor_all(shards[:drop] + shards[drop + 1:]) != key

def test_split_key_shards_rejects_bad_count():
    with pytest.raises(ValueError):
        split_key_shards(KEY, 1)
    with pytest.raises(ValueError):
        split_key_shards(KEY, 17)

def test_chunk_nonce_unique_per_chunk():
    base = bytes(range(NONCE_LEN))
    nonces = {derive_chunk_nonce(base, i) for i in range(1024)}
    assert len(nonces) == 1024
    assert derive_chunk_nonce(base, 0) == base
    n = derive_chunk_nonce(base, 0x0102030405060708)
    assert len(n) == NONCE_LEN
    assert n[: NONCE_LEN - 8] == base[: NONCE_LEN - 8]
    assert derive_chunk_nonce(b"\xff" * NONCE_LEN, 1) != derive_chunk_nonce(base, 1)

def test_aead_roundtrip():
    key = b"\x42" * 32
    aad = b"file 0 chunk 0"
    nonce, ct = aead_encrypt(key, b"hello protected world", aad)
    assert len(nonce) == NONCE_LEN
    assert ct != b"hello protected world"
    assert aead_decrypt(key, nonce, ct, aad) == b"hello protected world"

def test_aead_tampered_tag_raises():
    key = b"\x42" * 32
    aad = b"file 0 chunk 0"
    nonce, ct = aead_encrypt(key, b"sensitive bytes", aad)
    bad = bytearray(ct)
    bad[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        aead_decrypt(key, nonce, bytes(bad), aad)
    with pytest.raises(InvalidTag):
        aead_decrypt(key, nonce, ct, b"different aad")
    with pytest.raises(InvalidTag):
        aead_decrypt(b"\x43" * 32, nonce, ct, aad)
