
from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
TAG_LEN = 16

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    nonce = nonce or os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct

def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)

def derive_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    n = bytearray(base_nonce)
    ctr = chunk_index.to_bytes(8, "little")
    for i in range(8):
        n[NONCE_LEN - 8 + i] ^= ctr[i]
    return bytes(n)
