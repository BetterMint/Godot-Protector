
from __future__ import annotations

import secrets
from dataclasses import dataclass
from hashlib import blake2b

_KEY_LEN = 32

def _kdf(*parts: bytes, label: bytes) -> bytes:
    h = blake2b(digest_size=_KEY_LEN, person=b"gdprotect\x00" + label[:6])
    for p in parts:
        h.update(len(p).to_bytes(4, "little"))
        h.update(p)
    return h.digest()

@dataclass(frozen=True)
class BuildKey:

    key: bytes
    salt: bytes

    @staticmethod
    def generate(seed: int | None = None) -> "BuildKey":
        if seed is not None:
            import random
            rng = random.Random(seed)
            return BuildKey(key=rng.randbytes(_KEY_LEN), salt=rng.randbytes(8))
        return BuildKey(key=secrets.token_bytes(_KEY_LEN), salt=secrets.token_bytes(8))

def derive_table_key(bk: BuildKey) -> bytes:
    return _kdf(bk.key, bk.salt, label=b"table")

def derive_file_key(bk: BuildKey, file_index: int) -> bytes:
    return _kdf(bk.key, bk.salt, file_index.to_bytes(8, "little"), label=b"file")

def split_key_shards(key: bytes, shards: int = 4) -> list[bytes]:
    if not 2 <= shards <= 16:
        raise ValueError("shards must be 2..16")
    out = [secrets.token_bytes(len(key)) for _ in range(shards - 1)]
    last = bytearray(key)
    for s in out:
        for i, b in enumerate(s):
            last[i] ^= b
    out.append(bytes(last))
    return out
