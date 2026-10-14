
from __future__ import annotations

import json
import re
import zlib
from dataclasses import dataclass
from pathlib import Path

from .crypto.keys import split_key_shards
from .util import ProtectionError

FOOTER_MAGIC = b"GDPKKEY!"
FOOTER_LEN = 4 + len(FOOTER_MAGIC)

_BLOB_VER = 1
_KEY_LEN = 32
_SHARD_MIN, _SHARD_MAX = 2, 16
_BLOB_PREFIX_LEN = 1 + 1 + 8
_CRC_LEN = 4

__all__ = [
    "FOOTER_MAGIC",
    "FOOTER_LEN",
    "PatchResult",
    "OverlayInfo",
    "embed_key",
    "probe_key",
    "strip_key",
    "overlay_info",
    "pe_end",
    "load_key_material",
]

@dataclass(frozen=True)
class PatchResult:

    offset: int
    size: int
    crc: int

@dataclass(frozen=True)
class OverlayInfo:

    offset: int
    size: int
    crc: int
    version: int
    shards: int
    salt: int

def _u16(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 2], "little")

def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little")

def _open(p: Path, mode: str):
    try:
        return p.open(mode)
    except OSError as e:
        raise ProtectionError(f"{p}: {e.strerror or e}") from e

def _pe_end_f(f) -> int:
    f.seek(0)
    head = f.read(0x40)
    if len(head) < 0x40 or head[:2] != b"MZ":
        raise ProtectionError("not a PE (missing MZ header)")
    e_lfanew = _u32(head, 0x3C)
    f.seek(e_lfanew)
    hdr = f.read(24)
    if len(hdr) < 24 or hdr[:4] != b"PE\0\0":
        raise ProtectionError("not a PE (missing PE\\0\\0 signature)")
    nsec = _u16(hdr, 6)
    opt_size = _u16(hdr, 20)
    opt = f.read(opt_size)
    sec = f.read(nsec * 40)
    if len(sec) < nsec * 40:
        raise ProtectionError("truncated PE section table")
    end = e_lfanew + 24 + opt_size + nsec * 40
    for i in range(nsec):
        s = sec[i * 40:(i + 1) * 40]
        raw_end = _u32(s, 20) + _u32(s, 16)
        end = max(end, raw_end)
    if len(opt) >= 96:
        magic = _u16(opt, 0)
        if magic == 0x20B and len(opt) >= 112:
            n_dirs, dir_base = _u32(opt, 108), 112
        elif magic == 0x10B:
            n_dirs, dir_base = _u32(opt, 92), 96
        else:
            n_dirs, dir_base = 0, 0
        if n_dirs > 4 and len(opt) >= dir_base + 5 * 8:
            cert_va = _u32(opt, dir_base + 32)
            cert_sz = _u32(opt, dir_base + 36)
            if cert_va and cert_sz:
                end = max(end, cert_va + cert_sz)
    return end

def pe_end(path: str | Path) -> int:
    with _open(Path(path), "rb") as f:
        return _pe_end_f(f)

def _locate_f(f, size: int) -> tuple[int, bytes] | None:
    if size < FOOTER_LEN:
        return None
    f.seek(size - FOOTER_LEN)
    foot = f.read(FOOTER_LEN)
    if foot[4:] != FOOTER_MAGIC:
        return None
    blob_len = _u32(foot, 0)
    min_len = _BLOB_PREFIX_LEN + _SHARD_MIN * _KEY_LEN + _CRC_LEN
    if blob_len < min_len or blob_len > size - FOOTER_LEN:
        raise ProtectionError("corrupt key overlay (bad blob length)")
    off = size - FOOTER_LEN - blob_len
    f.seek(off)
    blob = f.read(blob_len)
    if len(blob) != blob_len:
        raise ProtectionError("corrupt key overlay (short read)")
    return off, blob

def _parse_blob(blob: bytes) -> tuple[int, list[bytes], int]:
    if len(blob) < _BLOB_PREFIX_LEN + _CRC_LEN:
        raise ProtectionError("corrupt key overlay (blob too small)")
    ver, count = blob[0], blob[1]
    if ver != _BLOB_VER:
        raise ProtectionError(f"unsupported key overlay version {ver}")
    if not _SHARD_MIN <= count <= _SHARD_MAX:
        raise ProtectionError(f"corrupt key overlay (shard count {count})")
    want = _BLOB_PREFIX_LEN + count * _KEY_LEN + _CRC_LEN
    if len(blob) != want:
        raise ProtectionError("corrupt key overlay (blob length mismatch)")
    crc = _u32(blob, len(blob) - _CRC_LEN)
    if zlib.crc32(blob[:-_CRC_LEN]) != crc:
        raise ProtectionError("key overlay crc32 mismatch — tampered or truncated")
    salt = int.from_bytes(blob[2:10], "little")
    shards = [blob[10 + i * _KEY_LEN:10 + (i + 1) * _KEY_LEN]
              for i in range(count)]
    return salt, shards, crc

def probe_key(path: str | Path) -> tuple[int, bytes] | None:
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as e:
        raise ProtectionError(f"{p}: {e.strerror or e}") from e
    with _open(p, "rb") as f:
        loc = _locate_f(f, size)
    if loc is None:
        return None
    salt, shards, _crc = _parse_blob(loc[1])
    key = bytearray(_KEY_LEN)
    for s in shards:
        for i, b in enumerate(s):
            key[i] ^= b
    return salt, bytes(key)

def overlay_info(path: str | Path) -> OverlayInfo | None:
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as e:
        raise ProtectionError(f"{p}: {e.strerror or e}") from e
    with _open(p, "rb") as f:
        loc = _locate_f(f, size)
    if loc is None:
        return None
    salt, shards, crc = _parse_blob(loc[1])
    return OverlayInfo(offset=loc[0], size=len(loc[1]) + FOOTER_LEN,
                       crc=crc, version=_BLOB_VER, shards=len(shards),
                       salt=salt)

def embed_key(exe_path: str | Path, key: bytes, salt: int,
              shards: int = 4, force: bool = False) -> PatchResult:
    p = Path(exe_path)
    if len(key) != _KEY_LEN:
        raise ProtectionError(f"key must be {_KEY_LEN} bytes, got {len(key)}")
    if not 0 <= salt < 1 << 64:
        raise ProtectionError("salt must fit in u64")
    if not _SHARD_MIN <= shards <= _SHARD_MAX:
        raise ProtectionError(f"shards must be {_SHARD_MIN}..{_SHARD_MAX}")
    parts = split_key_shards(key, shards)

    with _open(p, "r+b") as f:
        end = _pe_end_f(f)
        f.seek(0, 2)
        size = f.tell()
        if size < end:
            raise ProtectionError("PE headers extend past end of file")
        loc = _locate_f(f, size)
        if loc is not None:
            if not force:
                raise ProtectionError(
                    f"{p}: key overlay already present — use --force to replace")
            f.truncate(loc[0])
        blob = (bytes([_BLOB_VER, len(parts)])
                + salt.to_bytes(8, "little")
                + b"".join(parts))
        crc = zlib.crc32(blob)
        blob += crc.to_bytes(4, "little")
        f.seek(0, 2)
        off = f.tell()
        f.write(blob + len(blob).to_bytes(4, "little") + FOOTER_MAGIC)
    return PatchResult(offset=off, size=len(blob) + FOOTER_LEN, crc=crc)

def strip_key(exe_path: str | Path) -> bool:
    p = Path(exe_path)
    with _open(p, "r+b") as f:
        end = _pe_end_f(f)
        f.seek(0, 2)
        loc = _locate_f(f, f.tell())
        if loc is None:
            return False
        if loc[0] < end:
            raise ProtectionError(
                "key overlay begins inside the PE body — refusing to truncate")
        f.truncate(loc[0])
        return True

def load_key_material(path: str | Path) -> tuple[bytes, int]:
    p = Path(path)
    try:
        text = p.read_text()
    except OSError as e:
        raise ProtectionError(f"{p}: {e.strerror or e}") from e

    m = re.search(r"BUILD_SALT\s*=\s*0x([0-9a-fA-F]+)", text)
    shard_decls = re.findall(r"KEY_SHARD_\d+\[32\]\s*=\s*\{([^}]*)\}", text)
    if m and shard_decls:
        salt = int(m.group(1), 16)
        key = bytearray(_KEY_LEN)
        for decl in shard_decls:
            shard = bytes(int(t, 16) for t in decl.split(","))
            if len(shard) != _KEY_LEN:
                raise ProtectionError(f"{p}: malformed KEY_SHARD_n array")
            for i, b in enumerate(shard):
                key[i] ^= b
        return bytes(key), salt

    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        d = None
    if isinstance(d, dict):
        key_hex = d.get("key") or d.get("key_hex") or d.get("build_key")
        salt_v = d.get("salt", d.get("salt_hex", d.get("build_salt")))
        if key_hex and salt_v is not None:
            salt = (salt_v if isinstance(salt_v, int)
                    else int(str(salt_v).removeprefix("0x"), 16))
            return bytes.fromhex(str(key_hex)), salt
        raise ProtectionError(f"{p}: key file needs 'key' and 'salt' fields")

    parts = re.split(r"[\s:]+", text.strip())
    parts = [t for t in parts if t]
    if len(parts) == 2 and all(re.fullmatch(r"[0-9a-fA-F]+", t) for t in parts):
        return bytes.fromhex(parts[0]), int(parts[1], 16)
    raise ProtectionError(
        f"{p}: unrecognized key file — expected key_shard.h, JSON "
        "{'key','salt'}, or '<key_hex>:<salt_hex>'")
