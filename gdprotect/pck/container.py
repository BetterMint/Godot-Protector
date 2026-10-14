
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from enum import IntEnum
from hashlib import blake2b, sha256
from pathlib import Path

from ..crypto.cipher import NONCE_LEN, TAG_LEN, aead_decrypt, aead_encrypt, derive_chunk_nonce
from ..crypto.keys import BuildKey, derive_file_key, derive_table_key

MAGIC = b"GDPK"
VERSION = (1, 0)
HEADER_LEN = 96
TABLE_VERSION = 1

FLAG_TABLE_ENC = 1 << 0
FLAG_CHUNKED = 1 << 1
FLAG_TREE = 1 << 2
FLAG_VM = 1 << 3

FILE_FLAG_VIRTUALIZED = 1 << 0

class FileKind(IntEnum):
    DATA = 0
    GDSCRIPT_SOURCE = 1
    VM_BYTECODE = 2
    SCENE = 3
    RESOURCE = 4
    CONFIG = 5
    NATIVE = 6

def classify(path: str) -> FileKind:
    ext = Path(path).suffix.lower()
    if ext in (".gd", ".gdc", ".gdshader"):
        return FileKind.GDSCRIPT_SOURCE
    if ext == ".gvmb":
        return FileKind.VM_BYTECODE
    if ext in (".tscn", ".scn"):
        return FileKind.SCENE
    if ext in (".tres", ".res", ".theme", ".import"):
        return FileKind.RESOURCE
    if ext in (".cfg", ".godot", ".toml", ".json"):
        return FileKind.CONFIG
    if ext in (".dll", ".so", ".dylib", ".wasm"):
        return FileKind.NATIVE
    return FileKind.DATA

@dataclass
class TableEntry:
    index: int
    path: str
    kind: FileKind
    codec: int
    flags: int
    data_offset: int
    stored_size: int
    orig_size: int
    nonce_base: bytes
    digest: bytes

    @property
    def virtualized(self) -> bool:
        return bool(self.flags & FILE_FLAG_VIRTUALIZED)

def _hash_leaf(b: bytes) -> bytes:
    return blake2b(b, digest_size=32, person=b"gdpkleaf").digest()

def _hash_node(l: bytes, r: bytes) -> bytes:
    return blake2b(l + r, digest_size=32, person=b"gdpknode").digest()

def _merkle(leaves: list[bytes]) -> bytes:
    if not leaves:
        return struct.pack("<I", 0)
    nodes = list(leaves)
    interior: list[bytes] = []
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes), 2):
            l = nodes[i]
            r = nodes[i + 1] if i + 1 < len(nodes) else l
            nxt.append(_hash_node(l, r))
        interior.extend(nxt)
        nodes = nxt
    return struct.pack("<I", len(leaves)) + b"".join(leaves + interior)

def _merkle_root(leaves: list[bytes]) -> bytes:
    blob = _merkle(leaves)
    n = struct.unpack_from("<I", blob, 0)[0]
    if n == 0:
        return b"\x00" * 32
    return blob[len(blob) - 32:len(blob)]

class GdpkWriter:
    def __init__(self, build_key: BuildKey, chunk_size: int = 64 * 1024,
                 compress: bool = True, integrity_tree: bool = True):
        self.bk = build_key
        self.chunk_size = chunk_size
        self.compress = compress
        self.integrity_tree = integrity_tree
        self._files: list[tuple[str, FileKind, int, bytes]] = []

    def add_file(self, path: str, data: bytes, kind: FileKind | None = None,
                 flags: int = 0) -> None:
        path = path.replace("\\", "/")
        if not path.startswith("res://"):
            path = "res://" + path.lstrip("/")
        self._files.append((path, kind or classify(path), flags, data))

    def finalize(self, out_path: str | Path) -> dict:
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        data_offset = HEADER_LEN
        blob = bytearray()
        entries: list[TableEntry] = []
        all_leaves: list[bytes] = []
        any_vm = False

        for i, (path, kind, flags, plain) in enumerate(self._files):
            codec = 0
            body = plain
            if self.compress and len(plain) > 256:
                comp = zlib.compress(plain, 9)
                if len(comp) < len(plain):
                    body, codec = comp, 1

            fkey = derive_file_key(self.bk, i)
            nonce_base = blake2b(self.bk.salt + i.to_bytes(4, "little"),
                                 digest_size=NONCE_LEN, person=b"gdpknonc").digest()

            enc = bytearray()
            n_chunks = max(1, (len(body) + self.chunk_size - 1) // self.chunk_size)
            for c in range(n_chunks):
                chunk = body[c * self.chunk_size:(c + 1) * self.chunk_size]
                aad = self.bk.salt + i.to_bytes(4, "little") + c.to_bytes(4, "little")
                _, ct = aead_encrypt(fkey, chunk, aad,
                                     nonce=derive_chunk_nonce(nonce_base, c))
                all_leaves.append(_hash_leaf(ct))
                enc += ct

            entries.append(TableEntry(
                index=i, path=path, kind=kind, codec=codec, flags=flags,
                data_offset=data_offset + len(blob), stored_size=len(enc),
                orig_size=len(plain), nonce_base=nonce_base,
                digest=sha256(plain).digest(),
            ))
            blob += enc
            any_vm |= bool(flags & FILE_FLAG_VIRTUALIZED)

        tbl = bytearray(struct.pack("<III", TABLE_VERSION, len(entries),
                                    self.chunk_size))
        for e in entries:
            p = e.path.encode()
            tbl += struct.pack("<H", len(p)) + p
            tbl += struct.pack("<BBHQQQ", e.kind, e.codec, e.flags,
                               e.data_offset, e.stored_size, e.orig_size)
            tbl += e.nonce_base + e.digest
        tree_blob = _merkle(all_leaves) if self.integrity_tree else b""
        if self.integrity_tree:
            tbl += _merkle_root(all_leaves)

        table_nonce, table_ct = aead_encrypt(
            derive_table_key(self.bk), bytes(tbl), aad=self.bk.salt)

        table_offset = data_offset + len(blob)
        tree_offset = table_offset + len(table_ct)

        flags = FLAG_TABLE_ENC | FLAG_CHUNKED
        flags |= FLAG_TREE if self.integrity_tree else 0
        flags |= FLAG_VM if any_vm else 0

        header = struct.pack(
            "<4sBBH8sQQ12sQQQQ20s",
            MAGIC, *VERSION, flags, self.bk.salt,
            table_offset, len(table_ct), table_nonce,
            data_offset, len(blob), tree_offset, len(tree_blob),
            b"\x00" * 20,
        )
        out.write_bytes(header + blob + table_ct + tree_blob)
        return {
            "files": len(entries), "bytes_in": sum(len(f[3]) for f in self._files),
            "bytes_out": out.stat().st_size, "chunks": len(all_leaves),
            "out": str(out),
        }

class GdpkReader:
    def __init__(self, path: str | Path, build_key: BuildKey):
        self.path = Path(path)
        self.bk = build_key
        d = self.path.read_bytes()
        (magic, vmaj, vmin, flags, salt, t_off, t_len, t_nonce,
         d_off, d_len, tr_off, tr_len, _res) = struct.unpack_from(
            "<4sBBH8sQQ12sQQQQ20s", d, 0)
        if magic != MAGIC:
            raise ValueError("not a GDPK container")
        if vmaj != VERSION[0]:
            raise ValueError(f"unsupported GDPK v{vmaj}")
        self.d, self.flags = d, flags
        self.data_off, self.tree_off, self.tree_len = d_off, tr_off, tr_len

        tkey = derive_table_key(self.bk)
        if self.bk.salt != salt:
            raise ValueError("build salt mismatch — wrong key for this container")
        tbl = aead_decrypt(tkey, t_nonce, d[t_off:t_off + t_len], aad=salt)
        self._parse_table(tbl)

    def _parse_table(self, tbl: bytes) -> None:
        ver, count, self._chunk_size = struct.unpack_from("<III", tbl, 0)
        if ver != TABLE_VERSION:
            raise ValueError(f"bad table version {ver}")
        pos = 12
        self.entries: list[TableEntry] = []
        for i in range(count):
            (plen,) = struct.unpack_from("<H", tbl, pos); pos += 2
            path = tbl[pos:pos + plen].decode(); pos += plen
            kind, codec, flags, doff, ssize, osize = struct.unpack_from("<BBHQQQ", tbl, pos)
            pos += 28
            nonce_base = tbl[pos:pos + NONCE_LEN]; pos += NONCE_LEN
            digest = tbl[pos:pos + 32]; pos += 32
            self.entries.append(TableEntry(i, path, FileKind(kind), codec, flags,
                                           doff, ssize, osize, nonce_base, digest))
        self.tree_root = tbl[pos:pos + 32] if self.flags & FLAG_TREE else None

    def read_file(self, entry_or_path) -> bytes:
        e = entry_or_path if isinstance(entry_or_path, TableEntry) else next(
            x for x in self.entries if x.path == entry_or_path)
        fkey = derive_file_key(self.bk, e.index)
        raw = self.d[e.data_offset:e.data_offset + e.stored_size]
        n_chunks = e.stored_size // (self._chunk_span(e)) if self._is_chunked(e) else 1
        plain = bytearray()
        pos = 0
        c = 0
        while pos < len(raw):
            take = self.chunk_size + TAG_LEN if pos + self.chunk_size + TAG_LEN <= len(raw) else len(raw) - pos
            ct = raw[pos:pos + take]
            aad = self.bk.salt + e.index.to_bytes(4, "little") + c.to_bytes(4, "little")
            plain += aead_decrypt(fkey, derive_chunk_nonce(e.nonce_base, c), ct, aad)
            pos += take
            c += 1
        body = zlib.decompress(bytes(plain)) if e.codec == 1 else bytes(plain)
        if sha256(body).digest() != e.digest:
            raise ValueError(f"{e.path}: plaintext digest mismatch")
        return body

    def _is_chunked(self, e: TableEntry) -> bool:
        return bool(self.flags & FLAG_CHUNKED)

    def _chunk_span(self, e: TableEntry) -> int:
        return self.chunk_size + TAG_LEN

    @property
    def chunk_size(self) -> int:
        return getattr(self, "_chunk_size", 64 * 1024)

    def verify_integrity(self) -> bool:
        if not (self.flags & FLAG_TREE):
            return True
        leaves: list[bytes] = []
        for e in self.entries:
            pos = e.data_offset
            end = pos + e.stored_size
            c = 0
            while pos < end:
                take = (self.chunk_size + TAG_LEN
                        if pos + self.chunk_size + TAG_LEN <= end else end - pos)
                leaves.append(_hash_leaf(self.d[pos:pos + take]))
                pos += take
                c += 1
        if _merkle_root(leaves) != self.tree_root:
            return False
        blob = self.d[self.tree_off:self.tree_off + self.tree_len]
        if len(blob) < 36:
            return False
        (n,) = struct.unpack_from("<I", blob, 0)
        if 4 + n * 32 > len(blob):
            return False
        stored_root = blob[len(blob) - 32:]
        stored_leaves = [blob[4 + i * 32:4 + (i + 1) * 32] for i in range(n)]
        return (stored_root == self.tree_root
                and _merkle_root(stored_leaves) == self.tree_root)
