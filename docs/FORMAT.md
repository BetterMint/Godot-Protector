# GDPK container format — version 1.0

GDPK is the protected container that replaces a stock `.pck`. Unlike `.pck`,
there is no plaintext directory: the file table is AEAD-encrypted as a single
blob under the table key, and every file body is chunked, independently
nonced, and authenticated, with chunk position bound into the AAD. A
whole-file transplant, chunk swap, or bit flip fails authentication at read
time.

This document mirrors `gdprotect/pck/container.py` and specifies everything a
third-party reader or writer needs.

**Conventions.** All multi-byte integers are little-endian. `u8/u16/u32/u64`
are unsigned integers of that width; `i32` is signed. `u8[n]` is a byte array
of fixed length. `‖` denotes concatenation. Byte offsets are decimal.
`NONCE_LEN = 12`, `TAG_LEN = 16`.

---

## 1. File layout

```
┌───────────────┬───────────────────────────────┐
│ offset 0      │ header, fixed 96 bytes        │
│ data offset   │ data region (chunked files)   │
│ table offset  │ encrypted file table          │
│ tree offset   │ Merkle integrity tree blob    │
└───────────────┴───────────────────────────────┘
```

In this implementation the regions are written contiguously in the order
header → data → table → tree, so `data_offset = 96`,
`table_offset = data_offset + data_length`, and
`tree_offset = table_offset + table_length`. Readers must not rely on this
ordering — use the offset/length fields in the header.

## 2. Header (96 bytes)

| Offset | Size | Type   | Field | Description |
|---:|---:|---|---|---|
| 0  | 4  | u8[4]  | magic | ASCII `"GDPK"` (`0x47 0x44 0x50 0x4B`) |
| 4  | 1  | u8     | version_major | currently `1` |
| 5  | 1  | u8     | version_minor | currently `0` |
| 6  | 2  | u16    | flags | header flags, see below |
| 8  | 8  | u8[8]  | build_salt | per-build random salt; feeds KDF, nonce derivation, chunk AAD, and the GVM-1 dialect permutation |
| 16 | 8  | u64    | table_offset | absolute offset of the encrypted file table |
| 24 | 8  | u64    | table_length | byte length of the encrypted table (ciphertext + tag) |
| 32 | 12 | u8[12] | table_nonce | AES-GCM nonce used to encrypt the table |
| 44 | 8  | u64    | data_offset | absolute offset of the data region |
| 52 | 8  | u64    | data_length | byte length of the data region |
| 60 | 8  | u64    | tree_offset | absolute offset of the integrity tree blob; `0` = none |
| 68 | 8  | u64    | tree_length | byte length of the integrity tree blob |
| 76 | 20 | u8[20] | reserved | zero |

A reader must reject the file if `magic != "GDPK"` or
`version_major != 1`. If the build key's salt does not equal `build_salt`,
the key does not belong to this container ("build salt mismatch — wrong key
for this container").

### 2.1 Header flags (u16, bitfield)

| Bit | Mask | Name | Meaning |
|---:|---:|---|---|
| 0 | `0x0001` | `FLAG_TABLE_ENC` | file table is AEAD-encrypted |
| 1 | `0x0002` | `FLAG_CHUNKED` | file bodies are chunked + per-chunk nonced |
| 2 | `0x0004` | `FLAG_TREE` | integrity tree blob present |
| 3 | `0x0008` | `FLAG_VM` | at least one file carries `FILE_FLAG_VIRTUALIZED` (a `.gvmb` payload exists) |

Bits 4–15 are reserved, write `0`. The reference writer always sets
`TABLE_ENC | CHUNKED`, sets `TREE` when the integrity tree is enabled, and
sets `VM` when any virtualized file was packed.

## 3. Key schedule

All sub-keys are domain-separated BLAKE2b-256 digests (digest size 32,
personalization `"gdprotect\x00" + label[:6]` — i.e. the 10-byte prefix
`gdprotect\x00` followed by up to 6 bytes of label, padded to 16 bytes).
Each KDF input is length-prefixed: `u32 len(part) ‖ part`, in the order
listed.

```
table_key = KDF(build_key, build_salt;                label "table")
file_key(i) = KDF(build_key, build_salt, u64le(i);    label "file")
```

where `build_key` is the 32-byte root secret (never stored in the container;
the runtime re-derives it from XOR shards — see §7) and `build_salt` is the
8-byte header field. `i` is the file's index in table order.

Because every file key is derived from `(build_key, salt, index)`, leaking one
file's plaintext key compromises neither the table key nor any sibling file.

## 4. File table

The table plaintext is serialized, then encrypted in one shot:

```
table_ct = AES-256-GCM(key=table_key,
                       nonce=table_nonce (from header),
                       plaintext=table,
                       aad=build_salt)
```

`table_nonce` is 12 fresh random bytes generated at pack time and stored in
the header. The AAD is exactly the 8-byte `build_salt` — nothing else.

### 4.1 Table plaintext layout

| Field | Type | Description |
|---|---|---|
| table_version | u32 | `= 1` |
| file_count | u32 | number of entries |
| chunk_size | u32 | plaintext bytes per chunk (§6.2); stored span adds the 16-byte tag per chunk |
| entries… | per-file records | see below |
| tree_root | u8[32] | **only if `FLAG_TREE`** — Merkle root mirrored inside the encrypted table so the (unencrypted) tree blob itself is authenticated |

### 4.2 Per-file record

| Field | Type | Description |
|---|---|---|
| path_len | u16 | byte length of `path` |
| path | u8[path_len] | normalized `"res://…"` path, UTF-8, **no** NUL padding |
| kind | u8 | `FileKind` enum (§5) |
| codec | u8 | `0` = none, `1` = deflate (zlib) |
| flags | u16 | per-file flags; bit0 `FILE_FLAG_VIRTUALIZED` (`0x0001`) |
| data_offset | u64 | absolute file offset of the file's first chunk |
| stored_size | u64 | encrypted byte span on disk, **tags included** |
| orig_size | u64 | plaintext size **after decompression** (pre-codec size) |
| nonce_base | u8[12] | base nonce for this file's chunks (§6.2) |
| digest | u8[32] | SHA-256 of the decompressed plaintext |

Paths are normalized: backslashes become `/`, and the path is prefixed with
`res://` if it does not already start with it.

## 5. FileKind enum

| Value | Name | Extensions |
|---:|---|---|
| 0 | `DATA` | anything not matched below |
| 1 | `GDSCRIPT_SOURCE` | `.gd` `.gdc` `.gdshader` |
| 2 | `VM_BYTECODE` | `.gvmb` |
| 3 | `SCENE` | `.tscn` `.scn` |
| 4 | `RESOURCE` | `.tres` `.res` `.theme` `.import` |
| 5 | `CONFIG` | `.cfg` `.godot` `.toml` `.json` |
| 6 | `NATIVE` | `.dll` `.so` `.dylib` `.wasm` |

## 6. Data region

### 6.1 Compression

If compression is enabled and `len(plaintext) > 256`, the body is
`zlib.compress(plaintext, 9)` and kept only if smaller than the input; then
`codec = 1`. Otherwise `codec = 0` and the raw bytes are packed. The codec
choice is recorded per file in the table — readers must check it rather than
infer it.

### 6.2 Chunking and per-chunk AEAD

Let `body` be the post-codec byte string and `chunk_size` the configured
chunk size (default `64 * 1024`). `chunk_size` is stored in the encrypted
table header (§4.1) so readers learn it after decryption — the Python
`GdpkReader` honors it. **The C runtime still decodes a fixed 64 KiB**, so
non-default sizes currently require patching the runtime reader.

```
n_chunks = max(1, ceil(len(body) / chunk_size))

per file i, per chunk c:
    nonce_base(i) = BLAKE2b-12(build_salt ‖ u32le(i), person="gdpknonc")
    nonce(c)      = nonce_base with the LAST 8 bytes XORed by u64le(c)
    aad(i, c)     = build_salt ‖ u32le(i) ‖ u32le(c)
    ct            = AES-256-GCM(key=file_key(i), nonce=nonce(c),
                                plaintext=chunk, aad=aad(i,c))
    stored        = ct_ciphertext ‖ 16-byte tag   (tag appended per chunk)
```

- Every chunk is independently nonced; `nonce_base` is unique per file and
  the low 8 bytes carry a per-chunk counter, so `(file, chunk)` never
  repeats a nonce.
- The AAD binds `(build_salt, file_index, chunk_index)` — a chunk moved to
  any other position or file decrypts to garbage / fails the tag check.
- `stored_size` in the table is `len(ciphertext) + TAG_LEN` summed over the
  file's chunks — i.e. the full on-disk span including tags.
- An empty file still produces 1 chunk (`max(1, …)`).

### 6.3 Read path

For each file: derive `file_key(index)`, slice `stored_size` bytes from
`data_offset`, walk `chunk_size + TAG_LEN`-byte records (the final record is
short), decrypt each with the AAD above, concatenate, `zlib.decompress` if
`codec == 1`, then verify `SHA-256(plaintext) == digest`. Any AEAD failure
or digest mismatch aborts the read.

## 7. Integrity tree (optional, `FLAG_TREE`)

Leaves: one BLAKE2b-256 hash per **ciphertext** chunk across all files, in
write order — `BLAKE2b-256(ct_with_tag, person="gdpkleaf")`.

Interior: binary Merkle reduction — for each pair `(l, r)` compute
`BLAKE2b-256(l ‖ r, person="gdpknode")`; an unpaired node is duplicated
(`r = l`). Repeat until one node remains: the root.

### 7.1 Serialized blob

```
u32 leaf_count
u8[32] leaf[0] … leaf[leaf_count-1]
u8[32] interior nodes, in reduction order (level by level, left to right)
u8[32] root                  (the last 32 bytes of the blob)
```

An empty container serializes as just `u32 0` and the mirrored root is
32 zero bytes.

### 7.2 Verification

The same root is mirrored inside the encrypted table (§4.1). `verify` runs
two independent checks against the authenticated `tree_root` from the
decrypted table:

1. **Stored-tree check** — reads the stored leaves from the tree blob and
   re-reduces them with `_hash_node`; a swapped or truncated tree blob fails.
2. **Ciphertext check** — re-hashes every ciphertext chunk on disk with
   `_hash_leaf` and reduces them into a fresh root; flipped ciphertext bits
   fail even if the tree blob is untouched.

Both must match the mirrored root. The tree carries no authority of its
own — the encrypted table is the trust anchor.

## 8. Key shards (runtime)

Nothing in the container stores `build_key`. `gdprotect build --emit-key`
writes a C++ header that splits the 32-byte key into `N` (default 4,
allowed 2–16) XOR shards: `N-1` are random, the last is the key XORed with
all the others — every shard is required to rebuild it. The header exposes
`BUILD_SALT`, `KEY_SHARD_COUNT`, `KEY_SHARD_i[32]`, and a `rebuild_key()`
that XORs all shards. The runtime is expected to scatter the shards across
separate translation units so no single `.rodata` range holds the key.

## 9. Constants reference

| Constant | Value |
|---|---|
| `MAGIC` | `b"GDPK"` |
| `VERSION` | `(1, 0)` |
| `HEADER_LEN` | `96` |
| `TABLE_VERSION` | `1` |
| `NONCE_LEN` / `TAG_LEN` | `12` / `16` |
| default `chunk_size` | `64 * 1024` = 65536 |
| header flags | `TABLE_ENC=0x1` `CHUNKED=0x2` `TREE=0x4` `VM=0x8` |
| file flags | `FILE_FLAG_VIRTUALIZED=0x0001` |
| codec ids | `0` none · `1` deflate (zlib level 9) |
| `FileKind` | `0` DATA · `1` GDSCRIPT_SOURCE · `2` VM_BYTECODE · `3` SCENE · `4` RESOURCE · `5` CONFIG · `6` NATIVE |
| hash/KDF | BLAKE2b (keys 32 B, leaves/nodes 32 B, nonce_base 12 B); SHA-256 for per-file plaintext digest |
| AEAD | AES-256-GCM, 12-byte nonces, 16-byte tags |
| BLAKE2b personalizations | KDF `"gdprotect\x00"+label[:6]`; nonce_base `"gdpknonc"`; leaves `"gdpkleaf"`; nodes `"gdpknode"` |

## 10. Interop checklist for third-party readers

1. Parse the 96-byte header; check magic, `version_major == 1`, and that
   your key's salt equals `build_salt`.
2. Derive `table_key`; decrypt `table_length` bytes at `table_offset` with
   `table_nonce`, AAD = `build_salt`.
3. Check `table_version == 1`; read `file_count` and `chunk_size`, then
   parse the entries (§4.2); if `FLAG_TREE`, read the trailing 32-byte root.
4. For each file: derive `file_key(index)`, walk `chunk_size + 16` byte
   records, decrypt each chunk with nonce = `nonce_base` ⊕ `u64le(c)` in the
   last 8 bytes and AAD = `salt ‖ u32le(index) ‖ u32le(c)`.
5. Decompress if `codec == 1`; verify the SHA-256 digest.
6. If `FLAG_TREE`: re-reduce the stored leaves AND re-hash the ciphertext
   into a fresh root; both must equal the table's root.
