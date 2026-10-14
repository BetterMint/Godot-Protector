# gdpk runtime — reading `.gdpk` containers inside Godot

`gdprotect build` produces a `.gdpk` container: a 96-byte header, an
AEAD-encrypted file table, chunked AES-256-GCM file bodies, an optional
BLAKE2b Merkle integrity tree, and `.gvmb` virtual-machine payloads for
virtualized scripts. The 256-bit build key is never stored in the
container — it is split into XOR shards emitted as `runtime/key_shard.h`
(`gdprotect build --emit-key`) and compiled into whatever binary reads
the container.

There are **two integration paths**, pick per build:

```
                       ┌───────────────────────────────────────────┐
 game.gdpk ──(open)──► │ shared/gdpk_format.h  (+ _blake2b, _aesgcm)│
                       └───────────────┬───────────────────────────┘
               path A (strong)         │          path B (easy)
        ┌──────────────────────────┐   │   ┌─────────────────────────┐
        │ packsource/              │   │   │ src/  GDExtension        │
        │ GdpkPackSource : PackSrc │   │   │ Gdpk : Object singleton  │
        │ engine-level mount       │   │   │  + GvmVM interpreter     │
        └──────────────────────────┘   │   └─────────────────────────┘
```

Both paths share `runtime/shared/` — wire-format constants, LE readers,
the BLAKE2b KDF (`keys.py`), nonce derivation (`cipher.py`), table
parsing and the Merkle reduce (`container.py`). Change the Python format
and those headers must change in lockstep.

---

## Path A — `packsource/GdpkPackSource` (strong)

The container mounts **like a native .pck**: Godot's resource loader,
script server, `FileAccess`, `load()` — everything — reads through
`PackedData` without knowing GDPK exists. No plaintext ever touches
`user://` or the filesystem; chunks are decrypted into RAM on demand and
the key exists only inside the rebuilt-shard window during open.

### Integration (requires custom export templates)

1. Copy the `runtime/` tree into your engine source, e.g.
   `modules/gdpk/` or alongside `core/io/` — it needs no SConscript
   registration if placed where the build globs sources (a canonical
   spot is `core/io/gdpk/` + one include patch). Simplest robust option:
   drop `packsource/gdpk_pack_source.{h,cpp}`, `shared/*.h` and a
   generated `key_shard.h` into `core/io/gdpk/` and add a tiny
   `SCsub`/`register` file — or compile the .cpp from `core/SCsub`.

2. Generate key shards **from the same build that produced the .gdpk**:
   ```sh
   gdprotect build game/ -o game.gdpk --emit-key runtime/key_shard.h
   ```
   `BUILD_SALT` in that header is the 8 header salt bytes read
   big-endian; the source checks it against the container header before
   attempting decryption — a stale header fails fast.

3. Compile the engine with `-DGDPK_HAS_KEY_SHARD` (e.g. via `CPPDEFINES`
   in the module SCsub or `custom.py`).

4. Register the source where the stock `PackSourcePCK` is registered —
   in `core/io/file_access_pack.cpp`, inside `PackedData::setup()` (or in
   `main/main.cpp`'s pack setup for the boot pck, depending on version):
   ```cpp
   PackedData::get_singleton()->add_pack_source(memnew(GdpkPackSource));
   ```
   Order matters: add it *before* `PackSourcePCK` so `.gdpk` wins on the
   magic check, or after — `try_open_pack` returns `false` on non-GDPK
   files so either order is safe.

   Reference implementation: `PackedSourcePCK::try_open_pack(path,
   replace_files, offset)` in the same file. `try_open_pack` is called
   for **each** candidate pack in Godot's fixed discovery order —
   `--main-pack <p>` → `<exe>.pck` → the executable itself (embedded).
   `GdpkPackSource` answers all three: a literal `.gdpk` mounts directly;
   a missing `<exe>.pck` is retried as `<exe>.gdpk`; and a binary with
   no GDPK magic at `p_offset` gets the EOF-footer scan (below).

5. Replace the game's `.pck` with the `.gdpk` (same filename, or rely on
   the `.pck`→`.gdpk` sibling retry), or **embed** it. The embed layout
   reuses the stock PCK trailer — append to the executable:
   `[container][pad to 8][u64le embed_len][u32le 0x4B504447 "GDPK"]`
   (`gdpk::EMBED_MAGIC`/`EMBED_FOOTER_LEN` in `shared/gdpk_format.h`).
   `try_open_pack` then derives the container base as
   `file_size - 12 - embed_len` — no offset flags, no engine patching
   beyond registering the source.

### What the mount gives you

- `try_open_pack` reads the 96-byte header, verifies `GDPK` magic +
  version 1.x, checks the salt, XORs the key shards back into the build
  key, AEAD-decrypts the file table (key = BLAKE2b `person
  "gdprotect\x00table"` KDF; nonce = header field; AAD = salt), then
  registers every entry with `PackedData::add_path`.
- `get_file` returns `FileAccessGdpk`: codec-0 files decrypt **one 64 KiB
  chunk window lazily** as the read cursor moves (random access maps
  file offset → `chunk = pos / 65536`); codec-1 (zlib) files inflate
  once to memory on first read since deflate isn't addressable.
- `verify_integrity()` re-hashes every ciphertext chunk and reduces the
  Merkle tree, comparing against the root mirrored inside the *encrypted
  table* (the same check `GdpkReader.verify_integrity` performs; the
  Python side additionally re-reduces the stored tree blob — the C++
  ciphertext-derived root already pins it, so that's redundant).
- Engine-version risk is isolated: `CryptoCore::sha256`,
  `Compression::decompress`, and `PackedData::add_path` are each used
  inside one small static function/loop — grep for them in
  `gdpk_pack_source.cpp` if a release drifts.

`.gvmb` payloads still need the VM: the engine doesn't know that file
type. With path A alone, virtualized scripts arrive as opaque bytes —
see "running virtualized scripts" below.

## Path B — `src/` GDExtension (easy)

A normal `libgdpk` extension — no engine rebuild, works on stock export
templates. Exposes a `Gdpk` singleton (registered via
`Engine::register_singleton`) plus the `GvmVM` class:

```gdscript
func _ready() -> void:
    # .gdpk sits next to the executable (or wherever you put it)
    var ok := Gdpk.open_container(OS.get_executable_path()
            .get_base_dir().path_join("game.gdpk"))
    assert(ok and Gdpk.verify_integrity())

    var tex_bytes := Gdpk.read_file("res://art/logo.png")   # to memory
    var img := Image.new()
    img.load_png_from_buffer(tex_bytes)

    # virtualized script — CALL consts resolve by name; register what the
    # bytecode calls beyond builtin utility fns (print/str/… work free)
    Gdpk.vm_register_host_call("save_game", save_game)
    Gdpk.vm_load("res://player.gvmb")
    Gdpk.vm_set_self(self)
    var ret = Gdpk.vm_call(0, [])
```

Nothing is written to `user://`; `read_file` returns `PackedByteArray`
and callers feed `Image.load_*_from_buffer`, `GDScript.new()` + `source`,
`XMLParser.open_buffer`, etc. — every Godot loader has a memory path.

### Building

```sh
gdprotect build game/ -o game.gdpk --emit-key runtime/key_shard.h
scons -C runtime platform=windows target=template_release \
        godot_cpp_path=../godot-cpp
```

`SConstruct` auto-adds `-DGDPK_HAS_KEY_SHARD` when `key_shard.h` contains
the generated marker. Without it the extension still compiles but
`open_container` refuses cleanly.

### The cipher vtable

`Gdpk` never calls AES-GCM directly — `decrypt_chunk()` routes through
`CipherVtable::aead_open` (default: the vendored implementation in
`shared/gdpk_aes256gcm.h`). To substitute mbedTLS/OpenSSL/a TPM-backed
primitive, call `set_cipher()` from C++ before opening. Same for
`sha256` (default `HashingContext`).

## Running virtualized scripts

`FLAG_VM` containers carry `.gvmb` members (kind `VM_BYTECODE`,
flag `FILE_FLAG_VIRTUALIZED`) — GDScript compiled to the GVM-1 ISA whose
opcode bytes are permuted per build and whose immediates are
Feistel-encoded per cell. `GvmVM` (path B) executes them:

- `load_image` parses the GVMB header, rebuilds the `Dialect` from the
  stored u64 salt — including a bit-exact port of CPython's `random.Random`
  (init_by_array seeding, high-bit `getrandbits`, `_randbelow` rejection
  sampling) that `isa.py::Dialect` uses — then decodes all code cells up
  front so function entries and jump targets stay cell-indexed.
- `call_func(func_idx, args)` binds `args` to `r1..rN` (r0 is the
  accumulator convention) and runs the dispatch loop. `RET` returns the
  rA operand; `YIELD` suspends and returns `{_gvm_yield: true, value}` —
  feed the awaited value back with `resume(v)`.
- `CALL`/`CALLM` pop `argc` then `argc` args off the operand stack
  (caller pushes args in order, then argc on top). Their const operand
  is the callee **name** (a String const per `compiler.py::HOST_SLOTS`):
  CALL resolves a glue-registered `Callable` first
  (`vm_register_host_call`), then `Variant::call_utility_function`
  (print/str/sin/…), then the VM's own fallbacks for names Godot lacks —
  `bnot/band/bor/bxor/bshl/bshr` and the Variant type constructors via
  `Variant::construct`. CALLM dispatches through `Callable(base, name)`
  so both `Object` and builtin `Variant` methods work — and bare `f()`
  module calls compile to `CALLM self, "f"`, which is how the stub
  delegation below loops back into the VM.
- Arithmetic/comparison uses typed fast paths (int, float, String,
  Vector2/3) and falls back to `Variant::evaluate`, so every remaining
  Variant type gets exact GDScript operator semantics. Iteration uses the
  `iter_init`/`iter_next`/`iter_get` protocol keyed by cell index, so
  `for k in dict` yields keys like stock GDScript and nested loops over
  the same source register can't collide; a jump that leaves a loop's
  cell span drops its iterator state (break/continue re-entry stays
  correct).
- `__gvm_member_init` (always funcs[0] in compiler images) materializes
  member `var` initializers into the VM globals dict. The runtime runs
  it automatically once per binding — on `vm_set_self` and lazily before
  the first `vm_call`. `GETG`/`SETG` address the globals dict; a `GETG`
  miss falls through to `self` members and then Engine singletons
  (`Input`, `OS`, …), so bare-name autoload access works unseeded.
- `Gdpk.vm_func_index("name")` maps a function name to its table index —
  stub generators use it to hardcode `vm_call` indices.

### Two ways to wire `.gvmb` into the tree

**Pragmatic (recommended): a thin `.gd` stub per virtualized script.**
The compiled `.gvmb` rides inside the `.gdpk`; a plain GDScript file
keeps the engine's script system happy and delegates every real function
into the VM:

```gdscript
# player.gd — ships as normal script; logic lives in player.gvmb
extends CharacterBody2D

func _ready() -> void:
    Gdpk.vm_set_self(self)
    Gdpk.vm_call(Gdpk.vm_func_index("_ready"), [])

func heal(amount: int) -> int:
    return Gdpk.vm_call(Gdpk.vm_func_index("heal"), [amount])
```

Bare `helper()` calls inside the virtualized code emit `CALLM self,
"helper"`, which lands back on the stub — every module function reachable
that way needs a stub method that forwards to `vm_call`. Host
integration (signals, saves, native calls) is `vm_register_host_call`
plus whatever the bytecode calls beyond the builtins.

**Heavy: `ScriptLanguageExtension`.** Registering a full custom script
language (with `ScriptExtension` wrapping each `.gvmb` as a first-class
script resource) makes virtualized files attachable directly — no stubs,
editor-integrated, correct script identity in the inspector. It is also
a large API surface with per-version risk for zero gain in the common
case: the stub route reaches the same VM with the same semantics and
needs no language plumbing. Start with stubs; escalate to
`ScriptLanguageExtension` only if you need `extends`-style inheritance or
real script objects on exported members.

## Crypto/format notes for porters

- **chunk_size is serialized** in the encrypted table header (`<III`:
  table_version, file_count, chunk_size) — the reader honors the stored
  value, 64 KiB is just the writer's default. `TableEntry::chunk_ct_span`
  and all chunk loops take it as a parameter; a container built with a
  non-default `pack.chunk_size` reads correctly.
- **`BUILD_SALT` byte order**: `key_shard.h` stores `0x{salt.hex()}ULL`
  = salt bytes big-endian. `gdpk::salt_u64_to_bytes` converts back.
  The `.gvmb` dialect salt instead reads the salt little-endian
  (`int.from_bytes(salt, "little")`) — and is stored inside the image,
  so the VM never derives it.
- **`verify_integrity` parity**: both sides hash ciphertext chunks to
  leaves and compare the Merkle root against the table-mirrored one.
  Python additionally re-reduces the stored tree blob's leaf list; the
  C++ check already covers that case (a forged blob disagrees with the
  mirrored root).
- **Python `read_file` chunk walk** is `take = min(CHUNK+16, remaining)`;
  `TableEntry::chunk_ct_span` in `gdpk_format.h` is the same formula.
- **NEG is in-place**: `encode_insn` emits only the `a` operand byte for
  it, so `b` can't reach the image. `gvm_vm` treats NEG as `rA = -rA`.
- **SETM name index is u8** (the `c` slot in the 3-register encoding
  group) — member-name consts beyond 255 can't be targeted by SETM.
  ITER's exit target is u16 — code spans > 65535 cells can't be branched
  out of by ITER. Both mirror the encoder's limits exactly.
- **`.gvmb` layout** is written by `gdprotect/vm/compiler.py::_image`
  (the serializer of record): `magic, u32 ver, u64 salt, u32 nconst,
  u32 code_byte_span, u32 nfuncs, consts…, funcs…, code…`. Field +20 is
  the code region's **byte span**, not a cell count — `load_image`
  decodes until the span is consumed and counts cells as it goes.
- **Key extraction threat model**: every public Godot-pack key extractor
  (gdke, KeyDot, Godot-AES-key-extractor) works the same way — find the
  `lea reg, [rip+off]` that loads the engine's static 32-byte key, follow
  it, dump the key. The defence is not a better hiding spot, it's that
  **no contiguous key exists**: `key_shard.h` carries N XOR shards (each
  compiled into a separate TU), `rebuild_key()` materializes the key only
  in the register/stack window of the mount path, and the salt guard
  fails wrong-key builds before a GCM round ever runs. Keep shard TUs
  separate and strip symbols so the shards stay anonymous.
- **Why not stock encryption**: Godot's built-in encrypted-pack members
  are FAE blobs — `md5[16] ‖ u64 len ‖ iv[16] ‖ AES-256-CFB`. CFB has no
  MAC, so ciphertexts are malleable and each file is one monolithic blob.
  GDPK deliberately diverges and is *not* FAE-compatible: chunked
  AES-256-GCM (per-chunk nonce = `nonce_base ⊕ counter`, AAD =
  `salt‖idx‖ctr`), an AEAD-sealed file table, and an optional Merkle
  tree over the ciphertext. Stock decryptors and extractors produce
  garbage on a `.gdpk` — that incompatibility is the point.

## Release hardening checklist

Anchors are what make extractor tooling cheap — strip them before ship:

- **Build silent**: `GDPK_ERR()` sites in `gdpk_pack_source.cpp` emit
  only under `-DGDPK_VERBOSE_ERRORS` (dev builds). Release templates omit
  the define — a failed GDPK mount then returns `false` with no string
  trail, exactly like a nonexistent file. The GDExtension's `push_error`
  path is user-facing diagnostics; grep for "Gdpk:"/"GvmVM:" if you want
  them gone too.
- **Symbols**: `scons debug_symbols=no` + `strip` the shipped binary; the
  shard symbol names (`KEY_SHARD_0…`) and type names are free signposts.
- **Strings audit**: search the built binary for `gdpk`, `GDPK`,
  `key_shard`, `gvmb` — anything left should be deliberate.
- **Template hygiene**: build `tools=no` release templates; editor builds
  carry extra attack surface and verbose error paths.
- **Per-build freshness**: the salt/dialect/key all change per
  `gdprotect build` — never reuse `key_shard.h` across releases.

## Files

| file | purpose |
|---|---|
| `shared/gdpk_blake2b.h` | streaming BLAKE2b + personalization + `keys.py::_kdf` |
| `shared/gdpk_aes256gcm.h` | AES-256-GCM encrypt/decrypt (spec GHASH) |
| `shared/gdpk_format.h` | header/table parsers, KDF, nonce/AAD, Merkle — one wire-format impl |
| `packsource/gdpk_pack_source.*` | `PackSource` + lazy `FileAccessGdpk` (path A) |
| `src/gdpk.*` | `Gdpk` singleton: open/read/verify/info + VM glue (path B) |
| `src/gvm_vm.*` | GVM-1 interpreter: dialect rebuild, cell decode, dispatch |
| `src/register_types.*` | GDExtension init, `Engine` singleton registration |
| `key_shard.h` | placeholder — regenerate via `--emit-key` per build |
| `gdpk.gdextension`, `SConstruct` | manifest + build glue |
