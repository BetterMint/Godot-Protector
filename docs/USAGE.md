# Usage — workflows, CLI reference, config reference, CI, FAQ

```
gdprotect [--config FILE] [--seed N] <command> …

commands:
  scan    inventory a project dir or .pck/.exe
  build   full pipeline: obfuscate → virtualize → pack (+ key shards)
  pack    pack only (no transforms)
  verify  check integrity + list a .gdpk
  keygen  print a fresh build key
```

Requires Python ≥ 3.10. Install:

```bash
pip install -e .          # from the repo root
# or, for development:
pip install -e '.[dev]'   # adds pytest
```

---

## 1. Common workflows

### 1.1 Protect a project directory (recommended)

```bash
gdprotect build path/to/mygame -o build/game.gdpk \
    --emit-key runtime/key_shard.h \
    --virtualize 'res://src/net/**' 'res://src/shop/**' \
    --report build/report.json
```

This runs the full pipeline: inventory → obfuscate every `.gd` →
virtualize the scripts matching the globs → pack into an AEAD'd `.gdpk`
→ split the build key into XOR shards for the runtime.

**The build key is printed once, to stdout.** Store it in a secret
manager / CI secret. It is the only way to `verify` the container later
(the runtime doesn't need it — it rebuilds the key from the shards).

### 1.2 Repack an existing `.pck` or export `.exe`

```bash
gdprotect build game.pck -o game.gdpk --emit-key key_shard.h
gdprotect build game.exe -o game.gdpk --emit-key key_shard.h
```

`PckReader` handles pack format **v2 (Godot 4.x)** and, best-effort,
**v1 (Godot 3.x)**, plus packs embedded in an executable (located by
scanning backwards for the `GDPC` magic at the file's tail).
Already-encrypted packs are refused:

```
gdprotect: game.pck: directory is already encrypted — supply the export
key or protect from the project directory instead
```

Prefer building from the project directory — repacking a `.pck` gives
you container protection but obfuscation can't rewrite compiled `.gdc`.

### 1.3 Pack without transforms

```bash
gdprotect pack mygame -o game.gdpk --emit-key key_shard.h
```

`pack` is `build` with obfuscation and virtualization off — useful for
testing the container layer or for assets-only packs.

### 1.4 Verify a build (release gate)

```bash
gdprotect verify game.gdpk --key $GDPROTECT_BUILD_KEY
```

Prints JSON: file count, `integrity: "ok"|"FAILED"`, how many entries
are virtualized, and the full listing. Exit code `0` on ok, `1` on
failure — wire it into CI as a release gate.

### 1.5 Look before you leap

```bash
gdprotect scan mygame -v        # per-file listing
gdprotect scan game.pck         # kind histogram for an export
```

---

## 2. CLI reference

### Global flags

| Flag | Meaning |
|---|---|
| `--config FILE` | Load `.gdprotect.toml` or `.json` config (see §3). CLI flags override config values. |
| `--seed N` | Deterministic build seed for the key/salt RNG — **testing only**; deterministic builds are reproducible, not secure. |

### `gdprotect scan <input> [-v]`

`input` may be a project directory, a `.pck`, or an `.exe` with an
embedded pack. Prints `N files · kind=count, …`; `-v` lists every file
with size and `res://` path.

### `gdprotect build <input> -o <out.gdpk> [flags]`

| Flag | Meaning |
|---|---|
| `-o, --output` | Output `.gdpk` path (required). Parent dirs are created. |
| `--emit-key FILE` | Write the C++ `key_shard.h` header (§4). |
| `--virtualize GLOB…` | Enable virtualization for `res://` glob matches, e.g. `'res://src/net/**'`. (To use `virtualize.scripts` from the config instead, set `virtualize.enabled = true` there and omit this flag.) |
| `--no-obfuscate` | Skip the obfuscation stage. |
| `--no-compress` | Store file bodies uncompressed (codec 0). |
| `--report FILE` | Write a JSON build report (files, sizes, chunks, virtualized count, build key — **secret**). |
| `-v, --verbose` | Print per-stage detail, including obfuscation skips. |

### `gdprotect pack <input> -o <out.gdpk> [flags]`

Same spine as `build` with obfuscation disabled and no `--virtualize`.
Accepts `--emit-key`, `--no-compress`, `-v`.

### `gdprotect verify <in.gdpk> --key <hex>`

`--key` is the 64-hex-char build key printed at build time (or produced
by `keygen` for test containers). The salt in the container header must
match the salt the key was generated with — a mismatched key fails with
"build salt mismatch — wrong key for this container".

### `gdprotect keygen`

Prints a fresh 64-hex-char build key. Mostly for tests; `build`
generates its own per-build key automatically.

## 3. Config file reference

`gdprotect --config .gdprotect.toml …` — every field maps 1:1 to a CLI
flag; CLI wins. JSON is also accepted (same shape).

```toml
seed = 12345                    # optional; deterministic builds (testing only)

[pack]
input          = "mygame"       # project dir, .pck, or .exe
output         = "build/game.gdpk"
chunk_size     = 65536          # bytes per AEAD chunk (see warning below)
compress       = true           # zlib level 9 per file, kept only if smaller
integrity_tree = true           # BLAKE2b Merkle tree over all chunks

[obfuscate]
enabled            = true
rename_identifiers = true
encrypt_strings    = true       # lift string literals into decode calls
control_flow       = true       # mangle control-flow shape
strip_comments     = true
preserve = [                    # identifiers that must NOT be renamed:
    "_ready", "_process",       #   engine callbacks
    "Health", "Player",         #   names referenced from .tscn/.tres,
    "on_hit",                   #   exported vars, signals, autoloads
]

[virtualize]
enabled   = false               # requires the runtime interpreter!
scripts   = ["res://src/net/**", "res://src/shop/**"]
hardening = 1                   # opaque-predicate density, 0..3
```

> **`chunk_size` warning.** `chunk_size` is stored in the encrypted table
> and the Python `GdpkReader` honors any value. The C runtime reader still
> decodes a fixed 64 KiB — change `pack.chunk_size` only if you are also
> patching the runtime reader.

> **`preserve` is load-bearing.** Obfuscation is not type-aware across
> scenes: if a `.tscn`, `.tres`, autoload declaration, or signal
> connection names an identifier, renaming it breaks the game at load.
> When in doubt, `preserve` it.

## 4. Runtime integration (`--emit-key`)

```bash
gdprotect build mygame -o game.gdpk --emit-key runtime/key_shard.h
```

emits a header shaped like:

```cpp
namespace gdpk {
constexpr uint64_t BUILD_SALT = 0x…ULL;
constexpr int KEY_SHARD_COUNT = 4;
constexpr uint8_t KEY_SHARD_0[32] = { … };
constexpr uint8_t KEY_SHARD_1[32] = { … };
constexpr uint8_t KEY_SHARD_2[32] = { … };
constexpr uint8_t KEY_SHARD_3[32] = { … };
inline void rebuild_key(uint8_t out[32]) { … }
}
```

A reference runtime ships in `runtime/` — see `runtime/README.md` for
the full integration guide. In brief:

| Path | Contents | Use |
|---|---|---|
| `runtime/shared/` | `gdpk_format.h` · `gdpk_blake2b.h` · `gdpk_aes256gcm.h` | Pure-C++ mirror of the wire format + KDF + AEAD — the *single* implementation both integrations share |
| `runtime/packsource/` | `gdpk_pack_source.h` (+ `.cpp`) | Engine-module `PackSource` — drop into a custom Godot build; mounts `.gdpk` and decrypts chunks on demand (path A) |
| `runtime/src/` | GDExtension loader | Alternative for stock templates — same shared headers, engine-unmodified install (path B) |
| `runtime/key_shard.h` | placeholder | Regenerated per build by `--emit-key`; **gitignored — never commit the real one** |

Whatever ships it, the runtime must:

1. **Scatter the shards.** `#include` the header in *different
   translation units* and copy each `KEY_SHARD_i` somewhere distinct —
   separate `.cpp` files, a data-section copy XORed with a position
   stream, one inside the license blob. Colocating all four in one
   `.rodata` array re-creates the stock static-key failure by hand.
2. **Rebuild at pack-open time** via `rebuild_key()` → 32-byte build key.
3. **Open the `.gdpk`** using the FORMAT.md spec: parse the 96-byte
   header, check `build_salt`, derive `table_key` and per-file keys
   (BLAKE2b domain-separated KDF), decrypt the table, then stream chunks
   with `AES-256-GCM(file_key, nonce_base ⊕ ctr, aad = salt‖idx‖ctr)`.
4. **Feed the loader** — `GdpkPackSource` registers every entry with
   `PackedData` and hands out `FileAccessGdpk` readers; the `.gvmb`
   interpreter handles `FILE_FLAG_VIRTUALIZED` entries (VM.md).

## 5. CI recipe (GitHub Actions)

The repo's own `.github/workflows/ci.yml` runs pytest plus a
deterministic smoke build — mirror it for your game:

```yaml
name: protect
on:
  release:
    types: [published]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e '.[dev]'
      - run: pytest -q
      - name: protect
        run: |
          gdprotect build game -o out/game.gdpk \
              --emit-key runtime/key_shard.h \
              --virtualize 'res://src/net/**' | tee /tmp/build.log
      - name: verify
        # each build mints a FRESH key — pull it from build output, not a
        # static secret (a stored secret only matches a --seed build)
        run: |
          KEY=$(grep -oP 'build key \(keep secret\): \K[0-9a-f]+' /tmp/build.log)
          gdprotect verify out/game.gdpk --key "$KEY"
```

Notes:

- Keep `key_shard.h` out of commits (`.gitignore` already covers it) —
  generate it per release build.
- `--seed` exists only to make *tests* reproducible (the CI smoke job
  uses `--seed 1`). Release builds must use fresh entropy.
- The key can also be pulled from `--report out/report.json`
  (`report['build_key']`) instead of grepping stdout — your pick; both
  are secrets.
- `verify` exits non-zero on integrity failure, so it doubles as a
  tamper gate after any post-build binary mangling (signing, updater
  patching).

## 6. FAQ

**Can I feed it a `.pck` made with Godot's "encrypted pck" option?**
No — `scan_pck` refuses encrypted directories. Protect from the project
directory, or from an unencrypted `.pck`.

**Does the runtime need the printed build key?**
No. The key is for *you* (`verify`, debugging, third-party readers). The
shipped runtime rebuilds it from shards.

**Will gdsdecomp open a `.gdpk`?**
No — magic is `"GDPK"`, not `GDPC`; the directory is encrypted; and
virtualized scripts are GVM-1, not `.gdc` token streams. It has no
codepath that touches any layer of the format.

**What about KeyDot-style key extraction on my binary?**
There is no 32-byte key array in `.data` to `lea`-scan. The attacker has
to find and reverse *your* shard scheme in *your* binary — dynamic work,
per build — which is the entire point (THREAT_MODEL.md §3).

**Virtualization made my script fail with `VirtualizeUnsupported`.**
The compiler covers a subset of GDScript (VM.md §7). Rewrite the
construct or remove the file's glob from `virtualize.scripts`; it will
still ship obfuscated.

**How big can a `.gdpk` get?**
Header is fixed at 96 B; each file costs `ceil(len/chunk_size)` GCM tags
(16 B each) plus Merkle leaf+interior nodes (~64 B per chunk). Roughly
80 B per 64 KiB chunk — ≈0.1% of stored size, usually more than offset
by compression.

**Is the obfuscation reversible?**
Identifier renaming and comment stripping are one-way. String
"encryption" is obfuscation, not secrecy — decode calls ship in the
container. Treat obfuscated output as *harder to read*, not encrypted.

**Does it work with GodotSteam / other GDExtension plugins?**
Yes — the container doesn't care what your scripts call. The plugin's
native binaries pack as `FileKind.NATIVE` like anything else and load
through `res://`. The only caveat is a plugin that itself parses `.pck`
layout (rare) — everything else goes through the pack layer.

**Does it work with multiplayer / netcode?**
Protection is purely client-side — the server never sees `.gdpk` bytes,
only game traffic. What changes is what a client-side attacker can read:
protocol logic, packet handlers, and anti-cheat rules stop being
recoverable source. Virtualize `res://net/**` if that's your worry —
and keep actual authority on the server.

**What about asset DLCs / downloadable packs?**
Build each DLC as its own `.gdpk`. `--emit-key` gives each container its
own shard header for its own loader — or share the same `BuildKey` +
salt across builds (a fixed `--seed` pipeline or a stored key) so one
runtime opens both the base game and the DLC.

**Does it conflict with Godot's own "encrypted pck" option?**
Don't stack them — the pipeline refuses an already-encrypted directory.
Pick one layer; `.gdpk` is strictly stronger for the index and the
per-file bodies.
