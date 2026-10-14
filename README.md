# godot-protector

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

`gdprotect` packs, virtualizes, and protects Godot Engine games against decompilation — turning an exported project into an encrypted `.gdpk` container whose script payloads run on a per-build VM dialect instead of stock GDScript bytecode.

## Why this exists

A stock Godot export is not protected in any meaningful sense. The `.pck` container is an unencrypted archive with a plaintext directory, and in Godot 4.x your scripts ship as `.gdc` **token streams** (`script_export_mode` defaults to `2`, "compressed binary tokens") — a fully documented, deterministic compilation target that preserves every identifier in your source. The container and bytecode formats are defined in the open in [godotengine/godot](https://github.com/godotengine/godot) itself. That means decompilation is *near-lossless*, not approximate. Off-the-shelf tooling already automates the whole pipeline:

- [gdsdecomp](https://github.com/bruvzg/gdsdecomp) and the [GDRETools](https://github.com/nikita38838/GDRETools) GUI built on it — full project recovery from a `.pck`/`.exe`/`.apk`: unpacks, decompiles `.gdc` back to readable GDScript nearly losslessly, rebuilds scenes and the project file, and supports custom bytecode maps plus decryptor plugins for non-stock builds.
- [GodotPCKExplorer](https://github.com/DmitriySalnikov/GodotPCKExplorer) — GUI explorer for `.pck` files whose **Bruteforcer** module recovers stock encryption keys.
- [gdke](https://github.com/char-ptr/gdke) and [KeyDot](https://github.com/Titoot/KeyDot) — static key extractors. KeyDot pulls the embedded 32-byte export key out of a shipping Windows `.exe` in **~50 ms**, no debugger required: it anchors on engine error strings such as `"Can't open encrypted pack directory"`, follows a single `lea [rip+disp]`, and dereferences a pointer into `.data` where the key sits unprotected.
- [decompiler.com/godot](https://www.decompiler.com/godot) — point-and-click `.gdc` → GDScript in a browser.

And the encryption Godot *does* offer is cryptographically soft: the encrypted directory is AES-256-**CFB** with nothing but an MD5 for integrity — no MAC, so tampering isn't even detected — and the whole scheme reduces to that one static key in `.data`. Once the key is out (milliseconds, see above), the pack is plaintext. If your game's logic, monetization checks, or anti-cheat rules ship as recoverable GDScript, they are effectively public. `gdprotect` is an attempt to raise the bar past "download a tool, click unpack": no static key anywhere, AEAD on every blob, and script payloads that aren't GDScript bytecode at all.

## Quick start

```bash
pip install -e .

# full pipeline: obfuscate + virtualize + pack + emit runtime key shard
gdprotect build mygame -o game.gdpk \
    --emit-key runtime/key_shard.h \
    --virtualize 'res://src/core/**'

# check the result
gdprotect verify game.gdpk --key <build-key-hex>
```

`--emit-key` writes a C++ header of XOR key shards for the runtime side (see `docs/USAGE.md` for how it integrates with your export template / GDExtension). The build key itself is printed once — keep it out of version control.

## Pipeline

```
 project dir / .pck
        │
        ▼
      scan ──────────────► inventory + classify files (kind, size, flags)
        │
        ▼
   obfuscate ────────────► .gd source: identifier rename, string encryption,
        │                  control-flow mangling, comment strip
        ▼
  virtualize ────────────► selected .gd scripts → .gvmb bytecode for a
        │                  per-build GVM-1 dialect
        ▼
      pack ──────────────► compress, chunked AES-256-GCM encrypt, emit .gdpk
        │
        ▼
   key shard ────────────► split build key into N XOR shards → key_shard.h
                           for the runtime loader
```

## Features

| Feature | What it does |
|---|---|
| **Encrypted file table** | The `.gdpk` index is AEAD-encrypted as one blob under a table key — no plaintext directory to walk, unlike `.pck`. |
| **Chunked AEAD bodies** | Every file is split into chunks, each independently nonced and authenticated under AES-256-GCM, with file index + chunk index + build salt bound into the AAD. A lifted or transplanted chunk fails authentication. |
| **Per-build VM dialects** | GVM-1 opcode space is permuted by the build salt and immediates are Feistel-encoded per cell position. Two builds of the same game share zero byte-level similarity. |
| **Identifier + string obfuscation** | GDScript identifiers are renamed, string literals are lifted into decode calls, control flow is mangled, comments stripped. |
| **Merkle integrity tree** | BLAKE2b-256 leaf per ciphertext chunk reduced to a root mirrored inside the encrypted table — tampering with the tree or a chunk is detected at verify/read time. |
| **XOR key shards** | The 256-bit build key is never stored whole; `--emit-key` splits it into N shards the runtime XORs back together across separate translation units. |

## Limitations

- **Nothing client-side stops a determined reverser.** This raises the cost of ripping your game; it does not make it impossible. See `docs/THREAT_MODEL.md`.
- **Virtualized scripts need the runtime.** A `.gvmb` file is not loadable by a stock Godot export template — you must ship the interpreter (GDExtension or patched template) described in `docs/USAGE.md`.
- **Compilation coverage is a subset.** The GVM-1 compiler covers a practical subset of GDScript; anything outside it raises `VirtualizeUnsupported` and you either rewrite the script or leave it as obfuscated source (see `docs/VM.md`).
- **Obfuscation is not type-aware across scenes.** If a `.tscn`/`.tres` references a renamed identifier (exported vars, signal names, autoloads), add the name to `obfuscate.preserve`.
- **Already-encrypted inputs are refused.** A `.pck` with an encrypted directory can't be repacked — protect from the project directory instead.
- **The C runtime assumes the default chunk size.** `chunk_size` is stored in the encrypted table and the Python `GdpkReader` honors it, but the runtime reader decodes a fixed 64 KiB — keep `pack.chunk_size` at the default unless you also patch the runtime.

## Threat model, in one paragraph

`gdprotect` stops the casual path — gdsdecomp full-recovery runs, `.pck` unpackers, `strings` greppers — and specifically denies the *static key-extraction* path that kills stock encryption: there is no 32-byte blob in `.data` for a KeyDot-style `lea [rip+disp]` scan to find, because the container holds no key at all and the runtime rebuilds it from scattered XOR shards. For the serious path the bar is higher too: a reverser needs a debugger, must reverse the shard scheme to recover the build key, and then faces a per-build bytecode dialect with no public decompiler. It does **not** stop someone with time and skill, because no purely client-side scheme can. If a piece of logic is genuinely critical, keep it on a server. The full write-up is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Prior art and how this compares

- [GDMaim](https://github.com/cherriesandmochi/gdmaim) — the reference GDScript obfuscator: an editor addon that rewrites identifiers, strings, and constants at export time. It operates on the *source layer* only — output is still stock `.gdc` that gdsdecomp's decompiler and KeyDot's key extractor handle as usual. `gdprotect` pairs comparable source obfuscation with container AEAD and VM virtualization, so decompilation stops at bytecode nobody recognizes.
- [Godot-Secure](https://github.com/KnifeXRage/Godot-Secure) — patches the engine source for per-build Camellia-256/AES-256 encryption, randomized PCK magic, and a token-split key embedded in the binary. Closest in spirit to our shard scheme; the difference is we keep the entire format outside the engine (`.gdpk` + runtime loader), so hardening the container doesn't require rebuilding Godot.
- [BeatAC](https://github.com/kimbunner/BeatAC) — a GDScript-level anti-cheat reference; complementary rather than competing (script-layer heuristics vs. binary-layer protection).
- Upstream [godotengine/godot#87696](https://github.com/godotengine/godot/pull/87696) — PCK signing proposal (directory signed, per-file SHA-256 hashes, template refuses unsigned packs). If it lands it authenticates the *stock* container; `gdprotect` additionally encrypts the index, binds chunk position into AAD, and virtualizes script payloads, so the two compose rather than overlap.

## Documentation

- [`docs/FORMAT.md`](docs/FORMAT.md) — the `.gdpk` container format, specified for third-party implementers
- [`docs/VM.md`](docs/VM.md) — the GVM-1 virtual instruction set and `.gvmb` module layout
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — what this does and does not protect against
- [`docs/USAGE.md`](docs/USAGE.md) — workflows, config reference, CLI reference, CI, FAQ
- [`runtime/README.md`](runtime/README.md) — the loader side: engine-module `PackSource` vs. GDExtension paths, shard contract
- [`examples/protect.toml`](examples/protect.toml) — a fully commented config
- [`examples/before_after.md`](examples/before_after.md) — what obfuscation does to real GDScript

## Roadmap

- **v0.1** — `.gdpk` encrypted container (AEAD chunks + encrypted index + Merkle tree), GDScript source obfuscation, GVM-1 ISA/dialect groundwork, XOR key shards.
- **v0.2** *(current)* — direct `.exe` key patching: `gdprotect patch embed` appends an authenticated EOF overlay carrying the build's XOR shards, so a stock export binary loads the key without recompiling; the runtime probes the overlay when `GDPK_HAS_KEY_SHARD` isn't compiled in.
- **v0.3** — stringpool virtualization: `[virtualize] stringpool = true` hoists string literals out of non-virtualized scripts into per-module `.gvms` blobs (AES-256-GCM under a domain-separated key); sources keep only `__s(idx)` calls resolved by `Gdpk.str_at` at runtime.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security issues: open a private GitHub security advisory — please do not open public issues for vulnerabilities.

## License

MIT — see [`LICENSE`](LICENSE). Copyright BetterMint contributors 2026.
