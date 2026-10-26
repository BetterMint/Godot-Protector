# Godot Protector

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

`gdprotect` takes your GDScript, turns it into godot-cpp C++, builds that into a real GDExtension — then deletes the `.gd` files from the build. By the time it finishes there's no script source left in the export at all. Nothing to decompile, nothing to lift. Whatever remains (scenes, assets, the few scripts you keep interpreted) goes into an encrypted `.gdpk` container. Chunked AES-256-GCM, an encrypted index, a per-build bytecode dialect for virtualized scripts, and a build key split into XOR shards rather than sitting in the binary as one blob.

## Why this exists

Godot does not protect your game out of the box. A `.pck` is a plain archive with a plaintext directory, and Godot 4 exports your scripts as `.gdc` token streams, a documented format that keeps every identifier you wrote. Pulling the source out of a shipping Godot game is a solved problem:

- [gdsdecomp](https://github.com/bruvzg/gdsdecomp) + [GDRETools](https://github.com/nikita38838/GDRETools): point at a `.pck`/`.exe`/`.apk`, get a working project back. GDScript, scenes, the project file, nearly lossless.
- [GodotPCKExplorer](https://github.com/DmitriySalnikov/GodotPCKExplorer): pck explorer; its Bruteforcer module recovers stock encryption keys.
- [gdke](https://github.com/char-ptr/gdke) + [KeyDot](https://github.com/Titoot/KeyDot): pull the embedded 32-byte export key straight out of the shipping exe. KeyDot does it in ~50ms with no debugger, anchoring on the `"Can't open encrypted pack directory"` error string and following a single `lea` into `.data`.
- [decompiler.com/godot](https://www.decompiler.com/godot): paste a `.gdc` into a browser tab, get GDScript back.

Engine-side encryption doesn't rescue it. The encrypted directory is AES-256-CFB with only an MD5 for integrity, so tampering isn't even detected, and everything reduces to the same static key in `.data`. If your game logic ships as recoverable GDScript it might as well be in a public repo.

## Why the other tools fall short

Everything built so far has the same flaw: your code still ships. Maybe as tokens, maybe encrypted tokens, maybe renamed identifiers, maybe a custom bytecode — but the bytes are in the build and the CPU can read them. So can anyone else.

- Source obfuscators (GDMaim etc.) rename identifiers and mangle strings, then emit the same stock `.gdc`. The decompilers don't care. You get uglier source back, but you get source back.
- Encrypted `.pck` puts a lock on the index and the key for that lock inside the exe. Extracting it is automated now.
- Custom bytecode / VM layers, our own `.gvmb` included, do better — there's no public decompiler — but the interpreter still has to decode the payload to run it. A reverser tracing the VM recovers the logic. Hard target, not a lost cause.
- Engine patches like Godot-Secure move the key around inside the engine binary. It's still inside the engine binary.

None of this is theoretical. The tools linked above all exist and work today; GDRETools will hand you a project back from a shipping Godot game in minutes.

`gdprotect` is the only one that takes the code out of the build instead of rearranging it. A transpiled script becomes machine code through godot-cpp, the `.gd` file is deleted, and the pack keeps a `.dll`/`.so` plus a manifest. Getting anything back means disassembling a binary in Ghidra or IDA: no decompiler output, no `.gd`, nothing GDScript-shaped to find. That's the same position a game written in C++ is in. For client-side software it's as good as it gets, because the thing being stolen isn't in the box.

## Quick start

```bash
pip install -e .

# native-compile every script, then obfuscate + virtualize + pack the rest
gdprotect build mygame -o game.gdpk \
    --emit-key runtime/key_shard.h \
    --native --native-fallback \
    --virtualize 'res://src/core/**'

gdprotect verify game.gdpk --key <build-key-hex>
```

`--native` transpiles every `.gd` to C++ (needs godot-cpp + scons — see `docs/USAGE.md` §1.6) and removes the sources from the pack. `--native-fallback` keeps untranspilable scripts on the obfuscate/virtualize path instead of aborting. `--emit-key` writes the XOR key shards as a C++ header for the runtime. The build key prints once — keep it out of version control.

## Pipeline

```
 project dir / .pck
        │
        ▼
      scan ──────────────► inventory + classify files (kind, size, flags)
        │
        ▼
     native ─────────────► .gd → godot-cpp C++ → scons → GDExtension .dll;
        │                  the .gd sources are DELETED from the pack and
        │                  scenes/dependents are rewritten to native classes
        ▼
   obfuscate ────────────► remaining .gd source: identifier rename, string
        │                  encryption, control-flow mangling, comment strip
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

## What it does

- **GDScript → C++ transpiler.** The main event. Marked scripts compile to godot-cpp source, build into a real GDExtension, and leave the pack. Getting code back means reversing a binary. Coverage: `await`/`yield` coroutines including lambdas that await, `super()`, `set`/`get` blocks and Godot 3 `setget`, `match`, `func` lambdas with captures, enums, `is`/`as` against script classes, inner classes, `static`, `assert`, `@export`/`@onready` and friends, `class_name` and `preload` cross-refs, autoloads. We ran it on a shipped commercial game and all **120 scripts made it through.**
- **Auto native pipeline.** `native.auto` transpiles everything and `exclude` globs subtract. `extends`-ed base scripts get pulled in transitively, autoloads resolve from `project.godot`, `@tool` scripts stay interpreted. If a script can't transpile, `on_error = "fallback"` cascades it and its dependents back to obfuscate/virtualize instead of killing the build.
- **Encrypted file table.** The `.gdpk` index encrypts as a single AEAD blob — no plaintext directory to walk like `.pck` has.
- **Chunked AEAD bodies.** Files split into chunks, each independently nonced and authenticated under AES-256-GCM, with file index + chunk index + build salt in the AAD. A lifted or transplanted chunk fails verification.
- **Per-build VM dialects.** The GVM-1 opcode space is permuted by the build salt and immediates are Feistel-encoded per cell position. Two builds of the same game share zero byte-level similarity.
- **Obfuscation.** Identifier rename, string literals lifted into decode calls, control-flow mangling, comment strip for the scripts that stay interpreted.
- **Merkle integrity tree.** BLAKE2b-256 leaf per ciphertext chunk reduced to a root mirrored inside the encrypted table — tamper with a chunk or the tree and it gets caught.
- **XOR key shards.** The 256-bit build key never exists whole; `--emit-key` splits it into N shards the runtime XORs back together across separate translation units.

## Limitations

- **The DLL is still a binary.** There's no source form to recover because there is no source form, but machine code can always be disassembled. Every C++ game ships with the same exposure — it's the ceiling, not a weakness of this tool specifically.
- **Native builds need godot-cpp + scons + a C++ toolchain.** Without one the emit stage still produces a complete buildable project (`BUILD.md` inside explains the scons invocation); `require_build = false` packs without the dll for inspection.
- **Virtualized scripts need the runtime.** A `.gvmb` file won't load in a stock export template — you ship the interpreter (GDExtension or patched template) described in `docs/USAGE.md`.
- **GVM-1 compiles a subset of GDScript.** Anything outside it raises `VirtualizeUnsupported` — rewrite the script or leave it as obfuscated source (`docs/VM.md` has the grammar).
- **Obfuscation isn't type-aware across scenes.** If a `.tscn`/`.tres` references a renamed identifier (exported vars, signal names, autoloads), add it to `obfuscate.preserve`.
- **Already-encrypted inputs are refused.** A `.pck` with an encrypted directory can't be repacked — protect from the project directory.
- **The C runtime assumes the default chunk size.** `chunk_size` lives in the encrypted table and the Python `GdpkReader` honors it, but the runtime reader decodes a fixed 64 KiB. Leave `pack.chunk_size` at default unless you're patching the runtime too.

## Threat model, in one paragraph

Two tiers. Native-compiled scripts have no source to recover, which is the strongest thing any client-side scheme can say, what's left is a binary that can be disassembled like every C++ program ever shipped. For the interpreted tier: it kills the casual path (`strings`, `.pck` unpackers, gdsdecomp full-recovery) and, more importantly, the static key-extraction path that sinks stock encryption — there's no 32-byte blob in `.data` for a KeyDot-style `lea` scan to grab, because the container holds no key and the runtime rebuilds it from scattered XOR shards. Against a serious reverser on interpreted code the bar is high but not infinite: they need a debugger, need to reverse the shard scheme for the build key, and then still face a per-build bytecode dialect nobody's written a decompiler for. Anything you can't afford to lose should be native-compiled, and anything you can't afford to lose *period* belongs on a server. Full write-up in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Prior art

One question separates this from everything else: does your code still ship? Every tool below leaves a recoverable representation in the build. The native stage removes it.

- [GDMaim](https://github.com/cherriesandmochi/gdmaim) — the reference GDScript obfuscator; an editor addon that rewrites identifiers, strings and constants at export time. Source-layer only — the output is stock `.gdc` that the same decompilers handle as usual. `gdprotect` runs comparable obfuscation underneath container AEAD, VM virtualization and the native stage.
- [Godot-Secure](https://github.com/KnifeXRage/Godot-Secure) — patches the engine for per-build Camellia-256/AES-256 encryption, randomized PCK magic, and a token-split key embedded in the binary. Closest in spirit to our shard scheme; the difference is we keep the format outside the engine, so hardening the container doesn't mean rebuilding Godot.
- [BeatAC](https://github.com/kimbunner/BeatAC) — GDScript-level anti-cheat reference. Complementary, not competing — script-layer heuristics vs binary-layer protection.
- [godotengine/godot#87696](https://github.com/godotengine/godot/pull/87696) — PCK signing proposal (signed directory, per-file SHA-256, templates refuse unsigned packs). If it lands it authenticates the stock container; this encrypts the index, binds chunk position into AAD and can remove scripts entirely, so they compose rather than overlap.

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
- **v0.2** — direct `.exe` key patching: `gdprotect patch embed` appends an authenticated EOF overlay carrying the build's XOR shards, so a stock export binary loads the key without recompiling; the runtime probes the overlay when `GDPK_HAS_KEY_SHARD` isn't compiled in.
- **v0.3** — stringpool virtualization: `[virtualize] stringpool = true` hoists string literals out of non-virtualized scripts into per-module `.gvms` blobs (AES-256-GCM under a domain-separated key); sources keep only `__s(idx)` calls resolved by `Gdpk.str_at` at runtime.
- **v0.4** *(current)* — native source destruction: GDScript → godot-cpp C++ → GDExtension, with coroutine state machines for `await` (including awaiting lambdas), the full property/annotation/static/inner-class surface, transitive base pull-in, autoload resolution from `project.godot`, `auto`/`exclude`/`on_error` pipeline modes, and `@tool` skip. 120/120 scripts on a real shipped game.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security issues: open a private GitHub security advisory — please do not open public issues for vulnerabilities.

## License

MIT — see [`LICENSE`](LICENSE). Copyright BetterMint contributors 2026.
