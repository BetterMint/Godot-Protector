# Threat model

`godot-protector` is a client-side obfuscation and protection tool. Before
you rely on it, read this file — it is deliberately honest about where the
line sits.

> **Protection is economics.** No client-side scheme makes reverse
> engineering impossible; it can only make it more expensive than the value
> of what's inside. Our job is to push the cost of an attack well above the
> cost of just… buying the game — or above the attacker's patience. The
> question is never "can this be cracked" but "who can crack it, how long
> does it take them, and what do they get when they're done."

## 1. Assets

What you're typically protecting in a Godot game:

- **Game logic / proprietary mechanics** — the thing that makes your game
  yours, recoverable from `.gdc` bytecode in a stock build.
- **Monetization / license checks** — DLC unlock logic, key validation.
- **Anti-cheat rules** — client-side heuristics you don't want readable.
- **Assets** — scenes, resources, art, configs.

## 2. How a stock export actually falls

Two facts define the baseline you're up against:

1. **`.gdc` is a token stream, not a real compilation.** With
   `script_export_mode` at its default (`2`, "compressed binary
   tokens"), a Godot 4.x export ships each script as a serialized token
   stream — every identifier, function name, and string literal
   survives. Decompilation is *near-lossless*: attackers get back
   essentially your source minus comments.
2. **Stock "encrypted pck" is soft.** The 32-byte export key is one
   contiguous array in the template's `.data`, loaded by a single
   `lea [rip+disp]` inside the function that error strings like
   `"Can't open encrypted pack directory"` point straight at. The
   encrypted directory itself is AES-256-**CFB** guarded only by an MD5
   — no MAC, so tampering isn't even detected.

None of this is hypothetical — the whole kill chain is off the shelf:

| Tool | What it does to a stock export |
|---|---|
| [GDRETools / gdsdecomp](https://github.com/GDRETools/gdsdecomp) | Full project recovery from `.pck`/`.exe`/`.apk`: unpacks, batch-decompiles `.gdc` to readable GDScript, rebuilds scenes and `project.godot`. Ships custom bytecode maps + decryptor plugins for non-stock builds. |
| [GodotPCKExplorer](https://github.com/DmitriySalnikov/GodotPCKExplorer) | `.pck` browsing/extraction with a **Bruteforcer** module for stock encryption keys. |
| [KeyDot](https://github.com/Titoot/KeyDot) | Static key extractor: `lea [rip+disp]` scan anchored on the error string above → 32-byte key out of a shipping `.exe` (or `.wasm`) in **~50 ms**. No debugger, no memory dump. |
| [gdke](https://github.com/char-ptr/gdke) · [godot-key-extract](https://github.com/char-ptr/godot-key-extract) | Same class: static signature search, or dynamic extraction via DLL injection. |
| [decompiler.com/godot](https://www.decompiler.com/godot) | Zero-install `.gdc` → GDScript in a browser tab. |

Once the key is out — milliseconds — every file in the pack is
plaintext. That is the bar `gdprotect` was designed to clear: nothing in
the container to walk, no static key in the binary, and script payloads
that aren't GDScript bytecode at all.

## 3. What this stops

| Attacker / attack | Stock export | With `gdprotect` |
|---|---|---|
| Casual GDRETools / gdsdecomp user | `.pck` → `.gd` source in minutes | No plaintext directory; `.gvmb` payloads are not GDScript bytecode at all |
| `.pck` unpackers / `pckdump`-style tools | Works out of the box | Fails — there is no `.pck` to unpack; the `.gdpk` index is AEAD-encrypted |
| **Static key extractors** (KeyDot, gdke, Bruteforcer) | `lea`-scan `.data` → done in ~50 ms | There is no key array to find — the container stores no key; the runtime rebuilds it from scattered XOR shards |
| `strings` / grepping for secrets, URLs, messages | Plaintext everywhere | String literals lifted into decode calls; file table encrypted |
| Script kiddies / mod-menu builders | Easy — hooks and scripts are documented | Needs a debugger and reversing skill; per-build dialect defeats any public lifter |
| Copy-paste cheats from a forum | Trivial — bytecode is stable across builds | Each release is a fresh dialect + fresh key; yesterday's tools don't carry over |

## 4. What this raises the cost of

| Attack | New cost |
|---|---|
| **Bytecode lifting** | No public GVM-1 decompiler exists; the attacker must write a lifter *per dialect* — and the opcode space is reshuffled per build, so the lifter doesn't transfer. |
| **Key extraction** | The 32-byte build key is never stored whole — the KeyDot-style `lea`-scan finds nothing because no array exists in one place. The attacker must find N XOR shards scattered across translation units, reverse the shard scheme, and XOR them back — under a debugger, not by scanning `.rodata`. |
| **Tampering / modding** | Chunked AEAD + Merkle tree + per-file digests mean flipped bits and swapped chunks fail authentication. Repacking a modified file requires the build key. |
| **Static analysis of immediates/jumps** | Feistel-encoded immediates and position-masked jump targets mean the encoded stream can't be read without recomputing per-cell keys. |

## 5. What this does NOT stop

- **A determined reverser with time.** Someone with a debugger, patience,
  and reversing skill will eventually recover the key and the dialect.
  Nothing that runs entirely on the user's machine can prevent this — not
  ours, not Denuvo's, not anyone's.
- **Runtime memory dumping.** Once the VM interprets a script, its behavior
  is observable. Virtualization makes the *artifact* hard to lift; it cannot
  hide what the code *does* at runtime.
- **Server-side-answerable secrets.** If a check can be answered by the
  client, it can be forged by the client. Keep anything critical
  (entitlements, competitive rules, economy writes) **on a server** and use
  the client only to ask.
- **Shared-responsibility failures.** If you commit the build key, check in
  `key_shard.h`, or reuse a seed, you've handed back every byte of the
  protection. See §6.
- **Encrypted-input repacking.** If the input `.pck` already has an
  encrypted directory, the tool refuses — protect from the project tree.
- **OS/API-level extraction.** A compromised OS, a DMA reader, or a
  debugger that sees the runtime decrypting files can recover plaintext one
  file at a time — the container raises the bar; it doesn't put plaintext
  behind an unobservable boundary.

## 6. OPSEC — how you keep the protection real

These are cheap to follow and expensive to get wrong:

- **Never commit the build key.** `gdprotect build` prints it once — and
  every build mints a fresh one. Capture it in a password manager or
  pull it from the build log/`--report` when you need to `verify` — not
  in git, not in a Discord message, not in a build log that gets
  archived.
- **`--emit-key` only writes into the runtime tree.** Point it at the C++
  source directory of your export template / GDExtension — never at a
  directory that ships with the game or gets committed to a public repo.
  `key_shard.h` is in `.gitignore` for a reason.
- **Rotate the build salt per release.** A fresh `BuildKey` per build (the
  default; do **not** pass `--seed` outside tests) gives every release a new
  salt → new dialect → new key → new nonce bases. Never reuse a salt across
  releases.
- **Shard count ≥ default.** 4 shards in separate translation units is the
  floor; more is cheap and buys more reversing time.
- **Keep `--virtualize` scoped to what matters.** Every virtualized script
  is bytecode a reverser has to lift; don't virtualize `res://**` just
  because you can — virtualize the logic you actually care about.
- **Treat the seed like a key.** `--seed` is for reproducible test builds.
  A release built with a committed seed is a release with a committed salt.

## 7. Summary

| Layer | Defeats | Doesn't defeat |
|---|---|---|
| Encrypted `.gdpk` container | pck unpackers, `strings` greppers | a key extractor with a debugger |
| Chunked AEAD + Merkle | tampering, transplant, modification | an attacker who has already recovered the key |
| Per-build GVM-1 dialect | public lifters, cross-build tooling | a lifter written for *this* build |
| XOR key shards | `.data`/`.rodata` scanning, KeyDot-style `lea` key dumps | someone who traces `rebuild_key()` at runtime |
| Obfuscation | casual source reading, identifier mining | patient deobfuscation |

The stack is meant to be *layered* — each layer filters out a wider class of
attacker than the one below it. Combined with the economics framing above,
the realistic goal is: make yourself a harder target than the next game of
comparable value.
