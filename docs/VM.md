# GVM-1 — virtual instruction set and `.gvmb` module format

GVM-1 is the register-machine ISA that selected GDScript sources are
compiled into. A `.gvmb` image replaces a `.gd`/`.gdc` file inside the
`.gdpk` container and is executed by the runtime interpreter
(GDExtension or patched template — see `docs/USAGE.md`).

This document mirrors `gdprotect/vm/isa.py`. All integers are
little-endian unless noted.

**Why it protects.** The *encoded* opcode byte is not the semantic
opcode — every build permutes the opcode space with a build-salt-keyed
shuffle and encodes each cell's immediate field through a keyed Feistel
network. Two builds of the same game share zero byte-level similarity,
and a decompiler written against one build teaches you nothing about the
next. There is no public GVM-1 decompiler; semantics exist only inside
your shipped interpreter.

---

## 1. Machine model

- **Registers:** 16 general registers `r0..r15`. `r0` is the accumulator
  by convention (call/arithmetic results land there).
- **Operand stack:** value stack for argument marshalling (`PUSH`/`POP`)
  and iterators.
- **Constant pool:** per-module table of literals (`nil`, `bool`, `i64`,
  `f64`, `str`, `bytes`) — also holds host-call names and member names
  referenced by `CALL`/`CALLM`/`GETM`/`SETM`/`GETG`/`SETG`.
- **Host-call table:** engine/builtin calls are not opcodes; `CALL`
  resolves a const-pool name against the runtime's host API at load.
  This keeps the ISA engine-version-independent.
- **Globals:** module-level store addressed by name via `GETG`/`SETG`.

## 2. Opcodes (semantic order)

The encoded byte for each opcode is a **per-build permutation** (§4) —
the numbers below are semantic IDs, *never* what appears on disk.

| ID | Mnemonic | Operands | Semantics |
|---:|---|---|---|
| 0  | `NOP`    | — | no operation |
| 1  | `LOADK`  | `rA, kx` | `rA = K[kx]` |
| 2  | `LOADI`  | `rA, imm` | `rA = imm` (i32, Feistel-encoded) |
| 3  | `MOVE`   | `rA, rB` | `rA = rB` |
| 4  | `ADD`    | `rA, rB, rC` | `rA = rB + rC` — Variant-typed: VM handles int/float/str/vec |
| 5  | `SUB`    | `rA, rB, rC` | `rA = rB - rC` |
| 6  | `MUL`    | `rA, rB, rC` | `rA = rB * rC` |
| 7  | `DIV`    | `rA, rB, rC` | `rA = rB / rC` |
| 8  | `MOD`    | `rA, rB, rC` | `rA = rB % rC` |
| 9  | `NEG`    | `rA, rB` | `rA = -rB` |
| 10 | `NOT`    | `rA, rB` | `rA = !rB` |
| 11 | `AND`    | `rA, rB, rC` | `rA = rB && rC` |
| 12 | `OR`     | `rA, rB, rC` | `rA = rB \|\| rC` |
| 13 | `CMPEQ`  | `rA, rB, rC` | `rA = rB == rC` |
| 14 | `CMPNE`  | `rA, rB, rC` | `rA = rB != rC` |
| 15 | `CMPLT`  | `rA, rB, rC` | `rA = rB < rC` |
| 16 | `CMPLE`  | `rA, rB, rC` | `rA = rB <= rC` |
| 17 | `CMPGT`  | `rA, rB, rC` | `rA = rB > rC` |
| 18 | `CMPGE`  | `rA, rB, rC` | `rA = rB >= rC` |
| 19 | `JMP`    | `J` | `pc = J` |
| 20 | `JT`     | `rA, J` | `if rA: pc = J` |
| 21 | `JF`     | `rA, J` | `if !rA: pc = J` |
| 22 | `PUSH`   | `rA` | push `rA` onto the operand stack |
| 23 | `POP`    | `rA` | `rA = pop` |
| 24 | `CALL`   | `rA, kx` | `rA = host_call[K[kx]](args popped)` |
| 25 | `CALLM`  | `rA, rB, kx` | `rA = rB.method[K[kx]](args popped)` |
| 26 | `GETG`   | `rA, kx` | `rA = globals[K[kx]]` |
| 27 | `SETG`   | `rA, kx` | `globals[K[kx]] = rA` |
| 28 | `GETM`   | `rA, rB, kx` | `rA = rB.member[K[kx]]` |
| 29 | `SETM`   | `rB, rA, kx` | `rB.member[K[kx]] = rA` |
| 30 | `NEWARR` | `rA` | `rA = []` |
| 31 | `NEWDICT`| `rA` | `rA = {}` |
| 32 | `AGET`   | `rA, rB, rC` | `rA = rB[rC]` |
| 33 | `ASET`   | `rB, rA, rC` | `rB[rC] = rA` |
| 34 | `ITER`   | `rA, rB, J` | iterate `rB` → `rA` (iterator object); jump to `J` when exhausted |
| 35 | `RET`    | `rA` | return `rA` |
| 36 | `YIELD`  | `rA` | await / coroutine suspend |
| 37 | `SELF`   | `rA` | `rA = self` |

## 3. Instruction encoding

Variable width: **1 encoded-opcode byte + operand bytes**. The operand
*kind* is chosen per instruction by the compiler:

| Kind | Meaning | Encoding |
|---|---|---|
| `R` | register index(es) | `u8` — high nibble `rA`, low nibble `rB` when two regs are packed |
| `K` | const-pool index | `u16` |
| `I` | immediate | `i32`, Feistel-encoded against the cell key (§4.2) |
| `J` | jump target | `u32` cell index XORed with the cell key (§4.3) |

Concrete layouts emitted by `encode_insn()`:

| Instruction class | Layout | Width |
|---|---|---:|
| 3-register ops — `ADD SUB MUL DIV MOD AND OR CMPEQ CMPNE CMPLT CMPLE CMPGT CMPGE AGET ASET SETM` | `op` · `u8 (rA<<4 ‖ rB)` · `u8 rC` | 3 B |
| reg+wide ops — `MOVE NOT GETM CALLM ITER` | `op` · `u8 (rA<<4 ‖ rB)` · `u16 c` | 4 B |
| `K` operand — `LOADK CALL GETG SETG` | `op` · `u8 rA` · `u16 kx` | 4 B |
| `I` operand — `LOADI` | `op` · `u8 rA` · `i32` Feistel | 6 B |
| `J` operand — `JMP JT JF` | `op` · `u8 rA` · `u32` XOR | 6 B |
| register-only — `NOP PUSH POP RET YIELD SELF NEWARR NEWDICT` | `op` · `u8 rA` | 2 B |

(The encoder's default form emits `op` + `u8 rA` for any instruction
whose operand kind is `R` and that isn't in the two multi-register
classes above — e.g. single-operand forms.)

## 4. The per-build dialect

Every `gdprotect build` generates a fresh 8-byte **build salt** (stored in
the `.gdpk` header). The salt keys the whole dialect:

### 4.1 Opcode permutation

`Dialect(salt)` seeds a PRNG with `salt ^ 0x47564D31` (`'GVM1'`) and
shuffles the list `[0..OP_COUNT)` into `encode_map`: semantic opcode `s`
is emitted as byte `encode_map[s]`; the interpreter decodes via the
inverse `decode_map`. `OP_COUNT = 38`.

### 4.2 Cell key schedule and Feistel immediates

Each *cell index* (byte offset domain position of the instruction in the
code stream) gets a position key:

```
cell_key(i):  x  = (salt + i * 0x9E3779B97F4A7C15) mod 2^64   # golden ratio
              x ^= x >> 30;  x *= 0xBF58476D1CE4E5B9          # splitmix64
              x ^= x >> 27;  return (x * 0x94D049BB133111EB) mod 2^32
```

`I` immediates pass through a 4-round keyed Feistel over 32 bits
(`_feistel`/`_unfeistel` in `isa.py`), keyed by `cell_key(cell_index)`:

```
per round r (0..3), with m = (R*0x9E37 + key + r*0x85EB) mod 2^32:
    F = (m >> 8) | ((m & 0xFF) << 24)
    (L, R) = (R, L ^ (F & 0xFFFF))
```

Decoding runs the rounds in reverse, then re-signs from bit 31
(`u - 2^32` if `u & 0x80000000`).

### 4.3 Jump targets

`J` operands are stored as `target ^ cell_key(cell_index)` — a lifted
instruction's jump field is meaningless at any other position.

### 4.4 Result

Same source → different salt → different opcode bytes, different
immediate bytes, different jump encodings. Byte-level diffing across
builds yields nothing; a static decoder must recover the salt *and*
re-implement the position-keyed transforms.

## 5. `.gvmb` module format

```
u8[4]   magic "GVMB"
u32     format version          (= 1)
u64     dialect salt            (the build salt the permutation was built from)
u32     const pool count
u32     code byte span            (decoder walks it as a byte span, not a cell count)
u32     function count
```

Then, in order:

**Constant pool** — `const pool count` entries, each `u8 tag + payload`:

| Tag | Type | Payload |
|---:|---|---|
| 0 | `nil` | — |
| 1 | `bool` | `u8` |
| 2 | `i64` | `i64` |
| 3 | `f64` | `f64` (IEEE-754 double) |
| 4 | `str` | `u32 len` + UTF-8 bytes |
| 5 | `bytes` | `u32 len` + raw bytes |

**Function table** — `function count` records:

| Field | Type | Meaning |
|---|---|---|
| `entry_cell` | `u32` | cell index of the function's first instruction |
| `arg_count`  | `u16` | arity |
| `name_kx`    | `u16` | const-pool index of the function name |

**Code** — the encoded instruction stream, exactly `code byte span`
bytes of variable-width cells (§3). Decoders walk `pos < byte span`,
consuming however many bytes each opcode's layout needs — cell counts
aren't meaningful at decode time because cells are packed, not
fixed-width.

## 6. In the container

- Virtualized files are stored at `res://…​.gvmb` (the `.gd` suffix is
  replaced), `kind = VM_BYTECODE (2)`, `flags |= FILE_FLAG_VIRTUALIZED
  (0x0001)`, and the header sets `FLAG_VM (0x0008)` when any exist.
- They are chunked/AEAD'd like everything else (FORMAT.md §6).

## 7. Coverage limits — the compiler's GDScript subset

The GVM-1 compiler (`gdprotect/vm/compiler.py`) covers a **practical
subset** of GDScript 2.x. Constructs outside the subset raise
`VirtualizeUnsupported` (naming the construct and source location) and
fail the build for that script — either rewrite the construct or exclude
the file from `virtualize.scripts` and let it ship as obfuscated `.gd`
source. The `virtualize.hardening` config knob (0–3) controls the density
of opaque predicates injected into generated bytecode.

### Supported

- `func` definitions, parameters, `return`, local `var` / `const`
- arithmetic / comparison / boolean operators → `ADD`…`OR`, `CMP*`
- unary `-` / `!` → `NEG` / `NOT`
- `if` / `elif` / `else`, `while`, `for` over iterables → `JT`/`JF`/`JMP`/`ITER`
- `break`, `continue` → `JMP` to loop pads
- literals: `nil`, bool, int, float, string, bytes → const pool
- `[]` / `{}` construction and indexing → `NEWARR` / `NEWDICT` / `AGET` / `ASET`
- function calls and method calls → `CALL` / `CALLM` via the host-call table
- global / member reads and writes → `GETG` / `SETG` / `GETM` / `SETM`
- `self` → `SELF`; `await` → `YIELD`; `pass` → `NOP`

### Raises `VirtualizeUnsupported`

- `match` statements (pattern matching has no opcode)
- lambdas / closures / nested `func`
- inner `class` declarations; `super(...)` calls and inherited dispatch
- `signal` declarations and `emit_signal` (use a host call instead)
- dynamic `preload` / `load` paths (a *static* `preload` may lower to a
  const when the compiler resolves it)
- `is` / `as` checks and casts that can't lower to a host call
- `set`/`get` property accessors; `static` members touching instance state
- tuple unpacking (`x, y = …`), spread/variadic call forms
- `$Node` shorthand — write `get_node("…")` explicitly
- `enum` beyond int-valued members; `yield` (Godot 3 spelling — use `await`)

**Runtime requirement.** A stock export template cannot load `.gvmb`.
You must ship the interpreter — see `docs/USAGE.md` §Runtime
integration. Do not enable `virtualize` for builds that have no runtime.
