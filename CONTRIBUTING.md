# Contributing

Glad you're here. This file is just the house rules — what's in them
keeps the codebase consistent and the docs honest.

## Setup

```bash
pip install -e .[dev]
pytest -q
```

## Code style

- Formatting follows black loosely — 88 columns, double quotes, trailing
  commas. If black is installed, run `black gdprotect/` before pushing;
  CI doesn't enforce it. Don't reformat files you aren't already editing
  though, it makes reviews miserable.
- Type hints go on everything public: functions, dataclass fields. Every
  module already has `from __future__ import annotations` up top, so
  there's nothing extra to import.
- `ProtectionError` is for user-facing failures (bad input, unsupported
  construct, wrong key) — the CLI maps it to exit code 2 with a clean
  message. `ValueError`/`TypeError` stay reserved for actual programmer
  bugs.

## Tests

PRs need `pytest` green. Adding a transform — an obfuscation pass, a VM
opcode, a codec? A round-trip test goes in with it: pack a thing, verify
it, read it back. The small Godot project in `tests/fixture/` is what CI
runs against; keep it tiny.

## Format & spec changes

The docs are the spec. If you change the container, VM, or config format,
the matching doc update lands in the same PR:

| You change… | You must also update… |
|---|---|
| `gdprotect/pck/container.py` | `docs/FORMAT.md` (offsets, flags, table layout, chunk AAD, tree serialization) |
| `gdprotect/vm/isa.py` | `docs/VM.md` (opcode list, operand kinds, dialect encoding, `.gvmb` layout) |
| `gdprotect/config.py` | `docs/USAGE.md` §3 + `examples/protect.toml` |
| `gdprotect/cli.py` | `docs/USAGE.md` §2 + `README.md` quick-start |
| `runtime/shared/gdpk_format.h` | `docs/FORMAT.md` + `gdprotect/pck/container.py` (wire-format parity — see `runtime/README.md`) |
| `gdprotect/pipeline.py` | `README.md` pipeline diagram + `docs/USAGE.md` workflows |

A spec change without the doc update gets sent back — third-party
implementers only ever read the docs.

## Security issues

Don't open public issues for vulnerabilities. A flaw in a protection tool
is sensitive by itself — use a private GitHub security advisory. Bugs,
features, docs: a normal issue or PR is fine.

## License

Send a PR and you're agreeing it ships under MIT like the rest of it
(`LICENSE` has the full text).
