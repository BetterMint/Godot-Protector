# Contributing

Thanks for helping make `gdprotect` better. A few rules keep the codebase
consistent and the docs honest.

## Setup

```bash
pip install -e .[dev]
pytest -q
```

## Code style

- **Formatting:** black-ish — 88-col lines, double quotes, trailing commas.
  Run `black gdprotect/` before pushing if you have it; the CI doesn't
  enforce it, but don't reformat files you aren't touching.
- **Type hints:** all public functions and dataclass fields are annotated.
  Keep it that way — `from __future__ import annotations` is already at the
  top of every module.
- **Errors:** raise `ProtectionError` for user-facing failures (bad input,
  unsupported construct, wrong key) — the CLI maps it to exit code 2 with a
  clean message. Reserve `ValueError`/`TypeError` for programmer errors.

## Tests

Every PR needs `pytest` to pass. If you add a transform (obfuscation pass,
VM opcode, codec), add a round-trip test — pack it, verify it, read it
back. `tests/fixture/` holds the small Godot project used by CI; keep it
tiny.

## Format & spec changes

The docs are normative — if you change the container, VM, or config format,
update the matching spec in the same PR:

| You change… | You must also update… |
|---|---|
| `gdprotect/pck/container.py` | `docs/FORMAT.md` (offsets, flags, table layout, chunk AAD, tree serialization) |
| `gdprotect/vm/isa.py` | `docs/VM.md` (opcode list, operand kinds, dialect encoding, `.gvmb` layout) |
| `gdprotect/config.py` | `docs/USAGE.md` §3 + `examples/protect.toml` |
| `gdprotect/cli.py` | `docs/USAGE.md` §2 + `README.md` quick-start |
| `runtime/shared/gdpk_format.h` | `docs/FORMAT.md` + `gdprotect/pck/container.py` (wire-format parity — see `runtime/README.md`) |
| `gdprotect/pipeline.py` | `README.md` pipeline diagram + `docs/USAGE.md` workflows |

A spec change without a doc update will be sent back — a third-party
implementer reads only the docs.

## Security issues

Do **not** open public issues for vulnerabilities — a flaw in a protection
tool is itself sensitive. Use a private GitHub security advisory. For
everything else (bugs, features, docs), open a normal issue or PR.

## License

By contributing you agree your changes are licensed under the MIT license
(see `LICENSE`).
