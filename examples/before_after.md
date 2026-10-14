# Before / after — what the obfuscation stage does to GDScript

The obfuscate stage runs on `.gd` **source** before packing (and before
virtualization, for scripts selected there). Pass order is deliberate —
`strip_comments → encrypt_strings → rename → control_flow` — so nothing
later has to look inside comments, the decoder is renamed as ordinary
code, and control flow splices text that earlier passes never re-lex.

Below is representative input/output. Identifier names, string keys,
and injected predicates vary per file and per build.

> These transforms make recovered source *harder to read*. They are not
> encryption — the decoder ships inside the container. The secrecy layer
> is the `.gdpk` container itself; see `docs/THREAT_MODEL.md`.

---

## Example — shop logic

### Before (`res://src/shop/purchase.gd`)

```gdscript
extends Node

# how much the player has spent this session — used for the
# "big spender" achievement and the bundle upsell screen
var session_spend := 0
var pending_offers: Array = []

const BUNDLE_THRESHOLD := 2500  # cents

func record_purchase(sku: String, price_cents: int) -> void:
	session_spend += price_cents
	pending_offers.erase(sku)
	if session_spend >= BUNDLE_THRESHOLD:
		_show_bundle_upsell()
	Analytics.track("purchase", {"sku": sku, "cents": price_cents})

func _show_bundle_upsell() -> void:
	print("upsell: showing whale bundle")
	var panel = preload("res://ui/bundle_panel.tscn").instantiate()
	add_child(panel)
```

### After (representative)

```gdscript
extends Node

static func __d(b: Array, k: int) -> String:
	var _b := PackedByteArray(b)
	for _i in _b.size():
		_b[_i] = _b[_i] ^ ((k + _i * 7) & 0xFF)
	return _b.get_string_from_utf8()

var _x3a := 0
var _x9f: Array = []

const BUNDLE_THRESHOLD := 2500

func _x1e(_dlf: String, _bls: int) -> void:
	if (0x2a ^ 0x15) == 0x3f:
		_x3a += _bls
	else:
		var _c0 := (59 ^ 19) * 58
	_x9f.erase(_dlf)
	if _x3a >= BUNDLE_THRESHOLD:
		_show_bundle_upsell()
	Analytics.track(__d([117, 121, 97, 121, 73, 73, 92, 83], 5), {"sku": _dlf, "cents": _bls})

func _show_bundle_upsell() -> void:
	print(__d([98, 89, 90, 94, 87, 87, ...], 5))
	var panel = preload("res://ui/bundle_panel.tscn").instantiate()
	add_child(panel)
```

## What happened, transform by transform

| Transform | In the example |
|---|---|
| **Comment strip** | All comments gone — `BUNDLE_THRESHOLD`'s intent ("cents") now exists nowhere |
| **String encryption** | `"purchase"` → `__d([115, 107, …], 5)` — each byte XORed with `(k + i*7) & 0xFF` under a per-file key `k`; one `static func __d` decoder injected after the header |
| **Identifier rename** | `session_spend→_x3a`, `pending_offers→_x9f`, `record_purchase→_x1e`, params `sku→_dlf`, `price_cents→_bls` — private definitions become `_xNN`-style names |
| **Control-flow mangle** | `session_spend += …` wrapped in `if (0x2a ^ 0x15) == 0x3f:` — an always-true arithmetic identity — with an unreachable decoy `else:` |
| **Preserved by construction** | `extends`, `preload`, `add_child`, `_show_bundle_upsell`, `Analytics.track`, `BUNDLE_THRESHOLD` untouched — see below |

## Why some names survive

The renamer is conservative *by construction* — a name is only renamed
when the file provably owns its definition:

- **Engine callbacks and anything `_`-leading** (`_show_bundle_upsell`,
  the `__d` decoder itself) — never renamed.
- **`const` / `signal` / `enum` / `class_name` / `extends` names** —
  `BUNDLE_THRESHOLD` keeps its name because `const` must stay a compile-
  time referenceable symbol; so do exported vars and `@rpc`/`@onready`
  definitions (the editor serializes them by name).
- **Attribute accesses** — `Analytics.track`: `Analytics` isn't defined
  in this file, `.track` is an attribute access. Neither is renameable.
- **Strings that name things** — a literal like `call("record_purchase")`
  *vetoes* the rename: the string's contents are compared against
  definitions before renaming, so reflective lookups keep working (and
  the string itself still gets `__d`-encoded).
- **Literals that must stay literal** — `preload("res://…")` args,
  `extends "res://…"`, `const` initializers, parameter defaults,
  match-arm heads, dict keys, `&"sn"`/`^"np"`/`$path` sigils, and
  docstrings are never touched.

## What it does NOT do

- **Cross-file references.** The protections above work *within* one
  file. A `.tscn` signal hookup or another script's `call("name")`
  against a *renamed* function still breaks — add the name to
  `obfuscate.preserve`.
- **`.tscn`/`.tres` content.** Scenes and resources are packed as-is
  (encrypted, but not rewritten) — they still reference names verbatim.
- **Semantic secrecy.** Determination beats obfuscation; the point is to
  raise read cost, not to be uncrackable. See `docs/THREAT_MODEL.md`.

## Verifying a build didn't break references

```bash
gdprotect build mygame -o game.gdpk --emit-key runtime/key_shard.h -v
# watch for:  ! obfuscate skipped res://…: <reason>

gdprotect verify game.gdpk --key <build-key-hex>
```

Then smoke-test the protected export — rename bugs fail fast at load
(missing autoload, dangling signal), not subtly at runtime.
