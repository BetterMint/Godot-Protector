
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import patcher
from .config import Config
from .pipeline import (emit_key_header, run_build, scan_pck, scan_project,
                       verify_container, write_report)
from .crypto.keys import BuildKey
from .util import ProtectionError

def _cfg(args) -> Config:
    cfg = Config.load(args.config) if args.config else Config()
    if getattr(args, "input", None):
        cfg.pack.input = args.input
    if getattr(args, "output", None):
        cfg.pack.output = args.output
    if getattr(args, "seed", None) is not None:
        cfg.seed = args.seed
    if getattr(args, "no_obfuscate", False):
        cfg.obfuscate.enabled = False
    if getattr(args, "no_compress", False):
        cfg.pack.compress = False
    if getattr(args, "virtualize", None):
        cfg.virtualize.enabled = True
        cfg.virtualize.scripts = args.virtualize
    return cfg

def cmd_scan(args) -> int:
    p = Path(args.input)
    recs = scan_project(p) if p.is_dir() else scan_pck(p)
    by_kind: dict[str, int] = {}
    for r in recs:
        by_kind[r.kind.name] = by_kind.get(r.kind.name, 0) + 1
    print(f"{len(recs)} files  ·  " +
          ", ".join(f"{k.lower()}={v}" for k, v in sorted(by_kind.items())))
    if args.verbose:
        for r in recs:
            print(f"  {r.kind.name:<16} {r.size:>10}  {r.res_path}")
    return 0

def cmd_build(args) -> int:
    cfg = _cfg(args)
    stats = run_build(cfg, emit_key=args.emit_key, verbose=args.verbose)
    print(f"packed {stats['files']} files "
          f"({stats['bytes_in']} -> {stats['bytes_out']} bytes, "
          f"{stats['chunks']} chunks)")
    print(f"  virtualized scripts: {stats['virtualized']}")
    if args.emit_key:
        print(f"  key shard header: {stats['key_shard']}")
    print(f"  build key (keep secret): {stats['build_key']}")
    if getattr(args, "patch", None):
        salt = int.from_bytes(Path(cfg.pack.output).read_bytes()[8:16], "big")
        res = patcher.embed_key(args.patch,
                                bytes.fromhex(stats["build_key"]), salt)
        print(f"  patched {args.patch}: key overlay @+0x{res.offset:x} "
              f"({res.size} B)")
    if args.report:
        write_report(stats, args.report)
    return 0

def cmd_verify(args) -> int:
    info = verify_container(args.input, args.key)
    print(json.dumps(info, indent=2))
    return 0 if info["integrity"] == "ok" else 1

def cmd_keygen(_args) -> int:
    print(BuildKey.generate().key.hex())
    return 0

def cmd_patch_embed(args) -> int:
    if args.key_hex:
        if not args.salt_hex:
            raise ProtectionError("--key-hex requires --salt-hex")
        try:
            key = bytes.fromhex(args.key_hex)
            salt = int(args.salt_hex, 16)
        except ValueError as e:
            raise ProtectionError(f"bad --key-hex/--salt-hex: {e}")
    else:
        key, salt = patcher.load_key_material(args.emit_key)
    res = patcher.embed_key(args.exe, key, salt, shards=args.shards,
                            force=args.force)
    print(f"embedded {res.size} B key overlay @+0x{res.offset:x} "
          f"(crc {res.crc:08x}, salt 0x{salt:016x})")
    return 0

def cmd_patch_verify(args) -> int:
    got = patcher.probe_key(args.exe)
    if got is None:
        print(f"{args.exe}: no key overlay")
        return 1
    salt, key = got
    print(f"{args.exe}: overlay ok — salt 0x{salt:016x}, "
          f"{len(key) * 8}-bit key recovered")
    return 0

def cmd_patch_strip(args) -> int:
    if patcher.strip_key(args.exe):
        print(f"{args.exe}: key overlay stripped")
        return 0
    print(f"{args.exe}: no key overlay")
    return 1

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="gdprotect", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", help=".gdprotect.toml / .json")
    ap.add_argument("--seed", type=int, help="deterministic build seed (testing)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="inventory a project dir or .pck")
    p.add_argument("input")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("build", help="full pipeline: obfuscate+virtualize+pack")
    p.add_argument("input")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--emit-key", help="write runtime key_shard.h here")
    p.add_argument("--no-obfuscate", action="store_true")
    p.add_argument("--no-compress", action="store_true")
    p.add_argument("--virtualize", nargs="*", metavar="GLOB",
                   help="enable VM + res:// globs of scripts to virtualize")
    p.add_argument("--report", help="write a JSON build report")
    p.add_argument("--patch", metavar="EXE",
                   help="embed this build's key into a Windows .exe overlay")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(fn=cmd_build)

    p = sub.add_parser("pack", help="pack only (no transforms)")
    p.add_argument("input")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--no-compress", action="store_true")
    p.add_argument("--emit-key")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(fn=lambda a: (setattr(a, "no_obfuscate", True),
                                 cmd_build(a))[1])

    p = sub.add_parser("verify", help="check integrity + list a .gdpk")
    p.add_argument("input")
    p.add_argument("--key", required=True, help="hex build key")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("keygen", help="print a fresh build key")
    p.set_defaults(fn=cmd_keygen)

    p = sub.add_parser("patch",
                       help="embed/verify/strip a build key in a .exe overlay")
    psub = p.add_subparsers(dest="patch_cmd", required=True)

    pe = psub.add_parser("embed", help="append a key overlay to an .exe")
    pe.add_argument("exe")
    src = pe.add_mutually_exclusive_group(required=True)
    src.add_argument("--emit-key",
                     help="key_shard.h / .gdkey / .json key file")
    src.add_argument("--key-hex", help="64-hex build key (needs --salt-hex)")
    pe.add_argument("--salt-hex", help="16-hex build salt (with --key-hex)")
    pe.add_argument("--shards", type=int, default=4)
    pe.add_argument("--force", action="store_true",
                    help="replace an existing overlay")
    pe.set_defaults(fn=cmd_patch_embed)

    pv = psub.add_parser("verify", help="check overlay crc + recover salt")
    pv.add_argument("exe")
    pv.set_defaults(fn=cmd_patch_verify)

    ps = psub.add_parser("strip", help="remove the key overlay")
    ps.add_argument("exe")
    ps.set_defaults(fn=cmd_patch_strip)
    return ap

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except ProtectionError as e:
        print(f"gdprotect: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
