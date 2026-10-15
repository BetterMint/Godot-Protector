
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .crypto.keys import BuildKey, split_key_shards
from .pck.container import FileKind, GdpkReader, GdpkWriter, classify
from .pck.reader import PckReader
from .util import ProtectionError, iter_project_files, matches_any, to_res_path
from .vm.isa import Dialect

@dataclass
class FileRecord:
    res_path: str
    kind: FileKind
    size: int
    flags: int = 0
    notes: list[str] = field(default_factory=list)

def scan_project(root: str | Path) -> list[FileRecord]:
    root = Path(root)
    return [FileRecord(to_res_path(root, p), classify(p.name), p.stat().st_size)
            for p in iter_project_files(root)]

def scan_pck(path: str | Path) -> list[FileRecord]:
    r = PckReader(path)
    if r.encrypted_dir:
        raise ProtectionError(
            f"{path}: directory is already encrypted — supply the export key "
            "or protect from the project directory instead")
    return [FileRecord(f.path, classify(f.path), f.size,
                       notes=["encrypted"] if f.encrypted else [])
            for f in r.files]

def run_build(cfg: Config, emit_key: str | Path | None = None,
              verbose: bool = False) -> dict:
    src = Path(cfg.pack.input)
    bk = BuildKey.generate(cfg.seed)
    dialect = Dialect(int.from_bytes(bk.salt, "little"))

    if src.is_dir():
        files = [(to_res_path(src, p), p.read_bytes()) for p in iter_project_files(src)]
    else:
        r = PckReader(src)
        files = [(f.path, r.read_file(f)) for f in r.files]

    native_stats: dict = {"compiled": 0, "artifacts": []}
    if cfg.native.enabled and (cfg.native.scripts or cfg.native.auto):
        files, native_stats = _native_stage(files, cfg, verbose)

    strpool_contents: dict[str, set[str]] = {}
    if cfg.virtualize.stringpool:
        from .vm.strpool import hoist_source, pack_pool, pool_path_for
        out = []
        for res_path, data in files:
            if not res_path.endswith(".gd") or (
                    cfg.virtualize.enabled
                    and matches_any(res_path, cfg.virtualize.scripts)):
                out.append((res_path, data))
                continue
            try:
                new_src, pooled, contents = hoist_source(
                    data.decode("utf-8"), pool_path_for(res_path))
            except Exception as e:
                if verbose:
                    print(f"  ! strpool skipped {res_path}: {e}")
                out.append((res_path, data))
                continue
            out.append((res_path, new_src.encode("utf-8")))
            if pooled:
                pool_path = pool_path_for(res_path)
                out.append((pool_path, pack_pool(pooled, bk, pool_path)))
                strpool_contents[res_path] = contents
        files = out

    if cfg.obfuscate.enabled:
        from .obfuscate.api import obfuscate_source
        out = []
        for res_path, data in files:
            if res_path.endswith(".gd"):
                try:
                    data = obfuscate_source(
                        data.decode("utf-8"), cfg.obfuscate, res_path,
                        extra_str_contents=strpool_contents.get(res_path)
                        ).encode()
                except Exception as e:
                    if verbose:
                        print(f"  ! obfuscate skipped {res_path}: {e}")
            out.append((res_path, data))
        files = out

    vm_paths: set[str] = set()
    if cfg.virtualize.enabled:
        from .vm.compiler import compile_source
        out = []
        for res_path, data in files:
            if res_path.endswith(".gd") and matches_any(
                    res_path, cfg.virtualize.scripts):
                try:
                    image = compile_source(data.decode("utf-8"), dialect,
                                           filename=res_path,
                                           hardening=cfg.virtualize.hardening)
                except Exception as e:
                    raise ProtectionError(f"virtualize {res_path}: {e}") from e
                out.append((res_path[:-3] + ".gvmb", image))
                vm_paths.add(res_path)
            else:
                out.append((res_path, data))
        files = out

    w = GdpkWriter(bk, chunk_size=cfg.pack.chunk_size,
                   compress=cfg.pack.compress,
                   integrity_tree=cfg.pack.integrity_tree)
    for res_path, data in files:
        flags = 0
        if res_path.endswith(".gvmb"):
            flags = 1
        w.add_file(res_path, data, flags=flags)
    stats = w.finalize(cfg.pack.output)

    key_hex = bk.key.hex()
    shard_info = None
    if emit_key:
        shard_info = emit_key_header(bk, emit_key)

    stats.update({
        "virtualized": len(vm_paths),
        "stringpooled": len(strpool_contents),
        "obfuscated": cfg.obfuscate.enabled,
        "native": native_stats,
        "build_key": key_hex,
        "key_shard": shard_info,
    })
    return stats

def _native_stage(files, cfg: Config, verbose: bool):
    from .native import (NativeError, transpile_source, emit_project,
                         rewrite_scene, rewrite_gd, build_extension,
                         find_toolchain)

    data_map = dict(files)
    all_gd = {p for p, _ in files if p.endswith(".gd")}
    if cfg.native.auto:
        targets = set(all_gd)
    else:
        targets = {p for p in all_gd
                   if matches_any(p, cfg.native.scripts)}
    targets -= {p for p in targets if matches_any(p, cfg.native.exclude)}
    if not targets:
        return files, {"compiled": 0, "artifacts": []}


    from .native.ast import parse as native_parse


    script_classes: dict[str, str] = {}
    for path, data in files:
        if not path.endswith(".gd"):
            continue
        m = re.search(r"(?m)^[ \t]*class_name[ \t]+([A-Za-z_]\w*)",
                      data.decode("utf-8", "replace"))
        if m:
            script_classes[m.group(1)] = path

    autoloads = _read_autoloads(data_map)

    class_map: dict[str, str] = {}
    parsed: dict[str, list] = {}
    dropped: dict[str, str] = {}
    queue = sorted(targets)
    while queue:
        path = queue.pop(0)
        if path in parsed:
            continue
        try:
            nodes = native_parse(data_map[path].decode("utf-8"), path)
        except Exception as e:
            if cfg.native.on_error == "fallback":
                targets.discard(path)
                dropped[path] = f"parse error: {e}"
                if verbose:
                    print(f"  ! native fallback {path}: {e}")
                continue
            raise ProtectionError(f"native: {path}: {e}") from e
        parsed[path] = nodes
        ext = next((n[3] for n in nodes
                    if n[0] == "meta" and n[2] == "extends" and n[3]),
                   None)
        cname = next((n[3] for n in nodes
                      if n[0] == "meta" and n[2] == "class_name" and n[3]),
                     None)
        if cname:
            class_map[path] = cname.split(".")[-1]
        dep = _base_dep(ext, script_classes, path)
        if dep and dep in all_gd and dep not in targets:


            targets.add(dep)
            queue.append(dep)
            if verbose:
                print(f"  + native {dep} (base class of {path})")

    for path in sorted(targets):
        if path not in class_map:
            stem = Path(path).stem
            name = "Gx" + "".join(
                p[:1].upper() + p[1:] for p in stem.replace("-", "_").split("_")
                if p)
            while name in set(class_map.values()):
                name += "X"
            class_map[path] = name


    units: list = []
    while True:
        active = sorted(targets - set(dropped))
        amap = {p: class_map[p] for p in active if p in class_map}
        errs: dict[str, str] = {}
        round_units: list = []
        for path in active:
            try:
                unit = transpile_source(
                    data_map[path].decode("utf-8"), path, amap,
                    script_classes, autoloads)
            except NativeError as e:
                errs[path] = str(e)
                continue
            if unit.tool and cfg.native.skip_tool:
                errs[path] = "@tool editor script stays interpreted"
                continue
            round_units.append(unit)
        if not errs:
            units = round_units
            break
        if cfg.native.on_error != "fallback":
            first = sorted(errs)[0]
            raise ProtectionError(f"native: {errs[first]}")
        for p in errs:
            class_map.pop(p, None)
        dropped.update(errs)
        if verbose:
            for p, why in sorted(errs.items()):
                print(f"  ! native fallback {p}: {why}")

    for unit in units:
        if verbose:
            print(f"  + native {unit.res_path} -> class {unit.class_name} "
                  f"({unit.file_stem}.cpp)")
    targets -= set(dropped)

    out_dir = Path(cfg.native.out_dir)
    artifacts: list[Path] = []
    if cfg.native.build:
        proj = emit_project(units, out_dir, ext_name=cfg.native.ext_name,
                            lib_names=[], compat="4.1")
        res = build_extension(out_dir, platform=cfg.native.platform,
                              target=cfg.native.target,
                              arch=cfg.native.arch,
                              godot_cpp=cfg.native.godot_cpp or None)
        if res.built:
            artifacts = res.artifacts
            if verbose:
                for a in artifacts:
                    print(f"  + native artifact {a.name}")
        else:
            msg = (f"native build skipped: {res.reason}; emit buildable "
                   f"project at {out_dir} (build with scons + godot-cpp, "
                   f"then re-pack so the dll ships)")
            if cfg.native.require_build:
                raise ProtectionError(msg)
            if verbose:
                print(f"  ! {msg}")
    else:
        proj = emit_project(units, out_dir, ext_name=cfg.native.ext_name)

    from .native.emit import gdextension_text
    lib_names = [a.name for a in artifacts]
    gtext = gdextension_text(cfg.native.ext_name, lib_names)


    out = []
    for res_path, data in files:
        if res_path in targets:
            continue
        low = res_path.lower()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            out.append((res_path, data))
            continue
        if low.endswith(".gd"):
            new = rewrite_gd(text, class_map)
            if new != text and verbose:
                print(f"  ~ rewrote references in {res_path}")
            out.append((res_path, new.encode("utf-8")))
        elif low.endswith((".tscn", ".tres", ".scn", ".res", ".theme")):
            new = rewrite_scene(text, class_map)
            if new != text and verbose:
                print(f"  ~ rewrote scene refs in {res_path}")
            out.append((res_path, new.encode("utf-8")))
        elif res_path == "res://.godot/extension_list.cfg":
            lines = [l for l in text.splitlines() if l.strip()]
            new_ext = f"res://{cfg.native.ext_name}.gdextension"
            if new_ext not in lines:
                lines.append(new_ext)
            out.append((res_path, ("\n".join(lines) + "\n").encode()))
        else:
            out.append((res_path, data))
    if not any(p == "res://.godot/extension_list.cfg" for p, _ in out):
        out.append(("res://.godot/extension_list.cfg",
                    (f"res://{cfg.native.ext_name}.gdextension\n").encode()))
    out.append((f"res://{cfg.native.ext_name}.gdextension", gtext.encode()))
    for a in artifacts:
        out.append((f"res://bin/{a.name}", a.read_bytes()))

    return out, {"compiled": len(units),
                 "artifacts": [a.name for a in artifacts],
                 "classes": {u.res_path: u.class_name for u in units},
                 "fallback": dropped or None,
                 "project": str(out_dir)}

def _base_dep(ext, script_classes, from_path) -> str | None:
    if not ext or not isinstance(ext, str):
        return None
    if ".gd" in ext:
        if ext.startswith("res://"):
            return ext
        import posixpath
        base = posixpath.dirname(from_path[6:])
        return "res://" + posixpath.normpath(posixpath.join(base, ext))
    return script_classes.get(ext.split(".")[-1])

def _read_autoloads(data_map: dict) -> dict[str, str]:
    src = data_map.get("res://project.godot")
    if src is None:
        return {}
    text = src.decode("utf-8", "replace")
    m = re.search(r"(?ms)^\[autoload\]\s*\n(.*?)(?=^\[|\Z)", text)
    if not m:
        return {}
    out = {}
    for line in m.group(1).splitlines():
        am = re.match(r'\s*([A-Za-z_]\w*)\s*=\s*"\*?(res://[^"]+)"', line)
        if am:
            out[am.group(1)] = am.group(2)
    return out

KEY_HEADER_TEMPLATE = """// AUTO-GENERATED by gdprotect build — do not commit secrets downstream.
// Per-build key shards for this protected container. Rebuild the 32-byte
// build key by XOR-ing all shards together; keep the shards in separate
// translation units so no single .rodata range holds the key.
#pragma once
#include <cstdint>

namespace gdpk {{

constexpr uint64_t BUILD_SALT = 0x{salt}ULL;
constexpr int KEY_SHARD_COUNT = {n};
{shards}
inline void rebuild_key(uint8_t out[32]) {{
{rebuild}
}}

}}  // namespace gdpk
"""

def emit_key_header(bk: BuildKey, path: str | Path, shards: int = 4) -> str:
    parts = split_key_shards(bk.key, shards)
    decls = "\n".join(
        "constexpr uint8_t KEY_SHARD_{}[32] = {{{}}};".format(
            i, ", ".join(f"0x{b:02x}" for b in s))
        for i, s in enumerate(parts))
    body = ["    out[i] = 0;".replace("i", "i")]
    body = ["    for (int i = 0; i < 32; i++) out[i] = KEY_SHARD_0[i];"]
    body += [f"    for (int i = 0; i < 32; i++) out[i] ^= KEY_SHARD_{j}[i];"
             for j in range(1, shards)]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(KEY_HEADER_TEMPLATE.format(
        salt=bk.salt.hex(), n=shards, shards=decls, rebuild="\n".join(body)))
    return str(path)

def verify_container(path: str | Path, key_hex: str) -> dict:
    bk = BuildKey(bytes.fromhex(key_hex), _read_salt(path))
    r = GdpkReader(path, bk)
    ok = r.verify_integrity()
    return {
        "files": len(r.entries),
        "integrity": "ok" if ok else "FAILED",
        "virtualized": sum(1 for e in r.entries if e.virtualized),
        "entries": [{"path": e.path, "kind": e.kind.name, "size": e.orig_size}
                    for e in r.entries],
    }

def _read_salt(path: str | Path) -> bytes:
    d = Path(path).read_bytes()
    if d[:4] != b"GDPK":
        raise ProtectionError("not a GDPK container")
    return d[8:16]

def write_report(stats: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(stats, indent=2))
