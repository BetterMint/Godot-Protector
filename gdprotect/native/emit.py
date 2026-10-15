from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .gdpx_rt import GDPX_RT_H
from .transpile import NativeUnit

_GDEXT_TMPL = """\
[configuration]
entry_symbol = "{entry}"
compatibility_minimum = "{compat}"
reloadable = false

[libraries]
{libs}
"""

_LIB_PLATFORM = {
    ".dll": "windows",
    ".so": "linux",
    ".dylib": "macos",
    ".wasm": "web",
}

def library_lines(ext_name: str, lib_names: list[str]) -> list[str]:
    lines = []
    for lib in sorted(lib_names):
        stem = Path(lib).name
        sfx = Path(lib).suffix.lower()
        plat = _LIB_PLATFORM.get(sfx, "windows")
        bits = stem.split(".")

        tags = bits[1:-1] if len(bits) > 2 else []
        target = next((t for t in tags if "template" in t or t in
                       ("editor", "debug", "release")), "template_release")
        arch = next((a for a in tags if a in
                     ("x86_32", "x86_64", "arm32", "arm64", "rv64",
                      "wasm32")), "x86_64")
        key = f"{plat}.{target}" + (f".{arch}" if plat != "macos" else "")
        lines.append(f'{key} = "res://bin/{stem}"')
    return lines

def gdextension_text(ext_name: str, lib_names: list[str],
                     compat: str = "4.1") -> str:
    libs = "\n".join(library_lines(ext_name, lib_names))
    return _GDEXT_TMPL.format(entry="gdpx_init_entry", compat=compat,
                              libs=libs)

REGISTER_TYPES_CPP = """\
#include "register_types.h"
#include "classes.h"

using namespace godot;
using namespace gdextension;

void gdpx_initialize(ModuleInitializationLevel p_level) {
    if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) {
        return;
    }
{registrations}
}

void gdpx_uninitialize(ModuleInitializationLevel p_level) {
}

extern "C" {

GDExtensionBool GDE_EXPORT gdpx_init_entry(
        GDExtensionInterfaceGetProcAddress p_get_proc_address,
        const GDExtensionClassLibraryPtr p_library,
        GDExtensionInitialization *r_initialization) {
    GDExtensionBinding::InitObject init_obj(p_get_proc_address, p_library,
                                            r_initialization);
    init_obj.register_initializer(gdpx_initialize);
    init_obj.register_terminator(gdpx_uninitialize);
    init_obj.set_minimum_library_initialization_level(
        MODULE_INITIALIZATION_LEVEL_SCENE);
    return init_obj.init();
}
}
"""

REGISTER_TYPES_H = """\
#pragma once

#include <godot_cpp/godot.hpp>
#include <godot_cpp/core/class_db.hpp>

namespace gdextension {
void gdpx_initialize(godot::ModuleInitializationLevel p_level);
void gdpx_uninitialize(godot::ModuleInitializationLevel p_level);
}
"""

CLASSES_H = """\
#pragma once
{includes}
"""

SCONSTRUCT = """\
#!/usr/bin/env python
# Build script for the gdprotect-generated GDExtension.
# Requires godot-cpp checked out next to this file (or pass godot_cpp=PATH).
import os

godot_cpp = ARGUMENTS.get("godot_cpp", os.environ.get("GODOT_CPP", "godot-cpp"))

env = SConscript(os.path.join(godot_cpp, "SConstruct"))
env.Append(CPPPATH=["src"])
sources = Glob("src/*.cpp")

lib_name = "{ext_name}"
if env["platform"] == "windows":
    ext = "dll"
elif env["platform"] == "linux":
    ext = "so"
elif env["platform"] == "macos":
    ext = "dylib"
elif env["platform"] == "web":
    ext = "wasm"
else:
    ext = "dll"

if env["platform"] == "macos":
    out = f"bin/{{lib_name}}.{{env['platform']}}.{{env['target']}}.{{ext}}"
else:
    out = (f"bin/{{lib_name}}.{{env['platform']}}.{{env['target']}}."
           f"{{env.get('arch', 'x86_64')}}.{{ext}}")

library = env.SharedLibrary(out, source=sources)
Default(library)
"""

BUILD_MD = """\
# {ext_name} — generated GDExtension

These C++ sources were transpiled from GDScript by `gdprotect`. Build them
into a native library with SCons + godot-cpp:

```
git clone --depth 1 -b 4.x https://github.com/godotengine/godot-cpp
scons platform=windows target=template_release
```

Result lands in `bin/` — pack it into the game (gdprotect's pipeline does
this automatically when the build succeeds). The `.gdextension` manifest
next to `bin/` tells Godot which library to load per platform.
"""

@dataclass
class EmittedProject:
    dir: Path
    gdextension_name: str
    gdextension_text: str
    sources: list[Path]
    lib_names: list[str]

def emit_project(units: list[NativeUnit], out_dir: str | Path,
                 ext_name: str = "gdprotect_native",
                 lib_names: list[str] | None = None,
                 compat: str = "4.1") -> EmittedProject:
    out_dir = Path(out_dir)
    src_dir = out_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)


    used_stems: set[str] = set()
    for u in units:
        stem, k = u.file_stem, 1
        while u.file_stem in used_stems:
            u.file_stem = f"{stem}_{k}"
            k += 1
        used_stems.add(u.file_stem)

    written = []
    (src_dir / "gdpx_rt.h").write_text(GDPX_RT_H, encoding="utf-8")
    written.append(src_dir / "gdpx_rt.h")
    (src_dir / "register_types.h").write_text(REGISTER_TYPES_H,
                                              encoding="utf-8")
    written.append(src_dir / "register_types.h")

    regs = []
    for u in units:
        h_path = src_dir / f"{u.file_stem}.h"
        c_path = src_dir / f"{u.file_stem}.cpp"
        h_path.write_text(u.header, encoding="utf-8")
        c_path.write_text(u.source, encoding="utf-8")
        written += [h_path, c_path]
        regs.append(u)

    includes = "\n".join(f'#include "{u.file_stem}.h"' for u in units)
    (src_dir / "classes.h").write_text(
        CLASSES_H.replace("{includes}", includes), encoding="utf-8")
    written.append(src_dir / "classes.h")

    reg_names = [n for u in units for n in (u.all_names or [u.class_name])]
    reg_block = "\n".join(
        f'    godot::ClassDB::register_class<{n}>();' for n in reg_names)
    internal = ["GxCo", "GxScriptRef"] + [
        n for u in units for n in u.co_classes]
    if internal:
        reg_block += "\n" + "\n".join(
            f'    godot::ClassDB::register_internal_class<{n}>();'
            for n in dict.fromkeys(internal))
    (src_dir / "register_types.cpp").write_text(
        REGISTER_TYPES_CPP.replace("{registrations}", reg_block),
        encoding="utf-8")
    written.append(src_dir / "register_types.cpp")

    (out_dir / "SConstruct").write_text(
        SCONSTRUCT.replace("{ext_name}", ext_name), encoding="utf-8")
    (out_dir / "BUILD.md").write_text(BUILD_MD.format(ext_name=ext_name),
                                      encoding="utf-8")

    libs = lib_names or []
    gext = gdextension_text(ext_name, libs, compat=compat)
    gext_name = f"{ext_name}.gdextension"

    return EmittedProject(dir=out_dir, gdextension_name=gext_name,
                          gdextension_text=gext, sources=written,
                          lib_names=libs)
