from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BuildResult:
    built: bool
    artifacts: list[Path] = field(default_factory=list)
    reason: str = ""


_COMPILERS = ("cl", "g++", "clang++", "gcc", "clang")


def find_toolchain() -> dict:
    """Locate a SCons + C++ toolchain for building the GDExtension."""
    scons = shutil.which("scons")
    compiler = next((c for c in _COMPILERS if shutil.which(c)), None)
    return {"scons": scons, "compiler": compiler,
            "python": shutil.which("python")}


def build_extension(project_dir: str | Path,
                    platform: str = "windows",
                    target: str = "template_release",
                    arch: str = "x86_64",
                    godot_cpp: str | None = None) -> BuildResult:
    """Run `scons` inside the generated extension project. Returns the
    artifacts produced (empty if no toolchain is installed)."""
    tc = find_toolchain()
    if tc["scons"] is None or tc["compiler"] is None:
        missing = []
        if tc["scons"] is None:
            missing.append("scons")
        if tc["compiler"] is None:
            missing.append("a C++ compiler (cl/g++/clang++)")
        return BuildResult(False, [],
                           "missing " + " and ".join(missing))
    project_dir = Path(project_dir)
    cmd = [tc["scons"], f"platform={platform}", f"target={target}"]
    if platform != "macos":
        cmd.append(f"arch={arch}")
    if godot_cpp:
        cmd.append(f"godot_cpp={godot_cpp}")
    proc = subprocess.run(cmd, cwd=project_dir, capture_output=True,
                          text=True, timeout=600)
    if proc.returncode != 0:
        return BuildResult(False, [],
                           proc.stderr.strip() or proc.stdout.strip())
    bin_dir = project_dir / "bin"
    artifacts = sorted(p for p in bin_dir.glob("*") if p.is_file()) \
        if bin_dir.is_dir() else []
    return BuildResult(True, artifacts, "ok")
