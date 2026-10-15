
from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field, asdict
from pathlib import Path

@dataclass
class ObfuscateConfig:
    enabled: bool = True
    rename_identifiers: bool = True
    encrypt_strings: bool = True
    control_flow: bool = True
    strip_comments: bool = True
    preserve: list[str] = field(default_factory=list)

@dataclass
class VirtualizeConfig:
    enabled: bool = False
    scripts: list[str] = field(default_factory=list)
    hardening: int = 1
    stringpool: bool = False

@dataclass
class NativeConfig:
    enabled: bool = False
    scripts: list[str] = field(default_factory=list)
    ext_name: str = "gdprotect_native"
    out_dir: str = "build/native"
    godot_cpp: str = ""
    platform: str = "windows"
    target: str = "template_release"
    arch: str = "x86_64"
    build: bool = True
    require_build: bool = True

@dataclass
class PackConfig:
    input: str = "."
    output: str = "build/game.gdpk"
    chunk_size: int = 64 * 1024
    compress: bool = True
    integrity_tree: bool = True

@dataclass
class Config:
    pack: PackConfig = field(default_factory=PackConfig)
    obfuscate: ObfuscateConfig = field(default_factory=ObfuscateConfig)
    virtualize: VirtualizeConfig = field(default_factory=VirtualizeConfig)
    native: NativeConfig = field(default_factory=NativeConfig)
    seed: int | None = None

    @staticmethod
    def load(path: str | Path) -> "Config":
        p = Path(path)
        raw = p.read_bytes()
        data = tomllib.loads(raw.decode()) if p.suffix == ".toml" else json.loads(raw)
        cfg = Config()
        for section, cls in (("pack", PackConfig), ("obfuscate", ObfuscateConfig),
                             ("virtualize", VirtualizeConfig),
                             ("native", NativeConfig)):
            if section in data:
                setattr(cfg, section, cls(**data[section]))
        cfg.seed = data.get("seed")
        return cfg

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2))
