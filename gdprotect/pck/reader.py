
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

PCK_MAGIC = 0x43504447
FLAG_DIR_ENCRYPTED = 1 << 0
FLAG_REL_FILEBASE = 1 << 1
FILE_FLAG_ENCRYPTED = 1 << 0

@dataclass
class PckFile:
    path: str
    offset: int
    size: int
    md5: bytes
    encrypted: bool

    @property
    def extension(self) -> str:
        return Path(self.path).suffix.lower()

class PckReader:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.files: list[PckFile] = []
        self.version = 0
        self.encrypted_dir = False
        self._parse()

    def _find_base(self, d: bytes) -> int:
        magic = struct.pack("<I", PCK_MAGIC)
        if len(d) >= 16 and d[-4:] == magic:
            (pck_size,) = struct.unpack_from("<Q", d, len(d) - 12)
            base = len(d) - 12 - pck_size
            if 0 <= base < len(d) and d[base:base + 4] == magic:
                return base
        pos = d.rfind(magic)
        if pos < 0:
            raise ValueError("no pck found in file")
        return pos

    def _parse(self) -> None:
        d = self.data
        base = self._find_base(d)
        magic, fmt = struct.unpack_from("<II", d, base)
        if magic != PCK_MAGIC:
            raise ValueError("bad pck magic")
        if fmt not in (2, 3, 4):
            raise ValueError(f"unsupported pck format v{fmt}")
        self.version = fmt
        flags, file_base = struct.unpack_from("<IQ", d, base + 20)
        self.encrypted_dir = bool(flags & FLAG_DIR_ENCRYPTED)
        file_base_abs = (base + file_base) if (flags & FLAG_REL_FILEBASE) else file_base

        if fmt == 2:
            dir_abs = base + 20 + 4 + 8 + 16 * 4
        else:
            (dir_off,) = struct.unpack_from("<Q", d, base + 32)
            dir_abs = (base + dir_off) if (flags & FLAG_REL_FILEBASE) else dir_off

        if self.encrypted_dir:
            return
        self._parse_dir(dir_abs, file_base_abs)

    def _parse_dir(self, off: int, file_base: int) -> None:
        d = self.data
        (count,) = struct.unpack_from("<I", d, off)
        pos = off + 4
        for _ in range(count):
            (plen,) = struct.unpack_from("<I", d, pos)
            pos += 4
            path = d[pos:pos + plen].rstrip(b"\x00").decode("utf-8", "replace")
            pos += (plen + 3) & ~3
            foff, fsize = struct.unpack_from("<QQ", d, pos)
            pos += 16
            md5 = d[pos:pos + 16]
            pos += 16
            (fflags,) = struct.unpack_from("<I", d, pos)
            pos += 4
            self.files.append(PckFile(
                path=path, offset=file_base + foff, size=fsize,
                md5=md5, encrypted=bool(fflags & FILE_FLAG_ENCRYPTED),
            ))

    def read_file(self, f: PckFile) -> bytes:
        if f.encrypted:
            raise ValueError(f"{f.path}: file is encrypted")
        return self.data[f.offset:f.offset + f.size]
