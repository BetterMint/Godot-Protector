from __future__ import annotations

import re

_EXT_RES_ANY = re.compile(r'^\[ext_resource\s+(?P<attrs>[^\]]*)\]\s*$', re.M)
_ATTR = re.compile(r'(\w+)="([^"]*)"')
_SCRIPT_LINE = re.compile(
    r'^script\s*=\s*ExtResource\("(?P<id>[^"]+)"\)\r?\n?', re.M)
_NODE_HEAD = re.compile(r'^\[node\s+(?P<attrs>[^\]]*)\]', re.M)
_EXTENDS_RES = re.compile(
    r'^(extends)\s+"(?P<path>res://[^"]+\.gd)"', re.M)
_PRELOAD = re.compile(r'preload\("(?P<path>res://[^"]+\.gd)"\)')
_LOAD = re.compile(r'(?<!pre)load\("(?P<path>res://[^"]+\.gd)"\)')


def _attrs_dict(attr_text: str) -> dict:
    return dict(_ATTR.findall(attr_text))


def _attrs_text(attrs: dict) -> str:
    return " ".join(f'{k}="{v}"' for k, v in attrs.items())


def rewrite_scene(text: str, class_map: dict[str, str]) -> str:
    """Rewrite .tscn/.tres text: ext_resource Script entries whose path is a
    natively-compiled script are dropped, and the owning node's
    `script = ExtResource(...)` becomes `type="ClassName"` on the node."""
    if not class_map:
        return text
    ext = {}
    for m in _EXT_RES_ANY.finditer(text):
        a = _attrs_dict(m.group("attrs"))
        if a.get("type") == "Script" and "id" in a:
            ext[a["id"]] = a.get("path", "")
    id_to_cls = {i: class_map[p] for i, p in ext.items() if p in class_map}
    if not id_to_cls:
        return text

    heads = list(_NODE_HEAD.finditer(text))
    out = []
    cursor = 0
    used_ids = set()
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        block = text[m.start():end]
        sm = _SCRIPT_LINE.search(block)
        out.append(text[cursor:m.start()])
        if sm and sm.group("id") in id_to_cls:
            used_ids.add(sm.group("id"))
            block = block[:sm.start()] + block[sm.end():]
            hm = _NODE_HEAD.match(block)
            attrs = _attrs_dict(hm.group("attrs"))
            attrs["type"] = id_to_cls[sm.group("id")]
            block = f"[node {_attrs_text(attrs)}]" + block[hm.end():]
        out.append(block)
        cursor = end
    out.append(text[cursor:])
    body = "".join(out)

    lines = []
    for line in body.splitlines(keepends=True):
        if line.lstrip().startswith("[ext_resource"):
            a = _attrs_dict(line)
            if a.get("id") in used_ids:
                continue
        lines.append(line)
    return "".join(lines)


def rewrite_gd(text: str, class_map: dict[str, str]) -> str:
    """Rewrite .gd source: `extends "res://x.gd"`, `preload("res://x.gd")` and
    `load("res://x.gd")` pointing at natively-compiled scripts become the
    registered class name."""
    if not class_map:
        return text

    def ext_repl(m):
        cls = class_map.get(m.group("path"))
        return f"{m.group(1)} {cls}" if cls else m.group(0)

    def pl_repl(m):
        cls = class_map.get(m.group("path"))
        return cls if cls else m.group(0)

    text = _EXTENDS_RES.sub(ext_repl, text)
    text = _PRELOAD.sub(pl_repl, text)
    text = _LOAD.sub(pl_repl, text)
    return text
