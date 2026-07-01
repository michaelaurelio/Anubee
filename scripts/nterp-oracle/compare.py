"""Join ares interp-frame naming against a Frida/ART oracle; score precision."""
import json
import re

_DEXPC = re.compile(r"\+0x[0-9a-fA-F]+$")

# openat/openat2 pathname is arg index 1; open is index 0.
_PATH_ARG = {"openat": "1", "openat2": "1", "open": "0", "faccessat": "1",
             "newfstatat": "1", "statx": "1", "readlinkat": "1"}

def parse_frame_name(symbol):
    """(fqn, corroborated): strip a trailing +0x<hex> dex_pc marker."""
    m = _DEXPC.search(symbol)
    if m:
        return symbol[:m.start()], True
    return symbol, False

def _iter_jsonl(path):
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)

def _ares_path(rec):
    sa = rec.get("string_args") or {}
    key = _PATH_ARG.get(rec.get("syscall"))
    if key is not None and key in sa:
        return sa[key]
    # fall back to the first string arg that looks like a path
    for v in sa.values():
        if isinstance(v, str) and v.startswith("/"):
            return v
    return None

def _interp_chain(cfi_rec):
    out = []
    for fr in cfi_rec.get("cfi_backtrace", []):
        if fr.get("kind") == "interp" and fr.get("addr") == "0x0":
            out.append(parse_frame_name(fr.get("symbol", "")))
    return out

def load_ares(events_path, stacks_path):
    chains = {}
    for rec in _iter_jsonl(stacks_path):
        if rec.get("type") == "cfi_stack":
            chains[rec.get("stack_id")] = _interp_chain(rec)
    out = []
    for rec in _iter_jsonl(events_path):
        if rec.get("type") != "syscall":
            continue
        sid = rec.get("stack_id")
        if sid is None:
            continue
        out.append({
            "syscall": rec.get("syscall"),
            "path": _ares_path(rec),
            "tid": rec.get("tid"),
            "stack_id": sid,
            "interp": chains.get(sid, []),
        })
    return out
