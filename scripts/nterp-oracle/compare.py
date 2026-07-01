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

_LOC = re.compile(r"\(.*\)$")

def normalize_java(frame):
    """Strip Frida's trailing (File.java:NN) source location."""
    return _LOC.sub("", frame).strip()

def load_frida(path):
    out = []
    for rec in _iter_jsonl(path):
        out.append({
            "syscall": rec.get("syscall"),
            "path": rec.get("path"),
            "tid": rec.get("tid"),
            "java": [normalize_java(x) for x in rec.get("java_stack", [])],
        })
    return out

def join(ares_recs, frida_recs):
    by_key = {}
    for fr in frida_recs:
        by_key.setdefault((fr["syscall"], fr["path"]), []).append(fr)
    matches = []
    for a in ares_recs:
        cands = by_key.get((a["syscall"], a["path"]), [])
        chosen = None
        a_names = {n for n, _ in a["interp"]}
        for c in cands:
            if a_names & set(c["java"]):
                chosen = c
                break
        if chosen is None and cands:
            chosen = cands[0]
        matches.append((a, chosen))
    return matches

def score(matches):
    s = dict(corr_named=0, corr_correct=0, uncorr_named=0, uncorr_correct=0,
             truth_frames=0, recalled=0, exact_chains=0, matched=0, unmatched=0)
    for a, f in matches:
        if f is None:
            s["unmatched"] += 1
            continue
        s["matched"] += 1
        truth = set(f["java"])
        s["truth_frames"] += len(truth)
        a_names = [n for n, _ in a["interp"]]
        s["recalled"] += len(truth & set(a_names))
        for name, corro in a["interp"]:
            key = "corr" if corro else "uncorr"
            s[key + "_named"] += 1
            if name in truth:
                s[key + "_correct"] += 1
        if a_names and a_names == f["java"]:
            s["exact_chains"] += 1
    return s

def _pct(n, d):
    return "n/a" if d == 0 else f"{100.0*n/d:.1f}%"

def format_report(s):
    return "\n".join([
        "nterp precision oracle report",
        f"  matched syscalls   : {s['matched']}  (unmatched: {s['unmatched']})",
        f"  corroborated frames: {s['corr_named']} named, "
        f"{s['corr_correct']} correct -> precision {_pct(s['corr_correct'], s['corr_named'])}",
        f"  uncorrob.  frames  : {s['uncorr_named']} named, "
        f"{s['uncorr_correct']} correct -> precision {_pct(s['uncorr_correct'], s['uncorr_named'])}",
        f"  recall (frames)    : {s['recalled']}/{s['truth_frames']} "
        f"({_pct(s['recalled'], s['truth_frames'])})",
        f"  exact chains       : {s['exact_chains']}/{s['matched']}",
    ])

def main():
    import argparse
    ap = argparse.ArgumentParser(description="nterp precision oracle scorer")
    ap.add_argument("--ares-events", required=True)
    ap.add_argument("--ares-stacks", required=True)
    ap.add_argument("--frida", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    matches = join(load_ares(a.ares_events, a.ares_stacks), load_frida(a.frida))
    s = score(matches)
    print(json.dumps(s, indent=2) if a.json else format_report(s))

if __name__ == "__main__":
    main()
