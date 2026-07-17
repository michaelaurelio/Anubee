#!/usr/bin/env python3
# anubee-fold — post-process a syscalls JSON trace by detecting loops in the
# syscall sequence and folding each loop into a loop reference.
#
# Algorithm: per thread, tokenize each syscall by (name + call-stack signature),
# then repeatedly fold maximal *tandem runs* (a block B repeated k>=min consecutive
# times) into a single loop node, smallest period first, to a fixpoint — which
# naturally discovers nested loops. Output is a registry of loop bodies plus a
# folded per-thread timeline that references them. Original event ids are kept on
# every loop so any iteration can be expanded; nothing is discarded.
#
#   anubee-fold trace.json                 # text summary to stdout
#   anubee-fold trace.json --json out.json # write folded JSON
#
# Stdlib only.

import argparse
import json
import sys


# ---- loading -------------------------------------------------------------

def load_trace(path):
    """Accept either a single JSON array or JSONL (one record per line).
    Malformed lines (e.g. a truncated final record after a hard-kill) are
    skipped with a warning, so a crash-interrupted JSONL trace still loads."""
    with open(path, "r") as f:
        data = f.read()
    s = data.lstrip()
    if s.startswith("["):
        return json.loads(s)
    out, skipped = [], 0
    for line in data.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            skipped += 1
    if skipped:
        print("warning: skipped %d malformed line(s) (truncated trace?)" % skipped,
              file=sys.stderr)
    return out


# ---- tokenization --------------------------------------------------------

def ev_callsite(ev):
    bt = ev.get("backtrace") or []
    return bt[0]["symbol"] if bt else "?"


def ev_token(ev, depth):
    """Identity of an event for loop matching: syscall name + stack symbols.
    depth: None = whole stack, 0 = name only, N = top N frames."""
    name = ev.get("syscall", "?")
    bt = ev.get("backtrace") or []
    syms = tuple(fr.get("symbol", "?") for fr in bt)
    if depth == 0:
        syms = ()
    elif depth is not None:
        syms = syms[:depth]
    return (name, syms)


def make_leaf(ev, depth):
    return {
        "kind": "event",
        "ev": ev,
        "name": ev.get("syscall", "?"),
        "callsite": ev_callsite(ev),
        "tok": ev_token(ev, depth),
        "ids": [ev.get("id")],
    }


# ---- tandem-run detection ------------------------------------------------

def find_runs(toks, max_period, min_reps):
    """Maximal tandem runs (period p, start i, repeats k) with k>=min_reps.
    For each period the block is extended as far as it stays periodic, so the
    body is the smallest period when smaller periods are preferred in select()."""
    n = len(toks)
    runs = []
    maxp = min(max_period, n // 2)
    for p in range(1, maxp + 1):
        i = 0
        while i + p < n:
            m = 0
            while i + p + m < n and toks[i + m] == toks[i + p + m]:
                m += 1
            k = (m + p) // p          # number of whole repetitions of the block
            if k >= min_reps:
                runs.append((p, i, k))
                i += k * p
            else:
                i += 1
    return runs


def select_runs(runs):
    """Pick a non-overlapping set, preferring smallest period, then longest,
    then leftmost — i.e. the tightest innermost loops."""
    runs.sort(key=lambda r: (r[0], -(r[0] * r[2]), r[1]))
    chosen, occupied = [], []
    for p, i, k in runs:
        lo, hi = i, i + p * k
        if any(not (hi <= a or lo >= b) for a, b in occupied):
            continue
        chosen.append((p, i, k))
        occupied.append((lo, hi))
    return chosen


def fold_once(nodes, max_period, min_reps):
    toks = [nd["tok"] for nd in nodes]
    chosen = select_runs(find_runs(toks, max_period, min_reps))
    if not chosen:
        return nodes, False
    starts = {i: (p, k) for (p, i, k) in chosen}
    out, idx = [], 0
    while idx < len(nodes):
        if idx in starts:
            p, k = starts[idx]
            body = nodes[idx:idx + p]
            span = nodes[idx:idx + p * k]
            ids = [eid for nd in span for eid in nd["ids"]]
            out.append({
                "kind": "loop",
                "iters": k,
                "body": body,
                "ids": ids,
                "tok": ("LOOP", tuple(b["tok"] for b in body), k),
            })
            idx += p * k
        else:
            out.append(nodes[idx])
            idx += 1
    return out, True


def fold(nodes, max_period, min_reps, nesting):
    changed = True
    while changed:
        nodes, changed = fold_once(nodes, max_period, min_reps)
        if not nesting:
            break
    return nodes


# ---- loop registry -------------------------------------------------------

def struct_sig(node):
    """Body identity, ignoring iteration count, so the same loop pattern shares
    one id across occurrences."""
    if node["kind"] == "event":
        return ("s", node["name"], node["callsite"])
    return ("l", tuple(struct_sig(b) for b in node["body"]))


class Registry:
    def __init__(self):
        self.by_sig = {}
        self.order = []

    def register(self, node):
        if node["kind"] != "loop":
            return
        for b in node["body"]:
            self.register(b)                  # bottom-up: inner loops get ids first
        sig = struct_sig(node)
        entry = self.by_sig.get(sig)
        if entry is None:
            entry = {
                "id": "L%d" % (len(self.order) + 1),
                "period": len(node["body"]),
                "body": self._body_listing(node["body"]),
                "occurrences": 0,
                "iterations_total": 0,
            }
            self.by_sig[sig] = entry
            self.order.append(entry)
        entry["occurrences"] += 1
        entry["iterations_total"] += node["iters"]
        node["loop_id"] = entry["id"]

    def _body_listing(self, body):
        items = []
        for b in body:
            if b["kind"] == "event":
                items.append({"syscall": b["name"], "callsite": b["callsite"]})
            else:
                items.append({"loop": b["loop_id"], "iterations": b["iters"]})
        return items


# ---- output --------------------------------------------------------------

def timeline_item(node, inline):
    if node["kind"] == "event":
        return {"event": node["ev"]} if inline else {"id": node["ev"].get("id")}
    return {"loop": node["loop_id"], "iterations": node["iters"], "event_ids": node["ids"]}


def body_oneline(entry):
    parts = []
    for it in entry["body"]:
        if "loop" in it:
            parts.append("%s x%d" % (it["loop"], it["iterations"]))
        else:
            parts.append(it["syscall"])
    return " ; ".join(parts)


def render_text(meta, registry, threads, top):
    out = []
    out.append("trace: %d events / %d threads -> folded %d events into %d loop pattern(s)"
               % (meta["events"], meta["threads"], meta["folded_events"], len(registry.order)))
    hot = sorted(registry.order, key=lambda e: e["iterations_total"], reverse=True)
    if hot:
        out.append("\n== hot loops (by total iterations) ==")
        for e in hot[:top]:
            site = ""
            for it in e["body"]:
                if "syscall" in it:
                    site = "  @ " + it["callsite"]
                    break
            out.append("  %-4s x%-6d period %-2d  %s%s"
                       % (e["id"], e["iterations_total"], e["period"], body_oneline(e), site))
    for th in threads:
        out.append("\n== thread %s (%d events) ==" % (th["tid"], th["events"]))
        for node in th["nodes"]:
            if node["kind"] == "event":
                ev = node["ev"]
                ret = "" if ev.get("retval") is None else " = %s" % ev["retval"]
                out.append("  #%-6s %s%s" % (ev.get("id"), ev.get("syscall"), ret))
            else:
                ids = node["ids"]
                rng = "#%s..#%s" % (ids[0], ids[-1]) if ids else ""
                out.append("  LOOP %s x%d  [%s]" % (node["loop_id"], node["iters"], rng))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Fold loops in a syscalls trace.")
    ap.add_argument("trace", help="syscalls JSON (array) or JSONL trace")
    ap.add_argument("--json", metavar="OUT", help="write folded JSON to OUT")
    ap.add_argument("--min-reps", type=int, default=2, help="min iterations to fold (default 2)")
    ap.add_argument("--max-period", type=int, default=64, help="max loop body length (default 64)")
    ap.add_argument("--callsite-frames", type=int, default=-1,
                    help="backtrace frames in the match token (-1=all, 0=name only, N=top N)")
    ap.add_argument("--no-nesting", action="store_true", help="disable nested loop folding")
    ap.add_argument("--no-inline", action="store_true", help="JSON timeline keeps ids, not full records")
    ap.add_argument("--top", type=int, default=20, help="hot loops to show in text (default 20)")
    args = ap.parse_args()

    depth = None if args.callsite_frames < 0 else args.callsite_frames
    events = load_trace(args.trace)

    by_tid = {}
    for ev in events:
        by_tid.setdefault(ev.get("tid"), []).append(ev)

    registry = Registry()
    threads, folded_events = [], 0
    for tid in sorted(by_tid, key=lambda t: (t is None, t)):
        evs = sorted(by_tid[tid], key=lambda e: e.get("id", 0))
        nodes = [make_leaf(ev, depth) for ev in evs]
        nodes = fold(nodes, args.max_period, args.min_reps, not args.no_nesting)
        for nd in nodes:
            registry.register(nd)
        folded_events += sum(len(nd["ids"]) for nd in nodes if nd["kind"] == "loop")
        threads.append({"tid": tid, "events": len(evs), "nodes": nodes})

    meta = {
        "source": args.trace,
        "events": len(events),
        "threads": len(threads),
        "folded_events": folded_events,
        "loops": len(registry.order),
    }

    if args.json:
        doc = {
            "meta": meta,
            "loops": registry.order,
            "threads": [
                {
                    "tid": th["tid"],
                    "events": th["events"],
                    "timeline": [timeline_item(nd, not args.no_inline) for nd in th["nodes"]],
                }
                for th in threads
            ],
        }
        with open(args.json, "w") as f:
            json.dump(doc, f, indent=2)
        print("wrote %s (%d loops, %d events folded)"
              % (args.json, len(registry.order), folded_events), file=sys.stderr)

    print(render_text(meta, registry, threads, args.top))


if __name__ == "__main__":
    main()
