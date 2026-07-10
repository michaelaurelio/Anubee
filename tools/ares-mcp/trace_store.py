"""DuckDB-backed store for ares syscall traces.

Loads a trace (JSON array or JSONL) into an in-memory DuckDB database and exposes
aggregation/filter queries used by the MCP server. Everything returns small,
bounded Python structures — never the raw firehose — so results stay token-cheap
for an LLM client.

Schema note: ares trace records are type-discriminated ("type":"syscall" for
`ares syscalls`; "stack" for stack snapshots; future "call"/"return"/etc. for
`ares funcs`). This store currently models the syscall records; the explicit
column list below reads only those fields, and any record without an `id`
(stack snapshots, future funcs events) is dropped as a non-syscall row. Adding
funcs analysis means loading those types into their own tables — see
DOCUMENTATION.md "Unified trace schema".
"""

import bisect
import os
import duckdb

MAX_ROWS = 200                 # hard cap on rows any query returns

# Explicit schema so DuckDB never mis-infers the nested/heterogeneous fields.
_COLS = (
    "{'id':'BIGINT','pid':'INTEGER','tid':'INTEGER','syscall_nr':'BIGINT',"
    "'syscall':'VARCHAR','retval':'BIGINT','args':'VARCHAR[]',"
    "'string_args':'MAP(VARCHAR,VARCHAR)','fd_args':'MAP(VARCHAR,VARCHAR)',"
    "'decoded_args':'MAP(VARCHAR,VARCHAR)','sock_addr':'VARCHAR',"
    "'backtrace':'STRUCT(frame INTEGER, addr VARCHAR, symbol VARCHAR)[]'}"
)


def _clamp(n, default=MAX_ROWS):
    """Coerce a model-supplied row limit into [1, MAX_ROWS]. Guards against a
    negative LIMIT (a DuckDB error) or a 0/None/garbage value."""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return default
    return max(1, min(n, MAX_ROWS))


def _errname(ret):
    if ret is not None and ret < 0 and ret >= -4095:
        try:
            return os.strerror(-ret)
        except ValueError:
            return None
    return None


def _build_events(con, path, suffix=""):
    """Load a trace file into `events{suffix}` (+ `frames{suffix}`) tables in the
    given connection, with the derived paths/flags/stacksig columns. Returns
    (abspath, skipped_count). Shared by load() (suffix="") and diff() (which
    builds two table sets, "_a"/"_b", in one connection)."""
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "r", errors="replace") as f:
        head = f.read(64).lstrip()
    fmt = "array" if head.startswith("[") else "newline_delimited"
    esc = path.replace("'", "''")
    ev, fr = "events" + suffix, "frames" + suffix

    con.execute(
        f"CREATE TABLE {ev} AS SELECT * FROM read_json('{esc}', "
        f"format='{fmt}', columns={_COLS}, maximum_object_size=20000000, "
        f"ignore_errors=true)"
    )
    # `ignore_errors` keeps unparseable input as an all-null row rather than
    # dropping it; a real syscall record always has an id, so a null id marks
    # junk (or a non-syscall record type — stack snapshots, future funcs events).
    # Remove it (and count it) so it neither pollutes queries nor silently
    # inflates the event count.
    skipped = con.execute(f"SELECT count(*) FROM {ev} WHERE id IS NULL").fetchone()[0]
    if skipped:
        con.execute(f"DELETE FROM {ev} WHERE id IS NULL")
    # Derived, query-friendly columns.
    con.execute(f"ALTER TABLE {ev} ADD COLUMN paths VARCHAR")
    con.execute(
        f"UPDATE {ev} SET paths = trim(array_to_string("
        "list_concat(coalesce(map_values(string_args), []), "
        "coalesce(map_values(fd_args), [])), ' '))"
    )
    con.execute(f"ALTER TABLE {ev} ADD COLUMN flags VARCHAR")
    con.execute(
        f"UPDATE {ev} SET flags = trim(array_to_string("
        "coalesce(map_values(decoded_args), []), ' '))"
    )
    con.execute(f"ALTER TABLE {ev} ADD COLUMN stacksig VARCHAR")
    con.execute(
        f"UPDATE {ev} SET stacksig = list_aggregate("
        "list_transform(backtrace, x -> x.symbol), 'string_agg', ' ; ')"
    )
    # ASLR-invariant signature for cross-run diffing: keep only frames that
    # resolved to a module/region and drop the raw "0x… [unmapped]" / bare-address
    # frames (anonymous/JIT code or bad unwinds). Their values differ per run, so
    # in a diff they masquerade as new call sites; the module-relative frames are
    # the stable, comparable part. Empty when no frame resolved.
    con.execute(f"ALTER TABLE {ev} ADD COLUMN stack_inv VARCHAR")
    con.execute(
        f"UPDATE {ev} SET stack_inv = list_aggregate(list_filter("
        "list_transform(backtrace, x -> x.symbol), s -> s NOT LIKE '0x%'), "
        "'string_agg', ' ; ')"
    )
    # Flattened frames for origin ("via") queries.
    con.execute(
        f"CREATE TABLE {fr} AS SELECT id AS event_id, fr.frame AS idx, "
        f"fr.symbol AS symbol FROM {ev}, UNNEST(backtrace) AS t(fr)"
    )
    return path, skipped


class TraceStore:
    def __init__(self):
        self.con = None
        self.path = None
        self.last_load = None

    def loaded(self):
        return self.con is not None

    def _require(self):
        if self.con is None:
            raise RuntimeError("no trace loaded — call load_trace(path) first")

    # ---- loading ---------------------------------------------------------

    def load_structured(self, path):
        """Ingest a type-discriminated JSONL file (funcs -J / correlate -o) into
        calls/returns/func_spans/span_syscalls tables. Lines without a "type"
        (the legacy {ts,stream,tag,message} wrapper) are skipped and counted.
        Leaves the syscalls ingest (load()) untouched."""
        import json
        path = os.path.abspath(os.path.expanduser(path))
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        calls, returns, fspans, syscalls, coverage = [], [], [], [], []
        skipped = 0
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    skipped += 1
                    continue
                t = rec.get("type")
                if t == "call":
                    calls.append(rec)
                elif t == "return":
                    returns.append(rec)
                elif t == "func":
                    fspans.append(rec)
                elif t == "syscall" and "span" in rec:
                    syscalls.append(rec)
                elif t == "coverage":
                    coverage.append(rec)
                else:
                    # no "type" (legacy wrapper) or a plain syscalls-engine record
                    skipped += 1
        con = duckdb.connect()
        con.execute("CREATE TABLE calls(pid INTEGER, tid INTEGER, module VARCHAR, "
                    "symbol VARCHAR, entry_addr VARCHAR, args VARCHAR[])")
        con.execute("CREATE TABLE returns(pid INTEGER, tid INTEGER, module VARCHAR, "
                    "symbol VARCHAR, retval BIGINT, elapsed_ns BIGINT)")
        con.execute("CREATE TABLE func_spans(span BIGINT, parent_span BIGINT, "
                    "pid INTEGER, tid INTEGER, entry_addr VARCHAR, args VARCHAR[])")
        con.execute("CREATE TABLE span_syscalls(span BIGINT, pid INTEGER, tid INTEGER, "
                    "nr BIGINT, syscall VARCHAR, args VARCHAR[], decoded VARCHAR[])")
        con.execute("CREATE TABLE coverage(engine VARCHAR, clean BOOLEAN, "
                    "snaps_total BIGINT, snaps_truncated BIGINT, cfi_walks BIGINT, "
                    "ring_drops BIGINT, queue_drops BIGINT, managed_naming_off BOOLEAN, "
                    "prearm_drops BIGINT, depth_capped BIGINT, decode_partial BOOLEAN, "
                    "returns_spans BIGINT, returns_captured BIGINT, "
                    "cfi_stops MAP(VARCHAR, BIGINT))")
        if calls:
            con.executemany("INSERT INTO calls VALUES (?,?,?,?,?,?)",
                [[c.get("pid"), c.get("tid"), c.get("module"), c.get("symbol"),
                  c.get("entry_addr"), c.get("args") or []] for c in calls])
        if returns:
            con.executemany("INSERT INTO returns VALUES (?,?,?,?,?,?)",
                [[r.get("pid"), r.get("tid"), r.get("module"), r.get("symbol"),
                  r.get("retval"), r.get("elapsed_ns")] for r in returns])
        if fspans:
            con.executemany("INSERT INTO func_spans VALUES (?,?,?,?,?,?)",
                [[s.get("span"), s.get("parent_span"), s.get("pid"), s.get("tid"),
                  s.get("entry_addr"), s.get("args") or []] for s in fspans])
        if syscalls:
            con.executemany("INSERT INTO span_syscalls VALUES (?,?,?,?,?,?,?)",
                [[s.get("span"), s.get("pid"), s.get("tid"), s.get("nr"),
                  s.get("syscall"), s.get("args") or [], s.get("decoded") or []]
                 for s in syscalls])
        if coverage:
            def _cov_row(c):
                snaps = c.get("snaps") or {}
                cfi = c.get("cfi") or {}
                drops = c.get("drops") or {}
                rets = c.get("returns") or {}
                return [c.get("engine"), c.get("clean", False),
                        snaps.get("total", 0), snaps.get("truncated", 0),
                        cfi.get("walks", 0),
                        drops.get("ring", 0), drops.get("queue", 0),
                        c.get("managed_naming_off", False),
                        c.get("prearm_drops", 0), c.get("depth_capped", 0),
                        c.get("decode_partial", False),
                        rets.get("spans", 0), rets.get("captured", 0),
                        cfi.get("stops") or {}]
            con.executemany("INSERT INTO coverage VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [_cov_row(c) for c in coverage])
        self.con = con
        self.path = path
        return path, skipped

    def correlate_spans(self, top=50):
        """Join span syscalls to their enclosing function span. One row per
        in-span syscall, carrying the func entry_addr it ran inside."""
        self._require()
        top = _clamp(top)
        rows = self.con.execute(
            "SELECT s.span AS span, s.tid AS tid, s.syscall AS syscall, "
            "f.entry_addr AS func_entry, "
            "array_to_string(s.decoded, ' ') AS decoded "
            "FROM span_syscalls s LEFT JOIN func_spans f USING (span) "
            "ORDER BY s.span LIMIT ?", [top]
        ).fetchall()
        cols = ["span", "tid", "syscall", "func_entry", "decoded"]
        return [dict(zip(cols, r)) for r in rows]

    def coverage(self):
        """All ingested coverage-health records (one per engine record), flattened
        from the nested `{snaps,cfi,drops,returns}` JSON. `is_clean` mirrors the
        `clean` column."""
        self._require()
        return self._rows("SELECT *, clean AS is_clean FROM coverage")

    # ---- funcs analysis (calls/returns) -----------------------------------

    def call_histogram(self, top=40, module=None):
        """Count of function calls per (module, symbol), most frequent first.
        Optional `module` equality filter."""
        self._require()
        top = _clamp(top)
        w, p = ("WHERE module = ?", [module]) if module is not None else ("", [])
        return self._rows(
            f"SELECT module, symbol, COUNT(*) AS n FROM calls {w} "
            f"GROUP BY module, symbol ORDER BY n DESC LIMIT ?", p + [top])

    def call_timing(self, top=40, symbol=None, module=None):
        """Per (module, symbol) call-latency stats from `returns.elapsed_ns`:
        count, min/max/avg, and p50/p95. Optional `symbol`/`module` equality
        filters (AND-combined). Ordered by avg descending."""
        self._require()
        top = _clamp(top)
        where, p = [], []
        if symbol is not None:
            where.append("symbol = ?"); p.append(symbol)
        if module is not None:
            where.append("module = ?"); p.append(module)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        return self._rows(
            f"SELECT module, symbol, COUNT(*) AS count, "
            "MIN(elapsed_ns) AS min, MAX(elapsed_ns) AS max, AVG(elapsed_ns) AS avg, "
            "quantile_cont(elapsed_ns, 0.5) AS p50, quantile_cont(elapsed_ns, 0.95) AS p95 "
            f"FROM returns{w} GROUP BY module, symbol ORDER BY avg DESC LIMIT ?", p + [top])

    def calls_where(self, module=None, symbol=None, pid=None, tid=None, limit=50):
        """Filtered list of raw call records. Filters (AND-combined): `module`,
        `symbol`, `pid`, `tid` equality."""
        self._require()
        limit = _clamp(limit, default=50)
        where, p = [], []
        if module is not None:
            where.append("module = ?"); p.append(module)
        if symbol is not None:
            where.append("symbol = ?"); p.append(symbol)
        if pid is not None:
            where.append("pid = ?"); p.append(pid)
        if tid is not None:
            where.append("tid = ?"); p.append(tid)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        return self._rows(f"SELECT * FROM calls{w} LIMIT ?", p + [limit])

    def load(self, path):
        con = duckdb.connect()
        con.execute("PRAGMA threads=4")
        abspath, skipped = _build_events(con, path, "")
        self.con = con
        self.path = abspath

        # Report how many records loaded and how many malformed ones were
        # dropped, so a bad trace doesn't silently mis-count.
        report = {"rows": self._one("SELECT count(*) FROM events")}
        if skipped:
            report["skipped"] = skipped
        self.last_load = report

        ov = self.overview()
        ov["load_report"] = report
        return ov

    # ---- helpers ---------------------------------------------------------

    def _rows(self, sql, params=None):
        rel = self.con.execute(sql, params or [])
        cols = [d[0] for d in rel.description]
        return [dict(zip(cols, r)) for r in rel.fetchall()]

    def _one(self, sql, params=None):
        r = self.con.execute(sql, params or []).fetchone()
        return r[0] if r else None

    # ---- summaries -------------------------------------------------------

    def overview(self):
        self._require()
        return {
            "trace": self.path,
            "events": self._one("SELECT count(*) FROM events"),
            "id_range": [self._one("SELECT min(id) FROM events"),
                         self._one("SELECT max(id) FROM events")],
            "threads": self._rows(
                "SELECT tid, count(*) AS events FROM events GROUP BY 1 "
                "ORDER BY events DESC"),
            "top_syscalls": self._rows(
                "SELECT syscall, count(*) AS count FROM events GROUP BY 1 "
                "ORDER BY count DESC LIMIT 25"),
            "distinct_files": self._one(
                "SELECT count(DISTINCT v) FROM (SELECT unnest(map_values(string_args)) v "
                "FROM events WHERE cardinality(string_args) > 0)"),
            "socket_calls": self._one(
                "SELECT count(*) FROM events WHERE syscall IN "
                "('connect','sendto','recvfrom','bind','sendmsg','recvmsg')"),
            "distinct_endpoints": self._one(
                "SELECT count(DISTINCT sock_addr) FROM events WHERE sock_addr IS NOT NULL"),
            "errors_top": self._rows(
                "SELECT syscall, count(*) AS count FROM events WHERE retval < 0 "
                "GROUP BY 1 ORDER BY count DESC LIMIT 10"),
        }

    def syscall_histogram(self, top=40, tid=None):
        self._require()
        w, p = ("WHERE tid = ?", [tid]) if tid is not None else ("", [])
        top = _clamp(top)
        return self._rows(
            f"SELECT syscall, count(*) AS count FROM events {w} GROUP BY 1 "
            f"ORDER BY count DESC LIMIT {top}", p)

    def files(self, top=50, contains=None):
        self._require()
        top = _clamp(top)
        return self._rows(
            "SELECT path, count(*) AS count FROM "
            "(SELECT unnest(map_values(string_args)) AS path FROM events "
            " WHERE cardinality(string_args) > 0) "
            "WHERE (? IS NULL OR path LIKE '%' || ? || '%') "
            f"GROUP BY 1 ORDER BY count DESC LIMIT {top}", [contains, contains])

    def threads(self):
        self._require()
        out = []
        for t in self._rows("SELECT tid, count(*) AS events FROM events GROUP BY 1 "
                            "ORDER BY events DESC"):
            t["top_syscalls"] = self._rows(
                "SELECT syscall, count(*) AS count FROM events WHERE tid = ? "
                "GROUP BY 1 ORDER BY count DESC LIMIT 6", [t["tid"]])
            out.append(t)
        return out

    def sockets(self):
        """Network/socket activity. `endpoints` aggregates the decoded peer
        addresses (ip:port / unix path) with counts; `calls` lists the socket
        syscalls with fd + result. Peer addresses come from the syscalls engine's
        sockaddr decode (connect/bind/sendto)."""
        self._require()
        endpoints = self._rows(
            "SELECT sock_addr AS endpoint, any_value(syscall) AS syscall, "
            "count(*) AS count FROM events WHERE sock_addr IS NOT NULL "
            "GROUP BY sock_addr ORDER BY count DESC LIMIT %d" % MAX_ROWS)
        calls = self._rows(
            "SELECT id, tid, syscall, retval, sock_addr, "
            "array_to_string(map_values(fd_args), ' ') AS fd FROM events "
            "WHERE syscall IN ('connect','bind','sendto','recvfrom','sendmsg',"
            "'recvmsg','socket','accept','accept4') ORDER BY id LIMIT %d" % MAX_ROWS)
        return {"endpoints": endpoints, "calls": calls}

    def errors(self, top=40):
        self._require()
        top = _clamp(top)
        rows = self._rows(
            "SELECT syscall, retval, count(*) AS count FROM events WHERE retval < 0 "
            f"GROUP BY 1, 2 ORDER BY count DESC LIMIT {top}")
        for r in rows:
            r["errno"] = _errname(r["retval"])
        return rows

    # ---- filtered query --------------------------------------------------

    def query(self, syscall=None, tid=None, path_contains=None, via=None,
              only_errors=False, retval=None, id_min=None, id_max=None, limit=50):
        self._require()
        limit = _clamp(limit, default=50)
        where, p = [], []
        if syscall:
            names = [s.strip() for s in syscall.split(",") if s.strip()]
            where.append("syscall IN (" + ",".join(["?"] * len(names)) + ")")
            p += names
        if tid is not None:
            where.append("tid = ?"); p.append(tid)
        if path_contains:
            where.append("paths LIKE '%' || ? || '%'"); p.append(path_contains)
        if via:
            where.append("id IN (SELECT event_id FROM frames WHERE symbol LIKE '%' || ? || '%')")
            p.append(via)
        if only_errors:
            where.append("retval < 0")
        if retval is not None:
            where.append("retval = ?"); p.append(retval)
        if id_min is not None:
            where.append("id >= ?"); p.append(id_min)
        if id_max is not None:
            where.append("id <= ?"); p.append(id_max)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        matched = self._one(f"SELECT count(*) FROM events{w}", p)
        rows = self._rows(
            "SELECT id, tid, syscall, retval, "
            "array_to_string(map_values(string_args), ' ') AS str, "
            "array_to_string(map_values(fd_args), ' ') AS fd, flags "
            f"FROM events{w} ORDER BY id LIMIT {limit}", p)
        for r in rows:
            r["err"] = _errname(r["retval"])
        return {"matched": matched, "returned": len(rows), "limit": limit, "events": rows}

    def get_event(self, event_id):
        self._require()
        rows = self._rows(
            "SELECT id, pid, tid, syscall, syscall_nr, retval, args, "
            "string_args, fd_args, decoded_args, "
            "list_transform(backtrace, x -> {'frame': x.frame, 'symbol': x.symbol}) AS backtrace "
            "FROM events WHERE id = ?", [event_id])
        if not rows:
            return None
        ev = rows[0]
        ev["err"] = _errname(ev["retval"])
        return ev

    def distinct_backtraces(self, syscall=None, via=None, top=20):
        self._require()
        top = _clamp(top)
        where, p = [], []
        if syscall:
            where.append("syscall = ?"); p.append(syscall)
        if via:
            where.append("id IN (SELECT event_id FROM frames WHERE symbol LIKE '%' || ? || '%')")
            p.append(via)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        return self._rows(
            "SELECT stacksig AS stack, count(*) AS count, min(id) AS example_id, "
            "any_value(syscall) AS syscall "
            f"FROM events{w} GROUP BY stacksig ORDER BY count DESC LIMIT {top}", p)

    def search(self, text, limit=50):
        self._require()
        limit = _clamp(limit, default=50)
        return self._rows(
            "SELECT id, tid, syscall, retval, "
            "array_to_string(map_values(string_args), ' ') AS str "
            "FROM events WHERE paths LIKE '%' || ? || '%' OR stacksig LIKE '%' || ? || '%' "
            f"ORDER BY id LIMIT {limit}", [text, text])

    # ---- diff two traces -------------------------------------------------

    def diff(self, baseline, compare, top=50, via=None):
        """Compare a `baseline` trace (e.g. a clean device) against a `compare`
        trace (rooted/hooked/emulator) and report what is NEW in `compare` — the
        probes/branches/resources that fired only there. The diff is over
        ASLR-invariant dimensions: call stacks are compared on their resolved
        (module/region-relative) frames only — raw "0x… [unmapped]" frames are
        dropped so per-run address jitter doesn't fake up new stacks — and paths
        have volatile numeric segments normalized. Does not disturb the active
        trace. `via` restricts the new-stack list to events with that substring
        in a backtrace frame."""
        top = _clamp(top)
        con = duckdb.connect()
        con.execute("PRAGMA threads=4")
        try:
            pa, ska = _build_events(con, baseline, "_a")
            pb, skb = _build_events(con, compare, "_b")

            def rows(sql, params=None):
                rel = con.execute(sql, params or [])
                cols = [d[0] for d in rel.description]
                return [dict(zip(cols, r)) for r in rel.fetchall()]

            def one(sql, params=None):
                r = con.execute(sql, params or []).fetchone()
                return r[0] if r else None

            # Syscalls seen only in the compare run.
            new_syscalls = rows(
                "SELECT syscall, count(*) AS count FROM events_b b WHERE NOT EXISTS "
                "(SELECT 1 FROM events_a a WHERE a.syscall = b.syscall) "
                f"GROUP BY 1 ORDER BY count DESC LIMIT {top}")

            # (syscall, path) probed only in compare, with volatile numeric path
            # segments (pids/fds/tids) collapsed to '#' so the diff is meaningful.
            norm = (
                "WITH pa AS (SELECT DISTINCT syscall, "
                "  regexp_replace(p, '[0-9]+', '#', 'g') AS np "
                "  FROM (SELECT syscall, unnest(map_values(string_args)) AS p "
                "        FROM events_a WHERE cardinality(string_args) > 0)), "
                "pb AS (SELECT syscall, regexp_replace(p, '[0-9]+', '#', 'g') AS np "
                "       FROM (SELECT syscall, unnest(map_values(string_args)) AS p "
                "             FROM events_b WHERE cardinality(string_args) > 0)) ")
            new_paths = rows(
                norm +
                "SELECT np AS path, syscall, count(*) AS count FROM pb b "
                "WHERE NOT EXISTS (SELECT 1 FROM pa a WHERE a.np = b.np AND a.syscall = b.syscall) "
                f"GROUP BY np, syscall ORDER BY count DESC LIMIT {top}")

            # Distinct call stacks (branches/checks) that fired only in compare.
            # Compared on the ASLR-invariant signature (resolved frames only), so
            # differing raw [unmapped] addresses don't fake up new stacks.
            via_clause = ("AND id IN (SELECT event_id FROM frames_b "
                          "WHERE symbol LIKE '%' || ? || '%') ") if via else ""
            vp = [via] if via else []
            new_stacks = rows(
                "SELECT stack_inv AS stack, count(*) AS count, min(id) AS example_id, "
                "any_value(syscall) AS syscall FROM events_b b "
                "WHERE stack_inv IS NOT NULL AND stack_inv <> '' " + via_clause +
                "AND NOT EXISTS (SELECT 1 FROM events_a a WHERE a.stack_inv = b.stack_inv) "
                f"GROUP BY stack_inv ORDER BY count DESC LIMIT {top}", vp)

            # (syscall, errno) failures only in compare (new probes/denials).
            new_errors = rows(
                "SELECT syscall, retval, count(*) AS count FROM events_b b "
                "WHERE retval < 0 AND NOT EXISTS "
                "(SELECT 1 FROM events_a a WHERE a.syscall = b.syscall AND a.retval = b.retval) "
                f"GROUP BY 1, 2 ORDER BY count DESC LIMIT {top}")
            for r in new_errors:
                r["errno"] = _errname(r["retval"])

            # Peer endpoints contacted only in compare.
            new_endpoints = rows(
                "SELECT sock_addr AS endpoint, count(*) AS count FROM events_b b "
                "WHERE sock_addr IS NOT NULL AND NOT EXISTS "
                "(SELECT 1 FROM events_a a WHERE a.sock_addr = b.sock_addr) "
                f"GROUP BY 1 ORDER BY count DESC LIMIT {top}")

            summary = {
                "baseline": pa, "compare": pb,
                "baseline_events": one("SELECT count(*) FROM events_a"),
                "compare_events": one("SELECT count(*) FROM events_b"),
                "new_stacks": one(
                    "SELECT count(*) FROM (SELECT DISTINCT stack_inv FROM events_b "
                    "WHERE stack_inv IS NOT NULL AND stack_inv <> '' AND stack_inv NOT IN "
                    "(SELECT stack_inv FROM events_a WHERE stack_inv IS NOT NULL AND stack_inv <> ''))"),
                "new_syscalls": one(
                    "SELECT count(*) FROM (SELECT DISTINCT syscall FROM events_b "
                    "WHERE syscall NOT IN (SELECT syscall FROM events_a))"),
                "new_endpoints": one(
                    "SELECT count(*) FROM (SELECT DISTINCT sock_addr FROM events_b "
                    "WHERE sock_addr IS NOT NULL AND sock_addr NOT IN "
                    "(SELECT sock_addr FROM events_a WHERE sock_addr IS NOT NULL))"),
            }
            if ska:
                summary["baseline_skipped"] = ska
            if skb:
                summary["compare_skipped"] = skb

            return {
                "summary": summary,
                "new_syscalls": new_syscalls,
                "new_paths": new_paths,
                "new_stacks": new_stacks,
                "new_errors": new_errors,
                "new_endpoints": new_endpoints,
            }
        finally:
            con.close()

    # ---- W^X / memory-tamper finder --------------------------------------

    @staticmethod
    def _prot_str(prot):
        if prot == 0:
            return "PROT_NONE"
        parts = []
        if prot & 1: parts.append("PROT_READ")
        if prot & 2: parts.append("PROT_WRITE")
        if prot & 4: parts.append("PROT_EXEC")
        if prot & ~7: parts.append("0x%x" % (prot & ~7))
        return "|".join(parts)

    def wx_scan(self, top=50):
        """Surface self-modifying / unpacking memory behavior — the
        decrypt-then-execute signature of packers and JIT-decrypt RASP. Reports
        RWX maps (W+X in one call), W->X transitions (a region made executable
        after being writable), and self-targeting process_vm_readv/ptrace
        (integrity self-checks / anti-debug), each grouped by call site."""
        self._require()
        top = _clamp(top)
        PROT_W, PROT_X = 2, 4

        rows = self._rows(
            "SELECT id, retval, syscall, args, stack_inv AS stack "
            "FROM events WHERE syscall IN ('mprotect','pkey_mprotect','mmap') ORDER BY id")

        ever_w = []                  # merged [start,end) ranges ever made writable
        rwx, wtx = {}, {}
        n_mprotect = n_mmap = 0

        def add_ivl(s, e):
            i = bisect.bisect_left(ever_w, (s, e))
            ever_w.insert(i, (s, e))
            # ever_w stays sorted+disjoint everywhere except around the interval
            # we just inserted — merge only that local window (AA8).
            lo, hi = max(0, i - 1), min(len(ever_w), i + 2)
            merged = []
            for a, b in ever_w[lo:hi]:
                if merged and a <= merged[-1][1]:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], b))
                else:
                    merged.append((a, b))
            ever_w[lo:hi] = merged

        def overlaps(s, e):
            for a, b in ever_w:
                if s < b and a < e:
                    return True
                if a >= e:
                    break
            return False

        def bump(d, r, prot):
            k = r["stack"] or "<unresolved>"
            ent = d.get(k)
            if ent is None:
                ent = d[k] = {"stack": k, "count": 0, "example_id": r["id"],
                              "syscall": r["syscall"], "prot": self._prot_str(prot)}
            ent["count"] += 1

        for r in rows:
            args = r["args"] or []
            try:
                if r["syscall"] in ("mprotect", "pkey_mprotect"):
                    base = int(args[0], 16); length = int(args[1], 16); prot = int(args[2], 16)
                    n_mprotect += 1
                else:                                  # mmap: base is the return value
                    if r["retval"] is None or r["retval"] < 0:
                        continue
                    base = int(r["retval"]); length = int(args[1], 16); prot = int(args[2], 16)
                    n_mmap += 1
            except (IndexError, ValueError, TypeError):
                continue
            if length <= 0:
                continue
            s, e = base, base + length
            w, x = bool(prot & PROT_W), bool(prot & PROT_X)
            if w and x:
                bump(rwx, r, prot)                     # RWX in a single call
            elif x and overlaps(s, e):
                bump(wtx, r, prot)                     # made executable after being writable
            if w:
                add_ivl(s, e)

        # Self-inspection: process_vm_*/ptrace aimed at the app's own process.
        si = {}
        for r in self._rows(
                "SELECT id, pid, syscall, args, stack_inv AS stack "
                "FROM events WHERE syscall IN ('process_vm_readv','process_vm_writev','ptrace')"):
            args = r["args"] or []
            try:
                if r["syscall"] in ("process_vm_readv", "process_vm_writev"):
                    is_self = int(args[0], 16) == r["pid"]
                else:                                  # ptrace(request, pid, ...)
                    is_self = int(args[0], 16) == 0 or int(args[1], 16) == r["pid"]
            except (IndexError, ValueError, TypeError):
                continue
            if not is_self:
                continue
            k = r["stack"] or "<unresolved>"
            ent = si.get(k)
            if ent is None:
                ent = si[k] = {"stack": k, "count": 0, "example_id": r["id"],
                               "syscall": r["syscall"]}
            ent["count"] += 1

        def top_list(d):
            return sorted(d.values(), key=lambda v: v["count"], reverse=True)[:top]

        return {
            "summary": {
                "mprotect_events": n_mprotect,
                "mmap_events": n_mmap,
                "rwx_maps": len(rwx),
                "w_then_x_sites": len(wtx),
                "self_inspection_sites": len(si),
            },
            "rwx_maps": top_list(rwx),
            "w_then_x": top_list(wtx),
            "self_inspection": top_list(si),
        }

    # ---- loop folding ----------------------------------------------------

    def hot_loops(self, min_reps=3, max_period=32, tid=None, top=30):
        """Fold repeated consecutive syscall sequences (loops) per thread and
        return the bodies + iteration counts — the biggest data reducer."""
        self._require()
        tids = ([tid] if tid is not None
                else [r["tid"] for r in self._rows("SELECT DISTINCT tid FROM events")])
        loops = {}
        for t in tids:
            rows = self._rows(
                "SELECT id, syscall, coalesce(stacksig, '') AS sig FROM events "
                "WHERE tid = ? ORDER BY id", [t])
            nodes = [{"tok": (r["syscall"], r["sig"]), "name": r["syscall"],
                      "ids": [r["id"]], "body": None} for r in rows]
            for nd in _fold(nodes, max_period, min_reps):
                _collect_loops(nd, loops)
        out = sorted(loops.values(), key=lambda l: l["iterations_total"], reverse=True)
        return out[:top]


# ---- folding internals (tandem-run, smallest-period, nested) --------------

def _find_runs(toks, max_period, min_reps):
    n = len(toks)
    runs = []
    for p in range(1, min(max_period, n // 2) + 1):
        i = 0
        while i + p < n:
            m = 0
            while i + p + m < n and toks[i + m] == toks[i + p + m]:
                m += 1
            k = (m + p) // p
            if k >= min_reps:
                runs.append((p, i, k)); i += k * p
            else:
                i += 1
    return runs


def _select(runs):
    runs.sort(key=lambda r: (r[0], -(r[0] * r[2]), r[1]))
    chosen, occ = [], []
    for p, i, k in runs:
        lo, hi = i, i + p * k
        if any(not (hi <= a or lo >= b) for a, b in occ):
            continue
        chosen.append((p, i, k)); occ.append((lo, hi))
    return chosen


def _fold(nodes, max_period, min_reps):
    while True:
        chosen = _select(_find_runs([nd["tok"] for nd in nodes], max_period, min_reps))
        if not chosen:
            return nodes
        starts = {i: (p, k) for p, i, k in chosen}
        out, idx = [], 0
        while idx < len(nodes):
            if idx in starts:
                p, k = starts[idx]
                body = nodes[idx:idx + p]
                span = nodes[idx:idx + p * k]
                ids = [x for nd in span for x in nd["ids"]]
                out.append({"tok": ("LOOP", tuple(b["tok"] for b in body), k),
                            "name": None, "ids": ids, "body": (body, k)})
                idx += p * k
            else:
                out.append(nodes[idx]); idx += 1
        nodes = out


def _body_desc(body):
    parts = []
    for b in body:
        if b["body"]:
            inner, k = b["body"]
            parts.append("[%s]x%d" % (" ".join(_body_desc(inner)), k))
        else:
            parts.append(b["name"])
    return parts


def _collect_loops(node, loops):
    if not node.get("body"):
        return
    body, iters = node["body"]
    for b in body:
        _collect_loops(b, loops)            # nested loops first
    desc = _body_desc(body)
    sig = " ; ".join(desc)
    e = loops.get(sig)
    if e is None:
        e = loops[sig] = {"body": desc, "period": len(body),
                          "iterations_total": 0, "occurrences": 0,
                          "example_ids": [node["ids"][0], node["ids"][-1]]}
    e["iterations_total"] += iters
    e["occurrences"] += 1
