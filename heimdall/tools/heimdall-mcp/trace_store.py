"""DuckDB-backed store for heimdall syscall traces.

Loads a trace (JSON array or JSONL) into an in-memory DuckDB database and exposes
aggregation/filter queries used by the MCP server. Everything returns small,
bounded Python structures — never the raw firehose — so results stay token-cheap
for an LLM client.
"""

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

    def load(self, path):
        path = os.path.abspath(os.path.expanduser(path))
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        with open(path, "r", errors="replace") as f:
            head = f.read(64).lstrip()
        fmt = "array" if head.startswith("[") else "newline_delimited"
        esc = path.replace("'", "''")

        con = duckdb.connect()
        con.execute("PRAGMA threads=4")
        con.execute(
            f"CREATE TABLE events AS SELECT * FROM read_json('{esc}', "
            f"format='{fmt}', columns={_COLS}, maximum_object_size=20000000, "
            f"ignore_errors=true)"
        )
        # `ignore_errors` keeps unparseable input as an all-null row rather than
        # dropping it; a real heimdall record always has an id, so a null id marks
        # junk. Remove it (and count it for the load report) so it neither
        # pollutes queries nor silently inflates the event count.
        skipped = con.execute("SELECT count(*) FROM events WHERE id IS NULL").fetchone()[0]
        if skipped:
            con.execute("DELETE FROM events WHERE id IS NULL")
        # Derived, query-friendly columns.
        con.execute("ALTER TABLE events ADD COLUMN paths VARCHAR")
        con.execute(
            "UPDATE events SET paths = trim(array_to_string("
            "list_concat(coalesce(map_values(string_args), []), "
            "coalesce(map_values(fd_args), [])), ' '))"
        )
        con.execute("ALTER TABLE events ADD COLUMN flags VARCHAR")
        con.execute(
            "UPDATE events SET flags = trim(array_to_string("
            "coalesce(map_values(decoded_args), []), ' '))"
        )
        con.execute("ALTER TABLE events ADD COLUMN stacksig VARCHAR")
        con.execute(
            "UPDATE events SET stacksig = list_aggregate("
            "list_transform(backtrace, x -> x.symbol), 'string_agg', ' ; ')"
        )
        # Flattened frames for origin ("via") queries.
        con.execute(
            "CREATE TABLE frames AS SELECT id AS event_id, fr.frame AS idx, "
            "fr.symbol AS symbol FROM events, UNNEST(backtrace) AS t(fr)"
        )
        self.con = con
        self.path = path

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
        syscalls with fd + result. Peer addresses come from heimdall's sockaddr
        decode (connect/bind/sendto)."""
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
