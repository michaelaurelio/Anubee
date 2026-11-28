// SPDX-License-Identifier: GPL-2.0
// "What's new" findings core of the mod run view: a line-for-line port of
// tools/anubee-mcp/mod_findings.py, kept in step with it by the shared
// fixtures under testdata/. Plain script: defines the AnubeeModView global in
// a browser and sets module.exports under Node.
var AnubeeModView = (function () {
  'use strict';

  var PROFILE_VERSION = 1;
  var KNOWN_SECTIONS = { binder: 1, file: 1, exec: 1, net: 1, perm: 1, a11y: 1, dexload: 1, prop: 1, proc: 1 };

  var INSTALL_DIR = /\/data\/app\/~~[^/]+\/[^/]+-[^/]+\//g;
  var PROC_PID = /\/proc\/\d+/g;
  var TASK_TID = /\/task\/\d+/g;
  var HEX = /0x[0-9a-fA-F]+/g;
  var LONG_NUM = /\d{6,}/g;

  // Python truthiness: None, 0, "", [] and {} are all falsy.
  function truthy(v) {
    if (v === undefined || v === null || v === false || v === 0 || v === '') return false;
    if (Array.isArray(v)) return v.length > 0;
    if (typeof v === 'object') return Object.keys(v).length > 0;
    return true;
  }
  function or(a, b) { return truthy(a) ? a : b; }
  // Python str()/f-string of a JSON value.
  function str(v) {
    if (v === undefined || v === null) return 'None';
    if (v === true) return 'True';
    if (v === false) return 'False';
    return String(v);
  }
  function basename(p) {
    var i = p.lastIndexOf('/');
    return i < 0 ? p : p.slice(i + 1);
  }

  function norm(s, pkg) {
    if (!truthy(s)) return '';
    if (pkg) s = s.split(pkg).join('<pkg>');
    s = s.replace(INSTALL_DIR, '/data/app/<install>/');
    s = s.replace(PROC_PID, '/proc/<pid>');
    s = s.replace(TASK_TID, '/task/<tid>');
    s = s.replace(HEX, '<hex>');
    return s.replace(LONG_NUM, '<n>');
  }

  // null = SKIP (carries no behaviour); unknown types -> [type, type].
  function recordKey(r, pkg) {
    var t = r.type === undefined || r.type === null ? '' : r.type;
    if (t === 'coverage' || t.slice(-8) === '_summary') return null;
    if (t === 'binder_api') {
      var m = or(r.method, '#' + str(r.code));
      return ['binder', str(r.interface) + '.' + m];
    }
    if (t === 'file_access') {
      if ((r.categories || []).indexOf('own_app_dir') >= 0) return null;
      return ['file', norm(r.path, pkg)];
    }
    if (t === 'execve') {
      var argv = or(r.argv, [basename(r.filename || '')]);
      return ['exec', norm(argv.join(' '), pkg)];
    }
    if (t === 'net') {
      if (r.event === 'close') return null;
      return ['net', str(r.proto) + ' ' + norm(or(r.host, r.dest), pkg)];
    }
    if (t === 'perm_change') {
      if (r.change === 'baseline') return null;
      return ['perm', str(r.category) + ' ' + str(r.name) + ' -> ' + str(r.new)];
    }
    if (t === 'accessibility_detect') return ['a11y', str(r.category) + ' ' + str(r.method)];
    if (t === 'dexload_detect') return ['dexload', str(r.stage) + ' ' + str(r.kind) + ' ' + norm(r.path, pkg)];
    if (t === 'prop_read') return ['prop', str(or(r.name, r.property))];
    if (t === 'proc_exit') return ['proc', 'exit signal ' + str(r.signal)];
    if (t === 'spawn') return ['proc', 'spawn'];
    return [t, t];
  }

  function inferPackage(records) {
    for (var i = 0; i < records.length; i++) {
      var r = records[i];
      if (r.type === 'perm_change' && r.package) return r.package;
    }
    return null;
  }

  function isNoise(prof, section, key) {
    if (!KNOWN_SECTIONS[section]) return false;
    var n = (prof.keys || {})[section + '\t' + key] || 0;
    return n >= (prof.min_apps === undefined ? 1 : prof.min_apps);
  }

  function has(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }

  function findings(records, profile, pkg) {
    pkg = pkg || inferPackage(records);
    var sections = {}, order = [], hidden = {}, index = {};
    var cov = { records: 0, degraded: [] };
    records.forEach(function (r) {
      var k = recordKey(r, pkg);
      if (r.type === 'coverage') {
        cov.records++;
        if (!r.clean && !r.exempt) cov.degraded.push(r.engine);
      }
      if (k === null) return;
      var sec = k[0], key = k[1];
      if (isNoise(profile, sec, key)) {
        var h = has(hidden, sec) ? hidden[sec] : (hidden[sec] = { records: 0, keys: {} });
        h.records++;
        h.keys[key] = 1;
        return;
      }
      var ik = sec + '\u0000' + key;
      var f = has(index, ik) ? index[ik] : null;
      if (!f) {
        f = { key: key, count: 0, firstTs: r.ts_ns === undefined ? null : r.ts_ns, errors: {} };
        index[ik] = f;
        if (!has(sections, sec)) { sections[sec] = []; order.push(sec); }
        sections[sec].push(f);
      }
      f.count++;
      if (r.error) f.errors[r.error] = (f.errors[r.error] || 0) + 1;
    });
    function first(sec) {
      var best = 1e18 * 1e9;
      sections[sec].forEach(function (f) { if (f.firstTs !== null && f.firstTs < best) best = f.firstTs; });
      return best;
    }
    // Stable sort by earliest first appearance; sections with no timestamp go last.
    var sorted = order.map(function (s, i) { return [first(s), i, s]; })
      .sort(function (a, b) { return a[0] - b[0] || a[1] - b[1]; });
    var outSections = {}, outHidden = {};
    sorted.forEach(function (e) { outSections[e[2]] = sections[e[2]]; });
    Object.keys(hidden).forEach(function (s) {
      outHidden[s] = { records: hidden[s].records, keys: Object.keys(hidden[s].keys).length };
    });
    return { sections: outSections, hidden: outHidden, coverage: cov };
  }

  // ---- attribution and step building ----
  var NS = 1e9;
  var GRANT_EXTEND_NS = 2 * NS;       // a grant's effect lands up to 2 s after its end mark
  var LAB_MERGE_GAP_NS = 10 * NS;     // grant windows closer than this are one lab step
  var DROP_NET_WINDOW_NS = 120 * NS;  // a net open this soon before a drop = downloaded
  var TEMPLATE_ORDER = ['detonation', 'payload_packed', 'payload_downloaded', 'payload_memload',
    'persistence', 'c2_beacon', 'net_contact', 'lab_grant', 'perm_unattributed', 'a11y_abuse',
    'exec', 'file_probe', 'recorded'];

  function parseMarks(text) {
    var out = [];
    String(text || '').split('\n').forEach(function (line) {
      line = line.trim();
      if (!line) return;
      var o;
      try { o = JSON.parse(line); } catch (e) { return; }
      if (!o || typeof o.ts_ns !== 'number' || typeof o.label !== 'string') return;
      out.push({ ts: o.ts_ns, label: o.label });
    });
    return out;
  }

  // Grant windows: each grant-begin:<k> up to the next grant-end:<k>. A begin
  // with no end is not a window (we do not know when it stopped).
  function grantWindows(marks) {
    var sorted = (marks || []).slice().sort(function (a, b) { return a.ts - b.ts; });
    var wins = [];
    sorted.forEach(function (m, i) {
      var b = /^grant-begin:(.+)$/.exec(m.label);
      if (!b) return;
      for (var j = i + 1; j < sorted.length; j++) {
        if (sorted[j].label === 'grant-end:' + b[1]) {
          wins.push({ key: b[1], begin: m.ts, end: sorted[j].ts });
          return;
        }
      }
    });
    return wins;
  }
  function windowOf(rec, wins) {
    if (typeof rec.ts_ns !== 'number') return -1;
    for (var i = 0; i < wins.length; i++) {
      if (rec.ts_ns >= wins[i].begin && rec.ts_ns <= wins[i].end + GRANT_EXTEND_NS) return i;
    }
    return -1;
  }
  function labCaused(rec, marks) { return windowOf(rec, grantWindows(marks)) >= 0; }

  function median(xs) {
    var s = xs.slice().sort(function (a, b) { return a - b; });
    var n = s.length;
    return n % 2 ? s[(n - 1) >> 1] : (s[n / 2 - 1] + s[n / 2]) / 2;
  }

  // Longest run of >= 4 consecutive gaps all within +-20 % of the run's median.
  function beaconWindow(tsList) {
    var ts = tsList.slice().sort(function (a, b) { return a - b; });
    var gaps = [];
    for (var k = 1; k < ts.length; k++) gaps.push((ts[k] - ts[k - 1]) / NS);
    var best = null;
    for (var i = 0; i + 4 <= gaps.length; i++) {
      if (best && gaps.length - i <= best.len) break;   // cannot beat the best any more
      for (var j = i + 3; j < gaps.length; j++) {
        var med = median(gaps.slice(i, j + 1)), ok = med > 0;
        for (var q = i; ok && q <= j; q++) ok = Math.abs(gaps[q] - med) <= 0.2 * med;
        if (!ok) break;
        var len = j - i + 1;
        if (!best || len > best.len) best = { len: len, i: i, j: j, med: med };
      }
    }
    if (!best) return null;
    return { intervalS: best.med, fromTs: ts[best.i], toTs: ts[best.j + 1] };
  }

  // proc_exit records each paired with a distinct pid first seen after that
  // exit. Time order, not file order (the sink groups records by type).
  function respawns(records) {
    var seen = new Set(), pending = 0, n = 0;
    records.filter(function (r) { return typeof r.ts_ns === 'number'; })
      .sort(function (a, b) { return a.ts_ns - b.ts_ns; })
      .forEach(function (r) {
        if (typeof r.pid !== 'number') return;
        if (!seen.has(r.pid)) {
          seen.add(r.pid);
          if (pending > 0) { pending--; n++; }
        }
        if (r.type === 'proc_exit') pending++;
      });
    return n;
  }

  function minTs(recs) {
    var best = null;
    recs.forEach(function (r) {
      if (typeof r.ts_ns === 'number' && (best === null || r.ts_ns < best)) best = r.ts_ns;
    });
    return best;
  }
  function mkStep(template, actor, recs, data) {
    return { template: template, actor: actor, firstTs: minTs(recs), recs: recs, data: data || {} };
  }
  function permSummary(recs) {
    return recs.map(function (r) { return { category: r.category, name: r.name, change: r.change, old: r.old, new: r.new }; });
  }

  var PERSIST_KEYS = ['IAlarmManager.set', 'IActivityManager.setServiceForeground'];
  function isPersistKey(key) {
    return PERSIST_KEYS.some(function (s) { return key.slice(-s.length) === s; });
  }

  function netOpensBefore(opens, ts) {
    var found = null;
    opens.forEach(function (r) {
      if (typeof r.ts_ns === 'number' && r.ts_ns < ts && ts - r.ts_ns <= DROP_NET_WINDOW_NS &&
          (found === null || r.ts_ns > found)) found = r.ts_ns;
    });
    return found;
  }

  // A DNS question, or a flow to the resolver: a lookup, not a connection to the named host.
  function isLookup(r) {
    return r.type === 'net' && (r.event === 'dns' || r.host_source === 'dns' || /:53$/.test(str(r.dest)));
  }

  function payloadStep(recs, opens, hidden) {
    var drop = recs.filter(function (r) { return r.stage === 'drop'; })[0];
    var first = recs[0];
    var saved = null;
    recs.forEach(function (r) { if (r.saved) saved = r.saved; });
    var dts = drop && typeof drop.ts_ns === 'number' ? drop.ts_ns : null;
    var netTs = dts !== null ? netOpensBefore(opens, dts) : null;
    var anyOpen = function (list, test) {
      return dts !== null && list.some(function (r) { return typeof r.ts_ns === 'number' && test(r.ts_ns); });
    };
    var stages = recs.map(function (r) { return r.stage; });
    return mkStep(netTs !== null ? 'payload_downloaded' : 'payload_packed', 'sample', recs, {
      path: first.path === undefined ? null : first.path, kind: first.kind, ino: first.ino,
      stages: stages, dropped: !!drop, loaded: stages.indexOf('load') >= 0,
      deleted: stages.indexOf('delete') >= 0,
      sha256: saved ? saved.sha256 : null, size: saved ? saved.size : null,
      netBeforeTs: netTs,
      // from the same noise-filtered open set that classifies the step
      netBeforeAny: anyOpen(opens, function (t) { return t < dts; }),
      netAfter: anyOpen(opens, function (t) { return t > dts; }),
      hiddenNetBefore: anyOpen(hidden, function (t) { return t < dts && dts - t <= DROP_NET_WINDOW_NS; }),
      hiddenNetEver: anyOpen(hidden, function (t) { return t < dts; })
    });
  }

  function buildSteps(records, marks, profile, pkg) {
    pkg = pkg || inferPackage(records);
    marks = marks || [];
    var wins = grantWindows(marks);
    var steps = [];
    var groups = new Map();           // (section, key) -> records, in first-seen order
    var payloads = new Map();         // ino -> dexload records
    var memloads = [], persist = [], a11y = [], opens = [], hidden = [], labPerm = [], otherPerm = [];
    var lookups = new Map();          // looked-up name -> {name, count, firstTs}

    records.forEach(function (r) {
      var k = recordKey(r, pkg);
      if (k === null) return;
      if (isNoise(profile, k[0], k[1])) {
        if (k[0] === 'net' && r.event === 'open' && !isLookup(r)) hidden.push(r);
        return;
      }
      var sec = k[0], key = k[1];
      if (isLookup(r)) {
        // never a connection: only the looked-up names are kept
        var nm = str(r.host).trim();
        if (present(r.host) && nm) {
          var lk = lookups.get(nm) || { name: nm, count: 0, firstTs: null };
          lk.count++;
          if (typeof r.ts_ns === 'number' && (lk.firstTs === null || r.ts_ns < lk.firstTs)) lk.firstTs = r.ts_ns;
          lookups.set(nm, lk);
        }
        return;
      }
      if (sec === 'net' && r.event === 'open') opens.push(r);
      if (sec === 'dexload') {
        if (r.stage === 'memload') memloads.push(r);
        else {
          var pk = r.ino ? 'i' + r.ino : 'p' + str(r.path);
          if (!payloads.has(pk)) payloads.set(pk, []);
          payloads.get(pk).push(r);
        }
        return;
      }
      if (sec === 'perm') {
        (windowOf(r, wins) >= 0 ? labPerm : otherPerm).push(r);
        return;
      }
      if (sec === 'a11y') { a11y.push(r); return; }
      if (sec === 'binder') {
        if (isPersistKey(key)) persist.push(r);
        return;                       // unclaimed binder calls are footer counts only
      }
      if (sec === 'proc' && r.type === 'proc_exit') { persist.push(r); return; }
      var gk = sec + '\u0000' + key;
      if (!groups.has(gk)) groups.set(gk, { sec: sec, key: key, recs: [] });
      groups.get(gk).recs.push(r);
    });

    marks.forEach(function (m) {
      if (m.label === 'launch') steps.push({ template: 'detonation', actor: 'lab', firstTs: m.ts, recs: [], data: { label: m.label } });
    });

    payloads.forEach(function (recs) { steps.push(payloadStep(recs, opens, hidden)); });
    memloads.forEach(function (r) {
      steps.push(mkStep('payload_memload', 'sample', [r], { kind: r.kind, path: r.path === undefined ? null : r.path, start: r.start, regionSize: r.region_size }));
    });

    var hasEvidence = persist.some(function (r) { return r.type === 'binder_api'; }) || respawns(records) > 0;
    if (hasEvidence) {
      steps.push(mkStep('persistence', 'sample', persist, {
        alarmSets: persist.filter(function (r) { return r.type === 'binder_api' && r.method === 'set'; }).length,
        foregroundCalls: persist.filter(function (r) { return r.type === 'binder_api' && r.method === 'setServiceForeground'; }).length,
        exits: persist.filter(function (r) { return r.type === 'proc_exit'; }).length,
        respawns: respawns(records)
      }));
    } else {
      persist.forEach(function (r) {
        var g = groups.get('proc\u0000exit signal ' + str(r.signal));
        if (!g) groups.set('proc\u0000exit signal ' + str(r.signal), g = { sec: 'proc', key: 'exit signal ' + str(r.signal), recs: [] });
        g.recs.push(r);
      });
    }

    groups.forEach(function (g) {
      if (g.sec === 'net') {
        var ts = g.recs.map(function (r) { return r.ts_ns; }).filter(function (t) { return typeof t === 'number'; });
        var data = { dest: g.key.replace(/^\S+ /, ''), proto: g.recs[0].proto, host: or(g.recs[0].host, g.recs[0].dest),
          hostSource: g.recs[0].host_source, count: g.recs.length, lastTs: ts.length ? Math.max.apply(null, ts) : null };
        if (g.recs.length >= 3) { data.beacon = beaconWindow(ts); steps.push(mkStep('c2_beacon', 'sample', g.recs, data)); }
        else steps.push(mkStep('net_contact', 'sample', g.recs, data));
      } else if (g.sec === 'exec') steps.push(mkStep('exec', 'sample', g.recs, { cmd: g.key, count: g.recs.length }));
      else if (g.sec === 'file') steps.push(mkStep('file_probe', 'sample', g.recs, { path: g.key, count: g.recs.length }));
      else steps.push(mkStep('recorded', 'sample', g.recs, { section: g.sec, key: g.key, count: g.recs.length }));
    });

    if (a11y.length) steps.push(mkStep('a11y_abuse', 'sample', a11y, { count: a11y.length }));

    // Lab-caused permission changes: windows less than 10 s apart are one step.
    var byWin = new Map();
    labPerm.forEach(function (r) {
      var w = windowOf(r, wins);
      if (!byWin.has(w)) byWin.set(w, []);
      byWin.get(w).push(r);
    });
    var chains = [], prevEnd = null;
    Array.from(byWin.keys()).sort(function (a, b) { return wins[a].begin - wins[b].begin; }).forEach(function (w) {
      if (prevEnd !== null && wins[w].begin - prevEnd < LAB_MERGE_GAP_NS) chains[chains.length - 1].push(w);
      else chains.push([w]);
      prevEnd = wins[w].end;
    });
    chains.forEach(function (ws) {
      var recs = [];
      ws.forEach(function (w) { recs = recs.concat(byWin.get(w)); });
      steps.push(mkStep('lab_grant', 'lab', recs, { keys: ws.map(function (w) { return wins[w].key; }), perms: permSummary(recs) }));
    });

    // Permission changes with no lab window around them: nobody is credited.
    var clusters = [];
    otherPerm.slice().sort(function (a, b) { return (a.ts_ns || 0) - (b.ts_ns || 0); }).forEach(function (r) {
      var c = clusters[clusters.length - 1];
      if (c && typeof r.ts_ns === 'number' && r.ts_ns - c.last < LAB_MERGE_GAP_NS) { c.recs.push(r); c.last = r.ts_ns; }
      else clusters.push({ recs: [r], last: r.ts_ns });
    });
    clusters.forEach(function (c) { steps.push(mkStep('perm_unattributed', 'unattributed', c.recs, { perms: permSummary(c.recs) })); });

    var order = steps.map(function (s, i) { return [s, i]; });
    order.sort(function (a, b) {
      var x = a[0].firstTs === null ? Infinity : a[0].firstTs, y = b[0].firstTs === null ? Infinity : b[0].firstTs;
      if (x !== y) return x < y ? -1 : 1;
      return TEMPLATE_ORDER.indexOf(a[0].template) - TEMPLATE_ORDER.indexOf(b[0].template) || a[1] - b[1];
    });
    var out = order.map(function (e) { return e[0]; });
    // Names looked up in DNS, by first lookup: [{name, count, firstTs}]. Read as steps.lookups.
    out.lookups = Array.from(lookups.values()).sort(function (a, b) { return (a.firstTs || 0) - (b.firstTs || 0); });
    return out;
  }

  // ---- step wording and ATT&CK tags ----
  // Every word comes from templates.json or from record fields and counts.
  // A string is filled in; a placeholder with no value drops that piece.
  function present(v) { return v !== undefined && v !== null && v !== '' && v !== false; }
  function fill(s, vars) {
    var ok = true;
    var out = s.replace(/\{(\w+)\}/g, function (m, k) {
      if (!present(vars[k])) { ok = false; return ''; }
      return String(vars[k]);
    });
    return ok ? out : null;
  }
  function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
  function joinList(items, o) {
    if (!items.length) return null;
    var s;
    if (items.length === 1) s = items[0];
    else if (items.length === 2 && o.twoSep !== undefined) s = items[0] + o.twoSep + items[1];
    else s = items.slice(0, -1).join(o.sep) + (o.lastSep !== undefined ? o.lastSep : o.sep) + items[items.length - 1];
    return (o.keepCase ? s : cap(s)) + (o.end || '');
  }
  // A template field is a string, a list of " · " segments, {first}, {variants} or {list}.
  function words(f, vars) {
    if (f === undefined || f === null) return null;
    if (typeof f === 'string') return fill(f, vars);
    if (Array.isArray(f)) {
      var segs = f.map(function (x) { return fill(x, vars); }).filter(function (x) { return x !== null; });
      return segs.length ? segs.join(' · ') : null;
    }
    if (f.variants) return has(f.variants, vars.variant) ? fill(f.variants[vars.variant], vars) : null;
    if (f.first) {
      for (var i = 0; i < f.first.length; i++) { var w = fill(f.first[i], vars); if (w !== null) return w; }
      return null;
    }
    var items = f.list.map(function (x) { return fill(x, vars); }).filter(function (x) { return x !== null; });
    return joinList(items, f);
  }

  function fmtSize(n) {
    if (typeof n !== 'number') return null;
    if (n < 1000) return n + ' B';
    var v = n < 1e6 ? n / 1e3 : n / 1e6, u = n < 1e6 ? ' KB' : ' MB';
    return (v < 10 ? v.toFixed(1) : String(Math.round(v))) + u;
  }
  function fmtAt(ts, start, precise) {
    if (typeof ts !== 'number' || typeof start !== 'number') return null;
    var s = (ts - start) / NS;
    if (s < (precise ? 100 : 10)) return (Math.round(s * 10) / 10) + ' s';
    s = Math.round(s);
    return s < 120 ? s + ' s' : Math.floor(s / 60) + ':' + ('0' + (s % 60)).slice(-2);
  }
  // Seconds as "20 s", "1.5 s" or "300 ms"; never "0 s".
  function fmtDur(s) {
    if (s >= 10) return Math.round(s) + ' s';
    if (s >= 1) return (Math.round(s * 10) / 10) + ' s';
    return Math.max(1, Math.round(s * 1000)) + ' ms';
  }
  function plural(n, w, pl) { return n + ' ' + (n === 1 ? w : (pl || w + 's')); }

  function firstTsWhere(recs, pred) {
    var best = null;
    recs.forEach(function (r) {
      if (pred(r) && typeof r.ts_ns === 'number' && (best === null || r.ts_ns < best)) best = r.ts_ns;
    });
    return best;
  }
  function summaryOf(ctx, type) {
    if (ctx.summaries && ctx.summaries[type]) return ctx.summaries[type];
    var found = null;
    (ctx.records || []).forEach(function (r) { if (r.type === type) found = r; });
    return found;
  }
  // Total of one binder call over a binder_api_summary, or null when there is none.
  function binderTotal(ctx, iface, method) {
    var s = summaryOf(ctx, 'binder_api_summary');
    if (!s) return null;
    var n = 0, procs = 0;
    (s.processes || []).forEach(function (p) {
      var c = 0;
      (p.calls || []).forEach(function (k) {
        if (k.method === method && str(k.interface).slice(-iface.length) === iface) c += k.count || 0;
      });
      if (c) procs++;
      n += c;
    });
    return n ? { count: n, procs: procs } : null;
  }
  function pidsOf(recs, method) {
    var seen = new Set();
    recs.forEach(function (r) { if (r.type === 'binder_api' && r.method === method && r.pid !== undefined) seen.add(r.pid); });
    return seen.size;
  }
  function a11yCounts(ctx, recs) {
    var out = { global_action: 0, action: 0, gesture: 0, screen_read: 0, screenshot: 0 };
    var s = summaryOf(ctx, 'accessibility_detect_summary');
    out.total = !!s;
    if (s) {
      (s.processes || []).forEach(function (p) {
        Object.keys(out).forEach(function (k) { if (k !== 'total') out[k] += (p.calls || {})[k] || 0; });
      });
    } else {
      recs.forEach(function (r) { if (r.category !== 'total' && has(out, r.category)) out[r.category]++; });
    }
    return out;
  }

  // The run's start (launch mark, else first record) and end (stop mark, else last record).
  function runBounds(ctx) {
    var ts = (ctx.records || []).map(function (r) { return r.ts_ns; }).filter(function (t) { return typeof t === 'number'; });
    var launch = null, stop = null;
    (ctx.marks || []).forEach(function (m) {
      if (m.label === 'launch') launch = m.ts;
      if (m.label === 'stop') stop = m.ts;
    });
    var first = ts.length ? Math.min.apply(null, ts) : null, last = ts.length ? Math.max.apply(null, ts) : null;
    return { start: launch !== null ? launch : first, end: stop !== null ? stop : last };
  }

  var HTTP_SOURCES = { http: 'HTTP', https: 'HTTPS', sni: 'HTTPS' };
  var IPV4 = /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/;

  // Whether the destination was reached with no DNS lookup before the first
  // connection: true/false, or null when the records cannot say.
  function noLookupBefore(ctx, firstTs) {
    var recs = ctx.records || [];
    var dns = recs.filter(isLookup);
    if (dns.some(function (r) { return typeof r.ts_ns === 'number' && typeof firstTs === 'number' && r.ts_ns < firstTs; })) return false;
    var s = summaryOf(ctx, 'net_summary');
    if (!s && !dns.length) return null;
    if (s && (s.lookups || []).length && !dns.length) return null;   // lookups listed without times
    return true;
  }

  function netVars(step, T, b, ctx) {
    var d = step.data, W = T.steps.c2_beacon.words;
    var src = present(d.hostSource) ? String(d.hostSource).toLowerCase() : '';
    var web = has(HTTP_SOURCES, src);
    var host = present(d.host) ? d.host : d.dest;
    var v = {
      proto: web ? HTTP_SOURCES[src] : (present(d.proto) ? String(d.proto).toUpperCase() : null),
      host: host, count: d.count, web: web,
      first: fmtAt(minTs(step.recs), b.start, true), last: fmtAt(d.lastTs, b.start, true),
      connections: plural(d.count, 'connection'), beat: null
    };
    var ip = IPV4.test(str(host)), fixed = ip ? noLookupBefore(ctx, minTs(step.recs)) : false;
    v.variant = fixed ? 'ip' : ip ? 'ipOnly' : 'host';
    v.target = fixed ? W.hardcoded : ip ? W.ipAddress : host;
    v.serverAt = ip ? fill(W.serverAtIp, v) : host;
    v.noDomain = fixed ? W.noDomain : null;
    if (d.beacon && b.end !== null) {
      var bw = d.beacon;
      v.every = fmtDur(bw.intervalS);
      v.minutes = plural(Math.max(1, Math.round((b.end - bw.fromTs) / (60 * NS))), W.minute);
      v.from = fmtAt(bw.fromTs, b.start);
      v.to = fmtAt(bw.toTs, b.start);
      // "in the last N minutes" only while the beat runs to the end of the run
      v.beat = fill(b.end - bw.toTs <= 2 * bw.intervalS * NS ? W.beatLast : W.beatBetween, v);
    }
    return v;
  }

  function trafficOf(ctx, dest, T) {
    var s = summaryOf(ctx, 'net_summary');
    var row = s && (s.destinations || []).filter(function (x) { return x.dest === dest; })[0];
    if (!row || typeof row.tx !== 'number' || typeof row.rx !== 'number') return null;
    return fill(T.steps.c2_beacon.net.traffic, { tx: fmtSize(row.tx), rx: fmtSize(row.rx) });
  }

  // Tactic label: the techniques' tactics, once each, in ATT&CK matrix order.
  function techList(T, ids) {
    var techniques = [], tacs = {};
    ids.forEach(function (id) {
      var t = T.techniques[id];
      techniques.push({ id: id, name: t.name });
      t.tactics.forEach(function (x) { tacs[x] = 1; });
    });
    var tactic = T.tacticOrder.filter(function (x) { return tacs[x]; }).join(' · ');
    return { techniques: techniques, tactic: tactic || null };
  }

  function andList(l) {
    return l.length ? l.slice(0, -1).join(', ') + (l.length > 1 ? ' and ' : '') + l[l.length - 1] : null;
  }

  // describe(step, ctx, templates): the words and tags one card shows.
  // ctx = {records, marks, summaries, staticApk}; summaries maps a summary
  // record type to its record (read from ctx.records when absent); staticApk
  // is an optional [{name, size}] list of non-DEX files found in the APK.
  function describe(step, ctx, T) {
    ctx = ctx || {};
    var tpl = T.steps[step.template] || T.steps.recorded;
    var W = tpl.words || {}, E = tpl.evidence || {}, d = step.data;
    var b = runBounds(ctx);
    var vars = {}, ids = [], ev = [], net = null, approx = false, titleField = tpl.title;
    function at(ts) { return fmtAt(ts, b.start); }
    function atp(ts) { return fmtAt(ts, b.start, true); }
    function ev1(label, value) { if (present(label) && present(value)) ev.push([label, value]); }

    if (step.template === 'detonation') {
      vars.pkg = ctx.pkg || inferPackage(ctx.records || []);
    } else if (step.template === 'payload_packed' || step.template === 'payload_downloaded') {
      vars.variant = d.dropped ? (d.loaded ? 'both' : 'dropOnly') : (d.loaded ? 'loadOnly' : 'neither');
      vars.file = d.path ? basename(d.path) : null;
      vars.kind = d.kind ? str(d.kind).toUpperCase() : null;
      vars.size = fmtSize(d.size);
      vars.saved = d.sha256 ? W.saved : null;
      vars.deleted = d.deleted ? W.deleted : null;
      var dropTs = firstTsWhere(step.recs, function (r) { return r.stage === 'drop'; });
      var apk = (ctx.staticApk || []).filter(function (a) { return typeof d.size === 'number' && a.size === d.size; })[0];
      var netAfter = !!d.netAfter;
      var delTs = firstTsWhere(step.recs, function (r) { return r.stage === 'delete'; });
      var lastUse = null;
      step.recs.forEach(function (r) {
        if ((r.stage === 'drop' || r.stage === 'load') && typeof r.ts_ns === 'number' && (lastUse === null || r.ts_ns > lastUse)) lastUse = r.ts_ns;
      });
      if (d.deleted) vars.deleted = lastUse !== null && delTs !== null && delTs < lastUse ? (fill(W.deletedAt, { at: atp(delTs) }) || W.deletedIt) : W.deleted;
      var deleteOnly = !d.dropped && !d.loaded;
      if (deleteOnly) vars.deleted = W.deletedOnly;
      // a delete before the first load is told before the run, as the records order them
      var loadTs = firstTsWhere(step.recs, function (r) { return r.stage === 'load'; });
      var delFirst = d.loaded && d.deleted && delTs !== null && loadTs !== null && delTs < loadTs;
      if (delFirst && !d.dropped) vars.deleted = fill(W.deletedFirstAt, { at: atp(delTs) });
      ev1(d.dropped ? E.path : d.loaded ? E.pathLoaded : E.pathDeleted, d.path);
      ev1(E.sha, d.sha256);
      if (step.template === 'payload_packed') {
        vars.decodedClause = apk && d.dropped ? W.decoded : null;
        vars.wroteClause = d.dropped ? (apk ? W.wroteIt : dropTs !== null && !d.netBeforeAny && !d.hiddenNetEver ? (netAfter ? W.wroteEarly : W.wroteNoNet) : W.wroteCode) : null;
        vars.ranClause = d.loaded ? (d.dropped || apk ? W.ranIt : W.ranCode) : null;
        if (delFirst) { vars.ranLater = W.ranLater; vars.ranClause = null; }
        if (d.dropped) ids.push('T1406.002');
        if (dropTs !== null) {
          var bg = d.hiddenNetBefore;
          ev1(E.why, d.netBeforeAny || d.hiddenNetEver ? (bg ? E.whyNoNetBg : E.whyNoNet) : E.whyNoNetAtAll);
          ev1(E.notMapped, bg ? E.notMappedTextBg : E.notMappedText);
        }
        if (apk) ev1(E.static, fill(E.staticText, { size: d.size, name: apk.name }));
      } else {
        vars.wroteClause = d.dropped ? W.wroteCode : null;
        vars.ranClause = d.loaded ? (d.dropped ? W.ranIt : W.ranCode) : null;
        if (delFirst) { vars.ranLater = W.ranLater; vars.ranClause = null; }
        if (d.dropped) ids.push('T1407');
        vars.gap = d.netBeforeTs !== null && dropTs !== null ? fmtDur((dropTs - d.netBeforeTs) / NS) : null;
        ev1(E.why, fill(E.whyText, vars));
      }
    } else if (step.template === 'payload_memload') {
      vars.kind = d.kind ? str(d.kind).toUpperCase() : null;
      vars.region = fmtSize(d.regionSize);
      ev1(E.path, d.path);
      ev1(E.region, vars.region);
    } else if (step.template === 'persistence') {
      // Totals only from a summary row; first-seen records give "seen in N processes".
      var alarmSum = binderTotal(ctx, 'IAlarmManager', 'set'), fgSum = binderTotal(ctx, 'IActivityManager', 'setServiceForeground');
      var alarmSeen = d.alarmSets > 0, fgSeen = d.foregroundCalls > 0;
      var alarmProcs = plural(pidsOf(step.recs, 'set'), 'process', 'processes');
      var fgProcs = plural(pidsOf(step.recs, 'setServiceForeground'), 'process', 'processes');
      var anyAlarm = !!alarmSum || alarmSeen, anyFg = !!fgSum || fgSeen;
      var firstCall = function (m) { return firstTsWhere(step.recs, function (r) { return r.type === 'binder_api' && r.method === m; }); };
      vars.alarms = alarmSum ? plural(alarmSum.count, 'alarm') : alarmSeen ? fill(W.alarmsSeen, { p: alarmProcs }) : null;
      vars.alarmT = anyAlarm ? W.alarmT : null;
      vars.alarmClause = anyAlarm ? W.alarmClause : null;
      vars.fgT = anyFg ? W.fgT : null;
      vars.fgClause = anyFg ? W.fgClause : null;
      vars.fgFact = anyFg ? W.fgFact : null;
      var sigs = new Map();
      step.recs.forEach(function (r) { if (r.type === 'proc_exit') sigs.set(present(r.signal) ? String(r.signal) : '', 1); });
      var sk = Array.from(sigs.keys());
      var killed = sk.length > 0 && sk.every(function (x) { return x === '9' || x === '15'; });
      vars.respT = d.respawns ? W.respT : null;
      var all = d.respawns >= d.exits;
      vars.respawnClause = d.respawns ? (killed ? (all ? W.respawnKilledAll : W.respawnKilledSome) : (all ? W.respawnExitAll : W.respawnExitSome)) : null;
      vars.respawnsN = d.respawns ? plural(d.respawns, 'respawn') : null;
      vars.from = d.respawns ? at(firstTsWhere(step.recs, function (r) { return r.type === 'proc_exit'; })) : null;
      if (anyAlarm) {
        ids.push('T1603');
        ev1(E.alarms, alarmSum ? fill(E.alarmsText, { n: plural(alarmSum.count, 'AlarmManager.set call'), at: atp(firstCall('set')) })
          : fill(E.alarmsSeenText, { p: alarmProcs, at: atp(firstCall('set')) }));
      }
      if (anyFg) {
        ids.push('T1541');
        ev1(E.foreground, fgSum ? fill(E.foregroundText, { n: plural(fgSum.count, 'call'), p: plural(fgSum.procs, 'process', 'processes'), at: atp(firstCall('setServiceForeground')) })
          : fill(E.foregroundSeenText, { p: fgProcs, at: atp(firstCall('setServiceForeground')) }));
      }
      if (d.respawns) {
        var sig = sk.length !== 1 ? (sk.length ? 'several signals' : null) : sk[0] === '' ? null : (has(T.signalNames, sk[0]) ? T.signalNames[sk[0]] : 'signal ' + sk[0]);
        ev1(E.respawns, fill(E.respawnsText, { n: plural(d.respawns, 'respawn'), exits: d.exits, sigPart: sig ? ' (' + sig + ')' : '' }));
      }
    } else if (step.template === 'c2_beacon' || step.template === 'net_contact') {
      vars = netVars(step, T, b, ctx);
      if (vars.web) ids.push('T1437.001');
      if (step.template === 'c2_beacon') {
        if (!d.beacon) titleField = tpl.titleNoBeat;
        vars.traffic = trafficOf(ctx, d.dest, T);
        var why = E.whyText.map(function (x) { return fill(x, vars); }).filter(function (x) { return x !== null; });
        ev1(E.why, why.join(', ') + '. ' + E.whyEnd);
      }
      net = { endpoint: d.dest, sub: words(tpl.net.sub, vars) };
      ev1(E.seen, fill(E.seenText, vars));
    } else if (step.template === 'lab_grant' || step.template === 'perm_unattributed') {
      approx = true;
      var granted = [], others = [], a11y = false;
      d.perms.forEach(function (p) {
        ev1(E.changes, present(p.old) ? fill(E.changeText, { name: p.name, old: p.old, new: p.new }) : fill(E.changeNew, { name: p.name, new: p.new }));
        if (p.category === 'accessibility' && present(p.new)) { a11y = true; return; }
        var ok = p.new === 'granted' || p.new === 'allow';
        var label = ok && has(T.permissionWords, p.name) ? T.permissionWords[p.name] : p.name;
        var list = ok ? granted : others;
        if (list.indexOf(label) < 0) list.push(label);
      });
      vars.perms = andList(granted);
      vars.others = andList(others);
      vars.a11yClause = a11y ? W.a11yClause : null;
      vars.changes = plural(d.perms.length, 'permission change');
      vars.variant = granted.length && a11y ? 'both' : granted.length ? 'perms' : a11y ? 'a11y' : 'other';
    } else if (step.template === 'a11y_abuse') {
      var c = a11yCounts(ctx, step.recs);
      var input = c.global_action + c.action + c.gesture;
      // Counts are totals only from the summary; first-seen records say "seen".
      var cnt = function (n, one, many) { return !n ? null : c.total ? plural(n, one, many) : (many || one + 's') + ' ' + W.seen; };
      vars.presses = cnt(c.global_action, 'button press', 'button presses');
      vars.actions = cnt(c.action, 'node action');
      vars.gestures = cnt(c.gesture, 'gesture');
      vars.reads = cnt(c.screen_read, 'screen read');
      vars.shots = cnt(c.screenshot, 'screenshot');
      if (c.screen_read) ids.push('T1453');
      if (input) ids.push('T1516');
      vars.abuse = [input ? W.injection : null, c.screen_read ? W.reading : null].filter(present).join(' and ') || null;
      var cl = [], gl = [];
      if (c.global_action) { cl.push(W.pressClause); gl.push(W.glancePress); }
      if (c.action) cl.push(W.actionClause);
      if (c.gesture) cl.push(W.gestureClause);
      if (c.screen_read) { cl.push(W.readClause); gl.push(W.glanceRead); }
      if (c.screenshot) cl.push(W.shotClause);
      // Only a lab grant that came before the first accessibility call can be its cause.
      var firstA11y = minTs(step.recs);
      var labA11y = (ctx.records || []).filter(function (r) {
        return r.type === 'perm_change' && r.category === 'accessibility' && present(r.new) &&
          r.change !== 'baseline' && labCaused(r, ctx.marks) && typeof r.ts_ns === 'number' &&
          firstA11y !== null && r.ts_ns <= firstA11y;
      });
      vars.lead = labA11y.length ? W.leadLab : W.leadPlain;
      vars.clauses = joinList(cl, { sep: ', ', twoSep: ' and ', lastSep: ', and ', keepCase: true });
      vars.glanceClauses = joinList(gl, { sep: ', ', twoSep: ' and ', lastSep: ', and ' });
      [['global_action', E.presses], ['action', E.actions], ['gesture', E.gestures],
        ['screen_read', E.reads], ['screenshot', E.shots]].forEach(function (o) {
        if (c[o[0]]) ev1(o[1], fill(c.total ? E.text : E.textSeen, { n: plural(c[o[0]], 'call'), at: atp(firstTsWhere(step.recs, function (r) { return r.category === o[0]; })) }));
      });
      if (labA11y.length) ev1(E.depends, fill(E.dependsText, { at: at(minTs(labA11y)) }));
      ev1(E.notKnown, E.notKnownText);
    } else if (step.template === 'exec') {
      vars.cmd = d.cmd;
      vars.times = plural(d.count, 'time');
      ev1(E.cmd, d.cmd);
    } else if (step.template === 'file_probe') {
      vars.path = d.path;
      vars.times = plural(d.count, 'time');
      ev1(E.path, d.path);
    } else {
      vars.key = d.key;
      vars.records = plural(d.count, 'record');
      ev1(E.section, d.section);
      ev1(E.key, d.key);
    }

    var tl = techList(T, ids);
    return {
      tactic: tl.tactic,
      title: words(titleField, vars),
      plain: words(tpl.plain, vars),
      glance: words(tpl.glance, vars),
      short: words(tpl.short, vars),
      plainShort: words(tpl.plainShort, vars),
      facts: words(tpl.facts, vars) || '',
      net: net,
      techniques: tl.techniques,
      evidence: ev,
      approx: approx
    };
  }

  return {
    PROFILE_VERSION: PROFILE_VERSION,
    norm: norm,
    recordKey: recordKey,
    findings: findings,
    inferPackage: inferPackage,
    parseMarks: parseMarks,
    labCaused: labCaused,
    beaconWindow: beaconWindow,
    respawns: respawns,
    buildSteps: buildSteps,
    describe: describe
  };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = AnubeeModView;
