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
  // exit. Time order, not file order (the sink groups records by type). A pid
  // a traced process forked (a spawn record's child_pid) is a helper, not the
  // app coming back, and its exit is not the app dying.
  function respawns(records) {
    var seen = new Set(), forked = new Set(), pending = 0, n = 0;
    records.forEach(function (r) { if (r.type === 'spawn' && typeof r.child_pid === 'number') forked.add(r.child_pid); });
    records.filter(function (r) { return typeof r.ts_ns === 'number'; })
      .sort(function (a, b) { return a.ts_ns - b.ts_ns; })
      .forEach(function (r) {
        if (typeof r.pid !== 'number' || forked.has(r.pid)) return;
        if (!seen.has(r.pid)) {
          seen.add(r.pid);
          if (pending > 0) { pending--; n++; }
        }
        if (r.type === 'proc_exit') pending++;
      });
    return n;
  }

  // Loops, not Math.min/max.apply: spreading a long list overflows the stack.
  function minOf(xs) { var m = null; xs.forEach(function (x) { if (m === null || x < m) m = x; }); return m; }
  function maxOf(xs) { var m = null; xs.forEach(function (x) { if (m === null || x > m) m = x; }); return m; }
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
    var drops = recs.filter(function (r) { return r.stage === 'drop'; });
    var first = recs[0];
    var saved = null;
    recs.forEach(function (r) { if (r.saved) saved = r.saved; });
    var dts = minTs(drops);           // the earliest timed drop, the one describe() words too
    var netTs = dts !== null ? netOpensBefore(opens, dts) : null;
    var netAfterTs = null;                 // first open after the drop, visible or noise-hidden
    opens.concat(hidden).forEach(function (r) {
      if (dts !== null && typeof r.ts_ns === 'number' && r.ts_ns > dts && (netAfterTs === null || r.ts_ns < netAfterTs)) netAfterTs = r.ts_ns;
    });
    var anyOpen = function (list, test) {
      return dts !== null && list.some(function (r) { return typeof r.ts_ns === 'number' && test(r.ts_ns); });
    };
    var stages = recs.map(function (r) { return r.stage; });
    return mkStep(netTs !== null ? 'payload_downloaded' : 'payload_packed', 'sample', recs, {
      path: first.path === undefined ? null : first.path, kind: first.kind, ino: first.ino,
      stages: stages, dropped: drops.length > 0, loaded: stages.indexOf('load') >= 0,
      deleted: stages.indexOf('delete') >= 0,
      sha256: saved ? saved.sha256 : null, size: saved ? saved.size : null,
      netBeforeTs: netTs,
      // from the same noise-filtered open set that classifies the step
      netBeforeAny: anyOpen(opens, function (t) { return t < dts; }),
      netAfter: anyOpen(opens, function (t) { return t > dts; }),
      netAfterTs: netAfterTs,
      hiddenNetBefore: anyOpen(hidden, function (t) { return t < dts && dts - t <= DROP_NET_WINDOW_NS; }),
      hiddenNetEver: anyOpen(hidden, function (t) { return t < dts; })
    });
  }

  // Attempts, failures (an errno name, or a negative result) and the errno
  // names in first-seen order; an attempt with no result is not a failure.
  function outcomes(recs, data) {
    var errors = [];
    data.count = recs.length;
    data.failed = recs.filter(function (r) {
      var bad = present(r.error) || (typeof r.result === 'number' && r.result < 0);
      if (bad && present(r.error) && errors.indexOf(String(r.error)) < 0) errors.push(String(r.error));
      return bad;
    }).length;
    data.errors = errors;
    return data;
  }

  function buildSteps(records, marks, profile, pkg) {
    pkg = pkg || inferPackage(records);
    marks = marks || [];
    var wins = grantWindows(marks);
    var steps = [];
    var groups = new Map();           // (section, key) -> records, in first-seen order
    var payloads = new Map();         // ino -> dexload records
    var memloads = [], persist = [], a11y = [], opens = [], hidden = [], labPerm = [], otherPerm = [];
    var hiddenExits = [];             // ordinary apps get killed too, but a respawn needs its exit
    var lookups = new Map();          // looked-up name -> {name, count, firstTs}

    records.forEach(function (r) {
      var k = recordKey(r, pkg);
      if (k === null) return;
      if (isNoise(profile, k[0], k[1])) {
        if (k[0] === 'net' && r.event === 'open' && !isLookup(r)) hidden.push(r);
        if (r.type === 'proc_exit') hiddenExits.push(r);
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
      if (respawns(records) > 0) persist = persist.concat(hiddenExits);
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
          hostSource: g.recs[0].host_source, count: g.recs.length, lastTs: maxOf(ts) };
        if (g.recs.length >= 3) { data.beacon = beaconWindow(ts); steps.push(mkStep('c2_beacon', 'sample', g.recs, data)); }
        else steps.push(mkStep('net_contact', 'sample', g.recs, data));
      } else if (g.sec === 'exec') steps.push(mkStep('exec', 'sample', g.recs, outcomes(g.recs, { cmd: g.key })));
      else if (g.sec === 'file') steps.push(mkStep('file_probe', 'sample', g.recs, outcomes(g.recs, { path: g.key })));
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
    var items = [];
    f.list.forEach(function (x) {
      var spread = /^\{\*(\w+)\}$/.exec(x);   // "{*name}": the items of an array var
      if (spread) (vars[spread[1]] || []).forEach(function (y) { if (present(y)) items.push(String(y)); });
      else { var w = fill(x, vars); if (w !== null) items.push(w); }
    });
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

  // The run's launch (first launch mark) and stop (last stop mark), null when absent.
  function launchStop(marks) {
    var launch = null, stop = null;
    (marks || []).forEach(function (m) {
      if (m.label === 'launch' && (launch === null || m.ts < launch)) launch = m.ts;
      if (m.label === 'stop' && (stop === null || m.ts > stop)) stop = m.ts;
    });
    return { launch: launch, stop: stop };
  }
  // The run's start (launch mark, else first record) and end (stop mark, else
  // last record); stopped says which end it is.
  function runBounds(ctx) {
    var ts = (ctx.records || []).map(function (r) { return r.ts_ns; }).filter(function (t) { return typeof t === 'number'; });
    var ls = launchStop(ctx.marks), launch = ls.launch, stop = ls.stop;
    var first = minOf(ts), last = maxOf(ts);
    return { start: launch !== null ? launch : first, end: stop !== null ? stop : last, stopped: stop !== null };
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
      var mins = Math.max(1, Math.round((b.end - bw.fromTs) / (60 * NS)));
      v.minutes = mins === 1 ? W.minute : plural(mins, W.minute);   // "in the last minute", never "1 minute"
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
    var N = T.steps.c2_beacon.net;
    return fill(s.untracked > 0 ? N.trafficAtLeast : N.traffic, { tx: fmtSize(row.tx), rx: fmtSize(row.rx) });
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

  // The payload sentence's clauses, one per run of drop/load/delete records in
  // time order (a run of one kind is one clause), each only with its record.
  // Any of them without a time: the unordered wording (no "then", no "afterwards").
  // o.netTimed: the write clause places the write against the network, so the
  // next clause gets no "then" (it would read as after that network event).
  // o.ranEarly: the write+run wording used when the run also came before o.netAfterTs.
  function payloadClauses(recs, W, atp, wrote, o) {
    o = o || {};
    var ev = recs.filter(function (r) { return r.stage === 'drop' || r.stage === 'load' || r.stage === 'delete'; });
    var has3 = function (st) { return ev.some(function (r) { return r.stage === st; }); };
    if (ev.some(function (r) { return typeof r.ts_ns !== 'number'; })) {
      var out = has3('drop') ? wrote.slice() : [];
      if (has3('load')) out.push(has3('drop') ? W.ranIt : W.ranCode);
      if (has3('delete')) out.push(has3('drop') || has3('load') ? W.deletedIt : W.deletedOnly);
      return out;
    }
    ev = ev.map(function (r, i) { return { r: r, i: i }; })
      .sort(function (a, b) { return a.r.ts_ns - b.r.ts_ns || a.i - b.i; }).map(function (x) { return x.r; });
    var runs = [];
    ev.forEach(function (r) {
      var last = runs[runs.length - 1];
      if (!last || last.stage !== r.stage) runs.push({ stage: r.stage, ts: r.ts_ns, lastTs: r.ts_ns });
      else last.lastTs = r.ts_ns;
    });
    // a timed word falls back to its untimed one when the time can't be given
    var timedWord = function (w, ts, plain) { return fill(w, { at: atp(ts) }) || plain; };
    var many = runs.length > 1, clauses = [], dropped = false, prevNet = false, skip = -1;
    runs.forEach(function (run, i) {
      if (i === skip) return;
      var prev = i ? runs[i - 1].stage : null, c, timed = many && i === 0, net = false;
      if (run.stage === 'drop') {
        var next = runs[i + 1];
        if (!dropped && o.ranEarly && next && next.stage === 'load' && typeof o.netAfterTs === 'number' && next.lastTs < o.netAfterTs) {
          c = [o.ranEarly];
          skip = i + 1;
        } else c = dropped ? [W.wroteAgain] : wrote.slice();
        net = !dropped && !!o.netTimed;
        dropped = true;
      } else if (run.stage === 'load') {
        c = [prev === 'drop' ? W.ranIt : prev === 'delete' ? W.ranFromIt : timed ? timedWord(W.ranCodeAt, run.ts, W.ranCode) : W.ranCode];
      } else {
        var lastRun = i === runs.length - 1;
        c = [i === 0 ? (timed ? timedWord(W.deletedFirstAt, run.ts, W.deletedOnly) : W.deletedOnly)
          : lastRun ? W.deleted : timedWord(W.deletedAt, run.ts, W.deletedIt)];
        if (i && lastRun) {                    // "afterwards" orders itself
          // after a network-timed clause, set it off so it can't read as part of that timing
          if (prevNet) clauses[clauses.length - 1] = fill(W.andAfter, { a: clauses[clauses.length - 1], c: c[0] });
          else clauses.push.apply(clauses, c);
          prevNet = false;
          return;
        }
      }
      if (i && !prevNet) c[0] = fill(W.then, { c: c[0] });
      prevNet = net;
      clauses.push.apply(clauses, c);
    });
    return clauses;
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
    var vars = {}, ids = [], ev = [], net = null, approx = false, titleField = tpl.title, shortField = tpl.short;
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
      var dropTs = firstTsWhere(step.recs, function (r) { return r.stage === 'drop'; });
      var apk = (ctx.staticApk || []).filter(function (a) { return typeof d.size === 'number' && a.size === d.size; })[0];
      var netAfter = !!d.netAfter;
      ev1(d.dropped ? E.path : d.loaded ? E.pathLoaded : E.pathDeleted, d.path);
      ev1(E.sha, d.sha256);
      if (step.template === 'payload_packed') {
        var wrote = apk ? W.wroteIt : dropTs !== null && !d.netBeforeAny && !d.hiddenNetEver ? (netAfter ? W.wroteEarly : W.wroteNoNet) : W.wroteCode;
        vars.clauses = payloadClauses(step.recs, W, atp, apk ? [W.decoded, wrote] : [wrote], {
          netTimed: wrote === W.wroteEarly || wrote === W.wroteNoNet,
          ranEarly: wrote === W.wroteEarly ? W.wroteRanEarly : null, netAfterTs: d.netAfterTs
        });
        if (d.dropped) ids.push('T1406.002');
        if (dropTs !== null) {
          var bg = d.hiddenNetBefore;
          ev1(E.why, d.netBeforeAny || d.hiddenNetEver ? (bg ? E.whyNoNetBg : E.whyNoNet) : E.whyNoNetAtAll);
          ev1(E.notMapped, bg ? E.notMappedTextBg : E.notMappedText);
        }
        if (apk) ev1(E.static, fill(E.staticText, { size: d.size, name: apk.name }));
      } else {
        vars.clauses = payloadClauses(step.recs, W, atp, [W.wroteCode], { netTimed: true });
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
        if (!d.beacon) { titleField = tpl.titleNoBeat; shortField = tpl.shortNoBeat; }
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
        // a removed value (revoked, cleared) is a change too: counted, so listed
        ev1(E.changes, !present(p.new) ? words(E.changeRemoved, { name: p.name, old: p.old })
          : present(p.old) ? fill(E.changeText, { name: p.name, old: p.old, new: p.new }) : fill(E.changeNew, { name: p.name, new: p.new }));
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
      vars.abuseShort = vars.abuse ? W.abuseShort : null;
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
    } else if (step.template === 'exec' || step.template === 'file_probe') {
      // every attempt failed: nothing ran or was opened, so nothing says it was
      var failed = d.failed || 0, allFailed = failed > 0 && failed === d.count;
      vars.variant = allFailed ? 'failed' : 'ran';
      vars.cmd = d.cmd;
      vars.path = d.path;
      vars.times = allFailed ? null : plural(d.count, 'time');
      vars.errs = (d.errors || []).length ? ' (' + d.errors.join(', ') + ')' : '';
      vars.failedPart = !failed ? null : (allFailed ? fill(W.failedAll, { n: plural(failed, 'time') })
        : fill(W.failedSome, { n: String(failed) })) + vars.errs;
      ev1(step.template === 'exec' ? E.cmd : E.path, step.template === 'exec' ? d.cmd : d.path);
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
      short: words(shortField, vars),
      plainShort: words(tpl.plainShort, vars),
      facts: words(tpl.facts, vars) || '',
      net: net,
      techniques: tl.techniques,
      evidence: ev,
      approx: approx
    };
  }

  // ---- the page model ----
  var VIEW_HEADLINE_SKIP = { recorded: 1 };   // shown, not interpreted: no headline claim
  var GAP_NS = 10 * NS;                       // a gap this long is written on the line

  function lowerFirst(s) { return /^[A-Z][a-z]/.test(s) ? s.charAt(0).toLowerCase() + s.slice(1) : s; }
  function fmtLen(sec, D) {
    var t = Math.round(sec), h = Math.floor(t / 3600), m = Math.floor(t % 3600 / 60), x = t % 60;
    if (t < 60) return fill(D.s, { s: String(t) });
    if (h) return fill(D.hm, { h: String(h), m: String(m) });
    return x ? fill(D.ms, { m: String(m), s: String(x) }) : fill(D.m, { m: String(m) });
  }
  function fmtGap(ns, V) {
    var s = Math.round(ns / NS);
    return s < 120 ? fill(V.gapS, { n: String(s) }) : fill(V.gapMin, { n: String(Math.round(s / 60)) });
  }
  // Trace length {s, wall}: up to the stop mark, from the same start the end
  // row uses; else meta started/stopped (wall: the kicker names it); else the
  // same start to the last timed record. null when there is no length.
  function traceSeconds(meta, b) {
    if (b.stopped && b.end > b.start) return { s: (b.end - b.start) / NS, wall: false };
    var x = Date.parse(str(meta.started)), y = Date.parse(str(meta.stopped));
    if (present(meta.started) && present(meta.stopped) && !isNaN(x) && !isNaN(y) && y > x) return { s: (y - x) / 1000, wall: true };
    return b.start !== null && b.end > b.start ? { s: (b.end - b.start) / NS, wall: false } : null;   // one timestamp is no length
  }
  function smsEvidence(records) {
    return records.some(function (r) {
      return r.type === 'binder_api' && (/^content:\/\/(sms|mms|mms-sms)(\/|$)/i.test(str(r.uri)) ||
        (r.call && /^(sms|mms|mms-sms)$/i.test(str(r.call.authority))) || /\.ISms$/.test(str(r.interface)));
    });
  }
  // Clean: a clean coverage record for the engine and no degraded one.
  function cleanEngine(records, engine) {
    var cov = records.filter(function (r) { return r.type === 'coverage' && r.engine === engine; });
    return cov.some(function (r) { return r.clean === true; }) && !cov.some(function (r) { return !r.clean && !r.exempt; });
  }
  function permKey(n) { return str(n).replace(/^android\.permission\./, ''); }

  // buildView(input): everything the page shows, as plain text. input =
  // {records, marksText, profile, templates, meta?, badging?, staticApk?, hidden?, pkg?};
  // meta = {family, familySource, sha256, device, started, stopped} (any missing),
  // badging = {permissions: [...]}, staticApk = {entries: [{name, size, isDex}]},
  // hidden = findings()' hidden counts of the whole run when records was trimmed of noise,
  // pkg = the traced package when the caller knows it (else read from the records).
  function buildView(input) {
    var records = input.records || [], T = input.templates, V = T.view;
    var meta = input.meta || {}, profile = input.profile || {};
    var marks = parseMarks(input.marksText);
    var pkg = present(input.pkg) ? String(input.pkg) : inferPackage(records);
    var steps = buildSteps(records, marks, profile, pkg);
    var summaries = Object.create(null);
    records.forEach(function (r) { if (typeof r.type === 'string' && r.type.slice(-8) === '_summary') summaries[r.type] = r; });
    // only a proven non-DEX entry backs the static claim: an unknown (null) DEX check proves nothing
    var apk = input.staticApk && input.staticApk.entries ? input.staticApk.entries
      .filter(function (e) { return e.isDex === false; }).map(function (e) { return { name: e.name, size: e.size }; }) : null;
    var ctx = { records: records, marks: marks, summaries: summaries, staticApk: apk, pkg: pkg };
    var b = runBounds(ctx);
    var cards = steps.map(function (s) { return describe(s, ctx, T); });

    // kicker
    var kick = [];
    if (present(meta.family)) kick.push(words(V.kicker.family, { family: meta.family, source: meta.familySource }));
    if (present(meta.device)) kick.push(String(meta.device));
    var len = traceSeconds(meta, b);
    if (len !== null) kick.push(fill(len.wall ? V.kicker.tracedWall : V.kicker.traced, { dur: fmtLen(len.s, V.duration) }));

    // headline: the sample's steps' short forms, in step order, once each
    var shorts = [];
    steps.forEach(function (s, i) {
      var w = cards[i].short;
      if (s.actor === 'sample' && !VIEW_HEADLINE_SKIP[s.template] && present(w) && shorts.indexOf(w) < 0) shorts.push(w);
    });
    var f = findings(records, profile, pkg);
    var degraded = f.coverage.degraded.filter(function (e, i, a) { return a.indexOf(e) === i; }).map(str);
    var recordedOnly = steps.some(function (s) { return s.actor === 'sample' && VIEW_HEADLINE_SKIP[s.template]; });
    // a "nothing found" headline is hedged when an analyzer reported degraded coverage
    var hedge = { engines: degraded.join(', ') };
    var headline = shorts.length ? cap(andList(shorts.map(function (w, i) { return i ? lowerFirst(w) : w; })))
      : recordedOnly ? (degraded.length ? fill(V.headlineRecordedDegraded, hedge) : V.headlineRecorded)
      : (degraded.length ? fill(V.headlineNoneDegraded, hedge) : V.headlineNone);

    // glance and timeline
    var glance = [], timeline = [], prevTs = null;
    steps.forEach(function (s, i) {
      var n = i + 1, card = cards[i];
      glance.push({ n: n, actor: s.actor, text: card.glance || card.title });
      if (typeof s.firstTs === 'number') {
        if (prevTs !== null && s.firstTs - prevTs >= GAP_NS) timeline.push({ kind: 'gap', text: fmtGap(s.firstTs - prevTs, V) });
        prevTs = s.firstTs;
      }
      timeline.push({ kind: 'step', n: n, actor: s.actor, time: fmtAt(s.firstTs, b.start), approx: card.approx, card: card });
    });
    if (b.end !== null) timeline.push({ kind: 'end', time: fmtAt(b.end, b.start), text: b.stopped ? V.end.stopped : V.end.last });

    // IOCs: hashes, paths and endpoints only (never the saved copy's device path)
    var iocs = [], seenIoc = new Set(), otherHosts = [];
    function ioc(label, value) {
      if (!present(label) || !present(value) || seenIoc.has(label + '\u0000' + value)) return;
      seenIoc.add(label + '\u0000' + value);
      iocs.push([label, String(value)]);
    }
    ioc(V.ioc.sampleSha, meta.sha256);
    ioc(V.ioc.package, pkg);
    steps.forEach(function (s) {
      var d = s.data;
      if (s.template === 'payload_packed' || s.template === 'payload_downloaded') {
        var E = T.steps[s.template].evidence;
        ioc(words(V.ioc.payloadSha, { file: d.path ? basename(d.path) : null }), d.sha256);
        ioc(d.dropped ? E.path : d.loaded ? E.pathLoaded : E.pathDeleted, d.path);
      }
      if (s.template === 'c2_beacon') ioc(V.ioc.c2, d.dest);
      // contacted, not suspected: listed apart, never as an indicator
      if (s.template === 'net_contact' && present(d.dest) && otherHosts.indexOf(String(d.dest)) < 0) otherHosts.push(String(d.dest));
    });
    steps.lookups.forEach(function (l) { ioc(V.ioc.lookups, l.name); });

    // limits, each from a rule over the records
    var L = V.limits, limits = [];
    var has1 = function (t) { return steps.filter(function (s) { return s.template === t; }); };
    var c2 = has1('c2_beacon'), netSteps = c2.concat(has1('net_contact')), a11y = has1('a11y_abuse')[0];
    var ac = a11y ? a11yCounts(ctx, a11y.recs) : null;
    if (netSteps.length && ac && (ac.screen_read || ac.screenshot)) {
      limits.push(fill(L.exfil, { what: ac.screen_read ? L.screenReads : L.screenshots, net: c2.length ? L.c2Traffic : L.netTraffic }));
    }
    var ns = summaries.net_summary, rx = 0;
    var rxKnown = !!ns && c2.length > 0 && c2.every(function (s) {
      var row = (ns.destinations || []).filter(function (x) { return x.dest === s.data.dest; })[0];
      if (!row || typeof row.rx !== 'number') return false;
      rx += row.rx;
      return true;
    });
    // contents are never traced, so this states facts, never "no commands"
    if (rxKnown && cleanEngine(records, 'net') && !smsEvidence(records) && !records.some(function (r) { return r.type === 'execve'; }) &&
        cleanEngine(records, 'binder-api') && cleanEngine(records, 'execve')) {
      var rxText = ns.untracked > 0 ? fill(L.rxAtLeast, { rx: fmtSize(rx) }) : fmtSize(rx);
      limits.push(fill(c2.length > 1 ? L.noCommandsMany : L.noCommands, { rx: rxText }));
    }
    var pers = has1('persistence')[0];
    if (pers && pers.data.respawns > 0) {
      var kills = pers.recs.filter(function (r) { return r.type === 'proc_exit' && (str(r.signal) === '9' || str(r.signal) === '15'); });
      var kinds = new Set(kills.map(function (r) { return str(r.signal); }));
      if (kills.length && kinds.size === 1) {
        var sig = T.signalNames[str(kills[0].signal)];
        limits.push(kills.length === 1 ? fill(L.killOne, { sig: sig }) : fill(L.killMany, { n: String(kills.length), sig: sig }));
      } else if (kills.length) limits.push(fill(L.killMixed, { n: String(kills.length) }));
    }
    var coverageWarning = degraded.length ? fill(V.coverageWarning, { engines: degraded.join(', ') }) : null;
    if (degraded.length) limits.push(fill(L.coverage, { engines: degraded.join(', ') }));

    // footer: declared-only permissions, hidden noise, coverage, ATT&CK source
    var F = V.footer, foot = [];
    var declared = input.badging && Array.isArray(input.badging.permissions) ? input.badging.permissions.filter(function (p, i, a) { return present(p) && a.indexOf(p) === i; }) : null;
    if (declared && declared.length) {
      var perms = records.filter(function (r) { return r.type === 'perm_change'; });
      var granted = new Set();
      perms.forEach(function (r) { if (r.new === 'granted' || r.new === 'allow') granted.add(permKey(r.name)); });
      var only = declared.filter(function (p) { return !granted.has(permKey(p)); });
      var nDecl = plural(declared.length, 'permission');
      // "not granted" only when perm-watch covered the run cleanly
      if (!perms.length || !cleanEngine(records, 'perm-watch')) foot.push(fill(F.declaredUnchecked, { n: nDecl }));
      else if (!only.length) foot.push(fill(F.declaredAllGranted, { n: nDecl }));
      else {
        var list = only.length > 8 ? fill(F.declaredMore, { list: only.slice(0, 8).join(', '), k: String(only.length - 8) }) : only.join(', ');
        foot.push(fill(F.declared, { list: list, n: nDecl }));
      }
    }
    // a run trimmed of its noise records brings the whole run's hidden counts along
    var hid = input.hidden && typeof input.hidden === 'object' ? input.hidden : f.hidden, hiddenN = 0;
    Object.keys(hid).forEach(function (k) { hiddenN += hid[k] && typeof hid[k].records === 'number' ? hid[k].records : 0; });
    if (hiddenN) {
      foot.push(words(F.hidden, { n: plural(hiddenN, 'record'), v: profile.version,
        apps: Array.isArray(profile.apps) && profile.apps.length ? plural(profile.apps.length, 'app') : null }));
    }
    // exempt records had nothing to check: never counted as checks that ran
    var nEx = records.filter(function (r) { return r.type === 'coverage' && r.exempt; }).length;
    var nRan = f.coverage.records - nEx, cv = { k: String(degraded.length), n: plural(nRan, 'check'), e: String(nEx), engines: degraded.join(', ') };
    foot.push(!f.coverage.records ? F.coverageNone : !nRan ? fill(F.coverageAllExempt, { n: plural(nEx, 'check') })
      : degraded.length ? fill(nEx ? F.coverageBadExempt : F.coverageBad, cv)
      : nEx ? cap(fill(F.coverageOkExempt, cv)) : nRan === 1 ? F.coverageOkOne : fill(F.coverageOk, cv));
    foot.push(F.attack);

    return {
      kicker: kick.filter(present).join(V.kicker.sep),
      headline: headline,
      glance: glance,
      timeline: timeline,
      iocs: iocs,
      otherHosts: otherHosts,
      otherHostsLabel: V.otherHosts,
      limits: limits,
      coverageWarning: coverageWarning,
      footer: foot.filter(present).join(' ')
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
    describe: describe,
    buildView: buildView
  };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = AnubeeModView;
