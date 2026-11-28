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

  // proc_exit records followed later by a record from a pid first seen after
  // that exit. Time order, not file order (the sink groups records by type).
  function respawns(records) {
    var firstSeen = new Map(), exits = [], lastNew = -1;
    var timed = records.filter(function (r) { return typeof r.ts_ns === 'number'; })
      .sort(function (a, b) { return a.ts_ns - b.ts_ns; });
    timed.forEach(function (r, i) {
      if (typeof r.pid !== 'number') return;
      if (!firstSeen.has(r.pid)) { firstSeen.set(r.pid, i); lastNew = i; }
      if (r.type === 'proc_exit') exits.push(i);
    });
    return exits.filter(function (i) { return i < lastNew; }).length;
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

  function payloadStep(recs, opens) {
    var drop = recs.filter(function (r) { return r.stage === 'drop'; })[0];
    var first = recs[0];
    var saved = null;
    recs.forEach(function (r) { if (r.saved) saved = r.saved; });
    var netTs = drop && typeof drop.ts_ns === 'number' ? netOpensBefore(opens, drop.ts_ns) : null;
    var stages = recs.map(function (r) { return r.stage; });
    return mkStep(netTs !== null ? 'payload_downloaded' : 'payload_packed', 'sample', recs, {
      path: first.path === undefined ? null : first.path, kind: first.kind, ino: first.ino,
      stages: stages, dropped: !!drop, loaded: stages.indexOf('load') >= 0,
      deleted: stages.indexOf('delete') >= 0,
      sha256: saved ? saved.sha256 : null, size: saved ? saved.size : null,
      netBeforeTs: netTs
    });
  }

  function buildSteps(records, marks, profile, pkg) {
    pkg = pkg || inferPackage(records);
    marks = marks || [];
    var wins = grantWindows(marks);
    var steps = [];
    var groups = new Map();           // (section, key) -> records, in first-seen order
    var payloads = new Map();         // ino -> dexload records
    var memloads = [], persist = [], a11y = [], opens = [], labPerm = [], otherPerm = [];

    records.forEach(function (r) {
      var k = recordKey(r, pkg);
      if (k === null || isNoise(profile, k[0], k[1])) return;
      var sec = k[0], key = k[1];
      if (sec === 'net') opens.push(r);
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

    payloads.forEach(function (recs) { steps.push(payloadStep(recs, opens)); });
    memloads.forEach(function (r) {
      steps.push(mkStep('payload_memload', 'sample', [r], { kind: r.kind, path: r.path === undefined ? null : r.path, start: r.start, regionSize: r.region_size }));
    });

    var hasEvidence = persist.some(function (r) { return r.type === 'binder_api'; });
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
    return order.map(function (e) { return e[0]; });
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
    buildSteps: buildSteps
  };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = AnubeeModView;
