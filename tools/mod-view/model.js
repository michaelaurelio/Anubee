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

  return {
    PROFILE_VERSION: PROFILE_VERSION,
    norm: norm,
    recordKey: recordKey,
    findings: findings,
    inferPackage: inferPackage
  };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = AnubeeModView;
