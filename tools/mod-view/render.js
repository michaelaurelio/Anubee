// SPDX-License-Identifier: GPL-2.0
// HTML for the mod run view: turns a View (model.js buildView) into a string
// and wires the page's two interactive bits. Plain script: attaches to the
// AnubeeModView global in a browser and to module.exports under Node (where
// model.js is loaded first). Every record-derived string is escaped here.
(function (root) {
  'use strict';

  var M = root.AnubeeModView || (typeof require !== 'undefined' ? require('./model.js') : {});

  var ATTACK = 'https://attack.mitre.org/techniques/';

  function esc(s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Counts in a facts line are bolded piece by piece, so the escaping never
  // sees (or splits) the markup that bolds them.
  function factsHtml(s) {
    return String(s).split(/(\d+)/).map(function (p, i) { return i % 2 ? '<b>' + esc(p) + '</b>' : esc(p); }).join('');
  }

  function techUrl(id) { return ATTACK + String(id).replace('.', '/') + '/'; }

  function evidence(card, n) {
    if (!card.evidence.length) return '';
    var rows = card.evidence.map(function (kv) { return '<dt>' + esc(kv[0]) + '</dt><dd>' + esc(kv[1]) + '</dd>'; }).join('');
    return '<div class="more" id="d' + n + '" hidden><dl>' + rows + '</dl></div>';
  }

  function evButton(card, n) {
    return card.evidence.length
      ? '<button type="button" class="evb" aria-expanded="false" aria-controls="d' + n + '">Evidence</button>' : '';
  }

  function stepHtml(item, last) {
    var c = item.card, n = item.n, lab = item.actor === 'lab';
    var time = '<div class="t">' + (item.time === null || item.time === undefined ? '' : (item.approx ? '~' : '') + esc(item.time)) + '</div>' +
      '<div class="dot">' + n + '</div>';
    var open = '<div class="ev ' + (lab ? 'l' : 'a') + (last ? ' last' : '') + '" id="e' + n + '">' + time;
    if (lab) {
      return open + '<div class="body labnote"><b>Lab:</b> ' + esc(c.title) +
        (c.plain ? '<span>' + esc(c.plain) + '</span>' : '') +
        (c.facts ? '<span>' + factsHtml(c.facts) + '</span>' : '') +
        (c.evidence.length ? '<div class="row">' + evButton(c, n) + '</div>' + evidence(c, n) : '') + '</div></div>';
    }
    var h = '<div class="body"><div class="card">' +
      (c.tactic ? '<div class="tac">' + esc(c.tactic) + '</div>' : '') +
      '<h3>' + esc(c.title) + '</h3>' +
      (c.plain ? '<p>' + esc(c.plain) + '</p>' : '') +
      (c.facts ? '<div class="facts">' + factsHtml(c.facts) + '</div>' : '');
    if (c.net) {
      h += '<div class="net"><span class="arrow">talks to</span><span><b>' + esc(c.net.endpoint) + '</b>' +
        '<small>' + esc(c.net.sub) + '</small></span></div>';
    }
    var links = c.techniques.map(function (t) {
      return '<a class="att" href="' + esc(techUrl(t.id)) + '">' + esc(t.id) + ' ' + esc(t.name) + '</a>';
    }).join('');
    if (links || c.evidence.length) h += '<div class="row">' + links + evButton(c, n) + '</div>';
    return open + h + evidence(c, n) + '</div></div></div>';
  }

  function timelineHtml(tl) {
    return tl.map(function (item, i) {
      var last = i === tl.length - 1;
      if (item.kind === 'gap') {
        return '<div class="ev' + (last ? ' last' : '') + '"><div></div><div></div><div class="gap">' + esc(item.text) + '</div></div>';
      }
      if (item.kind === 'end') {
        return '<div class="ev endrow last"><div class="t">' + esc(item.time) + '</div><div class="dot"></div><div class="labnote">Trace stopped</div></div>';
      }
      return stepHtml(item, last);
    }).join('');
  }

  function glanceHtml(g) {
    return g.map(function (x) {
      var lab = x.actor === 'lab';
      return '<li><a href="#e' + x.n + '"' + (lab ? ' class="lab-row"' : '') + '><span class="n" style="background:var(--' + (lab ? 'lab' : 'app') + ')">' +
        x.n + '</span><span>' + esc(x.text) + '</span></a></li>';
    }).join('');
  }

  function renderView(view) {
    var iocs = view.iocs.map(function (kv, i) {
      return '<div><dt>' + esc(kv[0]) + '</dt><dd>' + esc(kv[1]) + '</dd>' +
        '<button type="button" class="cp" data-i="' + i + '" data-copy="' + esc(kv[1]) + '">Copy</button></div>';
    }).join('');
    var other = view.otherHosts && view.otherHosts.length
      ? '<h3 class="other">' + esc(view.otherHostsLabel) + '</h3><ul class="hosts">' +
        view.otherHosts.map(function (h) { return '<li>' + esc(h) + '</li>'; }).join('') + '</ul>' : '';
    var warn = view.coverageWarning
      ? '<div class="warn" role="note"><b>Coverage warning.</b> ' + esc(view.coverageWarning) + '</div>' : '';
    return '<section class="stage"><div class="in">' +
      '<p class="kicker">' + esc(view.kicker) + '</p><h1>' + esc(view.headline) + '</h1>' +
      '<div class="wrap"><div class="main">' + warn + '<div class="rail">' + timelineHtml(view.timeline) + '</div></div>' +
      '<aside class="side"><div class="glance"><h2>At a glance</h2><ol>' + glanceHtml(view.glance) + '</ol>' +
      '<div class="key"><span><i style="background:var(--app)"></i>the sample</span><span><i style="background:var(--lab)"></i>the lab (analyst)</span><span><i style="background:var(--net)"></i>the network</span></div></div>' +
      '<div class="iocs"><h2>Indicators of compromise</h2><dl class="ioc">' + iocs + '</dl>' + other + '</div></aside>' +
      '</div></div></section>' +
      '<section class="in below"><div class="limits"><h2>Limits of this run</h2><ul>' +
      view.limits.map(function (l) { return '<li>' + esc(l) + '</li>'; }).join('') + '</ul></div>' +
      '<p class="foot">' + esc(view.footer) + '</p></section>';
  }

  function wireView(el) {
    var doc = el.ownerDocument;
    el.addEventListener('click', function (ev) {
      var t = ev.target.closest ? ev.target : ev.target.parentElement;
      var b = t && t.closest('.evb');
      if (b) {
        var open = b.getAttribute('aria-expanded') === 'true';
        b.setAttribute('aria-expanded', open ? 'false' : 'true');
        b.textContent = open ? 'Evidence' : 'Hide evidence';
        doc.getElementById(b.getAttribute('aria-controls')).hidden = open;
        return;
      }
      var c = t && t.closest('.cp');
      if (!c) return;
      var done = function (text) { c.textContent = text; setTimeout(function () { c.textContent = 'Copy'; }, 1600); };
      var fallback = function () {
        var dd = c.parentNode.querySelector('dd'), sel = doc.defaultView.getSelection();
        if (dd && sel) { var r = doc.createRange(); r.selectNodeContents(dd); sel.removeAllRanges(); sel.addRange(r); }
        done('Select and copy');
      };
      try {
        doc.defaultView.navigator.clipboard.writeText(c.getAttribute('data-copy')).then(function () { done('Copied'); }, fallback);
      } catch (e) { fallback(); }
    });
  }

  M.renderView = renderView;
  M.wireView = wireView;
  if (typeof module !== 'undefined' && module.exports) module.exports = M;
  else root.AnubeeModView = M;
})(typeof window !== 'undefined' ? window : globalThis);
