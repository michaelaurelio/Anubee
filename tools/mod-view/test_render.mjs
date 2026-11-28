// Tests for the run view renderer: View -> HTML string.
// Run: node --test 'tools/mod-view/test_*.mjs'
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const req = createRequire(import.meta.url);
const M = req('./model.js');
req('./render.js');
const data = (n) => readFileSync(path.join(here, n), 'utf8');
const records = data('testdata/sample-run.jsonl').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const V = M.buildView({
  records, marksText: data('testdata/sample-run.marks'), profile: JSON.parse(data('testdata/profile.json')),
  templates: JSON.parse(data('templates.json')),
  meta: { family: 'ExampleFam', familySource: 'MalwareBazaar tag', sha256: 'aa'.repeat(32), device: 'real Android 16 phone' },
  badging: null, staticApk: null,
});
const step = (v) => v.timeline.find((i) => i.kind === 'step');

test('record text is escaped', () => {
  const v = structuredClone(V); step(v).card.title = '<img src=x onerror=1>&';
  const h = M.renderView(v);
  assert.ok(h.includes('&lt;img src=x onerror=1&gt;&amp;') && !h.includes('<img src=x'));
});

test('no interactive control inside another', () => {
  const h = M.renderView(V);
  assert.ok(!/<button[^>]*>(?:(?!<\/button>).)*<(a|button)\b/s.test(h));
  assert.ok(!/<a\b[^>]*>(?:(?!<\/a>).)*<(a|button)\b/s.test(h));
});

test('lab steps render as lab notes, sample steps as cards', () => {
  const h = M.renderView(V);
  assert.match(h, /Lab:<\/b> Granted/);
  assert.equal((h.match(/class="card"/g) || []).length, 4);
});

test('only ATT&CK links leave the page', () => {
  const urls = [...M.renderView(V).matchAll(/href="(https?:[^"]+)"/g)].map((m) => m[1]);
  assert.ok(urls.length > 0 && urls.every((u) => u.startsWith('https://attack.mitre.org/')));
  assert.ok(!/(src|href)="https?:(?!\/\/attack\.mitre\.org)/.test(M.renderView(V)));
});

test('a null step time leaves the slot empty', () => {
  const v = structuredClone(V); step(v).time = null;
  const h = M.renderView(v);
  assert.ok(!h.includes('null') && h.includes('<div class="t"></div>'));
});

test('coverage warning shows above the timeline; absent when null', () => {
  const v = structuredClone(V); v.coverageWarning = 'net <b> was degraded';
  const h = M.renderView(v);
  assert.ok(h.indexOf('class="warn"') > -1 && h.indexOf('class="warn"') < h.indexOf('class="rail"'));
  assert.ok(h.includes('net &lt;b&gt; was degraded'));
  assert.ok(!M.renderView(V).includes('class="warn"'));
});

test('other hosts get their own heading and no copy buttons', () => {
  const v = structuredClone(V); v.otherHosts = ['203.0.113.9:80'];
  const h = M.renderView(v);
  assert.ok(h.includes('<h3 class="other">Other hosts contacted</h3>') && h.includes('<li>203.0.113.9:80</li>'));
  assert.equal((h.match(/class="cp"/g) || []).length, V.iocs.length);
  assert.ok(!M.renderView(V).includes('class="other"'));
});

test('counts in facts are bolded after escaping', () => {
  const v = structuredClone(V); step(v).card.facts = 'a<b> 28 alarms & 12 respawns';
  const h = M.renderView(v);
  assert.ok(h.includes('a&lt;b&gt; <b>28</b> alarms &amp; <b>12</b> respawns'));
});

test('evidence buttons point at hidden panels; glance links hit step ids', () => {
  const h = M.renderView(V);
  for (const m of h.matchAll(/aria-controls="(d\d+)"/g)) assert.ok(h.includes(`id="${m[1]}" hidden`));
  for (const m of h.matchAll(/href="#(e\d+)"/g)) assert.ok(h.includes(`id="${m[1]}"`));
  assert.ok(h.includes('Trace stopped') && h.includes('Limits of this run'));
});

test('a technique id that is not an ATT&CK id gets no link', () => {
  const v = structuredClone(V);
  const c = v.timeline.find((i) => i.kind === 'step' && i.card.techniques.length).card;
  c.techniques = [{ id: 'T1406.002', name: 'Software Packing' }, { id: '../../evil', name: 'X' }, { id: 'T14060', name: 'Y' }];
  const h = M.renderView(v);
  assert.ok(h.includes('href="https://attack.mitre.org/techniques/T1406/002/"'));
  assert.ok(!h.includes('evil/') && !/href="[^"]*T14060/.test(h));
  assert.ok(h.includes('../../evil X') && h.includes('T14060 Y'));
});

const css = readFileSync(path.join(here, 'view.css'), 'utf8');
const phone = [...css.matchAll(/@media\(max-width:900px\)\{((?:[^{}]*\{[^}]*\})*)\}/g)].map((m) => m[1]).join('');

test('below 900 px the page reads: at a glance, timeline, then indicators', () => {
  const order = (sel) => { const m = new RegExp('(^|\\})' + sel.replace('.', '\\.') + '\\{[^}]*order:(-?\\d+)').exec(phone); return m ? +m[2] : 0; };
  assert.match(phone, /\.side\{[^}]*display:contents/);
  assert.ok(order('.glance') < order('.main') && order('.main') < order('.iocs'));
  const h = M.renderView(V);
  assert.ok(h.indexOf('class="main"') < h.indexOf('class="glance"') && h.indexOf('class="glance"') < h.indexOf('class="iocs"'));
});

test('bold counts in a lab note are not lab-coloured, only its lead is', () => {
  assert.ok(css.includes('.labnote>b{') && !/\.labnote b\{/.test(css));
});

// ---- Anubee Desktop theme ----
const LITERAL = {
  dark: { surface: '#0f0e11', panel: '#16151a', 'panel-2': '#1c1a20', bar: '#211f26', border: '#322e38', 'border-soft': '#29262f', text: '#e7e3d9', muted: '#97918a', hover: '#23202a', accent: '#c9a24a', 'accent-bd': '#d8b05a', 'accent-soft': '#c9a24a26', 'accent-fg': '#e0be6a', 'accent-ink': '#17140d', 'warn-bg': '#3a2f12', 'warn-bd': '#5c4a1a', 'warn-fg': '#e8c977', shadow: '0 2px 10px rgba(0,0,0,.35)', 'k-syscall': '#e8845c', 'cat-emulator': '#b888c8', 'cat-hook': '#4fb6a0' },
  light: { surface: '#f5f3ee', panel: '#fbfaf6', 'panel-2': '#f1eee7', bar: '#ede9e0', border: '#dcd6c9', 'border-soft': '#e8e3d8', text: '#201e1b', muted: '#6e675c', hover: '#f6ecea', accent: '#b0812e', 'accent-bd': '#9a6f24', 'accent-soft': '#f2e6cf', 'accent-fg': '#8a6417', 'accent-ink': '#17140d', 'warn-bg': '#fff3cd', 'warn-bd': '#ffe08a', 'warn-fg': '#7a5c00', shadow: '0 1px 4px rgba(0,0,0,.12)', 'k-syscall': '#c25a34', 'cat-emulator': '#8e5aa8', 'cat-hook': '#1e8f7e' },
};
const desktopHtml = path.join(here, '../../../Anubee-Desktop/src/renderer/index.html');
const block = (src, sel) => {
  const i = src.indexOf(sel + ' {') >= 0 ? src.indexOf(sel + ' {') : src.indexOf(sel + '{');
  assert.ok(i >= 0, 'missing block ' + sel);
  const j = src.indexOf('}', i);
  const out = {};
  for (const m of src.slice(i, j).matchAll(/--([\w-]+)\s*:\s*([^;]+);/g)) out[m[1]] = m[2].trim();
  return out;
};
for (const theme of ['dark', 'light']) {
  test(`view.css ${theme} tokens equal Desktop's`, (t) => {
    const mine = block(css, `:root[data-theme=${theme}]`);
    let want = LITERAL[theme];
    if (existsSync(desktopHtml)) {
      const d = block(readFileSync(desktopHtml, 'utf8'), `:root[data-theme="${theme}"]`);
      want = Object.fromEntries(Object.keys(LITERAL[theme]).map((k) => [k, d[k]]));
      assert.deepEqual(want, LITERAL[theme], 'literal table drifted from Desktop');
    } else t.diagnostic('Anubee-Desktop checkout absent; comparing to literal values');
    for (const [k, v] of Object.entries(want)) assert.equal(mine[k], v, `--${k} (${theme})`);
  });
}
test('actor colours resolve to Desktop tokens', () => {
  const root = block(css, ':root');
  assert.equal(root.app, 'var(--k-syscall)');
  assert.equal(root.lab, 'var(--cat-emulator)');
  assert.equal(root.net, 'var(--cat-hook)');
});
test('no dark-only palette is left, no embedded fonts or urls', () => {
  assert.ok(!/@font-face/.test(css) && !/url\(/.test(css));
  assert.ok(css.includes(":root[data-theme=light]") && css.includes(":root[data-theme=dark]"));
  assert.ok(!/light-dark\(/.test(css));
  assert.ok(css.includes("'Inter', system-ui, sans-serif") && css.includes("'JetBrains Mono', ui-monospace, \"SF Mono\", Menlo, monospace"));
  assert.ok(/prefers-color-scheme:\s*light/.test(css));
  assert.ok(!/\.stage\{[^}]*#0e1117/.test(css));
});

test('no actor-coloured fill carries text: glance numbers are classed, not inline-styled', () => {
  const html = M.renderView(V);
  assert.ok(/class="n [al]"/.test(html) && !/class="n[^"]*" style=/.test(html));
});

// ---- final review fixes ----
test('unattributed steps are neutral: their own class, a muted ring and border, a key entry, still in the sample lane', () => {
  const recs = [{ type: 'perm_change', ts_ns: records[0].ts_ns + 5e9, package: 'com.example.sample', category: 'appop', name: 'CAMERA', change: 'granted', old: null, new: 'allow' }];
  const W = M.buildView({ records: recs, marksText: '', profile: { keys: {} }, templates: JSON.parse(data('templates.json')) });
  const h = M.renderView(W);
  assert.match(h, /<div class="ev u" id="e1">/);
  assert.match(h, /class="card"/);                                        // a card in the sample lane, not a lab note
  assert.match(h, /<span class="n u">1<\/span>/);
  assert.ok(!/class="n a"|class="ev a/.test(h));
  assert.match(h, /<span><i style="background:var\(--muted\)"><\/i>Not attributed<\/span><\/div>/);
  assert.match(css, /\.u \.dot,\.n\.u\{border-color:var\(--muted\)\}/);
  assert.match(css, /\.u \.card\{border-left-color:var\(--muted\)\}/);
  assert.ok(!/\.u[^{]*\{[^}]*--app/.test(css));
});

test('a hovered glance row keeps full text contrast', () => {
  assert.match(css, /\.glance a:hover\{[^}]*color:var\(--text\)/);
});

test('facts bold only standalone numbers, never digits inside names', () => {
  const v = structuredClone(V); step(v).card.facts = '0.pobfs · DEX · 1.4 KB · 12 respawns from 48 s · x2 · 3465e6af · a/1/b · 777276-byte';
  const h = M.renderView(v);
  assert.ok(h.includes('0.pobfs · DEX · <b>1.4</b> KB · <b>12</b> respawns from <b>48</b> s · x2 · 3465e6af · a/1/b · <b>777276</b>-byte'), h.match(/class="facts">[^<]*(?:<b>[^<]*<\/b>[^<]*)*/)[0]);
});

test('the end row names its source', () => {
  const v = structuredClone(V); v.timeline[v.timeline.length - 1].text = 'Last record';
  assert.ok(M.renderView(v).includes('<div class="labnote">Last record</div>'));
});
