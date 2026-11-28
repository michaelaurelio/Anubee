// Tests for the run view renderer: View -> HTML string.
// Run: node --test 'tools/mod-view/test_*.mjs'
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
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
