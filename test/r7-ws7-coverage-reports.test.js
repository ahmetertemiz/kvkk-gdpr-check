// Round 7 / WS7: coverage honesty, review-list quality and rendering of the measured calibration (contract C-R7).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit, assessCoverage, applyLayerHonesty, organizeReview, calibrationRate } from '../src/audit/index.js';
import { PrivacyGraph } from '../src/audit/graph.js';
import { detectStack, assessLayers, layerCovered, normalizeLayers, configModules } from '../src/audit/legal/stack.js';
import { renderAudit } from '../src/audit/report/index.js';
import { S, layerRows, calibrationText, scoreView } from '../src/audit/report/common.js';
import { summarize } from '../src/summary.js';

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r7ws7-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}
const code = (rel, content) => ({ rel, kind: 'code', content });
const manifest = (rel, obj) => ({ rel, kind: 'manifest', content: JSON.stringify(obj) });
const ids = (files) => detectStack(files).techs.map((t) => t.id);

/* ------------------------------------------------------------------ 1) core layer partial → score unreliable */

test('WS7-1: a partial / unsupported core layer makes scoreReliable false and the warning names the layer', () => {
  const g = new PrivacyGraph();
  g.dataElement({ element: 'email', category: 'contact', sensitivity: 'normal', label: 'E-mail' });
  const files = [code('src/a.js', 'export const x = 1')];
  const ok = assessCoverage(g, { files, shared: {} }, 'en');
  assert.equal(ok.scoreReliable, true);
  // Code in a language no extractor parses, reported through C2 on the dbWrites layer.
  const unparsed = [{ layer: 'dbWrites', kind: 'code:kotlin', label: { tr: 'Kotlin kodu', en: 'Kotlin code' }, files: ['a.kt', 'b.kt', 'c.kt'], count: 3 }];
  const cov = assessCoverage(g, { files, shared: { unparsed } }, 'en');
  assert.ok(String(cov.layers.dbWrites.status).startsWith('unsupported:') || cov.layers.dbWrites.status === 'partial');
  assert.equal(cov.scoreReliable, false);
  assert.equal(cov.coverage, 'partial');
  assert.match(cov.warning, /score not reliable/);
  assert.match(cov.warning, /database writes/);
  assert.match(cov.warning, /Kotlin code: not parsed/);
});

test('WS7-1: applyLayerHonesty — vendors partial flips scoreReliable; a declarations gap makes declarations partial and says transparency goes to review', () => {
  const layers = {
    schema: { status: 'found', count: 3, gaps: [] }, routes: { status: 'found', count: 2, gaps: [] }, dbWrites: { status: 'found', count: 4, gaps: [] },
    vendors: { status: 'partial', count: 1, gaps: [{ tech: 'x', label: 'some-sdk', reason: 'unknown-sdk' }] },
    declarations: { status: 'found', count: 1, gaps: [{ tech: 'notice-language', label: { tr: 'Tayca aydınlatma metni', en: 'privacy notice in Thai' }, reason: 'not-parsed' }] },
  };
  const out = applyLayerHonesty({ coverage: 'ok', scoreReliable: true, warning: null }, layers, true);
  assert.equal(out.scoreReliable, false);
  assert.equal(out.coverage, 'partial');
  assert.match(out.warning, /vendors partial \(some-sdk: SDK not traced to a flow\)/);
  assert.equal(layers.declarations.status, 'partial');
  assert.match(out.warning, /privacy notice in Thai/);
  assert.match(out.warning, /transparency/);
  // Only a declarations gap: coverage partial, but the score stays reliable (declarations is not a core layer).
  const only = { schema: { status: 'found', count: 1 }, declarations: { status: 'unsupported:x', count: 0, gaps: [{ label: 'x', reason: 'not-parsed' }] } };
  const o2 = applyLayerHonesty({ coverage: 'ok', scoreReliable: true, warning: null }, only, false);
  assert.equal(o2.scoreReliable, true);
  assert.equal(o2.coverage, 'partial');
  assert.match(o2.warning, /şeffaflık/);
});

test('WS7-1: a declarations gap reported through C2 sends transparency conclusions to review via layer dependencies', () => {
  const g = new PrivacyGraph();
  g.dataElement({ element: 'email', category: 'contact', sensitivity: 'normal', label: 'E-mail' });
  g.addNode({ id: 'decl:1', type: 'Declaration', file: 'privacy.md' });
  const unparsed = [{ layer: 'declarations', kind: 'notice-language', label: { tr: 'desteklenmeyen dilde aydınlatma metni', en: 'privacy notice in an unsupported language' }, files: ['privacy.md'], count: 1 }];
  const cov = assessCoverage(g, { files: [code('src/a.js', '')], shared: { unparsed } }, 'en');
  assert.equal(cov.layers.declarations.status, 'partial');
  assert.equal(layerCovered(cov.layers, 'declarations'), false);
  const trn = { rule: { id: 'AUD-TRN-02', category: 'transparency', severity: 'medium' }, severity: 'medium', locations: [{ file: 'privacy.md', line: 1, basis: 'absence', confidence: 0.8, label: 'x', reviewReason: { tr: 'katman kapsanmadı', en: 'layer not covered' } }] };
  const { review } = organizeReview([], [trn], { layers: cov.layers, ruleBasis: { 'AUD-TRN-02': { basis: 'absence', layers: ['declarations'] } } });
  assert.equal(review[0].locations[0].reviewType, 'notice-language');
  assert.match(review[0].locations[0].reviewReason.en, /unsupported language/);
});

/* --------------------------------------------------------------------------------- 2) found (0) → none */

test('WS7-2: "found" with count 0 is never a status — deletes with traced writes but no deletion read none (covered)', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'table:users', type: 'Store', kind: 'table', table: 'users', file: 'db/schema.sql' });
  g.addNode({ id: 'endpoint:x', type: 'Endpoint', method: 'POST', path: '/x', file: 'api/x.js', framework: 'node' });
  g.addEdge({ from: 'endpoint:x', to: 'table:users', type: 'writes', evidence: [{ file: 'api/x.js', line: 3 }] });
  const files = [code('api/x.js', 'db.insert()'), manifest('package.json', { dependencies: { pg: '8' } })];
  const layers = assessLayers(g, files, detectStack(files), {});
  assert.equal(layers.dbWrites.status, 'found');
  assert.equal(layers.deletes.status, 'none');
  assert.equal(layers.deletes.count, 0);
  assert.equal(layerCovered(layers, 'deletes'), true, 'still a usable absence basis');
  for (const l of Object.values(layers)) assert.ok(!(l.status === 'found' && l.count === 0), JSON.stringify(l));
  const n = normalizeLayers({ a: { status: 'found', count: 0, gaps: [] } });
  assert.equal(n.a.status, 'none');
});

test('WS7-2: reports never show found (0)', () => {
  const result = { findings: [], review: [], layers: { schema: { status: 'found', count: 0, gaps: [] }, routes: { status: 'found', count: 2, gaps: [] } } };
  const rows = layerRows(result, S.en);
  assert.equal(rows[0].kind, 'none');
  assert.equal(rows[0].label, S.en.layerState.none);
  for (const fmt of ['text', 'md', 'html']) assert.doesNotMatch(renderAudit(result, { format: fmt, lang: 'en' }), /(?<!none )\bfound \(0\)/);
  const json = JSON.parse(renderAudit(result, { format: 'json', lang: 'en' }));
  assert.equal(json.layers.schema.status, 'none');
});

/* ----------------------------------------------------------------------------------- 3) stack detection */

test('WS7-3: a Next app-router route.ts exporting GET/POST is not Astro, even with astro in another package of the monorepo', () => {
  const files = [
    manifest('package.json', { dependencies: { next: '14' } }),
    manifest('packages/sdk-astro/package.json', { peerDependencies: { astro: '4' }, devDependencies: { astro: '4' } }),
    code('apps/web/app/api/users/route.ts', "import { NextResponse } from 'next/server';\nexport async function GET() { return NextResponse.json([]) }\nexport async function POST(req: Request) { return NextResponse.json({}) }"),
    code('packages/sdk-astro/src/index.ts', 'export function track() {}'),
  ];
  assert.ok(!ids(files).includes('astro'));
});

test('WS7-3: real Astro endpoints / actions are still detected (config + src/pages, astro: imports, .astro)', () => {
  const a = [
    { rel: 'astro.config.mjs', kind: 'code', content: "import { defineConfig } from 'astro/config'; export default defineConfig({})" },
    manifest('package.json', { dependencies: { astro: '4' } }),
    code('src/pages/api/subscribe.ts', 'export const POST = async ({ request }) => new Response("ok")'),
  ];
  assert.ok(ids(a).includes('astro'));
  // Different style: no config file, an action module importing astro:actions inside a sub-package.
  const b = [
    manifest('site/package.json', { dependencies: { astro: '5' } }),
    code('site/src/actions/index.ts', "import { defineAction } from 'astro:actions';\nexport const server = { join: defineAction({ handler: async () => ({}) }) }"),
  ];
  assert.ok(ids(b).includes('astro'));
});

test('WS7-3: Fastify (and other Node HTTP frameworks) are listed when used', () => {
  const f = [
    manifest('apps/api/package.json', { dependencies: { fastify: '4' } }),
    code('apps/api/src/index.ts', "import Fastify from 'fastify';\nconst app = Fastify({ logger: true });\napp.get('/health', async () => ({ ok: true }));"),
    code('apps/api/src/routes/user.ts', "import type { FastifyInstance } from 'fastify';\nexport default async function (fastify: FastifyInstance) { fastify.post('/user', async () => ({})) }"),
  ];
  assert.ok(ids(f).includes('fastify'));
  const k = [manifest('package.json', { dependencies: { koa: '2', '@koa/router': '12' } }), code('server.js', "const Koa = require('koa');\nconst Router = require('@koa/router');\nconst app = new Koa();\nconst r = new Router();")];
  assert.ok(ids(k).includes('koa'));
  // A dependency that is never used is not a detected technology.
  assert.ok(!ids([manifest('package.json', { dependencies: { koa: '2' } }), code('a.js', 'export const x = 1')]).includes('koa'));
});

test('WS7-3: an Express server that only hosts another framework handler is listed but is no routes-layer gap', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'ep:1', type: 'Endpoint', method: 'POST', path: '/login', file: 'app/routes/login.tsx', framework: 'remix' });
  const files = [
    manifest('package.json', { dependencies: { express: '4', '@remix-run/node': '2', '@remix-run/express': '2' } }),
    code('server.js', "import express from 'express';\nimport { createRequestHandler } from '@remix-run/express';\nconst app = express();\napp.use(express.static('public'));\napp.all('*', createRequestHandler({ build }));\n"),
    code('app/routes/login.tsx', 'export async function action({ request }) { return null }'),
  ];
  const stack = detectStack(files);
  assert.ok(stack.techs.some((t) => t.id === 'express'));
  const layers = assessLayers(g, files, stack, {});
  assert.equal(layers.routes.status, 'found');
  assert.ok(!layers.routes.gaps.some((x) => x.tech === 'express'));
  // An Express app with its own routes and nothing modelled is a gap.
  const own = [manifest('package.json', { dependencies: { express: '4' } }), code('api.js', "const express = require('express');\nconst app = express();\napp.post('/users', (req, res) => res.json({}));\n")];
  const l2 = assessLayers(new PrivacyGraph(), own, detectStack(own), {});
  assert.ok(String(l2.routes.status).startsWith('unsupported:'), l2.routes.status);
});

test('WS7-3: Nuxt module lists count as dependencies', () => {
  assert.deepEqual(configModules("export default defineNuxtConfig({ modules: ['@nuxtjs/supabase', \"@unocss/nuxt\", ['@nuxtjs/i18n', {}]], ssr: true })"), ['@nuxtjs/supabase', '@unocss/nuxt', '@nuxtjs/i18n']);
});

test('WS7-3: Nuxt server/api + @nuxtjs/supabase is reported (recognised-but-unsupported with gaps), never a silent 0', async () => {
  const dir = tmpProject({
    'package.json': JSON.stringify({ private: true, devDependencies: { nuxt: '3.8.0', '@nuxtjs/supabase': '1.1.0' } }),
    'nuxt.config.ts': "export default defineNuxtConfig({ modules: ['@nuxtjs/supabase'] })",
    'server/api/profile.post.ts': "import { serverSupabaseClient } from '#supabase/server'\nexport default defineEventHandler(async (event) => {\n  const body = await readBody(event)\n  const client = await serverSupabaseClient(event)\n  await client.from('profiles').upsert({ id: body.id, full_name: body.full_name, email: body.email })\n  return { ok: true }\n})\n",
    'pages/account.vue': "<script setup lang=\"ts\">\nconst client = useSupabaseClient()\nconst user = useSupabaseUser()\nconst { data } = await client.from('profiles').select('full_name, email').eq('id', user.value?.id)\n</script>\n<template><div>{{ data }}</div></template>\n",
  });
  const r = await audit(dir, { lang: 'en' });
  const stack = r.stack.map((t) => t.id);
  assert.ok(stack.includes('supabase'), stack.join(','));
  assert.ok(stack.includes('nuxt-server'), stack.join(','));
  const records = r.graph.nodesOf('Store').filter((s) => s.kind === 'table' || s.kind === 'collection');
  if (records.length) {
    // Another extractor resolved the composables: then the layers must say what they found, not 'none'.
    assert.notEqual(r.layers.schema.status, 'none');
    return;
  }
  for (const name of ['schema', 'dbWrites']) {
    const l = r.layers[name];
    assert.ok(String(l.status).startsWith('unsupported:'), `${name}: ${l.status}`);
    assert.ok(l.gaps.length > 0, `${name} has gaps`);
  }
  assert.ok(r.layers.dbWrites.gaps.some((g) => g.kind === 'nuxt-supabase'));
  assert.equal(r.scoreReliable, false);
  assert.ok(r.warnings.some((w) => /Nuxt composables/.test(w)));
  // Routes: either modelled (found) or reported as unsupported Nuxt server routes — never a silent none.
  assert.ok(r.layers.routes.status === 'found' || String(r.layers.routes.status).startsWith('unsupported:'), r.layers.routes.status);
});

/* ------------------------------------------------------------------------------------ 4) review quality */

const rule = (id, severity = 'medium', category = 'x') => ({ id, severity, category, title: { tr: id, en: id } });

test('WS7-4: review de-duplication (rule+file+line+sub, scored duplicates, blind vs check-produced) with reasons, sort and summary', () => {
  const findings = [{ rule: rule('AUD-SEC-03', 'high'), severity: 'high', locations: [{ file: 'api/a.ts', line: 5, label: 'scored' }] }];
  const review = [
    { rule: rule('AUD-SEC-03', 'high'), severity: 'high', locations: [
      { file: 'api/a.ts', line: 5, label: 'dup of scored', basis: 'absence', confidence: 0.7 },
      { file: 'api/b.ts', line: 9, label: 'b', basis: 'absence', confidence: 0.55 },
      { file: 'api/b.ts', line: 9, label: 'b again', basis: 'absence', confidence: 0.55 },
    ] },
    { rule: rule('AUD-DEL-02', 'low'), severity: 'low', locations: [
      { file: 'db/m.sql', line: 3, sub: 'DEL-02:fk-no-cascade', label: 'fk', confidence: 0.6, calibration: { sub: 'DEL-02:fk-no-cascade', status: 'demoted', tp: 3, fp: 16, n: 19, precision: 3 / 19, repos: 5 } },
      { file: 'db/m.sql', line: 3, sub: 'DEL-02:fk-no-cascade', label: 'fk dup', confidence: 0.6, calibration: { sub: 'DEL-02:fk-no-cascade', status: 'demoted', tp: 3, fp: 16 } },
      { file: 'db/m.sql', line: 3, sub: 'DEL-02:other', label: 'other sub', confidence: 0.9 },
    ] },
    // A blind-coverage item and a check-produced item of the same rule: the blind one goes.
    { rule: rule('AUD-DEL-01', 'high'), severity: 'high', locations: [{ file: null, line: null, blind: true, basis: 'absence', confidence: 0.5, reviewType: 'coverage', label: 'blind', reviewReason: { tr: 'kör', en: 'blind' } }] },
    { rule: rule('AUD-DEL-01', 'high'), severity: 'high', locations: [{ file: 'src/users.ts', line: 1, basis: 'absence', confidence: 0.8, label: 'checked' }] },
  ];
  const layers = { routes: { status: 'partial', count: 3, gaps: [{ tech: 'hapi', label: 'hapi', reason: 'unsupported' }] }, schema: { status: 'found', count: 2 }, dbWrites: { status: 'found', count: 2 }, deletes: { status: 'none', count: 0, covered: true } };
  const basis = { 'AUD-SEC-03': { basis: 'absence', layers: ['routes'] }, 'AUD-DEL-01': { basis: 'absence', layers: ['schema', ['dbWrites', 'deletes']] } };
  const { review: out, summary } = organizeReview(findings, review, { layers, ruleBasis: basis });
  const sec = out.find((f) => f.rule.id === 'AUD-SEC-03');
  assert.deepEqual(sec.locations.map((l) => l.label), ['b']);
  assert.equal(sec.locations[0].reviewType, 'layer');
  assert.match(sec.locations[0].reviewReason.en, /routes partial \(hapi: not supported\)/);
  const del2 = out.find((f) => f.rule.id === 'AUD-DEL-02');
  assert.equal(del2.locations.length, 2, 'same sub collapsed, other sub kept');
  assert.deepEqual(del2.locations.map((l) => l.label).sort(), ['fk', 'other sub']);
  const cal = del2.locations.find((l) => l.reviewType === 'calibration');
  assert.match(cal.reviewReason.en, /measured precision 16% \(3\/16, 5 projects\), n=19/);
  assert.match(cal.reviewReason.tr, /ölçülen isabet %16/);
  const del1 = out.find((f) => f.rule.id === 'AUD-DEL-01');
  assert.deepEqual(del1.locations.map((l) => l.label), ['checked']);
  assert.equal(del1.locations[0].reviewType, 'check');
  for (const f of out) for (const l of f.locations) assert.ok(l.reviewReason && l.reviewReason.tr && l.reviewReason.en, `reason on ${f.rule.id}`);
  // severity first: high entries before the low one
  assert.equal(out[out.length - 1].rule.id, 'AUD-DEL-02');
  assert.equal(summary.total, 4);
  assert.deepEqual(summary.byType, { layer: 1, calibration: 1, check: 2 });
});

test('WS7-4: a blind item alone is kept, with its coverage reason', () => {
  const { review, summary } = organizeReview([], [{ rule: rule('AUD-TRN-01', 'high'), severity: 'high', locations: [{ file: null, blind: true, reviewType: 'coverage', basis: 'absence', reviewReason: { tr: 'kapsam kör', en: 'coverage blind' } }] }], {});
  assert.equal(review.length, 1);
  assert.deepEqual(summary.byType, { coverage: 1 });
});

/* ---------------------------------------------------------------------------------- 5) report rendering */

function calResult(extra = {}) {
  let lineNo = 0;
  const loc = (label, calibration, more = {}) => ({ file: 'src/a.ts', line: ++lineNo, label, severity: 'high', confidence: 0.8, ...(calibration !== undefined ? { calibration } : {}), ...more });
  return {
    root: '/tmp/x', filesScanned: 3, score: 72, counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    findings: [{ rule: { id: 'AUD-SEC-04', category: 'security', severity: 'high', title: { tr: 'Log', en: 'Log' }, desc: { tr: 'd', en: 'd' }, fix: { tr: 'f', en: 'f' }, refs: [] }, severity: 'high', locations: [
      loc('reliable', { sub: 'SEC-04:x', status: 'reliable', tp: 45, fp: 5, n: 50, precision: 0.9, lower90: 0.82, upper90: 0.95, repos: 12, modifiers: [] }),
      loc('insufficient', { sub: 'SEC-04:y', status: 'insufficient', tp: 2, fp: 1 }),
      loc('unmeasured', { sub: 'SEC-04:z', status: 'unmeasured' }),
      loc('kept', { sub: 'SEC-04:w', status: 'kept-strong-evidence', tp: 5, fp: 6, repos: 5, strongEvidence: { code: 'handler-analysed', tr: 'işleyici incelendi', en: 'handler analysed' } }),
      loc('partial fields', { status: 'measured', tp: 7, fp: 3 }),
      loc('sub only', undefined, { sub: 'SEC-04:q' }),
      loc('legacy', undefined),
    ] }],
    review: [{ rule: { id: 'AUD-DEL-02', category: 'deletion', severity: 'low', title: { tr: 'Del', en: 'Del' } }, severity: 'low', review: true, locations: [
      { file: 'db/m.sql', line: 3, label: 'demoted', reviewType: 'calibration', reviewReason: { tr: 'neden', en: 'why' }, calibration: { sub: 'DEL-02:fk', status: 'demoted', tp: 3, fp: 16, repos: 5 } },
    ] }],
    reviewSummary: { total: 1, entries: 1, byType: { calibration: 1 }, byRule: { 'AUD-DEL-02': 1 } },
    warnings: [], coverage: 'ok', scoreReliable: true,
    ...extra,
  };
}

test('WS7-5: calibrationText tolerates missing fields', () => {
  assert.equal(calibrationText({}, S.tr, 'tr'), '');
  assert.equal(calibrationText({ sub: 'X:y' }, S.tr, 'tr'), 'ölçülmedi');
  assert.equal(calibrationText({ calibration: {} }, S.en, 'en'), 'not measured');
  assert.equal(calibrationText({ calibration: { status: 'reliable', tp: 45, fp: 5, precision: 0.9, repos: 12 } }, S.tr, 'tr'), 'ölçülen isabet %90 (45/5, 12 proje)');
  assert.equal(calibrationText({ calibration: { tp: 9, fp: 1 } }, S.en, 'en'), 'measured precision 90% (9/1)');
  assert.equal(calibrationText({ calibration: { status: 'insufficient', tp: 1, fp: 1 } }, S.tr, 'tr'), 'yetersiz veri (1/1)');
  assert.equal(calibrationText({ calibration: { status: 'insufficient' } }, S.en, 'en'), 'insufficient data');
  assert.match(calibrationText({ calibration: { status: 'kept-strong-evidence', tp: 5, fp: 6, strongEvidence: { tr: 'işleyici incelendi', en: 'handler analysed' } } }, S.en, 'en'), /measured precision 45% \(5\/6\) — kept on strong evidence: handler analysed/);
  assert.match(calibrationText({ calibration: { status: 'demoted', modifiers: ['path:nonprod-file'] } }, S.en, 'en'), /non-production file — low measured precision — not scored/);
  assert.equal(calibrationRate({ tp: 3, fp: 1, repos: 1 }, 'en'), 'measured precision 75% (3/1, 1 project)');
  assert.equal(calibrationRate({ status: 'unmeasured' }, 'en'), '');
});

test('WS7-5: calibration and its explanation are rendered in every report format (TR and EN)', () => {
  const r = calResult();
  for (const lang of ['tr', 'en']) {
    const t = S[lang];
    for (const fmt of ['text', 'md', 'html']) {
      const out = renderAudit(r, { format: fmt, lang });
      const plain = fmt === 'html' ? out.replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&') : out;
      assert.ok(plain.includes(t.calNote.slice(0, 40)), `${fmt}/${lang}: explanation`);
      assert.ok(plain.includes(lang === 'tr' ? 'ölçülen isabet %90 (45/5, 12 proje)' : 'measured precision 90% (45/5, 12 projects)'), `${fmt}/${lang}: rate`);
      assert.ok(plain.includes(lang === 'tr' ? 'yetersiz veri (2/1)' : 'insufficient data (2/1)'), `${fmt}/${lang}: insufficient`);
      assert.ok(plain.includes(t.calUnmeasured), `${fmt}/${lang}: unmeasured`);
      assert.ok(plain.includes(lang === 'tr' ? 'güçlü kanıtla tutuldu: işleyici incelendi' : 'kept on strong evidence: handler analysed'), `${fmt}/${lang}: strong evidence`);
      assert.ok(plain.includes(lang === 'tr' ? 'ölçülen isabet %16 (3/16, 5 proje)' : 'measured precision 16% (3/16, 5 projects)'), `${fmt}/${lang}: review item rate`);
      assert.ok(plain.includes(t.reviewTypes.calibration), `${fmt}/${lang}: review summary by type`);
    }
    const json = JSON.parse(renderAudit(r, { format: 'json', lang }));
    const l0 = json.findings[0].locations[0];
    assert.equal(l0.calibration.status, 'reliable');
    assert.equal(l0.calibration.repos, 12);
    assert.ok(l0.calibrationText);
    assert.equal(json.findings[0].locations.find((l) => l.label === 'legacy').calibration, undefined);
    assert.equal(json.review[0].locations[0].reviewType, 'calibration');
    assert.deepEqual(json.reviewSummary.byType, { calibration: 1 });
  }
  // A result with no calibration at all renders without the explanation.
  const bare = calResult({ findings: [], review: [], reviewSummary: null });
  assert.ok(!renderAudit(bare, { format: 'text', lang: 'en' }).includes(S.en.calNote.slice(0, 40)));
});

test('WS7-5: the score uses scored findings only; an unreliable score is N/A', async () => {
  const r = calResult();
  assert.equal(scoreView(r).text, '72/100 (C)');
  assert.equal(scoreView({ ...r, scoreReliable: false }).text, 'N/A');
  assert.match(renderAudit({ ...r, scoreReliable: false }, { format: 'text', lang: 'en' }), /N\/A/);
  // Engine: result.score equals summarize(findings) — review never counts.
  const dir = tmpProject({
    'package.json': JSON.stringify({ dependencies: { express: '4' } }),
    'server.js': "const express = require('express');\nconst app = express();\napp.post('/signup', (req, res) => { console.log(req.body.email); res.send('ok') });\napp.listen(3000);\n",
  });
  const res = await audit(dir, { lang: 'en' });
  assert.equal(res.score, summarize(res.findings).score);
  assert.ok(res.reviewSummary && typeof res.reviewSummary.total === 'number');
  for (const f of res.review) for (const l of f.locations) assert.ok(l.reviewReason, `${f.rule.id} has a reason`);
});

test('WS7-6: examples/audit-app reports exactly 19 finding ids (scored or review) and ok coverage', async () => {
  const r = await audit(path.resolve('examples/audit-app'));
  const ids = new Set([...r.findings, ...r.review].map((f) => f.rule.id));
  assert.equal(ids.size, 19, [...ids].join(' '));
  // which of them are scored follows the measured precision of their signal; most must be
  assert.ok(r.findings.length >= 14, r.findings.map((f) => f.rule.id).join(' '));
  assert.equal(r.coverage, 'ok');
  assert.equal(r.scoreReliable, true);
  for (const l of Object.values(r.layers)) assert.ok(!(l.status === 'found' && l.count === 0));
});
