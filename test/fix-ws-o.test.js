import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { walk, isTestPath } from '../src/walk.js';
import { buildGraph, audit, assessCoverage } from '../src/audit/index.js';
import { PrivacyGraph } from '../src/audit/graph.js';

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-wso-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

test('IDX-1: isTestPath recognises test dirs and file patterns', () => {
  for (const p of [
    'tests/models.py', 'test/app.js', 'src/__tests__/a.ts', 'src/__mocks__/db.js', 'spec/user_spec.rb',
    'tests/fixtures/users.json', 'e2e/login.ts', 'cypress/e2e/a.cy.ts', 'playwright/auth.ts',
    'src/user.test.ts', 'src/user.spec.js', 'app/login.e2e.ts', 'app/test_models.py', 'app/models_test.py',
    'pkg/user_test.go', 'conftest.py', 'src\\__tests__\\win.js',
  ]) assert.equal(isTestPath(p), true, p);
  for (const p of [
    'src/user.ts', 'app/models.py', 'src/testimonials.tsx', 'src/latest.js', 'app/contest/page.tsx',
    'src/attestation.ts', 'playwright.config.ts', 'src/protest_view.py', 'src/pages/Test/Page.tsx',
    'docs/specs/design.md',
  ]) assert.equal(isTestPath(p), false, p);
});

test('IDX-1: walk marks test files but still returns them (legacy scan unchanged)', () => {
  const dir = tmpProject({ 'src/a.js': 'x', 'src/a.test.js': 'y' });
  const files = walk(dir);
  assert.equal(files.length, 2);
  assert.equal(files.find((f) => f.rel === 'src/a.test.js').test, true);
  assert.equal(files.find((f) => f.rel === 'src/a.js').test, undefined);
});

const SCHEMA_FIXTURE = {
  'package.json': '{"name":"x"}',
  'db/schema.sql': 'create table customers (id serial primary key, email text);\n',
  'src/project.test.js': '// test file\n',
  'tests/fixtures/project.sql': 'create table projects (id serial primary key, owner_phone text, owner_email text);\n',
};

test('IDX-1: buildGraph drops test files unless includeTests', async () => {
  const dir = tmpProject(SCHEMA_FIXTURE);
  const { graph, ctx } = await buildGraph(dir);
  assert.ok(graph.has('store:table:customers'), 'non-test schema still parsed');
  assert.ok(!graph.has('store:table:projects'), 'test fixture schema dropped');
  assert.ok(ctx.files.every((f) => !f.test));
  assert.equal(ctx.testFilesSkipped, 2);

  const withTests = await buildGraph(dir, { includeTests: true });
  assert.ok(withTests.graph.has('store:table:projects'), 'includeTests keeps fixtures');
});

test('IDX-1: CLI --include-tests flag is accepted', async () => {
  const { execFileSync } = await import('node:child_process');
  const dir = tmpProject(SCHEMA_FIXTURE);
  const out = path.join(dir, 'out.json');
  const cli = path.resolve('bin/cli.js');
  execFileSync(process.execPath, [cli, 'audit', dir, '-f', 'json', '-o', out, '--fail-on', 'none', '--include-tests'], { stdio: 'pipe' });
  const json = JSON.parse(fs.readFileSync(out, 'utf8'));
  if (json.graph) assert.ok(json.graph.nodes.some((n) => n.id === 'store:table:projects'));
});

test('IDX-2: no personal elements but source + auth indicators → coverage none, score unreliable', async () => {
  const dir = tmpProject({
    'requirements.txt': 'flask\nflask-login\n',
    'app/routes.py': 'from flask_login import login_user\nfrom werkzeug.security import generate_password_hash\n\ndef index():\n    return "hi"\n',
  });
  const r = await audit(dir, { lang: 'en' });
  // Only meaningful while the Python stack yields nothing; if another workstream makes it parse, skip.
  if (r.graph.nodesOf('DataElement').length) return;
  assert.equal(r.coverage, 'none');
  assert.equal(r.scoreReliable, false);
  assert.match(r.warnings[0], /no personal data elements/);
  assert.match(r.warnings[0], /flask_login/);
  assert.match(r.warnings[0], /password_hash/);
  assert.deepEqual(r.coverageDetail.authIndicators.sort(), ['flask_login', 'password_hash']);
});

test('IDX-2: assessCoverage pure cases', () => {
  const empty = new PrivacyGraph();
  const code = [{ rel: 'a.js', kind: 'code', content: 'const bcrypt = require("bcryptjs")' }];

  const none = assessCoverage(empty, { files: code, shared: {} }, 'en');
  assert.equal(none.coverage, 'none');
  assert.equal(none.scoreReliable, false);
  assert.deepEqual(none.authIndicators, ['bcrypt']);

  const unparsed = assessCoverage(empty, { files: code, shared: { pythonModelsUnparsed: 3 } }, 'tr');
  assert.match(unparsed.warning, /3 Python modeli/);

  const staticSite = assessCoverage(empty, { files: [{ rel: 'index.html', kind: 'code', content: '<h1>hi</h1>' }], shared: {} });
  assert.equal(staticSite.coverage, 'ok');
  assert.equal(staticSite.scoreReliable, true);

  const nothing = assessCoverage(empty, { files: [], shared: {} });
  assert.equal(nothing.scoreReliable, true);

  const g = new PrivacyGraph();
  g.dataElement({ element: 'email', category: 'contact', sensitivity: 'normal', label: 'E-mail' });
  const ok = assessCoverage(g, { files: code, shared: {} });
  assert.equal(ok.coverage, 'ok');
  assert.equal(ok.scoreReliable, true);
  assert.equal(ok.warning, null);

  const partial = assessCoverage(g, { files: code, shared: { pythonModelsUnparsed: 2 } }, 'en');
  assert.equal(partial.coverage, 'partial');
  // Round 7 (WS7): unparsed Python models leave the schema layer (a core layer) not fully analysed, so the score is
  // no longer reliable (was true before r7).
  assert.equal(partial.scoreReliable, false);
  assert.match(partial.warning, /2 Python model/);
});

test('IDX-2: examples/audit-app keeps reliable coverage', async () => {
  const r = await audit(path.resolve('examples/audit-app'));
  assert.equal(r.coverage, 'ok');
  assert.equal(r.scoreReliable, true);
});
