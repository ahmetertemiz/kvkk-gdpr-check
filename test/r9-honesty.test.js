// Round 9: routes-layer self checks (census, unread handlers, undecided auth), measured support tiers, misses that
// count as closed only when the report shows them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit, buildGraph, organizeReview } from '../src/audit/index.js';
import { declaredRoutes, routeCensus } from '../src/audit/legal/route-census.js';
import { stackSupport, tierOf, SUPPORT } from '../src/audit/legal/support.js';
import { detectStack } from '../src/audit/legal/stack.js';
import { renderAudit } from '../src/audit/report/index.js';
import { missOrigin } from '../bench/lib.js';
import { scoreOutput } from '../bench/run.js';

function mk(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r9-'));
  for (const [rel, c] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, c);
  }
  return dir;
}
const code = (rel, content) => ({ rel, content, kind: 'code', test: false });
const gaps = (r) => r.layers.routes.gaps.map((g) => g.reason);

// ------------------------------------------------------------------------------------------------ census

test('census: registrations are counted per framework; comments, docstrings, clients and includes are not', () => {
  assert.equal(declaredRoutes(code('a.py', 'from flask import Flask\napp = Flask(__name__)\n@app.route("/a")\ndef a(): pass\n# @app.route("/x")\n"""\n@app.route("/doc")\n"""\n')), 1);
  assert.equal(declaredRoutes(code('v.py', 'from flask import Blueprint\nregister(bp, routes=["/a"], view_func=A.as_view("a"))\nbp.add_url_rule("/b", view_func=B.as_view("b"))\n')), 2);
  assert.equal(declaredRoutes(code('urls.py', 'urlpatterns = [\n path("a/", A.as_view()),\n re_path(r"^b$", b),\n path("x/", include("x.urls")),\n path("admin/", admin.site.urls),\n # path("c/", c),\n]\n')), 2);
  assert.equal(declaredRoutes(code('s.js', 'import express from "express";\nconst app = express();\napp.get("/a", h);\n// app.get("/b", h);\naxios.get("/c");\n')), 1);
  assert.equal(declaredRoutes(code('client.js', 'import axios from "axios";\napi.get("/a");\n')), 0, 'no server import');
  assert.equal(declaredRoutes({ ...code('t.py', '@app.route("/a")'), test: true }), 0);
});

test('census: unread = declared minus endpoints of the same file, never negative', () => {
  const files = [code('a.py', 'from flask import Flask\n@app.route("/a")\n@app.route("/b")\n'), code('b.py', 'from flask import Flask\n@app.get("/c")\n')];
  const c = routeCensus(files, [{ file: 'a.py' }, { file: 'b.py' }, { file: 'b.py' }]);
  assert.deepEqual([c.declared, c.unread], [3, 1]);
  assert.deepEqual(c.files, [{ file: 'a.py', declared: 2, read: 1 }]);
});

const FLASK_HELPER = {
  'requirements.txt': 'flask\nsqlalchemy\n',
  'app/models.py': 'from sqlalchemy import Column, Integer, String\nfrom .db import Base\nclass User(Base):\n    __tablename__ = "users"\n    id = Column(Integer, primary_key=True)\n    email = Column(String)\n',
  'app/views.py': ['from flask import Blueprint', 'from flask.views import MethodView', 'from .utils import register_view', 'bp = Blueprint("a", __name__)', 'class Login(MethodView):', '    def post(self):', '        return "x"', 'class Logout(MethodView):', '    def get(self):', '        return "x"', 'class Me(MethodView):', '    def get(self):', '        return "x"',
    'register_view(bp, routes=["/login"], view_func=Login.as_view("login"))', 'register_view(bp, routes=["/logout"], view_func=Logout.as_view("logout"))', 'register_view(bp, routes=["/me"], view_func=Me.as_view("me"))'].join('\n'),
};

test('routes registered through a project helper: layer partial, score withheld, the report says so', async () => {
  const r = await audit(mk(FLASK_HELPER), { lang: 'tr' });
  assert.ok(gaps(r).includes('routes-unread'), JSON.stringify(r.layers.routes));
  assert.equal(r.layers.routes.status, 'partial');
  assert.equal(r.coverage, 'partial');
  assert.equal(r.scoreReliable, false);
  assert.match(renderAudit(r, { lang: 'tr', format: 'text' }), /3 rota kaydının 3 tanesi: app\/views\.py/);
});

test('the same app with decorator routes has no routes gap', async () => {
  const r = await audit(mk({
    ...FLASK_HELPER,
    'app/views.py': 'from flask import Blueprint\nbp = Blueprint("a", __name__)\n@bp.route("/login", methods=["POST"])\ndef login():\n    return "x"\n@bp.route("/logout")\ndef logout():\n    return "x"\n@bp.route("/me")\ndef me():\n    return "x"\n',
  }), { lang: 'en' });
  assert.deepEqual(gaps(r), []);
  assert.equal(r.layers.routes.status, 'found');
});

const VIEWS = ['Home', 'Profile', 'Search', 'Apply'].map((n) => `class ${n}View(View):\n    def get(self, request):\n        return None\n`).join('');
const django = (init, urlsImport) => ({
  'requirements.txt': 'django\n',
  'shop/views/__init__.py': init,
  'shop/views/pages.py': `from django.views import View\n${VIEWS}`,
  'shop/urls.py': `from django.urls import path\n${urlsImport}\nurlpatterns = [\n    path("", HomeView.as_view()),\n    path("profile/", ProfileView.as_view()),\n    path("search/", SearchView.as_view()),\n    path("apply/", ApplyView.as_view()),\n]\n`,
});

test('Django handlers the import chain does not reach: unknown authentication, never "none", and a handlers gap', async () => {
  // (star re-exports resolve since round 10; names injected at run time do not)
  const dir = mk(django('import importlib\nglobals().update(vars(importlib.import_module("shop.views.pages")))\n', 'from .views import HomeView, ProfileView, SearchView, ApplyView'));
  const { graph } = await buildGraph(dir, {});
  const eps = graph.nodesOf('Endpoint');
  assert.equal(eps.length, 4);
  for (const e of eps) {
    assert.equal(e.handlerUnread, true, e.path);
    assert.equal(e.auth, 'unknown');
    assert.equal(e.authEnforced, false);
    assert.notEqual(e.authMode, 'none');
  }
  const r = await audit(dir, { lang: 'en' });
  assert.ok(gaps(r).includes('handlers-unread'));
  assert.equal(r.scoreReliable, false);
});

test('Django handlers that resolve, and third-party views, are not unread', async () => {
  const dir = mk({ ...django('', 'from .views.pages import HomeView, ProfileView, SearchView, ApplyView\nfrom django.contrib.auth.views import LoginView') });
  const p = path.join(dir, 'shop/urls.py');
  fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace(']\n', '    path("login/", LoginView.as_view()),\n]\n'));
  const r = await audit(dir, { lang: 'en' });
  assert.ok(r.graph.nodesOf('Endpoint').every((e) => !e.handlerUnread));
  assert.deepEqual(gaps(r), []);
});

// ------------------------------------------------------------------------------------------------ support tiers

test('support tiers follow the fixed rule', () => {
  assert.equal(tierOf({ repos: 3, tp: 95, fp: 5 }), 'supported');
  assert.equal(tierOf({ repos: 1, tp: 95, fp: 5 }), 'experimental', 'one project is not a measurement');
  assert.equal(tierOf({ repos: 2, tp: 95, fp: 5 }), 'limited');
  assert.equal(tierOf({ repos: 3, tp: 21, fp: 16 }), 'experimental');
  assert.equal(tierOf(undefined), 'experimental');
  // (scripts/measure-stack-support.js --check compares the table with the labels; not here, because labels grow between rounds.)
  assert.ok(Object.keys(SUPPORT).length > 10);
});

test('stackSupport: endpoints decide the server family, manifests only when nothing was read', () => {
  const stack = (deps) => ({ deps: new Set(deps) });
  const eps = (fw, n) => Array.from({ length: n }, () => ({ framework: fw }));
  assert.deepEqual(stackSupport(stack(['express', 'flask']), [...eps('express', 20), ...eps('flask', 1)]).families.map((f) => f.id), ['express']);
  assert.deepEqual(stackSupport(stack(['flask']), []).families.map((f) => [f.id, f.tier]), [['flask', 'experimental']]);
  assert.deepEqual(stackSupport(stack(['next', 'vite']), eps('nextjs-app', 3)).families.map((f) => f.id), ['nextjs'], 'the bundler of a meta framework is not a second stack');
  assert.deepEqual(stackSupport(stack(['expo', 'next']), eps('nextjs-app', 3)).families.map((f) => f.id), ['nextjs', 'expo-rn']);
  assert.deepEqual(stackSupport(stack(['@nestjs/core']), eps('graphql', 4)).families.map((f) => f.id), ['nestjs'], 'GraphQL nodes do not name the host');
  assert.equal(stackSupport(stack([]), eps('somethingnew', 4)).tier, 'experimental');
  assert.equal(stackSupport(stack([]), []), null);
});

test('an experimental stack withholds the score; pending high items are announced', () => {
  const base = { findings: [], review: [], warnings: [], counts: {}, score: 90, coverage: 'ok', layers: {}, root: 'x' };
  const fam = { id: 'flask', label: 'Flask', tier: 'experimental', repos: 1, tp: 20, fp: 6, missesPerRepo: 8 };
  for (const format of ['text', 'md', 'html']) {
    const out = renderAudit({ ...base, scoreReliable: false, support: { tier: 'experimental', families: [fam] }, pendingHigh: 2 }, { lang: 'en', format });
    assert.match(out, /Flask: experimental/);
    assert.match(out, /2 high \/ critical items await verification/);
    assert.doesNotMatch(out, /90\/100/);
  }
});

test('UI layer: a TypeScript generic is not a JSX element', () => {
  assert.equal(detectStack([code('src/a.ts', 'export const f = async (): Promise<User> => x as Map<Key, Value>;')]).uiFiles, 0);
  assert.equal(detectStack([code('src/a.tsx', 'export const A = () => <Button />')]).uiFiles, 1);
});

test('review keeps distinct objects that share one line (three buckets behind one helper, two methods of one route)', () => {
  const L = (label) => ({ file: 'lib/storage.ts', line: 11, sub: 'SEC-02:public-bucket', label, calibration: { status: 'demoted' }, reviewReason: { tr: 'x', en: 'x' } });
  const F = (id, locations) => ({ rule: { id, severity: 'high', category: 'x', title: { tr: id, en: id } }, severity: 'high', locations });
  const { review } = organizeReview([], [F('AUD-SEC-02', ['a', 'b', 'c', 'a'].map((n) => L(`bucket "${n}" is public`))), F('AUD-SEC-03', ['DELETE /p: x', 'PATCH /p: x', 'same thing said', 'same thing again'].map(L))], { layers: {}, ruleBasis: {} });
  const of = (id) => review.find((f) => f.rule.id === id).locations.map((l) => l.label);
  assert.deepEqual(of('AUD-SEC-02').length, 3);
  assert.deepEqual(of('AUD-SEC-03').length, 3, 'labels that name no object still collapse');
});

// ------------------------------------------------------------------------------------------------ misses

test('a miss is closed only by something the report shows', () => {
  const loc = { ruleId: 'AUD-TRF-01', file: 'a.ts', label: 'Stripe', snippet: '' };
  const miss = (expect) => ({ id: 'm', severity: 'high', title: 't', expect });
  const any = miss({ anyOf: [{ keywords: ['stripe'] }, { model: { section: 'transfers', keywords: ['stripe'] } }, { graph: { type: 'Sink', keywords: ['stripe'] } }] });
  const node = { type: 'Sink', name: 'Stripe' };
  const ctx = (x) => ({ locations: [], review: [], graphNodes: [], model: null, ...x });
  assert.equal(missOrigin(any, ctx({ graphNodes: [node] })), 'graph');
  assert.equal(missOrigin(any, ctx({ graphNodes: [node], model: { transfers: [{ vendor: 'Stripe' }] } })), 'register');
  assert.equal(missOrigin(any, ctx({ graphNodes: [node], review: [loc] })), 'review');
  assert.equal(missOrigin(any, ctx({ graphNodes: [node], locations: [loc] })), 'scored');
  assert.equal(missOrigin(any, ctx({})), null);
  const { row } = scoreOutput('x', { locations: [], reviewLocs: [], graphNodes: [node], model: null }, { findings: [], misses: [any] });
  assert.equal(row.missesOpen.length, 1);
  assert.equal(row.missesInternal, 1);
  assert.equal(row.missesFixed.length, 0);
});
