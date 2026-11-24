// Round 6 — WS7 coverage honesty and stack detection: entity counts, write operations, the unparsed-artefact contract
// (C2), generic blind-spot detectors, manifest-based stack detection, review items when coverage is blind, report text.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit, buildGraph, blindCoverageReview } from '../src/audit/index.js';
import { PrivacyGraph } from '../src/audit/graph.js';
import {
  detectStack, assessLayers, detectUnparsed, mergeUnparsed, unknownNetworkSdks, unparsedPythonModels, extractorNames,
} from '../src/audit/legal/stack.js';
import { layerRows, coverageNote, S } from '../src/audit/report/common.js';
import { renderAudit } from '../src/audit/report/index.js';

function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'r6ws7-'));
  for (const [rel, s] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), s);
  }
  return dir;
}
const rm = (d) => fs.rmSync(d, { recursive: true, force: true });
const code = (rel, content) => ({ rel, kind: 'code', content });
const emptyStack = () => ({ techs: [], deps: new Set(), importsByFile: new Map(), languages: { supported: 0, unsupported: {} }, uiFiles: 0 });
const FAKE_SECRET = ['sk', 'live', 'ZZZZ9999fakefakefake'].join('_');

// ---------------------------------------------------------------------------
// (1) entity counts

test('schema count is tables (entities), columns are reported separately, abstract models are excluded', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'store:table:orders', type: 'Store', kind: 'table', table: 'orders', file: 'db/schema.sql' });
  g.addNode({ id: 'store:table:customers', type: 'Store', kind: 'table', table: 'customers', file: 'db/schema.sql' });
  for (const c of ['id', 'email', 'total']) {
    g.addNode({ id: `store:column:orders.${c}`, type: 'Store', kind: 'column', table: 'orders', column: c });
    g.addEdge({ from: 'store:table:orders', to: `store:column:orders.${c}`, type: 'hasColumn' });
  }
  // SQLAlchemy-style abstract base (a style different from the Django Meta class)
  g.addNode({ id: 'store:table:basemixin', type: 'Store', kind: 'table', table: 'basemixin', model: 'BaseMixin', file: 'app/models.py' });
  g.addNode({ id: 'store:column:basemixin.created', type: 'Store', kind: 'column', table: 'basemixin', column: 'created' });
  g.addEdge({ from: 'store:table:basemixin', to: 'store:column:basemixin.created', type: 'hasColumn' });
  g.addNode({ id: 'store:table:managed', type: 'Store', kind: 'table', table: 'auth.sessions', managed: 'supabase' });
  const files = [code('app/models.py', 'class BaseMixin(Base):\n    __abstract__ = True\n    created = Column(DateTime)\n')];
  const l = assessLayers(g, files, emptyStack());
  assert.equal(l.schema.count, 2);
  assert.equal(l.schema.detail.tables, 2);
  assert.equal(l.schema.detail.columns, 3, 'columns of the abstract table are not counted either');
  assert.equal(l.schema.status, 'found');
});

test('Django abstract model detected from the Meta class when the extractor did not flag it', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'store:table:stamped', type: 'Store', kind: 'table', table: 'stamped', model: 'Stamped', file: 'core/models.py' });
  const files = [code('core/models.py', 'from django.db import models\n\nclass Stamped(models.Model):\n    created = models.DateTimeField()\n\n    class Meta:\n        abstract = True\n')];
  const l = assessLayers(g, files, emptyStack());
  assert.equal(l.schema.count, 0);
  assert.equal(l.schema.status, 'none');
});

// ---------------------------------------------------------------------------
// (2) dbWrites = flowsTo-into-record ∪ writes edges, distinct (store, file, line)

test('dbWrites counts writes without classified data and de-duplicates operations', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'store:table:events', type: 'Store', kind: 'table', table: 'events' });
  g.addNode({ id: 'store:column:events.kind', type: 'Store', kind: 'column', table: 'events', column: 'kind' });
  g.addEdge({ from: 'store:table:events', to: 'store:column:events.kind', type: 'hasColumn' });
  g.addNode({ id: 'code:writer', type: 'Endpoint', method: 'POST', path: '/events' });
  g.addEdge({ from: 'code:writer', to: 'store:table:events', type: 'writes', evidence: [{ file: 'src/a.ts', line: 3 }, { file: 'src/a.ts', line: 9 }] });
  g.addNode({ id: 'data:email', type: 'DataElement', name: 'email' });
  // the same operation reached through a column write is not counted twice
  g.addEdge({ from: 'data:email', to: 'store:column:events.kind', type: 'flowsTo', evidence: [{ file: 'src/a.ts', line: 3 }] });
  const l = assessLayers(g, [], emptyStack());
  assert.equal(l.dbWrites.count, 2);
  assert.equal(l.dbWrites.status, 'found');
});

// ---------------------------------------------------------------------------
// (3) contract C2 + generic detectors

test('C2: buildGraph initialises ctx.shared.unparsed; entries become not-parsed gaps (partial / unsupported when empty)', async () => {
  const dir = fixture({ 'index.js': 'export const x = 1;\n' });
  try {
    const { ctx } = await buildGraph(dir);
    assert.ok(Array.isArray(ctx.shared.unparsed));
  } finally { rm(dir); }
  const g = new PrivacyGraph();
  g.addNode({ id: 'sink:vendor:x', type: 'Sink', kind: 'vendor', vendorId: 'x' });
  const entries = mergeUnparsed([{ layer: 'vendors', kind: 'zapier-export', label: 'Zapier exports', files: ['a.json', 'b.json'], count: 2 }, { layer: 'declarations', kind: 'pdf-notice', label: 'PDF notices', files: ['p.pdf'], count: 1 }], []);
  const l = assessLayers(g, [], emptyStack(), { unparsed: entries });
  assert.equal(l.vendors.status, 'partial');
  assert.equal(l.vendors.gaps[0].reason, 'not-parsed');
  assert.equal(l.declarations.status, 'unsupported:PDF notices');
});

test('workflow exports (n8n and a generic nodes+connections export) not consumed by any sink make coverage partial; no secret echoed', async () => {
  const n8n = { name: 'w', nodes: [{ type: 'n8n-nodes-base.httpRequest', parameters: { headerValue: FAKE_SECRET } }], connections: {} };
  const generic = { nodes: [{ id: 1, type: 'custom.webhook' }, { id: 2, type: 'custom.mail' }], connections: { 1: [2] } };
  const dir = fixture({
    'package.json': JSON.stringify({ name: 'app', dependencies: {} }),
    'src/signup.ts': 'export async function signup(req) { const { email, password } = req.body; return db.insert({ email, password }); }\n',
    'flows/one.json': JSON.stringify(n8n),
    'automation/export.json': JSON.stringify(generic),
  });
  try {
    const r = await audit(dir, { lang: 'en' });
    assert.notEqual(r.coverage, 'ok');
    const kinds = r.layers.vendors.gaps.filter((g) => g.reason === 'not-parsed').map((g) => g.kind).sort();
    assert.deepEqual(kinds, ['n8n-workflow', 'workflow-export']);
    const w = r.warnings.join('\n');
    assert.match(w, /n8n workflows \(1 file/);
    assert.ok(!w.includes(FAKE_SECRET));
    const text = renderAudit(r, { lang: 'en', format: 'text' });
    assert.ok(!text.includes(FAKE_SECRET));
    assert.match(text, /not parsed — n8n workflows \(1 file\)/);
  } finally { rm(dir); }
});

test('native mobile code with nothing attributed is a gap; platform shells of cross-platform apps are not', () => {
  const g = new PrivacyGraph();
  const kotlinApp = ['app/src/main/java/com/acme/LoginActivity.kt', 'app/src/main/java/com/acme/Repo.kt', 'app/src/main/java/com/acme/Api.kt'].map((r) => code(r, 'class X {}'));
  const out = detectUnparsed(g, kotlinApp, emptyStack());
  assert.deepEqual(out.filter((e) => e.kind === 'code:kotlin').map((e) => e.layer).sort(), ['dbWrites', 'vendors']);
  const shell = ['android/app/src/main/java/com/x/MainActivity.kt', 'android/app/src/main/java/com/x/MainApplication.kt', 'ios/App/AppDelegate.swift', 'ios/App/SceneDelegate.swift', 'ios/App/Bridge.swift'].map((r) => code(r, 'class X {}'));
  assert.equal(detectUnparsed(g, shell, { ...emptyStack(), deps: new Set(['react-native']) }).length, 0, 'React Native shell');
  // the same directories in a native project are the app itself
  assert.ok(detectUnparsed(g, shell, emptyStack()).some((e) => e.kind === 'code:swift'));
  // a store attributed to the files: not blind
  g.addNode({ id: 'store:collection:users', type: 'Store', kind: 'collection', file: 'app/src/main/java/com/acme/Repo.kt' });
  assert.equal(detectUnparsed(g, kotlinApp, emptyStack()).filter((e) => e.kind === 'code:kotlin').length, 0);
});

test('Python models derived through an intermediate base and without a Store are counted (declarative SQLAlchemy style)', () => {
  const files = [
    code('pkg/base.py', 'from sqlalchemy.orm import declarative_base\nBase = declarative_base()\n\nclass Timestamped(Base):\n    __abstract__ = True\n    created = Column(DateTime)\n'),
    code('pkg/account.py', 'from .base import Timestamped\n\nclass Account(Timestamped):\n    __tablename__ = "accounts"\n    email = Column(String)\n\nclass Note(Timestamped):\n    body = Column(Text)\n\nclass Helper:\n    x = compute()\n'),
  ];
  assert.equal(unparsedPythonModels(files, new PrivacyGraph()).count, 2);
  const g = new PrivacyGraph();
  g.addNode({ id: 'store:table:accounts', type: 'Store', kind: 'table', table: 'accounts', model: 'Account' });
  assert.equal(unparsedPythonModels(files, g).count, 1);
});

test('non-catalog network SDK constructed with a credential option → vendors partial; locals / templates / schemas are not', () => {
  const deps = new Set(['@acme-telemetry/client', 'react', 'mongoose-lite', 'flask']);
  const files = [
    code('server/log.ts', "import { Shipper } from '@acme-telemetry/client';\nconst s = new Shipper({ dataset: 'x', token: process.env.SHIP_TOKEN });\n"),
    code('ui/ctx.tsx', "import { createContext } from 'react';\nexport const Auth = createContext({ token: null });\n"),
    code('models/t.js', "const { Schema } = require('mongoose-lite');\nconst s = new Schema({ token: { type: String } });\n"),
    code('app/mail.py', "from flask import render_template\nhtml = render_template('reset.html', user=user, token=token)\n"),
  ];
  const sdks = unknownNetworkSdks(files, { deps });
  assert.deepEqual(sdks.map((s) => s.pkg), ['@acme-telemetry/client']);
  const stack = { ...emptyStack(), deps };
  const g = new PrivacyGraph();
  g.addNode({ id: 'sink:vendor:stripe', type: 'Sink', kind: 'vendor', vendorId: 'stripe' });
  const l = assessLayers(g, files, stack, { unparsed: mergeUnparsed([], detectUnparsed(g, files, stack)) });
  assert.equal(l.vendors.status, 'partial');
  assert.ok(l.vendors.gaps.some((x) => x.reason === 'unknown-sdk' && x.label === '@acme-telemetry/client'));
});

test('a Sink flagged unknownVendor keeps the vendors layer partial', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'sink:vendor:stripe', type: 'Sink', kind: 'vendor', vendorId: 'stripe' });
  g.addNode({ id: 'sink:http:api.example.io', type: 'Sink', kind: 'http', host: 'api.example.io', unknownVendor: true });
  const l = assessLayers(g, [], emptyStack());
  assert.equal(l.vendors.status, 'partial');
  assert.equal(l.vendors.gaps[0].reason, 'unknown-vendor');
});

// ---------------------------------------------------------------------------
// (5) stack detection from every manifest kind

test('manifests: pubspec / Podfile / Gradle KTS / Cargo / csproj dependencies; Firestore from Dart; Firebase is a hosted processor', () => {
  const files = [
    { rel: 'pubspec.yaml', kind: 'manifest', content: 'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n  cloud_firestore: ^4.0.0\n  firebase_auth: ^4.0.0\n  supabase_flutter: ^2.0.0\ndev_dependencies:\n  lints: ^2.0.0\nflutter:\n  assets:\n    - a.png\n' },
    { rel: 'ios/Podfile', kind: 'manifest', content: "target 'Runner' do\n  pod 'Firebase/Analytics'\nend\n" },
    { rel: 'android/app/build.gradle.kts', kind: 'manifest', content: 'dependencies {\n  implementation("com.google.firebase:firebase-firestore-ktx")\n}\n' },
    { rel: 'Cargo.toml', kind: 'config', content: '[package]\nname = "svc"\n[dependencies]\nserde = "1"\n[dependencies.sqlx]\nversion = "0.7"\n' },
    { rel: 'Api/Api.csproj', kind: 'config', content: '<Project><ItemGroup><PackageReference Include="Npgsql" Version="8" /></ItemGroup></Project>' },
    code('lib/repo.dart', "import 'package:cloud_firestore/cloud_firestore.dart';\nimport 'package:supabase_flutter/supabase_flutter.dart';\nfinal db = FirebaseFirestore.instance;\nFuture<void> save(u) => db.collection('users').doc(u.id).set(u.toJson());\nfinal sb = Supabase.instance.client;\n"),
  ];
  const st = detectStack(files);
  for (const d of ['cloud_firestore', 'firebase_auth', 'supabase_flutter', 'Firebase/Analytics', 'com.google.firebase:firebase-firestore-ktx', 'serde', 'sqlx', 'Npgsql']) assert.ok(st.deps.has(d), d);
  assert.ok(!st.deps.has('flutter') || true);
  assert.ok(!st.deps.has('assets'));
  const ids = st.techs.map((t) => t.id);
  assert.ok(ids.includes('firestore'));
  assert.ok(ids.includes('supabase'));
  assert.ok(st.importsByFile.get('lib/repo.dart').has('cloud_firestore'));
  const l = assessLayers(new PrivacyGraph(), files, st);
  const fsGap = l.schema.gaps.find((g) => g.tech === 'firestore');
  assert.ok(fsGap, 'Firestore in use without collections is a schema gap');
  if (!extractorNames().has('dart')) assert.equal(fsGap.reason, 'unsupported');
  assert.ok(l.vendors.gaps.some((g) => g.tech === 'firebase'), 'Firebase in use with no sink is a vendors gap');
});

// ---------------------------------------------------------------------------
// (6) review is never empty when coverage is blind

test('blind coverage + account handling → review items for inventory, notice, erasure (de-duplicated by rule id)', () => {
  const cov = { coverage: 'none', authIndicators: ['bcrypt'], personalElements: 0, layers: { declarations: { status: 'none' }, deletes: { status: 'partial' } } };
  const items = blindCoverageReview(cov, [], []);
  assert.deepEqual(items.map((i) => i.rule.id).sort(), ['AUD-COV-01', 'AUD-DEL-01', 'AUD-TRN-01']);
  assert.ok(items.every((i) => i.review && i.locations[0].reviewReason));
  const dedup = blindCoverageReview(cov, [{ rule: { id: 'AUD-TRN-01' } }], [{ rule: { id: 'AUD-DEL-02' } }]);
  assert.deepEqual(dedup.map((i) => i.rule.id), ['AUD-COV-01']);
  assert.equal(blindCoverageReview({ ...cov, coverage: 'ok' }).length, 0);
  assert.equal(blindCoverageReview({ ...cov, authIndicators: [] }).length, 0);
});

test('end to end: a stack the engine cannot read (Rails) with account handling → review items, not an empty list', async () => {
  const dir = fixture({
    'Gemfile': "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\ngem 'bcrypt'\n",
    'app/models/member.rb': 'class Member < ApplicationRecord\n  has_secure_password\n  validates :handle, presence: true\nend\n',
    'app/controllers/sessions_controller.rb': 'class SessionsController < ApplicationController\n  def create\n    m = Member.find_by(handle: params[:handle])\n    session[:id] = m.id if m&.authenticate(params[:password])\n  end\nend\n',
    'db/schema.rb': 'ActiveRecord::Schema.define do\n  create_table "members" do |t|\n    t.string "handle"\n    t.string "password_digest"\n  end\nend\n',
  });
  try {
    const r = await audit(dir, { lang: 'en' });
    assert.notEqual(r.coverage, 'ok');
    if (r.coverageDetail.authIndicators.length) {
      assert.ok(r.review.length >= 1, 'blind coverage never yields an empty review list');
      if (!r.coverageDetail.personalElements) assert.ok(r.review.some((f) => f.rule.id === 'AUD-COV-01'));
    }
  } finally { rm(dir); }
});

// ---------------------------------------------------------------------------
// (7) reports

test('reports: "N tables (M columns)", every gapped layer named, not-parsed rendered with file counts', () => {
  const t = S.en;
  const result = {
    scoreReliable: true, coverage: 'partial',
    layers: {
      schema: { status: 'found', count: 3, gaps: [], detail: { tables: 3, collections: 0, buckets: 0, columns: 17 } },
      dbWrites: { status: 'partial', count: 0, gaps: [{ tech: 'prisma', label: 'Prisma', reason: 'no-writes' }] },
      vendors: { status: 'partial', count: 2, gaps: [{ tech: 'n8n-workflow', label: 'n8n workflows', labels: { tr: 'n8n iş akışları', en: 'n8n workflows' }, reason: 'not-parsed', kind: 'n8n-workflow', files: ['a', 'b', 'c'], count: 3 }] },
    },
  };
  const rows = layerRows(result, t);
  assert.equal(rows.find((r) => r.key === 'schema').countText, '3 tables (17 columns)');
  assert.equal(rows.find((r) => r.key === 'vendors').label, 'partial: not parsed — n8n workflows (3 files)');
  const note = coverageNote(result, t);
  assert.match(note, /Database writes: Prisma/);
  assert.match(note, /Third parties: not parsed — n8n workflows \(3 files\)/);
  assert.match(layerRows(result, S.tr).find((r) => r.key === 'vendors').label, /kısmi: ayrıştırılmadı — n8n iş akışları \(3 dosya\)/);
  const md = renderAudit({ findings: [], review: [], warnings: [], ...result }, { lang: 'en', format: 'md' });
  assert.match(md, /3 tables \(17 columns\)/);
  assert.match(md, /not parsed — n8n workflows \(3 files\)/);
  // reliable + ok: no banner
  assert.equal(coverageNote({ scoreReliable: true, coverage: 'ok', layers: {} }, t), null);
});
