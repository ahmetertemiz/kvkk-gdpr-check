// r6 WS1: any imported SDK that talks to a remote service is a recipient by default — SDK egress fallback for
// catalogued vendors, unknown-SDK heuristic, client / transport injection, mail transports, new catalogue entries.
// Fixtures are synthetic and deliberately written in other styles than the benchmark repos that motivated them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit, buildGraph } from '../src/audit/index.js';
import { vendorForPackage, matchCall } from '../src/audit/extract/_sinks.js';
import { vendorForUrl, vendorById, unknownSdkVendor } from '../src/data/vendors.js';

function mkdir(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r6-ws1-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}
const graphOf = async (files) => (await buildGraph(mkdir(files))).graph;
const run = async (files) => audit(mkdir(files), { lang: 'en' });
const flowsInto = (g, id) => [...new Set(g.edgesTo(id, 'flowsTo').map((e) => e.from))];
const pkg = (deps) => JSON.stringify({ dependencies: deps });
const byId = (res, id) => res.findings.find((f) => (f.rule?.id || f.id) === id);
const labels = (f) => (f?.locations || []).map((l) => l.label?.en || '').join('\n');

// ---------------------------------------------------------------- catalogue
test('catalogue: log shippers, stock media, webhook relays, queues map to vendors with company / country / domains', () => {
  assert.equal(vendorForPackage('@axiomhq/js'), 'axiom');
  assert.equal(vendorForPackage('next-axiom'), 'axiom');
  assert.equal(vendorForPackage('@logtail/node'), 'betterstack');
  assert.equal(vendorForPackage('@google-cloud/logging-winston'), 'google-cloud-logging');
  assert.equal(vendorForPackage('winston-loggly-bulk'), 'papertrail-loggly');
  assert.equal(vendorForPackage('unsplash-js'), 'unsplash');
  assert.equal(vendorForPackage('pexels'), 'pexels');
  assert.equal(vendorForPackage('@giphy/js-fetch-api'), 'giphy');
  assert.equal(vendorForPackage('@upstash/qstash'), 'upstash-qstash');
  assert.equal(vendorForPackage('svix'), 'svix');
  for (const id of ['axiom', 'betterstack', 'unsplash', 'pexels', 'giphy', 'jina', 'upstash-qstash']) {
    const v = vendorById(id);
    assert.ok(v && v.company && v.country && v.domains.length && v.privacyUrl, id);
  }
  assert.equal(vendorForUrl('https://api.axiom.co/v1/datasets/x/ingest')?.id, 'axiom');
  assert.equal(vendorForUrl('https://images.unsplash.com/photo-1')?.id, 'unsplash');
  assert.equal(vendorForUrl('https://r.jina.ai/https://example.com')?.id, 'jina');
  assert.equal(vendorForUrl('https://s.jina.ai/q')?.id, 'jina');
  assert.equal(vendorForUrl('https://generativelanguage.googleapis.com/v1beta/models')?.id, 'gemini');
});

test('unknownSdkVendor: synthetic entry for unknown:<pkg>, never returned by URL lookups', () => {
  const v = vendorById('unknown:@acme/beacon');
  assert.equal(v.unknownVendor, true);
  assert.equal(v.package, '@acme/beacon');
  assert.equal(v.country, undefined);
  assert.equal(unknownSdkVendor('stripe'), null);
  assert.equal(vendorById('no-such-vendor'), null);
});

// ---------------------------------------------------------------- (1) SDK egress fallback
test('fallback: a log shipper client (Better Stack, function-style module) receives the logged fields', async () => {
  const g = await graphOf({
    'package.json': pkg({ express: '4', '@logtail/node': '0.4' }),
    'src/audit-log.js': [
      "const { Logtail } = require('@logtail/node');",
      'const logtail = new Logtail(process.env.LOGTAIL_SOURCE_TOKEN);',
      'function recordSignup(user) {',
      "  logtail.info('signup', { email: user.email, phone: user.phone });",
      '}',
      'module.exports = { recordSignup };',
    ].join('\n'),
    'src/server.js': [
      "const express = require('express');",
      "const { recordSignup } = require('./audit-log');",
      'const app = express();',
      "app.post('/signup', (req, res) => { const { email, phone } = req.body; recordSignup({ email, phone }); res.sendStatus(201); });",
    ].join('\n'),
  });
  const into = flowsInto(g, 'sink:vendor:betterstack');
  assert.ok(into.includes('data:email'), into.join(','));
});

test('fallback: Axiom ingest from a handler (class-based client) reaches the vendor; TRF-01 names it', async () => {
  const files = {
    'package.json': pkg({ hono: '4', '@axiomhq/js': '1' }),
    'src/obs.ts': [
      "import { Axiom } from '@axiomhq/js';",
      'export class Telemetry {',
      '  private ax = new Axiom({ token: process.env.AXIOM_TOKEN!, orgId: process.env.AXIOM_ORG! });',
      '  push(entry: { email: string; path: string }) {',
      "    const ax = new Axiom({ token: process.env.AXIOM_TOKEN!, orgId: 'org' });",
      "    ax.ingest('requests', [entry]);",
      '  }',
      '}',
    ].join('\n'),
    'src/index.ts': [
      "import { Hono } from 'hono';",
      "import { Telemetry } from './obs';",
      'const app = new Hono();',
      'const t = new Telemetry();',
      "app.post('/contact', async (c) => { const { email } = await c.req.json(); const ax2 = new (await import('@axiomhq/js')).Axiom({ token: 'x' }); t.push({ email, path: '/contact' }); return c.text('ok'); });",
      'export default app;',
    ].join('\n'),
  };
  const g = await graphOf(files);
  assert.ok(g.node('sink:vendor:axiom'), 'axiom sink exists');
  // Direct, same-function form: the logged object carries the email.
  const g2 = await graphOf({
    'package.json': pkg({ '@axiomhq/js': '1' }),
    'lib/log.js': [
      "import { Axiom } from '@axiomhq/js';",
      'export async function logRequest(event) {',
      '  const entry = { user: event.locals.user.email, path: event.url.pathname };',
      '  const axiom = new Axiom({ token: process.env.AXIOM_TOKEN });',
      "  await axiom.ingest('app', [entry]);",
      '}',
    ].join('\n'),
  });
  assert.ok(flowsInto(g2, 'sink:vendor:axiom').includes('data:email'));
});

test('fallback: config / getter / lifecycle verbs and results of vendor calls carry no data', () => {
  const base = { segments: [], rootArgs: null, isNew: false, strValue: () => null, objProp: () => null, originOfExpr: () => null };
  const id = (name) => ({ type: 'Identifier', name });
  const mk = (pkgName, segs, args = [id('email')]) => ({ ...base, pkg: pkgName, root: 'client', segs, segments: segs.map((s, i) => ({ name: s, args: i === segs.length - 1 ? args : null })), last: { name: segs[segs.length - 1], args } });
  assert.equal(matchCall(mk('@axiomhq/js', ['on'])), null, 'handler registration');
  assert.equal(matchCall(mk('@axiomhq/js', ['data', 'map'])), null, 'array method on a result');
  const get = matchCall(mk('unsplash-js', ['photos', 'getRandom'], [{ type: 'ObjectExpression', properties: [] }]));
  assert.equal(get.target.vendorId, 'unsplash');
  assert.deepEqual(get.dataArgs, []);
  const send = matchCall(mk('@axiomhq/js', ['ingest']));
  assert.equal(send.target.vendorId, 'axiom');
  assert.equal(send.dataArgs.length, 1);
  assert.ok(send.confidence < 0.85);
  // Vendors with a selective specific matcher are not second-guessed (stripe.customers.retrieve stays unmatched).
  assert.equal(matchCall(mk('stripe', ['customers', 'retrieve'])), null);
});

test('fallback: stock-media SDK called from a client component (Vue SFC style via a TS module) is a browser-side recipient', async () => {
  const g = await graphOf({
    'package.json': pkg({ next: '14', react: '18', pexels: '1' }),
    'lib/media.ts': "import { createClient } from 'pexels';\nexport const media = createClient(process.env.NEXT_PUBLIC_PEXELS_API_KEY!);\n",
    'components/Gallery.tsx': [
      "'use client';",
      "import { useEffect, useState } from 'react';",
      "import { media } from '../lib/media';",
      'export default function Gallery() {',
      '  const [p, setP] = useState([]);',
      "  useEffect(() => { media.photos.search({ query: 'nature', per_page: 9 }).then((r) => setP(r.photos)); }, []);",
      '  return <div>{p.length}</div>;',
      '}',
    ].join('\n'),
  });
  const s = g.node('sink:vendor:pexels');
  assert.ok(s, 'pexels sink');
  assert.ok((s.evidence || []).some((e) => e.file === 'components/Gallery.tsx'));
  assert.ok(/browser|both/.test(String(s.channel || '')), `channel ${s.channel}`);
});

// ---------------------------------------------------------------- (2) mail transports + (3) injection
test('injection: a nodemailer transport handed to another mailer (inline, ESM) gives its send() the SMTP recipient', async () => {
  const g = await graphOf({
    'package.json': pkg({ express: '4', nodemailer: '6', 'email-templates': '11' }),
    'src/mail.mjs': [
      "import Email from 'email-templates';",
      "import nodemailer from 'nodemailer';",
      'export const notifyPasswordChanged = async (account) => {',
      '  const mailer = new Email({ transport: nodemailer.createTransport({ host: process.env.MAIL_HOST, port: 587 }), send: true });',
      "  await mailer.send({ template: 'changed', message: { to: account.email }, locals: { fullName: account.fullName } });",
      '};',
    ].join('\n'),
    'src/app.mjs': [
      "import express from 'express';",
      "import { notifyPasswordChanged } from './mail.mjs';",
      'const app = express();',
      "app.post('/password', async (req, res) => { const { email, fullName } = req.body; await notifyPasswordChanged({ email, fullName }); res.end(); });",
    ].join('\n'),
  });
  const into = flowsInto(g, 'sink:vendor:email-services');
  assert.ok(into.includes('data:email'), into.join(','));
});

test('injection: any vendor client passed as `client` into a wrapper object (generic DI, not an email special case)', async () => {
  const g = await graphOf({
    'package.json': pkg({ resend: '3', 'notify-kit': '1' }),
    'server/notify.ts': [
      "import { Resend } from 'resend';",
      "import { Notifier } from 'notify-kit';",
      'const notifier = new Notifier({ client: new Resend(process.env.RESEND_API_KEY), retries: 2 });',
      'export async function welcome(user: { email: string }) {',
      "  const n = new Notifier({ client: new Resend(process.env.RESEND_API_KEY) });",
      "  await n.send({ to: user.email, subject: 'hi' });",
      '}',
    ].join('\n'),
  });
  assert.ok(flowsInto(g, 'sink:vendor:email-services').includes('data:email'));
});

test('injection: ORMs built on a vendor driver keep their own semantics (drizzle({ client }) is not a sender)', () => {
  const c = {
    pkg: 'drizzle-orm/neon-http', root: 'drizzle', segs: [], segments: [], isNew: false, last: { name: 'drizzle', args: [] },
    rootArgs: [{ type: 'ObjectExpression', properties: [{ type: 'ObjectProperty', key: { type: 'Identifier', name: 'client' }, value: { type: 'Identifier', name: 'sql' } }] }],
    strValue: () => null, objProp: () => null, originOfExpr: () => '@neondatabase/serverless',
  };
  const r = matchCall(c);
  assert.ok(!r || r.kind !== 'handle' || !r.facet?.injectedPkg);
});

test('mail transport: createTransport is the SMTP recipient; a provider host resolves through the URL catalogue', () => {
  const host = { type: 'StringLiteral', value: 'smtp.sendgrid.net' };
  const c = {
    pkg: 'nodemailer', root: 'nodemailer', segs: ['createTransport'], segments: [{ name: 'createTransport', args: [host] }], isNew: false,
    last: { name: 'createTransport', args: [{ type: 'ObjectExpression', properties: [] }] }, rootArgs: null,
    strValue: (n) => (n && n.type === 'StringLiteral' ? n.value : null), objProp: (o, k) => (k === 'host' ? host : null), originOfExpr: () => null,
  };
  const r = matchCall(c);
  assert.equal(r.kind, 'sink');
  assert.equal(r.target.vendorId, 'email-services');
  assert.deepEqual(r.dataArgs, []);
});

test('mail transport: transporter.sendMail through an env-configured host is reported as a generic SMTP transfer', async () => {
  const res = await run({
    'package.json': pkg({ fastify: '4', nodemailer: '6' }),
    'mailer.cjs': [
      "const nodemailer = require('nodemailer');",
      'const t = nodemailer.createTransport({ host: process.env.SMTP_HOST, auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });',
      "exports.sendInvite = (invitee) => t.sendMail({ to: invitee.email, subject: 'Invite', text: `Hello ${invitee.name}` });",
    ].join('\n'),
    'server.cjs': [
      "const fastify = require('fastify')();",
      "const { sendInvite } = require('./mailer.cjs');",
      "fastify.post('/invite', async (req) => { const { email, name } = req.body; await sendInvite({ email, name }); return { ok: true }; });",
    ].join('\n'),
  });
  assert.match(labels(byId(res, 'AUD-TRF-01')), /SMTP/);
});

// ---------------------------------------------------------------- svix
test('webhook relay: svix.message.create with explicit fields in a route handler reaches Svix', async () => {
  const g = await graphOf({
    'package.json': pkg({ next: '14', svix: '1' }),
    'app/api/members/route.ts': [
      "import { Svix } from 'svix';",
      'const svix = new Svix(process.env.SVIX_API_KEY!);',
      'export async function POST(req: Request) {',
      '  const { email, name } = await req.json();',
      "  await svix.message.create('app_1', { eventType: 'member.added', payload: { email, name } });",
      "  return Response.json({ ok: true });",
      '}',
    ].join('\n'),
  });
  assert.ok(flowsInto(g, 'sink:vendor:svix').includes('data:email'));
});

// ---------------------------------------------------------------- (4) unknown SDK
test('unknown SDK: credential-built client of an uncatalogued package + egress verb → unknown:<pkg> recipient', async () => {
  const g = await graphOf({
    'package.json': pkg({ express: '4', '@acme/notify-cloud': '2' }),
    'routes/notify.js': [
      "const express = require('express');",
      "const { CloudNotify } = require('@acme/notify-cloud');",
      'const router = express.Router();',
      'const notifyClient = new CloudNotify({ authorizationToken: process.env.ACME_AUTH_TOKEN });',
      "router.post('/notify', async (req, res) => {",
      '  const { email, message } = req.body;',
      "  await notifyClient.send({ message: { to: { email }, content: { body: message } } });",
      '  res.json({ ok: true });',
      '});',
      'module.exports = router;',
    ].join('\n'),
  });
  const s = g.node('sink:vendor:unknown:@acme/notify-cloud');
  assert.ok(s, 'unknown sink');
  assert.equal(s.category, 'unknown');
  assert.ok(flowsInto(g, s.id).includes('data:email'));
});

test('unknown SDK: credential keys in the options (apiKey / dsn) and a local-scope client', async () => {
  const g = await graphOf({
    'package.json': pkg({ 'beacon-sdk': '1' }),
    'lib/track.ts': [
      "import Beacon from 'beacon-sdk';",
      'export function trackSignup(email: string) {',
      "  const b = new Beacon({ apiKey: 'pk_test', region: 'eu' });",
      "  b.trackEvent('signup', { email });",
      '}',
    ].join('\n'),
  });
  assert.ok(flowsInto(g, 'sink:vendor:unknown:beacon-sdk').includes('data:email'));
});

test('unknown SDK: no recipient for local-only packages, relative modules, missing credentials or non-egress verbs', async () => {
  const g = await graphOf({
    'package.json': pkg({ pg: '8', 'tiny-cache': '1', 'beacon-sdk': '1' }),
    'lib/a.js': [
      "const { Pool } = require('pg');",
      "const { TinyCache } = require('tiny-cache');",
      "const Beacon = require('beacon-sdk');",
      "const Local = require('./local');",
      'const pool = new Pool({ password: process.env.DB_PASSWORD });',
      'const cache = new TinyCache({ max: 100 });',
      'const local = new Local({ token: process.env.LOCAL_TOKEN });',
      'const beacon = new Beacon({ apiKey: process.env.BEACON_API_KEY });',
      'exports.save = async (email) => {',
      '  cache.set(email, 1); cache.put(email, 2);',
      '  local.send({ email });',
      '  beacon.getStatus(email);',
      '};',
    ].join('\n'),
    'lib/local.js': 'module.exports = class Local { constructor(o) { this.o = o; } send() {} };',
  });
  const unknown = g.nodesOf('Sink', (n) => String(n.vendorId || '').startsWith('unknown:'));
  assert.deepEqual(unknown.map((n) => n.id), []);
});

test('unknown SDK: matchCall marks the spec unknownVendor with lower confidence', () => {
  const c = {
    pkg: 'beacon-sdk', root: 'b', segs: ['capture'], segments: [{ name: 'capture', args: [{ type: 'Identifier', name: 'email' }] }], isNew: false,
    last: { name: 'capture', args: [{ type: 'Identifier', name: 'email' }] }, rootArgs: null, rootValue: { t: new Map(), origin: 'beacon-sdk', remoteSdk: 'beacon-sdk' },
    strValue: () => null, objProp: () => null, originOfExpr: () => null,
  };
  const r = matchCall(c);
  assert.equal(r.target.vendorId, 'unknown:beacon-sdk');
  assert.equal(r.unknownVendor, true);
  assert.ok(r.confidence <= 0.5);
});
