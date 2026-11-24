// FIX2 flow workstream (src/audit/extract/flow.js): usage per column, recipient resolution, deletion recognition,
// OAuth profile import, IP addresses, uploads, voice streams, response shape (MIN-02 contract).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';

const SB_PKG = JSON.stringify({ name: 'fx', dependencies: { '@supabase/supabase-js': '2', next: '14', react: '18' } });

async function graphOf(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fix2-flow-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  const { graph, warnings } = await buildGraph(root);
  return { g: graph, warnings };
}
const edges = (g, type, pred = () => true) => g.edges.filter((e) => e.type === type && pred(e));

test('usage: IIFE body + Promise.all destructuring are analysed; usage is tracked per column', async () => {
  const { g } = await graphOf({
    'package.json': SB_PKG,
    'schema.sql': 'create table profiles (id uuid primary key, name text, linkedin_url text, twitter_url text);\n',
    'src/client.ts': "import { createClient } from '@supabase/supabase-js';\nexport const supabase = createClient(process.env.U!, process.env.K!);\n",
    'src/store.tsx': `import { useEffect } from "react";
import { supabase } from "./client";
export function P({ userId }: { userId: string }) {
  useEffect(() => {
    (async () => {
      const [w, p] = await Promise.all([
        supabase.from("profiles").select("id").eq("id", userId).maybeSingle(),
        supabase.from("profiles").select("*").eq("id", userId).maybeSingle(),
      ]);
      setSender({ linkedin: p.data?.linkedin_url });
    })().catch(() => {});
  }, [userId]);
  return null;
}
`,
  });
  const li = g.node('store:column:profiles.linkedin_url');
  const tw = g.node('store:column:profiles.twitter_url');
  assert.equal(li.used, true, 'dereferenced column is used');
  assert.notEqual(tw.used, true, 'unused sibling column of the same element stays unused');
  const colUse = edges(g, 'usedBy', (e) => e.from === li.id);
  assert.ok(colUse.length && colUse[0].column === 'linkedin_url' && colUse[0].store === 'profiles');
  const elUse = edges(g, 'usedBy', (e) => e.from === 'data:social_profile' && e.column === 'linkedin_url');
  assert.ok(elUse.length, 'element usedBy carries {column, store}');
});

test('responses: 204 / empty replies and the real payload shape are recorded on the Endpoint', async () => {
  const { g } = await graphOf({
    'package.json': SB_PKG,
    'schema.sql': 'create table profiles (id uuid primary key, full_name text, tckn text);\n',
    'lib/db.ts': "import { createClient } from '@supabase/supabase-js';\nexport const db = createClient(process.env.U!, process.env.K!);\n",
    'app/api/profile/route.ts': `import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
export async function GET() {
  const { data } = await db.from('profiles').select('*').single();
  return NextResponse.json(data);
}
export async function DELETE() {
  const { data } = await db.from('profiles').select('*').single();
  return new Response(null, { status: 204 });
}
export async function POST() {
  const { data } = await db.from('profiles').select('*').single();
  if (!data) return NextResponse.json({ error: 'missing' }, { status: 404 });
  return NextResponse.json({ ok: true });
}
`,
  });
  const get = g.node('endpoint:GET /api/profile');
  const del = g.node('endpoint:DELETE /api/profile');
  const post = g.node('endpoint:POST /api/profile');
  assert.ok(get && del && post, 'endpoints exist');
  assert.equal(get.responds, true);
  assert.ok(get.responseFields.includes('profiles.tckn'), 'whole row serialised');
  assert.equal(del.noBody, true);
  assert.equal(del.responseStatus, 204);
  assert.deepEqual(post.responseFields, [], 'existence check only: no row in the payload');
  assert.ok(post.responseKeys.includes('ok'));
  assert.equal(post.noBody, false);
});

test('deletion: compensating rollback is not a deletion flow; one helper reached from many routes is one flow', async () => {
  const { g } = await graphOf({
    'package.json': SB_PKG,
    'schema.sql': 'create table usage (id uuid primary key, user_id uuid, kind text);\ncreate table notes (id uuid primary key, user_id uuid, body text);\n',
    'lib/db.ts': "import { createClient } from '@supabase/supabase-js';\nexport const db = createClient(process.env.U!, process.env.K!);\n",
    'lib/limits.ts': `import { db } from './db';
export async function spend(userId: string) {
  const { data } = await db.from('usage').insert({ user_id: userId, kind: 'x' }).select('id').single();
  const over = await check(userId);
  if (over) await db.from('usage').delete().eq('id', data.id);
  return over;
}
async function check(u: string) { return false; }
export async function removeNote(id: string) { await db.from('notes').delete().eq('id', id); }
`,
    'app/api/a/route.ts': "import { spend, removeNote } from '@/lib/limits';\nexport async function POST(req: Request) { const { id } = await req.json(); await spend('u'); await removeNote(id); return Response.json({}); }\n",
    'app/api/b/route.ts': "import { spend, removeNote } from '@/lib/limits';\nexport async function POST(req: Request) { const { id } = await req.json(); await spend('u'); await removeNote(id); return Response.json({}); }\n",
  });
  const flows = g.nodesOf('Control', (c) => c.kind === 'deletion-flow');
  assert.ok(!edges(g, 'deletes', (e) => e.to === 'store:table:usage').length, 'rollback of a row inserted in the same function is not a deletion');
  const notes = edges(g, 'deletes', (e) => e.to === 'store:table:notes');
  assert.equal(notes.length, 1, `one deletion flow for the shared helper, got ${flows.map((f) => f.id)}`);
  const ctl = g.node(notes[0].from);
  assert.equal(ctl.endpoints?.length, 2);
});

test('deletion: unresolvable route registry member (path alias) still marks an account deletion', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'x', dependencies: { react: '18', jotai: '2' } }),
    'src/c/UserItem.tsx': `import { useAtom } from "jotai";
import { runRoutes } from "@nowhere/constants/runRoutes";
import { rowyRunAtom } from "@nowhere/atoms";
export default function UserItem({ user }: any) {
  const [rowyRun] = useAtom(rowyRunAtom);
  const handleDelete = async () => { await rowyRun({ route: runRoutes.deleteUser, body: { email: user.email } }); };
  return <button onClick={handleDelete}>x</button>;
}
`,
  });
  const c = g.nodesOf('Control', (n) => n.kind === 'deletion-flow' && n.external);
  assert.equal(c.length, 1);
  assert.equal(c[0].account, true);
});

test('recipients: destructured SDK payload (shorthand props) to Stripe; env-default base URL + spread fetch body', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'x', dependencies: { stripe: '14', next: '14' } }),
    'lib/stripe.ts': "import Stripe from 'stripe';\nexport const stripe = new Stripe(process.env.STRIPE_KEY ?? '');\n",
    'lib/billing.ts': `import { stripe } from './stripe';
export const copyBilling = async (pm: any) => {
  const { name, phone, address } = pm.billing_details;
  await stripe.customers.update(pm.customer, { name, phone, address });
};
`,
    'lib/film.ts': `export async function run(body: { fullName: string }, env: Record<string, string>) {
  const base = (env.FILM_URL || "https://films.example-render.com").replace(/\\/$/, "");
  const call = async (path: string, init: RequestInit = {}) => {
    const res = await fetch(\`\${base}\${path}\`, { ...init, headers: { a: '1' } });
    return res.json();
  };
  return call("/v1/films", { method: "POST", body: JSON.stringify({ sender: { name: body.fullName } }) });
}
`,
  });
  for (const el of ['full_name', 'phone', 'address']) {
    const fl = edges(g, 'flowsTo', (e) => e.from === `data:${el}` && e.to === 'sink:vendor:stripe');
    assert.ok(fl.length, `${el} → Stripe`);
  }
  const use = edges(g, 'usedBy', (e) => e.from === 'data:phone' && e.to === 'sink:vendor:stripe')[0];
  assert.equal(use.column, '(input)', 'payload data is not a read of an own column');
  assert.ok(edges(g, 'flowsTo', (e) => e.to === 'sink:http:films.example-render.com' && e.from === 'data:full_name').length, 'body via spread init reaches the env-default host');
});

test('OAuth: runtime provider falls back to UI provider literals; profile photo is imported', async () => {
  const { g } = await graphOf({
    'package.json': SB_PKG,
    'components/OauthSignIn.tsx': "export default function O() { const oAuthProviders = [{ name: 'github', displayName: 'GitHub' }]; return oAuthProviders.map((p) => <input type=\"hidden\" name=\"provider\" value={p.name} />); }\n",
    'utils/client.ts': `import { createClient } from '@supabase/supabase-js';
export async function signInWithOAuth(e: any) {
  const formData = new FormData(e.currentTarget);
  const provider = String(formData.get('provider')).trim();
  const supabase = createClient(process.env.U!, process.env.K!);
  await supabase.auth.signInWithOAuth({ provider: provider });
}
`,
  });
  assert.ok(g.has('source:oauth:github'), 'provider literal from the UI');
  assert.ok(!g.has('source:oauth:unknown'));
  assert.ok(edges(g, 'collects', (e) => e.from === 'source:oauth:github' && e.to === 'data:photo').length, 'avatar imported');
});

test('IP addresses: morgan preset to a logger stream; IP in a redis rate-limit key', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'x', dependencies: { morgan: '1', redis: '4', express: '4' } }),
    'src/morgan.js': "const morgan = require('morgan');\nconst logger = require('./logger');\nmodule.exports = morgan('combined', { stream: { write: (m) => logger.info(m) } });\n",
    'src/morgan2.js': "const morgan = require('morgan');\nmodule.exports = morgan('dev');\n",
    'lib/ratelimit.ts': `import { createClient } from "redis";
let client: any = null;
function getClient() { if (!client) client = createClient({ url: process.env.REDIS_URL }); return client; }
export async function checkIpRateLimit(ip: string | undefined) {
  const redis = getClient();
  const key = \`ip-rate-limit:\${ip}\`;
  await redis.multi().incr(key).expire(key, 3600).exec();
}
`,
    'app/api/chat/route.ts': "import { checkIpRateLimit } from '@/lib/ratelimit';\nexport async function POST(req: Request) { await checkIpRateLimit(req.headers.get('x-forwarded-for') ?? undefined); return Response.json({}); }\n",
  });
  assert.ok(edges(g, 'flowsTo', (e) => e.from === 'data:ip_address' && e.to === 'store:log:logger').length, 'morgan combined logs IPs');
  const logEv = edges(g, 'flowsTo', (e) => e.from === 'data:ip_address' && /^store:log/.test(e.to)).flatMap((e) => e.evidence.map((v) => v.file));
  assert.ok(!logEv.includes('src/morgan2.js'), "morgan('dev') does not log IPs");
  assert.ok(edges(g, 'flowsTo', (e) => e.from === 'data:ip_address' && e.to === 'store:cache:redis').length, 'IP in a redis key');
});

test('uploads: an uploaded image is a data element that reaches the blob store', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'x', dependencies: { '@vercel/blob': '1', next: '14', react: '18' } }),
    'app/api/upload/route.ts': `import { put } from "@vercel/blob";
export async function POST(request: Request) {
  const formData = await request.formData();
  const file = formData.get("file") as Blob;
  if (!["image/jpeg", "image/png"].includes(file.type)) return Response.json({ error: 'type' }, { status: 400 });
  const buf = await file.arrayBuffer();
  const data = await put("x.png", buf, { access: "public" });
  return Response.json(data);
}
`,
  });
  assert.ok(g.has('data:uploaded_image'));
  assert.equal(g.node('data:uploaded_image').category, 'audiovisual');
  assert.ok(edges(g, 'flowsTo', (e) => e.from === 'data:uploaded_image' && e.to === 'store:bucket:vercel-blob').length);
});

test('python: column references in views / templates are usage; export route launching a task is an export flow', async () => {
  const { g } = await graphOf({
    'app/models.py': `from app import db
import sqlalchemy as sa
import sqlalchemy.orm as so

class User(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True, unique=True)
    email: so.Mapped[str] = so.mapped_column(sa.String(120), index=True, unique=True)
    about_me: so.Mapped[str] = so.mapped_column(sa.String(140))
    phone: so.Mapped[str] = so.mapped_column(sa.String(20))

class Post(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    body: so.Mapped[str] = so.mapped_column(sa.String(140))
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(User.id), index=True)
`,
    'app/routes.py': `from flask import render_template
from flask_login import login_required, current_user
from app.models import User

@bp.route('/user/<username>')
def user(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    form.about_me.data = 'x'
    return render_template('user.html', user=user)

@bp.route('/export_posts')
@login_required
def export_posts():
    current_user.launch_task('export_posts', 'Exporting posts...')
    return redirect('/')
`,
    'app/tasks.py': `import json
def export_posts(user_id):
    user = db.session.get(User, user_id)
    data = [{'body': p.body} for p in user.posts]
    send_email('[x] posts', recipients=[user.email], attachments=[('posts.json', 'application/json', json.dumps({'posts': data}))])
`,
    'app/templates/user.html': '<h1>{{ user.username }}</h1>\n<p>{{ user.about_me }}</p>\n',
  });
  assert.equal(g.node('store:column:user.username')?.used, true);
  assert.equal(g.node('store:column:user.about_me')?.used, true, 'template reference');
  assert.notEqual(g.node('store:column:user.phone')?.used, true, 'never referenced column stays unused');
  const exp = g.nodesOf('Control', (c) => c.kind === 'export-flow');
  assert.equal(exp.length, 1);
  assert.ok(edges(g, 'exports', (e) => e.from === exp[0].id && e.to === 'store:table:post').length);
});
