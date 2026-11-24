// FIX3 flow workstream (src/audit/extract/flow.js), report item P5: a field is used when it reaches any sink,
// transfer payloads carry every interpolated field, public buckets, error data in logs, validation results,
// request input in handlers without a registered route, auth.users column reads.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';

const SB_PKG = JSON.stringify({ name: 'fx', dependencies: { '@supabase/supabase-js': '2', resend: '3', next: '14', react: '18' } });

async function graphOf(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fix3-flow-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  const { graph, warnings } = await buildGraph(root);
  return { g: graph, warnings };
}
const edges = (g, type, pred = () => true) => g.edges.filter((e) => e.type === type && pred(e));
const flowsTo = (g, el, to) => edges(g, 'flowsTo', (e) => e.from === `data:${el}` && (typeof to === 'string' ? e.to === to : to.test(e.to)));

test('email body: every field interpolated into a mail helper reaches the provider (Resend via $lib helper, SvelteKit-style action)', async () => {
  const { g, warnings } = await graphOf({
    'package.json': JSON.stringify({ name: 'fx', dependencies: { '@supabase/supabase-js': '2', resend: '3', '@sveltejs/kit': '2' } }),
    'schema.sql': 'create table contact_requests (id uuid primary key, email text, phone text, message_body text);\n',
    'src/lib/mailer.ts': `import { Resend } from "resend";
export const sendAdminEmail = async ({ subject, body }: { subject: string; body: string }) => {
  const resend = new Resend(process.env.KEY);
  await resend.emails.send({ from: process.env.FROM, to: [process.env.ADMIN], subject, text: body });
};
`,
    'src/routes/contact/+page.server.ts': `import { sendAdminEmail } from "$lib/mailer.js";
export const actions = {
  submit: async ({ request, locals: { supabaseServiceRole } }) => {
    const formData = await request.formData();
    const email = formData.get("email")?.toString() ?? "";
    const phone = formData.get("phone")?.toString() ?? "";
    const message = formData.get("message")?.toString() ?? "";
    await supabaseServiceRole.from("contact_requests").insert({ email, phone, message_body: message });
    await sendAdminEmail({ subject: "New contact", body: \`Email: \${email}\\nPhone: \${phone}\\nMessage: \${message}\` });
  },
};
`,
  });
  assert.deepEqual(warnings.filter((w) => /flow/.test(w)), []);
  for (const el of ['phone', 'free_text', 'email']) {
    assert.ok(flowsTo(g, el, /^sink:vendor:/).some((e) => /resend|email/.test(e.to)), `${el} reaches the email provider`);
    assert.ok(edges(g, 'usedBy', (e) => e.from === `data:${el}` && /^sink:vendor:/.test(e.to)).length, `${el} is used (sent)`);
  }
  assert.ok(flowsTo(g, 'phone', 'store:column:contact_requests.phone').length, 'phone stored (Supabase client from framework locals)');
  assert.ok(edges(g, 'collects', (e) => e.to === 'data:phone' && g.node(e.from)?.kind === 'request').length, 'request source for the unregistered handler');
});

test('templates and JSX: rendered email markup carries its props (react-email render, handlebars compile)', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'fx', dependencies: { '@react-email/render': '1', handlebars: '4', nodemailer: '6', postmark: '4', react: '18' } }),
    'emails/Welcome.tsx': 'export function Welcome({ phone }: { phone: string }) { return <div><p>Call {phone}</p></div>; }\n',
    'lib/send.ts': `import { render } from "@react-email/render";
import handlebars from "handlebars";
import nodemailer from "nodemailer";
import { ServerClient } from "postmark";
import { Welcome } from "../emails/Welcome";
const transporter = nodemailer.createTransport({ host: "smtp.example.com" });
const pm = new ServerClient(process.env.PM!);
export async function welcome(input: { phone: string; address: string; birth_date: string }) {
  const html = await render(<Welcome phone={input.phone} />);
  await transporter.sendMail({ to: process.env.ADMIN, html });
  const tpl = handlebars.compile("<p>{{address}}</p>");
  await transporter.sendMail({ to: process.env.ADMIN, html: tpl({ address: input.address }) });
  await pm.sendEmailWithTemplate({ To: process.env.ADMIN, TemplateAlias: "x", TemplateModel: { dob: input.birth_date } });
}
`,
  });
  assert.ok(flowsTo(g, 'phone', /^sink:vendor:/).length, 'react-email render() output keeps the phone');
  assert.ok(flowsTo(g, 'address', /^sink:vendor:/).length, 'handlebars compile()(data) output keeps the address');
  assert.ok(flowsTo(g, 'birth_date', /^sink:vendor:/).length, 'Postmark TemplateModel field reaches the provider');
});

test('JSX render: fields of a record shown in the UI are used; an input value echo or a flag name is not', async () => {
  const { g } = await graphOf({
    'package.json': SB_PKG,
    'schema.sql': 'create table profiles (id uuid primary key, phone text, tckn text);\n',
    'lib/db.ts': "import { createClient } from '@supabase/supabase-js';\nexport const db = createClient(process.env.U!, process.env.K!);\n",
    'components/Card.tsx': `export function Card({ profile }: any) { return <div><span>{profile.age}</span></div>; }\n`,
    'components/Form.tsx': `export function F({ allowPassword }: any) { return <form>{allowPassword && <input name="pw" />}</form>; }\n`,
    'app/page.tsx': `import { db } from "@/lib/db";
export default async function Page() {
  const { data } = await db.from("profiles").select("phone").single();
  return <main>{data && <p>{data.phone}</p>}</main>;
}
`,
  });
  const rendered = (el) => edges(g, 'usedBy', (e) => e.from === `data:${el}` && (e.evidence || []).some((v) => v.note === 'rendered in the UI'));
  assert.ok(g.node('store:column:profiles.phone')?.used, 'phone column read and rendered');
  assert.equal(rendered('password').length, 0, 'a flag named allowPassword is not a rendered password');
});

test('public buckets: getPublicUrl() on a bucket the app uploads to marks it public; createBucket config applies; dynamic or SQL-declared ones untouched', async () => {
  const { g } = await graphOf({
    'package.json': SB_PKG,
    'lib/storage.ts': `import { createClient } from "@supabase/supabase-js";
const supabase = createClient(process.env.U!, process.env.K!);
export async function uploadFile(bucket: string, path: string, blob: Blob) {
  await supabase.storage.from(bucket).upload(path, blob);
  const { data } = supabase.storage.from(bucket).getPublicUrl(path);
  return data.publicUrl;
}
export const uploadAvatar = (userId: string, blob: Blob) => uploadFile("avatars", \`\${userId}/a.png\`, blob);
export async function logos() { return supabase.storage.from("logos").getPublicUrl("x.png"); }
export async function setup() { await supabase.storage.createBucket("docs", { public: false }); await supabase.storage.createBucket("media", { public: true }); }
`,
  });
  const av = g.node('store:bucket:avatars');
  assert.equal(av?.public, true, 'uploaded-to + getPublicUrl → public');
  assert.equal(av.publicSource, 'inferred');
  assert.notEqual(g.node('store:bucket:logos')?.public, true, 'getPublicUrl alone (no uploads of user files) does not flag a bucket');
  assert.equal(g.node('store:bucket:media')?.public, true, 'createBucket({ public: true })');
  assert.equal(g.node('store:bucket:docs')?.public, false, 'createBucket({ public: false })');
});

test('error data in logs: cause / detail members are possible low-confidence flows; whole error objects only noted; never to vendors or the client', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'fx', dependencies: { 'drizzle-orm': '0.45', '@sentry/nextjs': '8', next: '14' } }),
    'lib/schema.ts': `import { pgTable, text, uuid } from "drizzle-orm/pg-core";
export const message = pgTable("message", { id: uuid("id").primaryKey(), content: text("content"), email: text("email") });
`,
    'lib/errors.ts': `export class AppError extends Error {
  constructor(public code: string, opts?: { cause?: unknown }) { super(code, opts); }
  toResponse() {
    const { cause, code } = this;
    console.error({ cause, code });
    return Response.json({ code }, { status: 500 });
  }
}
`,
    'lib/queries.ts': `import { db } from "./db";
import { message } from "./schema";
import { AppError } from "./errors";
import * as Sentry from "@sentry/nextjs";
export async function saveMessage({ content, email }: { content: string; email: string }) {
  try {
    return await db.insert(message).values({ content, email });
  } catch (error) {
    Sentry.captureException(error);
    throw new AppError("bad_request:database", { cause: error });
  }
}
export async function saveOther({ email }: { email: string }) {
  try {
    await db.insert(message).values({ email });
  } catch (err) {
    console.error("insert failed", err);
    return Response.json({ error: String(err) }, { status: 500 });
  }
}
`,
    'lib/db.ts': "import { drizzle } from 'drizzle-orm/postgres-js';\nexport const db = drizzle(process.env.DB!);\n",
  });
  const errFlows = edges(g, 'flowsTo', (e) => e.errorData && e.to === 'store:log:console');
  assert.ok(errFlows.some((e) => e.from === 'data:email'), 'cause of AppError (DB write params) logged in the class');
  for (const e of errFlows) {
    assert.equal(e.possible, true);
    assert.ok(e.evidence.every((v) => v.confidence <= 0.4), 'low confidence');
  }
  assert.ok((g.node('store:log:console')?.errorObjects || []).some((x) => /queries\.ts$/.test(x.file)), 'whole error object noted on the log store');
  assert.equal(edges(g, 'flowsTo', (e) => e.errorData && !String(e.to).startsWith('store:log')).length, 0, 'error data never flows to vendors / client');
  assert.equal(edges(g, 'flowsTo', (e) => /sentry/.test(e.to) && e.from === 'data:email').length, 0, 'captureException(error) does not invent an email transfer');
});

test('validation results: zod safeParse error messages and Joi { error } are not request fields', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'fx', dependencies: { zod: '3', joi: '17', next: '14' } }),
    'lib/validate.ts': `export const validateWithSchema = (schema: any, data: any) => {
  const result = schema.safeParse(data);
  if (!result.success) throw new Error(\`Validation Error: \${result.error.errors.map((e: any) => e.message)[0]}\`);
  return result.data;
};
`,
    'pages/api/password.ts': `import { validateWithSchema } from "../../lib/validate";
import Joi from "joi";
const schema = Joi.object({ email: Joi.string() });
export default async function handler(req: any, res: any) {
  const { email } = validateWithSchema({} as any, req.body);
  const { error, value } = schema.validate(req.body);
  if (error) return res.status(422).json({ message: error.details[0].message });
  res.json({ ok: !!email && !!value.email });
}
`,
  });
  assert.equal(edges(g, 'collects', (e) => e.to === 'data:free_text').length, 0, 'no free text element from validation messages');
});

test('depth: small string helpers past MAX_DEPTH keep the value (required(a.contact) → line(value))', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'fx', dependencies: { next: '14' } }),
    'lib/client.ts': `const line = (value: string, max: number) => value.replace(/\\s+/g, " ").trim().slice(0, max);
function required(value: string, min: number) { const r = line(value, 80); if (r.length < min) throw new Error("x"); return r; }
export function toProfile(a: { contact: string }) { return { cta: { contact: required(a.contact, 3) } }; }
export function makeClient() { return { create: (input: any) => fetch("https://films.example.com/v1/films", { method: "POST", body: JSON.stringify(input) }) }; }
`,
    'app/api/film/route.ts': `import { toProfile, makeClient } from "@/lib/client";
async function quietly(action: (c: any) => Promise<unknown>) { return action(makeClient()); }
export async function POST(req: Request) {
  const data = await req.json();
  return quietly(async (client) => {
    const a = { contact: data.sender?.email.includes("@") ? data.sender.email.trim() : "x" };
    const profile = toProfile(a);
    return client.create({ profile });
  });
}
`,
  });
  assert.ok(flowsTo(g, 'email', /^sink:http:films\.example\.com$/).length, 'email reaches the outbound API through nested helpers');
});

test('auth.users: only columns the app reads from the auth user object are used; values are not exposed as table reads', async () => {
  const { g } = await graphOf({
    'package.json': SB_PKG,
    'schema.sql': 'create table profiles (id uuid primary key references auth.users(id) on delete cascade, full_name text);\n',
    'lib/sb.ts': "import { createClient } from '@supabase/supabase-js';\nexport const supabase = createClient(process.env.U!, process.env.K!);\n",
    'app/api/me/route.ts': `import { supabase } from "@/lib/sb";
import { NextResponse } from "next/server";
export async function GET() {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({}, { status: 401 });
  return NextResponse.json({ email: user.email });
}
`,
  });
  const emailCol = g.node('store:column:auth.users.email');
  if (emailCol) {
    assert.equal(emailCol.used, true, 'auth.users.email is read');
    const phone = g.node('store:column:auth.users.phone');
    if (phone) assert.notEqual(phone.used, true, 'auth.users.phone never read');
    assert.equal(edges(g, 'exposes', (e) => e.table === 'auth.users').length, 0, 'no table exposure invented for the session user');
  }
});

test('soft delete: supabase auth.admin.deleteUser(id, true) is recorded as soft', async () => {
  const { g } = await graphOf({
    'package.json': SB_PKG,
    'lib/sb.ts': "import { createClient } from '@supabase/supabase-js';\nexport const supabase = createClient(process.env.U!, process.env.K!);\n",
    'app/api/account/route.ts': `import { supabase } from "@/lib/sb";
export async function DELETE(req: Request) {
  const { id } = await req.json();
  await supabase.auth.admin.deleteUser(id, true);
  return new Response(null, { status: 204 });
}
`,
  });
  const del = edges(g, 'deletes', (e) => e.to === 'store:table:auth.users');
  assert.ok(del.length && del.every((e) => e.soft === true), 'deletes edge marked soft');
  assert.equal(g.node(del[0].from)?.softDelete, true);
});

test('request input in a handler no route registered: h3 readBody(event) / Fetch request.json() get a file-level request source', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'fx', dependencies: { nuxt: '3', h3: '1' } }),
    'server/utils/contact.ts': `export async function readContact(event: any) {
  const body = await readBody(event);
  return { email: body.email };
}
`,
    'lib/helpers/handle.ts': `export async function handleSignup(request: Request) {
  const { phone } = await request.json();
  return phone;
}
`,
    'components/Client.tsx': `"use client";
export async function onReply(request: any) { const { phone } = await request.json(); return phone; }
`,
  });
  const src = (rel) => g.node(`source:request:${rel}`);
  assert.ok(src('server/utils/contact.ts')?.endpointless, 'h3 reader → endpointless request source');
  assert.ok(edges(g, 'collects', (e) => e.from === 'source:request:server/utils/contact.ts' && e.to === 'data:email').length);
  assert.ok(edges(g, 'collects', (e) => e.from === 'source:request:lib/helpers/handle.ts' && e.to === 'data:phone').length, 'Fetch request.json() in an unregistered handler');
  assert.equal(src('components/Client.tsx'), null, 'client code is not a request source');
});

test('branches: a value assigned in try and reassigned in catch / if-else keeps both possibilities', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'fx', dependencies: { next: '14' } }),
    'app/api/film/route.ts': `function build(a: any) { if (!a.ok) throw new Error("x"); return { contact: a.email }; }
export async function POST(req: Request) {
  const data = await req.json();
  let profile: any;
  try {
    profile = build({ ok: data.ok, email: data.email });
  } catch (e) {
    profile = { contact: "fallback" };
  }
  let phone = "none";
  if (data.usePhone) phone = data.phone;
  else phone = "n/a";
  await fetch("https://films.example.com/v1", { method: "POST", body: JSON.stringify({ profile, phone }) });
  return new Response(null, { status: 204 });
}
`,
  });
  assert.ok(flowsTo(g, 'email', /^sink:http:films\.example\.com$/).length, 'try-branch value survives the catch reassignment');
  assert.ok(flowsTo(g, 'phone', /^sink:http:films\.example\.com$/).length, 'if-branch value survives the else reassignment');
});
