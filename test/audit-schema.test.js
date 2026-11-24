import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildGraph } from '../src/audit/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(here, '../examples/audit-app');

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-schema-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}
const refEdge = (g, from, to) => g.edgesFrom(`store:table:${from}`, 'references').find((e) => e.to === `store:table:${to}`);
const represents = (g, table, col) => g.out(`store:column:${table}.${col}`, 'represents').map((n) => n.id);

let app;
test('audit-app graph builds', async () => {
  app = await buildGraph(APP);
  assert.deepEqual(app.warnings.filter((w) => /sql|prisma|drizzle|mongoose|orm|firestore|forms|mobile|declarations/.test(w)), []);
});

test('SQL: RLS state and policies per table', () => {
  const g = app.graph;
  const profiles = g.node('store:table:profiles');
  assert.equal(profiles.rls, true);
  assert.ok(profiles.policies.some((p) => p.name === 'own profile' && p.ownerCheck === true && p.cmd === 'all'));
  const health = g.node('store:table:health_logs');
  assert.equal(health.rls, true);
  const read = health.policies.find((p) => p.name === 'read all logs');
  assert.equal(read.public, true);
  assert.equal(read.ownerCheck, false);
  assert.equal(g.node('store:table:orders').rls, false);
  assert.equal(g.node('store:table:support_tickets').rls, true);
  assert.equal(g.node('store:table:support_tickets').policies.length, 0);
  assert.ok(g.has('control:rls-policy:health_logs:read all logs'));
});

test('SQL: foreign keys and ON DELETE', () => {
  const g = app.graph;
  assert.equal(refEdge(g, 'profiles', 'auth.users').onDelete, 'cascade');
  assert.equal(refEdge(g, 'health_logs', 'profiles').onDelete, 'cascade');
  const o = refEdge(g, 'orders', 'profiles');
  assert.ok(o);
  assert.ok(o.onDelete === null || o.onDelete === 'no action');
  assert.equal(g.edgesFrom('store:table:support_tickets', 'references').length, 0);
  assert.equal(refEdge(g, 'chat_messages', 'auth.users').onDelete, 'cascade');
  assert.equal(g.node('store:table:auth.users').external, true);
});

test('SQL: columns, defaults, vector, bucket', () => {
  const g = app.graph;
  assert.equal(g.node('store:column:profiles.marketing_opt_in').default, 'true');
  const emb = g.node('store:column:chat_messages.embedding');
  assert.equal(emb.vector, true);
  assert.deepEqual(emb.derivedFrom, ['content']);
  assert.equal(g.node('store:bucket:avatars').public, true);
  assert.deepEqual(represents(g, 'profiles', 'birth_date'), ['data:birth_date']);
  assert.deepEqual(represents(g, 'profiles', 'tckn'), ['data:national_id']);
  assert.deepEqual(represents(g, 'health_logs', 'symptoms'), ['data:health']);
  for (const [t, c] of [['health_logs', 'notes'], ['support_tickets', 'message'], ['chat_messages', 'content']]) assert.deepEqual(represents(g, t, c), ['data:free_text']);
  assert.equal(g.node('data:health').sensitivity, 'special');
  assert.ok(app.ctx.shared.tables.profiles.columns.includes('full_name'));
});

test('forms: signup form fields, pre-checked marketing, submit target', () => {
  const g = app.graph;
  const s = g.node('source:form:src/app/signup/page.tsx#SignupPage');
  assert.ok(s);
  assert.equal(s.submitsTo, '/api/signup');
  assert.equal(s.method, 'POST');
  assert.deepEqual(s.preChecked, ['marketing']);
  assert.equal(s.hasPrivacyLink, false);
  const collected = g.out(s.id, 'collects').map((n) => n.id).sort();
  assert.deepEqual(collected, ['data:birth_date', 'data:email', 'data:full_name', 'data:marketing_consent', 'data:national_id', 'data:password', 'data:phone']);
  const f = app.ctx.shared.forms.find((x) => x.sourceId === s.id);
  assert.ok(f.fields.some((x) => x.name === 'birthDate'));
});

test('forms: support form uses a server action', () => {
  const s = app.graph.node('source:form:src/app/support/page.tsx#SupportPage');
  assert.equal(s.action, 'submitTicket');
  assert.equal(s.actionFile, 'src/app/support/actions.ts');
  assert.deepEqual(app.graph.out(s.id, 'collects').map((n) => n.id).sort(), ['data:email', 'data:free_text']);
});

test('consent UI: cookie banner without reject', () => {
  const c = app.graph.node('control:consent-ui:src/components/CookieBanner.tsx');
  assert.equal(c.hasAccept, true);
  assert.equal(c.hasReject, false);
  assert.equal(app.ctx.shared.consentUi.length, 1);
});

test('declarations: privacy page facts', () => {
  const d = app.graph.node('declaration:policy:src/app/privacy/page.tsx');
  assert.ok(d);
  assert.equal(d.kind, 'privacy');
  for (const el of ['full_name', 'email', 'phone']) assert.ok(d.declaredData.includes(el), el);
  assert.ok(!d.declaredData.includes('address'), 'e-posta "adresine" is not a postal address');
  assert.deepEqual([...d.declaredVendors].sort(), ['stripe', 'supabase']);
  assert.equal(d.declaresNoTransferAbroad, true);
  assert.equal(d.declaredRights, true);
  assert.equal(d.controller, 'Örnek Teknoloji A.Ş.');
  assert.equal(d.contactEmail, 'kvkk@ornek.com');
  assert.ok(app.graph.edgesTo(d.id, 'declaredIn').some((e) => e.from === 'data:email'));
});

test('SQL: later migration drops a policy; pg_cron retention; ALTER ADD COLUMN; view over auth.users', async () => {
  const dir = tmpProject({
    'package.json': '{"dependencies":{"@supabase/supabase-js":"2"}}',
    'supabase/migrations/001.sql': `create table "public"."notes" (id int primary key, body text, user_id uuid references auth.users on delete set null);
alter table notes enable row level security;
create policy "everyone" on notes for select using (true);`,
    'supabase/migrations/002.sql': `drop policy if exists "everyone" on public.notes;
create policy "mine" on notes for select to authenticated using ((select auth.uid()) = user_id);
alter table public.notes add column phone_number text;
select cron.schedule('purge-notes', '0 3 * * *', $$ delete from public.notes where created_at < now() - interval '90 days' $$);
create view public.user_emails as select id, email from auth.users;`,
  });
  const { graph } = await buildGraph(dir);
  const t = graph.node('store:table:notes');
  assert.deepEqual(t.policies.map((p) => p.name), ['mine']);
  assert.equal(t.policies[0].ownerCheck, true);
  assert.deepEqual(t.policies[0].roles, ['authenticated']);
  assert.equal(graph.edgesFrom('store:table:notes', 'references')[0].onDelete, 'set null');
  assert.deepEqual(graph.out('store:column:notes.phone_number', 'represents').map((n) => n.id), ['data:phone']);
  const job = graph.node('control:retention-job:purge-notes');
  assert.equal(job.schedule, '0 3 * * *');
  assert.equal(job.action, 'delete');
  assert.equal(graph.edgesFrom(job.id, 'expires')[0].to, 'store:table:notes');
  const v = graph.node('store:table:user_emails');
  assert.equal(v.kind, 'view');
  assert.equal(v.exposesAuthUsers, true);
  assert.equal(v.securityInvoker, false);
});

test('Prisma models, relations and onDelete', async () => {
  const dir = tmpProject({
    'prisma/schema.prisma': `model User {
  id        String   @id @default(uuid())
  email     String   @unique
  phone     String?
  posts     Post[]
  @@map("users")
}
model Post {
  id       Int    @id
  content  String
  authorId String @map("author_id")
  author   User   @relation(fields: [authorId], references: [id], onDelete: Cascade)
}`,
  });
  const { graph, ctx } = await buildGraph(dir);
  assert.ok(graph.has('store:column:users.email'));
  assert.deepEqual(graph.out('store:column:users.phone', 'represents').map((n) => n.id), ['data:phone']);
  const ref = graph.edgesFrom('store:table:Post', 'references')[0];
  assert.equal(ref.to, 'store:table:users');
  assert.equal(ref.onDelete, 'cascade');
  assert.equal(ctx.shared.tables.users.model, 'User');
});

test('Drizzle tables with references and enableRLS', async () => {
  const dir = tmpProject({
    'src/db/schema.ts': `import { pgTable, uuid, text, boolean } from 'drizzle-orm/pg-core';
export const profiles = pgTable('profiles', {
  id: uuid('id').primaryKey(),
  fullName: text('full_name').notNull(),
  marketing: boolean('marketing_opt_in').default(true),
}).enableRLS();
export const orders = pgTable('orders', {
  id: uuid('id').primaryKey(),
  userId: uuid('user_id').references(() => profiles.id, { onDelete: 'cascade' }),
  shippingAddress: text('shipping_address'),
});`,
  });
  const { graph } = await buildGraph(dir);
  assert.equal(graph.node('store:table:profiles').rls, true);
  assert.deepEqual(graph.out('store:column:profiles.full_name', 'represents').map((n) => n.id), ['data:full_name']);
  assert.equal(graph.node('store:column:profiles.marketing_opt_in').default, 'true');
  const ref = graph.edgesFrom('store:table:orders', 'references')[0];
  assert.equal(ref.to, 'store:table:profiles');
  assert.equal(ref.column, 'user_id');
  assert.equal(ref.refColumn, 'id');
  assert.equal(ref.onDelete, 'cascade');
});

test('Mongoose schema + model', async () => {
  const dir = tmpProject({
    'models/user.js': `const mongoose = require('mongoose');
const { Schema } = mongoose;
const userSchema = new Schema({
  email: { type: String, required: true },
  phone: String,
  address: { street: String, city: String },
  owner: { type: Schema.Types.ObjectId, ref: 'Org' },
});
module.exports = mongoose.model('User', userSchema);`,
  });
  const { graph } = await buildGraph(dir);
  const t = graph.node('store:table:User');
  assert.equal(t.kind, 'collection');
  assert.ok(graph.has('store:column:User.address_street'));
  assert.deepEqual(graph.out('store:column:User.email', 'represents').map((n) => n.id), ['data:email']);
  assert.equal(graph.edgesFrom('store:table:User', 'references')[0].to, 'store:table:Org');
});

test('Django + SQLAlchemy models', async () => {
  const dir = tmpProject({
    'app/models.py': `from django.db import models
class Patient(models.Model):
    full_name = models.CharField(max_length=100)
    diagnosis = models.TextField(null=True)
    doctor = models.ForeignKey('Doctor', on_delete=models.CASCADE)
`,
    'api/db.py': `class Customer(Base):
    __tablename__ = 'customers'
    id = Column(Integer, primary_key=True)
    iban = Column(String, nullable=False)
    org_id = Column(Integer, ForeignKey('orgs.id', ondelete='CASCADE'))
`,
  });
  const { graph } = await buildGraph(dir);
  assert.deepEqual(graph.out('store:column:patient.diagnosis', 'represents').map((n) => n.id), ['data:health']);
  assert.equal(graph.edgesFrom('store:table:patient', 'references')[0].onDelete, 'cascade');
  assert.deepEqual(graph.out('store:column:customers.iban', 'represents').map((n) => n.id), ['data:iban']);
  assert.equal(graph.edgesFrom('store:table:customers', 'references')[0].to, 'store:table:orgs');
});

test('Firestore rules: public vs owner collections', async () => {
  const dir = tmpProject({
    'firestore.rules': `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    match /posts/{postId} {
      allow read: if true;
    }
  }
}`,
  });
  const { graph } = await buildGraph(dir);
  const users = graph.node('store:table:users');
  assert.equal(users.kind, 'collection');
  assert.equal(users.ownerCheck, true);
  assert.equal(users.public, false);
  assert.equal(graph.node('store:table:posts').public, true);
});

test('Mobile permissions → device sources', async () => {
  const dir = tmpProject({
    'android/app/src/main/AndroidManifest.xml': `<manifest><uses-permission android:name="android.permission.READ_CONTACTS"/><uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/></manifest>`,
    'ios/App/Info.plist': `<plist><dict><key>NSHealthShareUsageDescription</key><string>x</string><key>NSFaceIDUsageDescription</key><string>y</string></dict></plist>`,
  });
  const { graph } = await buildGraph(dir);
  assert.deepEqual(graph.out('source:device:contacts', 'collects').map((n) => n.id), ['data:contacts']);
  assert.equal(graph.node('data:contacts').thirdPartyData, true);
  assert.deepEqual(graph.out('source:device:location', 'collects').map((n) => n.id), ['data:precise_location']);
  assert.deepEqual(graph.out('source:device:health', 'collects').map((n) => n.id), ['data:health']);
  assert.equal(graph.node('source:device:biometric-auth').onDevice, true);
});

test('HTML form + zod schema + consent library', async () => {
  const dir = tmpProject({
    'public/contact.html': `<form action="/contact" method="post"><input name="email" type="email"><input type="checkbox" name="newsletter" checked><a href="/gizlilik">Aydınlatma Metni</a></form>`,
    'src/schema.ts': `import { z } from 'zod';\nexport const signupSchema = z.object({ email: z.string().email(), birthDate: z.string() });`,
    'src/consent.tsx': `import CookieConsent from 'react-cookie-consent';\nexport const C = () => <CookieConsent enableDeclineButton>Çerez</CookieConsent>;`,
  });
  const { graph } = await buildGraph(dir);
  const f = graph.node('source:form:public/contact.html#form-1');
  assert.equal(f.submitsTo, '/contact');
  assert.deepEqual(f.preChecked, ['newsletter']);
  assert.equal(f.hasPrivacyLink, true);
  const s = graph.node('source:schema:src/schema.ts#signupSchema');
  assert.deepEqual(graph.out(s.id, 'collects').map((n) => n.id).sort(), ['data:birth_date', 'data:email']);
  const c = graph.node('control:consent-ui:src/consent.tsx');
  assert.equal(c.library, 'react-cookie-consent');
  assert.equal(c.hasReject, true);
});
