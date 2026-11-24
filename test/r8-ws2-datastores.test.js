// R8 WS2: every data store the app uses is in the graph with parsed columns and traced writes.
//   (1) commented Supabase config  (2) Supabase TypeScript types  (3) Dart indirect Firestore / RTDB writes
//   (4) Realtime Database paths (JS)  (5) DDL in code, ClickHouse  (6) SQLModel / SQLAlchemy session writes
// All fixtures are synthetic.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';
import { assessLayers, detectStack } from '../src/audit/legal/stack.js';
import { stripTomlComments, configTomlBuckets, parseSqlFiles } from '../src/audit/extract/sql.js';
import { typeMembers, sqlTypeOf, queryBindings, blankComments } from '../src/audit/extract/supabase-types.js';
import { rtdbKey } from '../src/audit/extract/firestore.js';
import { clickhouseColumn, clickhouseType, parseSql, pythonStrings } from '../src/audit/extract/rawsql.js';
import { isMessageRecord } from '../src/audit/extract/_schema.js';

async function graphOf(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r8-ws2-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
      fs.writeFileSync(path.join(root, rel), content);
    }
    const { graph, ctx, warnings } = await buildGraph(root);
    return { g: graph, ctx, warnings: warnings || [] };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}
const edges = (g, type, pred = () => true) => g.edges.filter((e) => e.type === type && pred(e));
const cols = (g, key) => edges(g, 'hasColumn', (e) => e.from === `store:table:${key}`).map((e) => e.to.slice(`store:column:${key}.`.length));
const represents = (g, key, col) => edges(g, 'represents', (e) => e.from === `store:column:${key}.${col}`).map((e) => e.to);
const writesTo = (g, key) => edges(g, 'writes', (e) => e.to === `store:table:${key}`);
const deletesOf = (g, key) => edges(g, 'deletes', (e) => e.to === `store:table:${key}`);
const tableKeys = (g) => g.nodesOf('Store', (n) => n.id.startsWith('store:table:')).map((n) => n.table);
const gap = (ctx, kind) => (ctx.shared.unparsed || []).filter((u) => u.kind === kind);

// ---------------------------------------------------------------------------
// (1) config.toml

test('config.toml: commented bucket is not a bucket; trailing comments, # in strings and arrays are handled', async () => {
  const toml = [
    'project_id = "demo"', '', '# [storage.buckets.ghost]', '# public = true', '',
    '[storage.buckets.receipts] # user receipts', 'public = false # not [public]', 'file_size_limit = "50MiB"', 'note = "a # b [storage.buckets.fake]"',
    'allowed_mime_types = [', '  "image/png", # png', '  ["nested"],', ']', 'public = true', '',
    '[storage.buckets."user-avatars"]', 'public = true', '[auth]', 'site_url = "x"',
  ].join('\n');
  const b = configTomlBuckets(toml);
  assert.deepEqual(b.map((x) => [x.id, x.public, x.line]), [['receipts', true, 6], ['user-avatars', true, 16]]);
  assert.equal(stripTomlComments('a = "x # y" # z').trimEnd(), 'a = "x # y"');
  assert.equal(stripTomlComments("k = 'a#b'\n# c\nd=1").split('\n').length, 3);
  const { g } = await graphOf({ 'supabase/config.toml': toml.replace(/\n/g, '\r\n') });
  assert.deepEqual(g.nodesOf('Store', (n) => n.kind === 'bucket').map((n) => n.name).sort(), ['receipts', 'user-avatars']);
});

test('sql: objects a migration dropped are reported as dropped, re-created ones are not', () => {
  const r = parseSqlFiles([{ rel: 'm/1.sql', content: 'create table a (id int, gone text);\ncreate table b (id int);\nalter table a drop column gone;\ndrop table b;\ncreate table b (id int);' }]);
  assert.deepEqual([...r.dropped], ['a.gone']);
});

// ---------------------------------------------------------------------------
// (2) Supabase types

const GEN_TYPES = `export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[]

export type Database = {
  __InternalSupabase: { PostgrestVersion: "12" }
  public: {
    Tables: {
      patients: {
        Row: {
          created_at: string
          email: string | null
          full_name: string
          // national_id: string
          "home phone": string | null
          meta: Json | null
          status: Database["public"]["Enums"]["patient_status"]
          tags: string[] | null
          user_id: string
        }
        Insert: { email?: string | null; full_name: string }
        Update: { email?: string | null }
        Relationships: []
      }
      visits: {
        Row: {
          id: string
          notes: string | null
          patient_id: string
        }
        Insert: { id?: string }
        Update: { id?: string }
        Relationships: [
          {
            foreignKeyName: "visits_patient_id_fkey"
            columns: ["patient_id"]
            isOneToOne: false
            referencedRelation: "patients"
            referencedColumns: ["email"]
          },
        ]
      }
      countries: { Row: { city: string; country: string; id: number }; Insert: {}; Update: {}; Relationships: [] }
    }
    Views: {
      active_patients: { Row: { email: string | null }; Relationships: [] }
    }
    Functions: { [_ in never]: never }
    Enums: { patient_status: "new" | "old" }
  }
}
`;

test('generated Supabase types (type, newline separated): tables, columns, FKs with unknown delete rule, rls unknown', async () => {
  const { g, ctx } = await graphOf({
    'package.json': '{"dependencies":{"@supabase/supabase-js":"2"}}',
    'src/lib/whatever.ts': GEN_TYPES,
    'src/a.ts': "import { createClient } from '@supabase/supabase-js';\nconst db = createClient('u','k');\nexport async function add(v){ await db.from('patients').insert({ full_name: v.name, email: v.email }) }",
  });
  assert.deepEqual(cols(g, 'patients').sort(), ['created_at', 'email', 'full_name', 'home phone', 'meta', 'status', 'tags', 'user_id']);
  assert.ok(represents(g, 'patients', 'email').includes('data:email'));
  const t = g.node('store:table:patients');
  assert.equal(t.rls, null);
  assert.equal(t.source, 'supabase-types');
  const fk = edges(g, 'references', (e) => e.from === 'store:table:visits' && e.to === 'store:table:patients')[0];
  assert.equal(fk.onDelete, null);
  assert.equal(fk.onDeleteUnknown, true);
  assert.equal(fk.fkFinal, undefined);
  const acc = edges(g, 'references', (e) => e.from === 'store:table:patients' && e.to === 'store:table:auth.users')[0];
  assert.equal(acc.implicit, true);
  assert.equal(g.node('store:table:active_patients').kind, 'view');
  // reference data: no link to a person, so `city` / `country` are not location data about someone
  assert.deepEqual(represents(g, 'countries', 'city'), []);
  assert.ok(ctx.shared.supabaseTypes.get('patients').columns.includes('email'));
  assert.ok(writesTo(g, 'patients').length >= 1, 'writes are traced to the types-only table');
  assert.equal(edges(g, 'collects', (e) => JSON.stringify(e.evidence).includes('whatever.ts')).length, 0);
});

test('generated types (interface, semicolons, .d.ts, two schemas): migrations win, only missing columns are added, dropped objects stay dropped', async () => {
  const { g } = await graphOf({
    'package.json': '{"dependencies":{"@supabase/supabase-js":"2"}}',
    'supabase/migrations/1.sql': `create table members (id uuid primary key, user_id uuid references auth.users(id) on delete cascade, email text, legacy_phone text);
alter table members enable row level security;
alter table members drop column legacy_phone;
create table old_leads (id int, email text);
drop table old_leads;`,
    'types/db.d.ts': `export interface Database {
  public: {
    Tables: {
      members: { Row: { id: string; user_id: string; email: string | null; phone?: string | null; legacy_phone: string | null; }; Insert: { id: string; }; Update: { id?: string; };
        Relationships: [{ foreignKeyName: "x"; columns: ["user_id"]; referencedRelation: "users"; referencedColumns: ["id"]; }]; };
      old_leads: { Row: { id: number; email: string; }; Insert: {}; Update: {}; Relationships: []; };
    };
  };
  crm: { Tables: { contacts: { Row: { id: string; phone: string; }; Insert: {}; Update: {}; }; }; };
  auth: { Tables: { users: { Row: { id: string; email: string; }; }; }; };
}
`,
  });
  assert.deepEqual(cols(g, 'members').sort(), ['email', 'id', 'phone', 'user_id']);
  const t = g.node('store:table:members');
  assert.equal(t.rls, true);
  assert.equal(t.source, 'sql');
  assert.match(t.file, /1\.sql$/);
  assert.equal(edges(g, 'references', (e) => e.from === 'store:table:members')[0].onDelete, 'cascade');
  assert.ok(!g.has('store:table:old_leads'));
  assert.deepEqual(cols(g, 'crm.contacts').sort(), ['id', 'phone']);
});

test('Supabase types FP guards: example / fixture paths, API DTOs and zod schemas are not schemas', async () => {
  const { g } = await graphOf({
    'package.json': '{"dependencies":{"@supabase/supabase-js":"2"}}',
    'examples/demo/types.ts': GEN_TYPES,
    'src/dto.ts': "import { z } from 'zod';\nexport interface CreatePatient { email: string; phone: string }\nexport const patientSchema = z.object({ email: z.string() });\nexport type Api = { public: { Routes: { patients: { Row: { email: string } } } } };\ntype Local = { public: { Tables: { hidden: { Row: { email: string } } } } };",
    'src/a.ts': "import { createClient } from '@supabase/supabase-js';\nconst x = Array.from<CreatePatient>('patients');\nconst y = Buffer.from('abc') as CreatePatient;",
  });
  assert.deepEqual(tableKeys(g).filter((k) => k !== 'auth.users'), []);
});

test('hand-written interfaces bound by queries (generic, select generic, cast, useState, .vue)', async () => {
  const { g, ctx } = await graphOf({
    'package.json': '{"dependencies":{"@nuxtjs/supabase":"1"}}',
    'types/rows.ts': `export interface Profile {
  id: string
  username: string | null
  avatar_url?: string
  posts: Post[]
  getName(): string
}
export interface Post { id: string; author_id: string /* foreign key to profiles.id */; body: string; profiles?: Profile }
export type Booking = { id: string; guest_email: string; phone: string | null };
export interface Guest { id: string; full_name: string; email: string }
export interface Unbound { email: string; phone: string }
`,
    'pages/index.vue': `<script setup lang="ts">
const client = useSupabaseClient()
const { data } = await client.from<Profile>("profiles").select("*")
</script><template><p>don't</p></template>`,
    'src/b.ts': `import type { Booking, Post } from '../types/rows';
export async function list(supabase) {
  const { data, error } = await supabase
    .from('bookings')
    .select('*')
    .order('id');
  if (error) throw error;
  return data as Booking[];
}
export const posts = (sb) => sb.from('posts').select<'*', Post>('*');`,
    'src/c.tsx': `export function G({ supabase }) {
  const [guests, setGuests] = useState<Guest[]>([]);
  const load = async () => {
    const { data } = await supabase.from('guests').select('*');
    setGuests(data || []);
  };
  return null;
}`,
  });
  assert.deepEqual(cols(g, 'profiles').sort(), ['avatar_url', 'id', 'username']);
  assert.deepEqual(cols(g, 'bookings').sort(), ['guest_email', 'id', 'phone']);
  assert.deepEqual(cols(g, 'posts').sort(), ['author_id', 'body', 'id']);
  assert.ok(cols(g, 'guests').includes('email'));
  assert.equal(g.node('store:table:profiles').rls, null);
  const fk = edges(g, 'references', (e) => e.from === 'store:table:posts' && e.to === 'store:table:profiles')[0];
  assert.equal(fk.onDeleteUnknown, true);
  assert.ok(ctx.shared.supabaseTypes.get('profiles').handWritten);
  assert.ok(!tableKeys(g).some((k) => /unbound/i.test(k)));
});

test('hand-written interface is not used for a table the migrations know, nor when its name is ambiguous', async () => {
  const { g } = await graphOf({
    'package.json': '{"dependencies":{"@supabase/supabase-js":"2"}}',
    'supabase/migrations/1.sql': 'create table profiles (id uuid, email text);',
    'a/types.ts': 'export interface Profile { id: string; email: string; isSelected: boolean }\nexport interface Row2 { id: string; email: string }',
    'b/types.ts': 'export interface Row2 { id: string; phone: string }',
    'c.ts': "export const q = (supabase) => supabase.from<Profile>('profiles').select();\nexport const r = (supabase) => supabase.from<Row2>('things').select();",
  });
  assert.deepEqual(cols(g, 'profiles').sort(), ['email', 'id']);
  assert.ok(!g.has('store:table:things') || cols(g, 'things').length === 0);
});

test('type text helpers', () => {
  const t = blankComments('type A = {\n  a: string | null // c\n  /* b: string */\n  c?:\n    | "x"\n    | null\n  fn(x: string): void\n  d: Array<{ z: string; y: number }>, e: boolean; "f g": Json }');
  assert.deepEqual(typeMembers(t, t.indexOf('{')).map((m) => [m.name, m.optional]), [['a', false], ['c', true], ['d', false], ['e', false], ['f g', false]]);
  assert.equal(sqlTypeOf('string | null', 'email'), 'text');
  assert.equal(sqlTypeOf('"a" | "b" | null', 'x'), 'enum');
  assert.equal(sqlTypeOf('Date', 'x'), 'timestamptz');
  assert.equal(sqlTypeOf('Profile[]', 'x'), null);
  assert.equal(sqlTypeOf('Json | null', 'x'), 'jsonb');
  assert.deepEqual(queryBindings("Observable.from<Foo>('x'); sb.storage.from<Foo>('b')"), []);
});

// ---------------------------------------------------------------------------
// (3) Dart

const PUB = 'name: demo\ndependencies:\n  flutter:\n    sdk: flutter\n  cloud_firestore: ^5.0.0\n  firebase_database: ^11.0.0\n';

test('Dart: class-scoped constants do not collide, map keys through constants, dynamic sub-collection, transaction', async () => {
  const { g } = await graphOf({
    'pubspec.yaml': PUB,
    'lib/paths.dart': `class StorePaths { static const people = 'people'; static const chats = "chats"; }
class UiPaths { static const people = 'people_tab'; }
class F { static const nick = 'nickname'; static const photo = 'photoUrl'; static const from = 'idFrom'; static const to = 'idTo'; static const body = 'content'; }
enum Coll { invoices('invoices'), logs('audit_logs'); const Coll(this.path); final String path; }
const String kRoot = 'tenants';
`,
    'lib/repo.dart': `import 'package:cloud_firestore/cloud_firestore.dart';
import 'paths.dart';
class Msg {
  final String a; final String b; final String text;
  Msg(this.a, this.b, this.text);
  Map<String, dynamic> toJson() => { F.from: a, F.to: b, F.body: text };
}
class Repo {
  final FirebaseFirestore db;
  Repo(this.db);
  Future<void> save(String uid, String name) async {
    await db.collection(StorePaths.people).doc(uid).set(<String, dynamic>{ F.nick: name, if (name.isNotEmpty) F.photo: 'x', ...{'phone': name} });
  }
  void send(String room, String me, String peer, String text) {
    final ref = db.collection(StorePaths.chats).doc(room).collection(room).doc('1');
    final m = Msg(me, peer, text);
    db.runTransaction((tx) async { tx.set(ref, m.toJson()); });
  }
  Future<void> invoice(String id) => db.collection(Coll.invoices.path).doc(id).set({'email': id});
  Future<void> tenant(String t, String u) => db.collection('$kRoot/$t/users').doc(u).update({'phone': u});
}
`,
  });
  assert.deepEqual(cols(g, 'people').sort(), ['nickname', 'phone', 'photoUrl']);
  assert.ok(!g.has('store:table:people_tab'));
  const m = g.node('store:table:chats/{dynamic}');
  assert.equal(m.name, 'chats');
  assert.deepEqual(cols(g, 'chats/{dynamic}').sort(), ['content', 'idFrom', 'idTo']);
  assert.ok(represents(g, 'chats/{dynamic}', 'content').length, 'message content classifies');
  assert.ok(g.has('store:table:invoices'));
  assert.deepEqual(cols(g, 'tenants/users'), ['phone']);
});

test('Dart: wrapper methods are instantiated at call sites across files (positional, named, two levels, data map built up)', async () => {
  const { g, ctx } = await graphOf({
    'pubspec.yaml': PUB,
    'lib/c.dart': "class C { static const users = 'users'; static const orders = 'orders'; }\n",
    'lib/store_service.dart': `import 'package:cloud_firestore/cloud_firestore.dart';
class StoreService {
  final _db = FirebaseFirestore.instance;
  Future<void> patch(String coll, String id, Map<String, dynamic> data) => _db.collection(coll).doc(id).update(data);
  Future<void> put({required String path, required Map<String, dynamic> body}) async {
    body['updatedAt'] = FieldValue.serverTimestamp();
    await _db.doc(path).set(body);
  }
  Future<void> drop(String coll, String id) async { await _db.collection(coll).doc(id).delete(); }
}
`,
    'lib/user_repo.dart': `import 'store_service.dart';
import 'c.dart';
class UserRepo {
  UserRepo(this._svc);
  final StoreService _svc;
  Future<void> savePhone(String id, String phone) {
    final data = <String, dynamic>{};
    data['phoneNumber'] = phone;
    data['lastName'] = phone;
    return _svc.patch(C.users, id, data);
  }
  Future<void> forward(String id, Map<String, dynamic> payload) => _svc.patch(C.orders, id, payload);
  Future<void> remove(String id) => _svc.drop(C.users, id);
}
`,
    'lib/screen.dart': `import 'user_repo.dart';
import 'store_service.dart';
class Screen {
  late UserRepo repo;
  final StoreService service = StoreService();
  void go(String uid) {
    repo.forward(uid, {'deliveryAddress': 'x'});
    service.put(path: 'customers/$uid', body: {'email': 'a'});
  }
}
`,
    'lib/unrelated.dart': `class Painter { void patch(String a, String b, Map<String, dynamic> c) {} }
class P2 { final Painter painter; P2(this.painter); void x() { painter.patch('not_a_store', '1', {'email': 'x'}); } }
`,
  });
  assert.ok(cols(g, 'users').includes('phoneNumber') && cols(g, 'users').includes('lastName'));
  assert.ok(cols(g, 'orders').includes('deliveryAddress'));
  assert.ok(cols(g, 'customers').includes('email'));
  assert.ok(deletesOf(g, 'users').length, 'delete through the wrapper');
  assert.ok(!g.has('store:table:not_a_store'));
  assert.ok(writesTo(g, 'users').some((e) => e.from.includes('user_repo.dart#savePhone')), 'the write belongs to the caller');
  assert.equal(gap(ctx, 'dart').length, 0);
});

test('Dart: unresolved collection path creates no store and is counted in the gap; generated and test files are ignored', async () => {
  const { g, ctx } = await graphOf({
    'pubspec.yaml': PUB,
    'lib/x.dart': `import 'package:cloud_firestore/cloud_firestore.dart';
class X { Future<void> w(String c) => FirebaseFirestore.instance.collection(c).doc('1').set({'email': 'x'}); }
`,
    'lib/m.g.dart': "import 'package:cloud_firestore/cloud_firestore.dart';\nvoid f() { FirebaseFirestore.instance.collection('gen').doc('1').set({'email': 'x'}); }\n",
    'test/a_test.dart': "import 'package:cloud_firestore/cloud_firestore.dart';\nvoid f() { FirebaseFirestore.instance.collection('tst').doc('1').set({'email': 'x'}); }\n",
  });
  assert.deepEqual(tableKeys(g).filter((k) => k !== 'firebase.auth.users'), []);
  assert.equal(gap(ctx, 'dart').length, 1);
});

test('Dart: Realtime Database refs, batch cascades, references shared across files, toMap built with assignments', async () => {
  const { g } = await graphOf({
    'pubspec.yaml': PUB,
    'lib/refs.dart': "import 'package:cloud_firestore/cloud_firestore.dart';\nfinal petsRef = FirebaseFirestore.instance.collection('pets');\n",
    'lib/rt.dart': `import 'package:firebase_database/firebase_database.dart';
class Rt {
  final DatabaseReference _root = FirebaseDatabase.instance.ref();
  Future<void> a(String uid, String mail) => FirebaseDatabase.instance.ref('drivers/$uid').set({'email': mail, 'phone': mail});
  Future<void> b(String uid) => _root.child('drivers').child(uid).remove();
  Future<void> c(String room) async { await _root.child('rooms/$room/messages').push().set({'senderId': 'a', 'receiverId': 'b', 'text': 'hi'}); }
}
`,
    'lib/pet.dart': `import 'package:cloud_firestore/cloud_firestore.dart';
import 'refs.dart';
class Pet {
  String? ownerName;
  Map<String, dynamic> toMap() {
    final Map<String, dynamic> data = new Map<String, dynamic>();
    data['ownerName'] = this.ownerName;
    data['ownerPhone'] = '';
    return data;
  }
}
Future<void> add(Pet pet) => petsRef.add(pet.toMap());
Future<void> bulk(String id) async {
  final batch = FirebaseFirestore.instance.batch();
  batch
    ..set(petsRef.doc(id), {'vetEmail': 'x'})
    ..delete(FirebaseFirestore.instance.collection('old_pets').doc(id));
  await batch.commit();
}
`,
  });
  assert.equal(g.node('store:table:drivers').provider, 'firebase-rtdb');
  assert.deepEqual(cols(g, 'drivers').sort(), ['email', 'phone']);
  assert.ok(deletesOf(g, 'drivers').length);
  assert.ok(represents(g, 'rooms/messages', 'text').length, 'a message body with two participants');
  assert.deepEqual(cols(g, 'pets').sort(), ['ownerName', 'ownerPhone', 'vetEmail']);
  assert.ok(deletesOf(g, 'old_pets').length);
});

test('message records: a body and two participants', () => {
  assert.equal(isMessageRecord(['senderId', 'receiverId', 'text']), true);
  assert.equal(isMessageRecord(['authorId', 'content']), false);
  assert.equal(isMessageRecord(['from', 'to', 'price']), false);
});

// ---------------------------------------------------------------------------
// (4) Realtime Database, JS

test('rtdbKey: head of the path, sub-collections, columns', () => {
  assert.deepEqual(rtdbKey(['users', null]), { key: 'users', column: null });
  assert.deepEqual(rtdbKey(['rooms', null, 'messages'], { push: true }), { key: 'rooms/messages', column: null });
  assert.deepEqual(rtdbKey(['users', null, 'email']), { key: 'users', column: 'email' });
  assert.deepEqual(rtdbKey(['app', 'users', null]), { key: 'app/users', column: null });
  assert.equal(rtdbKey([null, null]), null);
});

test('RTDB modular: template paths, push, typed argument, fan-out update, remove, set null; layer is covered', async () => {
  const { g, ctx } = await graphOf({
    'package.json': '{"dependencies":{"firebase":"10"}}',
    'src/fb.ts': "import { getDatabase } from 'firebase/database';\nexport const db = getDatabase();",
    'src/types.ts': 'export interface Expense { id: string; userId: string; payeeName: string; iban: string }',
    'src/svc.ts': `import { ref, set, push, update, remove, get, child } from 'firebase/database';
import { db } from './fb';
import { Expense } from './types';
const ROOT = 'expenses';
export const svc = {
  async add(uid: string, data: Omit<Expense, 'id'>) {
    const r = push(ref(db, \`\${ROOT}/\${uid}\`));
    await set(r, { ...data, createdAt: Date.now() });
  },
  async contact(uid, email) { await set(ref(db, 'contacts/' + uid + '/email'), email); },
  async post(uid, body) {
    const key = push(child(ref(db), 'posts')).key;
    const updates = {};
    updates['/posts/' + key] = { authorId: uid, body };
    updates[\`/user-posts/\${uid}/\${key}\`] = { body };
    return update(ref(db), updates);
  },
  async del(uid, id) { await remove(ref(db, \`expenses/\${uid}/\${id}\`)); },
  async clear(uid) { await set(ref(db, \`contacts/\${uid}\`), null); },
  async list(uid) { return (await get(ref(db, \`expenses/\${uid}\`))).val(); },
};`,
  });
  assert.equal(g.node('store:table:expenses').provider, 'firebase-rtdb');
  assert.deepEqual(cols(g, 'expenses').sort(), ['createdAt', 'iban', 'payeeName', 'userId']);
  assert.ok(cols(g, 'contacts').includes('email'));
  assert.ok(edges(g, 'flowsTo', (e) => e.to === 'store:column:contacts.email').length);
  assert.ok(cols(g, 'posts').includes('body') && cols(g, 'user-posts').includes('body'));
  assert.equal(deletesOf(g, 'expenses').length, 1);
  assert.equal(deletesOf(g, 'contacts').length, 1);
  assert.ok(writesTo(g, 'expenses').some((e) => e.from.endsWith('svc.ts#add')));
  const stack = detectStack(ctx.files);
  const layers = assessLayers(g, ctx.files, stack);
  assert.ok(!layers.schema.gaps.some((x) => x.tech === 'firebase-rtdb'));
});

test('RTDB namespaced: v8 db.ref, Admin, React Native, child chains, helper returning a ref', async () => {
  const { g } = await graphOf({
    'package.json': '{"dependencies":{"firebase":"8","@react-native-firebase/database":"20","firebase-admin":"12"}}',
    'web.js': "import firebase from 'firebase/app';\nimport 'firebase/database';\nconst db = firebase.database();\nexport function save(uid, u) { return db.ref('accounts/' + uid).set({ email: u.email, phoneNumber: u.phone }); }\nexport const gone = (uid) => db.ref('accounts').child(uid).remove();",
    'rn.js': "import database from '@react-native-firebase/database';\nconst userRef = (id) => database().ref(`/riders/${id}`);\nexport const up = (id, x) => userRef(id).update({ fullName: x.name });\nexport const push1 = (t) => database().ref('chats').push({ from: t.a, to: t.b, message: t.c });",
    'admin.js': "const admin = require('firebase-admin');\nexports.f = async (id, e) => { await admin.database().ref('audit').child(id).set({ email: e }); };",
  });
  assert.deepEqual(cols(g, 'accounts').sort(), ['email', 'phoneNumber']);
  assert.equal(deletesOf(g, 'accounts').length, 1);
  assert.ok(cols(g, 'riders').includes('fullName'));
  assert.ok(represents(g, 'chats', 'message').length);
  assert.ok(cols(g, 'audit').includes('email'));
});

test('RTDB FP guards: Firebase Storage refs, Vue refs, Map.set and unresolved paths create no store', async () => {
  const { g, ctx } = await graphOf({
    'package.json': '{"dependencies":{"firebase":"10","vue":"3"}}',
    'a.ts': "import { ref, uploadBytes, getStorage } from 'firebase/storage';\nexport const u = (f) => uploadBytes(ref(getStorage(), 'avatars/x'), f);",
    'b.ts': "import { ref } from 'vue';\nconst m = new Map();\nconst users = ref('users');\nm.set(users, { email: 'x' });\nexport const s = firebaseApp.storage().ref('docs/1').put(1);",
    'c.ts': "import { getDatabase, ref, set } from 'firebase/database';\nexport const w = (path, email) => set(ref(getDatabase(), path), { email });",
  });
  assert.deepEqual(tableKeys(g).filter((k) => !/auth\.users/.test(k)), []);
  assert.equal(gap(ctx, 'firebase-rtdb').length, 1);
});

// ---------------------------------------------------------------------------
// (5) DDL in code

test('ClickHouse types and columns', () => {
  assert.deepEqual(clickhouseColumn('`email` LowCardinality(Nullable(String)) CODEC(ZSTD(3))'), { name: 'email', type: 'text', nullable: true, ttl: null });
  assert.equal(clickhouseColumn('INDEX idx email TYPE bloom_filter'), null);
  assert.equal(clickhouseType('DateTime64(3)'), 'timestamptz');
  assert.equal(clickhouseType('Map(String, String)'), 'jsonb');
  assert.equal(clickhouseType('SimpleAggregateFunction(max, UInt64)'), 'numeric');
  assert.equal(parseSql('SELECT a FROM clusterAllReplicas(x, y) WHERE b = 1'), null);
});

test('ClickHouse: helper-built DDL, replayed renames, TTL, materialized view, inserts and deletes, name clash with the app database', async () => {
  const { g } = await graphOf({
    'package.json': '{"dependencies":{"@clickhouse/client":"1","pg":"8"}}',
    'db/app.sql': 'create table visitors (id uuid, email text);',
    'ch/names.ts': "export const T = { hits: 'hits', visitors: 'visitors' };",
    'ch/ddl.ts': "export function createTable({ name, columns, engine = 'MergeTree()' }) { return `CREATE TABLE IF NOT EXISTS ${name} (${columns.join(',')}) ENGINE = ${engine}`; }",
    'ch/migrations/1-init.ts': `import { createTable, createMaterializedView } from '../ddl';
const common = ['\`city\` String', '\`ip\` IPv4'];
export async function up() {
  return [
    ...createTable({ name: 'hits', columns: ['\`id\` UUID', '\`visitor_email\` String CODEC(ZSTD(3))', ...common], orderBy: ['id'] }),
    ...createTable({ name: 'visitors', columns: ['\`id\` String', '\`first_name\` LowCardinality(String)', '\`phone\` Nullable(String)'], engine: 'ReplacingMergeTree(v)', ttl: 'seen + INTERVAL 90 DAY' }),
    ...createMaterializedView({ name: 'hits_mv', tableName: 'hits', query: 'SELECT visitor_email, count() FROM {hits} GROUP BY visitor_email' }),
  ];
}
export async function down() { return ['DROP TABLE hits']; }`,
    'ch/migrations/10-reorder.ts': `import { createTable, renameTable, addColumns } from '../ddl';
const NEW = 'hits_next_2024';
export async function up() {
  return [
    ...createTable({ name: NEW, columns: ['\`id\` UUID', '\`visitor_email\` String', '\`ip\` IPv6'] }),
    ...renameTable({ from: 'hits', to: 'hits_2024' }),
    ...renameTable({ from: NEW, to: 'hits' }),
    ...addColumns('hits', ['\`user_agent\` String'], false),
  ];
}`,
    'src/track.ts': `import { ch } from './client';
import { T } from '../ch/names';
export async function track(x) { await ch.insert({ table: T.hits, values: [{ visitor_email: x.email, ip: x.ip }], format: 'JSONEachRow' }); }
export async function forget(id) {
  for (const t of [T.hits, T.visitors]) await ch.command({ query: \`ALTER TABLE \${t} DELETE WHERE id = \${id}\` });
}`,
  });
  assert.deepEqual(cols(g, 'hits').sort(), ['id', 'ip', 'user_agent', 'visitor_email']);
  assert.ok(!tableKeys(g).some((k) => /hits_next|hits_2024/.test(k)), tableKeys(g).join());
  assert.deepEqual(cols(g, 'clickhouse.visitors').sort(), ['first_name', 'id', 'phone']);
  assert.deepEqual(cols(g, 'visitors').sort(), ['email', 'id'], 'the application table is untouched');
  assert.equal(g.node('store:table:clickhouse.visitors').provider, 'clickhouse');
  assert.match(g.node('store:table:clickhouse.visitors').engine, /ReplacingMergeTree/);
  const mv = g.node('store:table:hits_mv');
  assert.equal(mv.kind, 'view');
  assert.equal(mv.derived, true);
  const ttl = g.nodesOf('Control', (n) => n.kind === 'retention-job');
  assert.match(ttl[0].expression, /90 DAY/);
  assert.ok(writesTo(g, 'hits').some((e) => e.op === 'insert'));
  assert.ok(edges(g, 'flowsTo', (e) => e.to === 'store:column:hits.visitor_email').length);
  assert.ok(deletesOf(g, 'hits').length && deletesOf(g, 'clickhouse.visitors').length);
});

test('ClickHouse: statements in template literals and Python strings, ON CLUSTER, distributed wrapper, column TTL not a table TTL', async () => {
  const { g } = await graphOf({
    'setup.js': "const stmts = [`CREATE TABLE IF NOT EXISTS sessions_local ON CLUSTER '{cluster}' (\n  session_id String,\n  user_email String,\n  started DateTime64(3)\n) ENGINE = ReplicatedMergeTree('/x','{replica}')\nORDER BY session_id\nTTL toDateTime(started) + INTERVAL 1 YEAR`, `CREATE TABLE sessions ON CLUSTER '{cluster}' AS sessions_local ENGINE = Distributed('c', currentDatabase(), sessions_local)`];\nmodule.exports = stmts;",
    'ddl.py': "DDL = \"\"\"\nCREATE TABLE leads (\n    id UUID,\n    phone LowCardinality(String)\n) ENGINE = MergeTree() ORDER BY id\n\"\"\"\n",
  });
  assert.deepEqual(cols(g, 'sessions').sort(), ['session_id', 'started', 'user_email']);
  assert.ok(!g.has('store:table:sessions_local'));
  assert.deepEqual(cols(g, 'leads').sort(), ['id', 'phone']);
  assert.ok(edges(g, 'expires', (e) => e.to === 'store:table:sessions').length === 1);
});

test('inline DDL: placeholder names create nothing, swap tables replay, rollback functions are ignored, Python raw SQL writes', async () => {
  const { g } = await graphOf({
    'package.json': '{"dependencies":{"better-sqlite3":"9"}}',
    'a.js': "const TABLE = 'customers';\nexport function up(db, name, defs) {\n  db.exec(`CREATE TABLE IF NOT EXISTS ${name} (${defs})`);\n  db.exec(`CREATE TABLE ${TABLE} (id INTEGER PRIMARY KEY, email TEXT)`);\n  db.exec('CREATE TABLE customers_new (id INTEGER, email TEXT, phone TEXT)');\n  db.exec('INSERT INTO customers_new SELECT id, email, null FROM customers');\n  db.exec('DROP TABLE customers');\n  db.exec('ALTER TABLE customers_new RENAME TO customers');\n}\nexport function down(db) { db.exec('DROP TABLE customers'); }",
    'app/store.py': `import sqlite3
def init(c):
    c.execute("""CREATE TABLE IF NOT EXISTS signups (
        id INTEGER PRIMARY KEY,
        email TEXT NOT NULL,
        phone TEXT
    )""")
    c.execute(f"CREATE TABLE {name} (id int, email text)")

def add(c, email, phone):
    c.execute("INSERT INTO signups (email, phone) "
              "VALUES (?, ?)", (email, phone))

def forget(c, email):
    c.execute('DELETE FROM signups WHERE email = ?', (email,))
`,
  });
  assert.deepEqual(cols(g, 'customers').sort(), ['email', 'id', 'phone']);
  assert.ok(!tableKeys(g).some((k) => k === 'x' || /_new$|__P|name/.test(k)), tableKeys(g).join());
  assert.deepEqual(cols(g, 'signups').sort(), ['email', 'id', 'phone']);
  assert.ok(writesTo(g, 'signups').some((e) => e.from.endsWith('store.py#add')));
  assert.ok(edges(g, 'flowsTo', (e) => e.to === 'store:column:signups.email').length);
  assert.ok(deletesOf(g, 'signups').length);
  assert.equal(pythonStrings('a = "x" # "y"\nb = f"z{q}"')[1].text.trim(), 'z__P0__');
});

test('helper-built DDL guard: a UI table with `columns` is not a data store', async () => {
  const { g } = await graphOf({
    'package.json': '{"dependencies":{"@clickhouse/client":"1"}}',
    'ui.tsx': "import { createTable } from './grid';\nexport const t = createTable({ name: 'users', columns: ['Email', 'Full name', 'Phone'] });\nexport const u = createDataTable({ name: 'people', columns: [{ name: 'email', header: 'Email' }] });",
  });
  assert.deepEqual(tableKeys(g), []);
});

// ---------------------------------------------------------------------------
// (6) SQLModel / SQLAlchemy

const SQLM = {
  'requirements.txt': 'fastapi\nsqlmodel\n',
  'app/models.py': `import uuid
from datetime import datetime
from pydantic import EmailStr
from sqlmodel import Field, Relationship, SQLModel


class MemberBase(SQLModel):
    """Shared."""
    email: EmailStr = Field(unique=True, max_length=255)
    full_name: str | None = Field(default=None)


class MemberCreate(MemberBase):
    password: str = Field(min_length=8)


class MemberUpdate(SQLModel):
    phone: str | None = None


class Member(MemberBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    hashed_password: str
    phone: str | None = None
    notes: list["Note"] = Relationship(back_populates="owner", cascade_delete=True)


class Note(SQLModel, table=True):
    __tablename__ = "member_notes"
    id: int | None = Field(default=None, primary_key=True)
    body: str
    owner_id: uuid.UUID = Field(foreign_key="member.id", nullable=False, ondelete="CASCADE")
    owner: Member | None = Relationship(back_populates="notes")


class MemberPublic(MemberBase):
    id: uuid.UUID
`,
};

test('SQLModel: tables with inherited fields, FK delete rule, no relation columns, DTOs are not tables', async () => {
  const { g } = await graphOf(SQLM);
  assert.deepEqual(cols(g, 'member').sort(), ['email', 'full_name', 'hashed_password', 'id', 'phone']);
  assert.deepEqual(cols(g, 'member_notes').sort(), ['body', 'id', 'owner_id']);
  assert.equal(edges(g, 'references', (e) => e.from === 'store:table:member_notes' && e.to === 'store:table:member')[0].onDelete, 'cascade');
  assert.ok(!tableKeys(g).some((k) => /create|update|public|base/i.test(k)));
});

test('SQLModel / FastAPI: model_validate, sqlmodel_update, session.delete, delete(Model) → writes, flows, deletion flows with their endpoint', async () => {
  const { g, ctx } = await graphOf({
    ...SQLM,
    'app/crud.py': `from sqlmodel import Session, select
from app.models import Member, MemberCreate, MemberUpdate

def create_member(*, session: Session, data: MemberCreate) -> Member:
    obj = Member.model_validate(
        data, update={"hashed_password": get_hash(data.password)}
    )
    session.add(obj)
    session.commit()
    return obj

def update_member(*, session: Session, db_obj: Member, data: MemberUpdate):
    values = data.model_dump(exclude_unset=True)
    db_obj.sqlmodel_update(values)
    session.add(db_obj)
    session.commit()
`,
    'app/routes.py': `from typing import Annotated
from fastapi import APIRouter, Depends
from sqlmodel import Session, delete, select
from app.models import Member, Note
CurrentMember = Annotated[Member, Depends(get_current)]
router = APIRouter(prefix="/members")

@router.delete("/me")
def erase_me(session: SessionDep, me: CurrentMember):
    session.exec(delete(Note).where(Note.owner_id == me.id))
    session.delete(me)
    session.commit()

class Thing:
    pass

def other(session):
    t = Thing()
    session.delete(t)
    session.add(t)
    session.commit()
`,
    'app/main.py': 'from fastapi import FastAPI\nfrom app.routes import router\napp = FastAPI()\napp.include_router(router)\n',
  });
  assert.ok(writesTo(g, 'member').some((e) => e.from.endsWith('crud.py#create_member') && e.op === 'create'));
  assert.ok(writesTo(g, 'member').some((e) => e.from.endsWith('crud.py#update_member') && e.op === 'update'));
  assert.ok(edges(g, 'flowsTo', (e) => e.to === 'store:column:member.email').length);
  assert.ok(edges(g, 'flowsTo', (e) => e.to === 'store:column:member.phone').length);
  assert.ok(edges(g, 'flowsTo', (e) => e.to === 'store:column:member.hashed_password').every((e) => e.transformed === 'hash'));
  const ctl = deletesOf(g, 'member').map((e) => g.node(e.from));
  assert.equal(ctl.length, 1);
  assert.match(String(ctl[0].endpoint), /DELETE .*\/me/);
  assert.ok(deletesOf(g, 'member_notes').some((e) => e.from === ctl[0].id));
  assert.ok(!writesTo(g, 'member').some((e) => e.from.endsWith('#other')), 'an unmapped object is ignored');
  const layers = assessLayers(g, ctx.files, detectStack(ctx.files));
  assert.equal(layers.dbWrites.status, 'found');
});

test('SQLAlchemy session style: Model(**dto.dict()), setattr loop, db.delete(query result), helper reached from a route', async () => {
  const { g } = await graphOf({
    'requirements.txt': 'fastapi\nsqlalchemy\n',
    'models.py': `from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base
Base = declarative_base()
class Contact(Base):
    __tablename__ = "contacts"
    id = Column(Integer, primary_key=True)
    email = Column(String)
    phone = Column(String)
`,
    'schemas.py': 'from pydantic import BaseModel\nclass ContactIn(BaseModel):\n    email: str\n    phone: str | None = None\n',
    'service.py': `from sqlalchemy.orm import Session
from models import Contact
from schemas import ContactIn

def create(db: Session, payload: ContactIn):
    row = Contact(**payload.dict())
    db.add(row)
    db.commit()

def edit(db: Session, cid: int, payload: ContactIn):
    row = db.query(Contact).filter(Contact.id == cid).first()
    for k, v in payload.dict().items():
        setattr(row, k, v)
    db.commit()

def remove_contact(db: Session, cid: int):
    row = db.query(Contact).filter(Contact.id == cid).first()
    db.delete(row)
    db.commit()
`,
    'main.py': `from fastapi import FastAPI, Depends
import service
app = FastAPI()

@app.delete("/contacts/{cid}")
def del_contact(cid: int, db=Depends(get_db)):
    service.remove_contact(db, cid)
`,
  });
  assert.ok(writesTo(g, 'contacts').some((e) => e.from.endsWith('#create')));
  assert.ok(edges(g, 'flowsTo', (e) => e.to === 'store:column:contacts.phone').length);
  assert.ok(writesTo(g, 'contacts').some((e) => e.from.endsWith('#edit')));
  const ctl = deletesOf(g, 'contacts').map((e) => g.node(e.from));
  assert.ok(ctl.some((c) => /DELETE \/contacts/.test(String(c.endpoint))), JSON.stringify(ctl));
});

test('SQLModel: a raw password stored in a *_hash column is not marked as hashed', async () => {
  const { g } = await graphOf({
    ...SQLM,
    'app/bad.py': 'from sqlmodel import Session\nfrom app.models import Member\n\ndef make(session: Session, payload):\n    m = Member(email=payload.email, hashed_password=payload.password)\n    session.add(m)\n    session.commit()\n',
  });
  assert.ok(edges(g, 'flowsTo', (e) => e.to === 'store:column:member.hashed_password').some((e) => !e.transformed));
});
