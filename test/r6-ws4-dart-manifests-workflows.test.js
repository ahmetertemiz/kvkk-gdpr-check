// R6 WS4: non-JS artefacts produce facts — Dart / Flutter data access (Firestore, FirebaseAuth, Firebase Storage,
// supabase_flutter), non-npm manifests (pubspec, Podfile, Gradle, Cargo), Firebase platform config files and
// workflow-automation exports (n8n, Make). All fixtures are synthetic; credential-looking values are generated at runtime.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';
import { lexDart } from '../src/audit/extract/dart.js';
import { pubspecPackages, podfilePackages, gradlePackages, cargoPackages, redactSecrets } from '../src/audit/extract/endpoints-ext.js';
import { vendorForEcosystemPackage, vendorForWorkflowNode } from '../src/data/ecosystems.js';
import { vendorById } from '../src/data/vendors.js';

async function graphOf(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r6-ws4-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  const { graph, ctx } = await buildGraph(root);
  return { g: graph, ctx };
}
const edges = (g, type, pred = () => true) => g.edges.filter((e) => e.type === type && pred(e));
const cols = (g, key) => edges(g, 'hasColumn', (e) => e.from === `store:table:${key}`).map((e) => e.to.split('.').pop());
const FAKE_KEY = 'AIza' + 'Q'.repeat(35);

const PUBSPEC = `name: demo_app
environment:
  sdk: ">=3.0.0 <4.0.0"
dependencies:
  flutter:
    sdk: flutter
  cloud_firestore: ^4.8.1
  firebase_auth: ^4.6.3
  firebase_storage: ^11.2.3
  # sentry_flutter: ^7.0.0
dev_dependencies:
  sentry_flutter: ^7.0.0
  flutter_test:
    sdk: flutter
`;

// ---------------------------------------------------------------------------
// (1) Dart Firestore — repository style (different from a field + toJson style): constants class, typed
// CollectionReference held in a field, toMap() with a block body, WriteBatch delete, withConverter.

const CONSTS = `class Collections {
  static const String members = 'members';
  static const String orders = 'orders';
}
`;
const MEMBER = `class Member {
  final String id;
  final String emailAddress;
  final String phoneNumber;
  final String displayName;
  Member({required this.id, required this.emailAddress, required this.phoneNumber, required this.displayName});

  Map<String, dynamic> toMap() {
    return {
      'email': emailAddress,
      'phone_number': phoneNumber,
      'display_name': displayName,
    };
  }

  factory Member.fromMap(Map<String, dynamic> map) => Member(
        id: map['id'],
        emailAddress: map['email'],
        phoneNumber: map['phone_number'],
        displayName: map['display_name'],
      );
}
`;
const ORDER = `import 'package:json_annotation/json_annotation.dart';
@JsonSerializable()
class Order {
  final String id;
  @JsonKey(name: 'shipping_address')
  final String address;
  final double total;
  Order(this.id, this.address, this.total);
  Map<String, dynamic> toJson() => _$OrderToJson(this);
}
`;
const REPO = `import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import '../models/member.dart';
import '../models/order.dart';
import '../constants.dart';

class MemberRepository {
  MemberRepository(this.db);
  final FirebaseFirestore db;
  late final CollectionReference<Map<String, dynamic>> _members = db.collection(Collections.members);

  Future<void> save(Member member) async {
    await _members.doc(member.id).set(member.toMap(), SetOptions(merge: true));
  }

  Future<void> placeOrder(String uid, Order order) {
    return db.collection(Collections.members).doc(uid).collection(Collections.orders).add(order.toJson());
  }

  Future<void> eraseAccount(String uid) async {
    final batch = db.batch();
    batch.delete(_members.doc(uid));
    await batch.commit();
    await FirebaseAuth.instance.currentUser?.delete();
  }

  Future<Member> load(String uid) async {
    final snap = await _members.doc(uid).get();
    return Member.fromMap(snap.data()!);
  }

  Future<void> logWithVariable(String name, Map<String, dynamic> m) async {
    await db.collection(name).add(m);
  }
}
`;

test('Dart Firestore (repository style): collections, columns from toMap / json_serializable, writes, deletes, unparsed', async () => {
  const { g, ctx } = await graphOf({ 'pubspec.yaml': PUBSPEC, 'lib/constants.dart': CONSTS, 'lib/models/member.dart': MEMBER, 'lib/models/order.dart': ORDER, 'lib/data/member_repository.dart': REPO });
  const members = g.node('store:table:members');
  assert.ok(members, 'members collection store');
  assert.equal(members.kind, 'collection');
  assert.equal(members.provider, 'firestore');
  assert.deepEqual(cols(g, 'members').sort(), ['display_name', 'email', 'id', 'phone_number'], 'toMap keys plus the id the fromMap factory reads');
  assert.ok(g.node('data:email'), 'email element from toMap');
  assert.ok(g.node('store:table:members/orders'), 'subcollection');
  assert.ok(cols(g, 'members/orders').includes('shipping_address'), 'json_serializable @JsonKey name');
  // C1 writes edges from the enclosing function
  const w = edges(g, 'writes', (e) => e.to === 'store:table:members');
  assert.ok(w.some((e) => e.from === 'consumer:lib/data/member_repository.dart#save' && e.op === 'set'));
  assert.ok(edges(g, 'flowsTo', (e) => e.from === 'data:email' && e.to === 'store:column:members.email').length);
  // batch.delete + currentUser.delete() → deletion flows
  const del = g.node('control:deletion-flow:lib/data/member_repository.dart#eraseAccount');
  assert.ok(del, 'deletion flow');
  const targets = edges(g, 'deletes', (e) => e.from === del.id).map((e) => e.to);
  assert.ok(targets.includes('store:table:members'));
  assert.ok(targets.includes('store:table:firebase.auth.users'));
  assert.equal(del.accountDeletion, true);
  // collection(name) with a runtime name → C2 unparsed entry
  assert.ok((ctx.shared.unparsed || []).some((u) => u.kind === 'dart' && u.layer === 'dbWrites' && u.files.includes('lib/data/member_repository.dart')));
  // pubspec → firebase sink; dev dependency (sentry) ignored
  assert.ok(g.node('sink:vendor:firebase'));
  assert.ok(!g.node('sink:vendor:sentry'), 'dev_dependencies are not shipped');
});

// (2) the motivating style: Firestore handle in a field, model toJson with arrow map, createUser + TextEditingController
const USER_MODEL = `class AppUser {
  final String email;
  final String uid;
  final String nickname;
  const AppUser({required this.email, required this.uid, required this.nickname});
  Map<String, dynamic> toJson() => {"email": email, "uid": uid, "nickname": nickname};
}
`;
const AUTH = `import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'app_user.dart';
class AuthService {
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  final FirebaseAuth _auth = FirebaseAuth.instance;
  Future<void> register({required String email, required String password, required String nickname}) async {
    UserCredential cred = await _auth.createUserWithEmailAndPassword(email: email, password: password);
    AppUser user = AppUser(email: email, uid: cred.user!.uid, nickname: nickname);
    await _firestore.collection("accounts").doc(cred.user!.uid).set(user.toJson());
  }
}
`;
const SCREEN = `import 'package:flutter/material.dart';
class RegisterScreen extends StatefulWidget { const RegisterScreen({super.key}); }
class _RegisterScreenState extends State<RegisterScreen> {
  final TextEditingController _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _searchController = TextEditingController();
  void submit() { AuthService().register(email: _emailController.text, password: _passwordController.text, nickname: 'x'); }
}
`;

test('Dart Firestore (field + toJson) with FirebaseAuth sign-up and TextEditingController sources', async () => {
  const { g } = await graphOf({ 'pubspec.yaml': PUBSPEC, 'lib/app_user.dart': USER_MODEL, 'lib/auth_service.dart': AUTH, 'lib/register_screen.dart': SCREEN });
  assert.deepEqual(cols(g, 'accounts').sort(), ['email', 'nickname', 'uid']);
  const auth = g.node('store:table:firebase.auth.users');
  assert.ok(auth && auth.managed === 'firebase');
  assert.ok(edges(g, 'flowsTo', (e) => e.from === 'data:email' && e.to === 'store:table:firebase.auth.users').length);
  assert.ok(edges(g, 'flowsTo', (e) => e.from === 'data:password' && e.to === 'sink:vendor:firebase').length);
  const src = g.node('source:form:register_screen');
  assert.ok(src, 'form source from controllers');
  const collected = edges(g, 'collects', (e) => e.from === src.id).map((e) => e.to);
  assert.ok(collected.includes('data:email') && collected.includes('data:password'));
});

// (3) Firebase Storage + supabase_flutter
const STORAGE = `import 'dart:io';
import 'package:firebase_storage/firebase_storage.dart';
import 'package:firebase_auth/firebase_auth.dart';
Future<String> uploadAvatar(File avatar) async {
  final uid = FirebaseAuth.instance.currentUser!.uid;
  final ref = FirebaseStorage.instance.ref().child('avatars').child(uid);
  await ref.putFile(avatar);
  return ref.getDownloadURL();
}
Future<void> removeAvatar(String url) => FirebaseStorage.instance.refFromURL(url).delete();
`;
const SUPA = `import 'package:supabase_flutter/supabase_flutter.dart';
final supabase = Supabase.instance.client;
Future<void> saveProfile(String email, String fullName) async {
  await supabase.from('profiles').upsert({'email': email, 'full_name': fullName});
}
Future<void> dropProfile(String id) async {
  await supabase.from('profiles').delete().eq('id', id);
}
`;

test('Firebase Storage uploads / deletes and supabase_flutter table writes', async () => {
  const { g } = await graphOf({
    'pubspec.yaml': 'name: x\ndependencies:\n  firebase_storage: ^11.0.0\n  supabase_flutter: ^2.0.0\n',
    'lib/storage.dart': STORAGE,
    'lib/profile.dart': SUPA,
  });
  const b = g.node('store:bucket:firebase-storage');
  assert.ok(b && b.userLinkedKey, 'user-linked bucket path');
  assert.ok(edges(g, 'flowsTo', (e) => e.to === b.id && e.from === 'data:photo').length, 'avatar upload is a photo');
  assert.ok(edges(g, 'deletes', (e) => e.to === b.id).length, 'refFromURL().delete()');
  assert.deepEqual(cols(g, 'profiles').sort(), ['email', 'full_name']);
  assert.ok(edges(g, 'deletes', (e) => e.to === 'store:table:profiles' && e.from.endsWith('#dropProfile')).length);
  assert.ok(g.node('sink:vendor:supabase'));
});

test('lexDart blanks comments and string contents without moving offsets', () => {
  const src = "var a = 'x(y'; // c(\n/* (\n */ var b = r'''q)''';";
  const { code, mask } = lexDart(src);
  assert.equal(code.length, src.length);
  assert.equal(mask.length, src.length);
  assert.ok(!mask.includes('('));
  assert.ok(code.includes("'x(y'"));
  assert.ok(!code.includes('// c'));
});

// ---------------------------------------------------------------------------
// (4) manifests for all ecosystems

test('manifest parsers: pubspec / Podfile / Gradle / Cargo', () => {
  assert.deepEqual(pubspecPackages(PUBSPEC).map((p) => p.name), ['cloud_firestore', 'firebase_auth', 'firebase_storage']);
  const pods = podfilePackages(`platform :ios, '13.0'
target 'Shop' do
  use_frameworks!
  pod 'Firebase/Auth'
  pod 'Google-Mobile-Ads-SDK', '~> 10.0'
  target 'ShopTests' do
    inherit! :search_paths
    pod 'Sentry'
  end
end
`).map((p) => p.name);
  assert.deepEqual(pods, ['Firebase/Auth', 'Google-Mobile-Ads-SDK']);
  const gradle = gradlePackages(`plugins {
    id("com.android.application")
    id("com.google.gms.google-services")
}
dependencies {
    implementation(platform("com.google.firebase:firebase-bom:33.0.0"))
    implementation("com.google.firebase:firebase-firestore")
    implementation 'io.sentry:sentry-android:7.0.0'
    testImplementation("com.mixpanel.android:mixpanel-android:7.0.0")
    // implementation("com.amplitude:analytics-android:1.0.0")
}
`);
  const names = gradle.map((p) => p.name);
  assert.ok(names.includes('com.google.firebase:firebase-bom') && names.includes('io.sentry:sentry-android') && names.includes('com.google.gms.google-services'));
  assert.ok(!names.some((n) => /mixpanel|amplitude/.test(n)));
  assert.deepEqual(cargoPackages(`[package]\nname = "svc"\n[dependencies]\nasync-openai = "0.20"\nserde = { version = "1" }\n[dev-dependencies]\nsentry = "0.32"\n`).map((p) => p.name), ['async-openai', 'serde']);
  assert.equal(vendorForEcosystemPackage('Google-Mobile-Ads-SDK', 'cocoapods', vendorById)?.vendor.id, 'admob');
  assert.equal(vendorForEcosystemPackage('com.google.gms.google-services', 'gradle-plugin', vendorById)?.vendor.id, 'firebase');
  assert.equal(vendorForEcosystemPackage('flutter_svg', 'pub', vendorById), null);
});

test('native Android / iOS manifests become vendor sinks (no Dart code)', async () => {
  const { g } = await graphOf({
    'app/build.gradle.kts': 'plugins { id("com.android.application") }\ndependencies {\n  implementation("io.sentry:sentry-android:7.0.0")\n  implementation("com.google.android.gms:play-services-ads:22.0.0")\n}\n',
    'ios/Podfile': "target 'App' do\n  pod 'Mixpanel-swift'\nend\n",
    'svc/Cargo.toml': '[dependencies]\nasync-openai = "0.20"\n',
  });
  for (const id of ['sentry', 'admob', 'mixpanel', 'openai']) assert.ok(g.node(`sink:vendor:${id}`), id);
  assert.equal(g.node('sink:vendor:sentry').channel, 'manifest');
});

// ---------------------------------------------------------------------------
// (5) platform config

const GSERVICES = JSON.stringify({
  project_info: { project_number: '1', firebase_url: 'https://demo-default-rtdb.europe-west1.firebasedatabase.app', project_id: 'demo', storage_bucket: 'demo.appspot.com' },
  client: [{ client_info: { mobilesdk_app_id: '1:1:android:1' }, api_key: [{ current_key: FAKE_KEY }] }],
}, null, 2);

test('google-services.json / GoogleService-Info.plist → Firebase sink with region, never the key', async () => {
  const plist = `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>\n<key>API_KEY</key>\n<string>${FAKE_KEY}</string>\n<key>PROJECT_ID</key>\n<string>demo</string>\n</dict></plist>\n`;
  const { g } = await graphOf({ 'android/app/google-services.json': GSERVICES, 'ios/Runner/GoogleService-Info.plist': plist, 'lib/main.dart': 'void main() {}\n' });
  const s = g.node('sink:vendor:firebase');
  assert.ok(s, 'firebase sink from platform config');
  assert.equal(s.region, 'europe-west1');
  assert.equal(s.regionCountry, 'EU');
  const files = s.evidence.map((e) => e.file);
  assert.ok(files.includes('android/app/google-services.json') && files.includes('ios/Runner/GoogleService-Info.plist'));
  assert.ok(!JSON.stringify(g.toJSON()).includes(FAKE_KEY), 'key value never copied');
  assert.ok(s.evidence.some((e) => /AIza_\[REDACTED\]/.test(e.snippet || '')));
});

test('google-services.json alone does not make Firebase the backend of a Supabase app', async () => {
  const { g } = await graphOf({
    'pubspec.yaml': 'name: x\ndependencies:\n  supabase_flutter: ^2.0.0\n  firebase_messaging: ^14.0.0\n',
    'lib/db.dart': "import 'package:supabase_flutter/supabase_flutter.dart';\nfinal supabase = Supabase.instance.client;\nFuture<void> save(String email) => supabase.from('people').insert({'email': email});\n",
    'android/app/google-services.json': GSERVICES,
  });
  assert.ok(g.node('sink:vendor:supabase'));
  assert.ok(!g.node('sink:vendor:firebase'));
});

test('firebase.json with hosting only adds nothing; with firestore it is evidence', async () => {
  const a = await graphOf({ 'firebase.json': JSON.stringify({ hosting: { public: 'dist' } }), 'index.html': '<p>hi</p>' });
  assert.ok(!a.g.node('sink:vendor:firebase'));
  const b = await graphOf({ 'firebase.json': JSON.stringify({ firestore: { rules: 'firestore.rules', location: 'eur3' } }), 'index.html': '<p>hi</p>' });
  const s = b.g.node('sink:vendor:firebase');
  assert.ok(s);
  assert.equal(s.regionCountry, 'EU');
});

// ---------------------------------------------------------------------------
// (6) workflow exports

const N8N = {
  name: 'Support triage',
  nodes: [
    { id: '1', name: 'Incoming ticket', type: 'n8n-nodes-base.webhook', parameters: { path: 'ticket' }, credentials: {} },
    { id: '2', name: 'Summarise', type: '@n8n/n8n-nodes-langchain.chainLlm', parameters: { text: '={{ $json.body.message }} from {{ $json.body.customer_email }}' } },
    { id: '3', name: 'Claude', type: '@n8n/n8n-nodes-langchain.lmChatAnthropic', parameters: { model: 'claude-x' }, credentials: { anthropicApi: { id: 'c1', name: 'acct' } } },
    { id: '4', name: 'Translate', type: 'n8n-nodes-base.httpRequest', parameters: { url: `=https://generativelanguage.googleapis.com/v1beta/models/m:generateContent?key=${FAKE_KEY}` } },
    { id: '5', name: 'Mystery', type: 'n8n-nodes-acme.superSync', parameters: {} },
    { id: '6', name: 'Note', type: 'n8n-nodes-base.stickyNote', parameters: { content: 'see https://api.openai.com' } },
  ],
  connections: {
    'Incoming ticket': { main: [[{ node: 'Summarise', type: 'main', index: 0 }]] },
    Claude: { ai_languageModel: [[{ node: 'Summarise', type: 'ai_languageModel', index: 0 }]] },
    Summarise: { main: [[{ node: 'Translate', type: 'main', index: 0 }]] },
  },
};

test('n8n export: LLM sub-node, HTTP Request to a vendor host, unknown node type → unparsed, secrets redacted', async () => {
  const { g, ctx } = await graphOf({ 'automation/triage.json': JSON.stringify(N8N, null, 2), 'index.html': '<p>x</p>' });
  const a = g.node('sink:vendor:anthropic');
  assert.ok(a, 'anthropic from lmChatAnthropic');
  assert.equal(a.channel, 'server');
  assert.equal(a.via, 'workflow-export');
  assert.ok(a.evidence.some((e) => e.file === "automation/triage.json" && /"Claude"/.test(e.snippet)), JSON.stringify(a.evidence));
  // the parent chain's prompt reads the request's e-mail and the message text
  assert.ok(edges(g, 'flowsTo', (e) => e.to === a.id && e.from === 'data:email').length);
  assert.ok(edges(g, 'flowsTo', (e) => e.to === a.id && e.from === 'data:free_text').length);
  const gem = g.node('sink:vendor:gemini');
  assert.ok(gem, 'gemini from the HTTP Request URL');
  assert.ok(!JSON.stringify(g.toJSON()).includes(FAKE_KEY), 'query-string key not copied');
  assert.ok(!g.node('sink:vendor:openai'), 'sticky notes are not nodes that send data');
  const u = (ctx.shared.unparsed || []).find((x) => x.kind === 'workflow-export');
  assert.ok(u && u.nodeTypes.includes('n8n-nodes-acme.superSync'));
});

test('Make blueprint: AI module and HTTP module', async () => {
  const bp = { name: 'Lead flow', flow: [{ id: 1, module: 'gateway:CustomWebHook', mapper: {} }, { id: 2, module: 'openai-gpt-3:CreateCompletion', mapper: { prompt: '{{1.body}}' } }, { id: 3, module: 'http:ActionSendData', mapper: { url: 'https://api.anthropic.com/v1/messages' } }], metadata: { version: 1 } };
  const { g } = await graphOf({ 'make/lead.blueprint.json': JSON.stringify(bp), 'index.html': '<p>x</p>' });
  assert.ok(g.node('sink:vendor:openai'));
  assert.ok(g.node('sink:vendor:anthropic'));
});

test('workflow node / credential tables and secret redaction', () => {
  assert.equal(vendorForWorkflowNode('@n8n/n8n-nodes-langchain.lmChatGoogleGemini', vendorById)?.id, 'gemini');
  assert.equal(vendorForWorkflowNode('@n8n/n8n-nodes-langchain.embeddingsOpenAi', vendorById)?.id, 'openai');
  assert.equal(vendorForWorkflowNode('n8n-nodes-base.set', vendorById), null);
  assert.equal(redactSecrets(`x ${FAKE_KEY} y`), 'x AIza_[REDACTED] y');
});

test('a plain JSON file with nodes/connections that is not n8n is ignored', async () => {
  const { g } = await graphOf({ 'graph.json': JSON.stringify({ nodes: [{ type: 'circle' }], connections: {} }), 'index.html': '<p>x</p>' });
  assert.equal(g.nodesOf('Sink', (n) => n.kind === 'vendor').length, 0);
});
