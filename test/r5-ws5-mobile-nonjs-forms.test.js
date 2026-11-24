// R5 WS5: mobile / BaaS / PHP coverage — input wrapper components at the call site, Appwrite + PocketBase stores,
// Laravel migrations / Eloquent / enum health values / deletes, Firestore whole-profile copies, Expo push tokens and
// declared-but-unused camera permissions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';
import { collectionNameFrom } from '../src/audit/extract/appwrite.js';
import { parseMigrations, parseEnums } from '../src/audit/extract/laravel.js';

async function graphOf(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r5-ws5-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  const { graph, warnings } = await buildGraph(root);
  return { g: graph, warnings };
}
const edges = (g, type, pred = () => true) => g.edges.filter((e) => e.type === type && pred(e));
const represents = (g, col) => edges(g, 'represents', (e) => e.from === `store:column:${col}`).map((e) => e.to.replace(/^data:/, ''));
const collected = (g, src) => edges(g, 'collects', (e) => e.from === src).map((e) => e.to.replace(/^data:/, ''));

const RN_PKG = JSON.stringify({ name: 'app', dependencies: { expo: '50', 'react-native': '0.73', react: '18' } });

// ---------------------------------------------------------------------------
// (1) forms: wrapper components resolved at the call site

const FORM_FIELD = `import { View, Text, TextInput } from "react-native";
const FormField = ({ title, value, placeholder, handleChangeText, ...props }) => (
  <View><Text>{title}</Text><TextInput value={value} placeholder={placeholder} onChangeText={handleChangeText} {...props} /></View>
);
export default FormField;
`;
const SIGN_UP = `import { useState } from "react";
import { View, Alert } from "react-native";
import FormField from "../components/FormField";
const SignUp = () => {
  const [form, setForm] = useState({ username: "", email: "", password: "" });
  return (
    <View>
      <FormField title="Username" value={form.username} handleChangeText={(e) => setForm({ ...form, username: e })} />
      <FormField title="Email" value={form.email} handleChangeText={(e) => setForm({ ...form, email: e })} keyboardType="email-address" />
    </View>
  );
};
export default SignUp;
`;

test('forms: project wrapper input at the call site names the bound state field (RN)', async () => {
  const { g } = await graphOf({ 'package.json': RN_PKG, 'components/FormField.jsx': FORM_FIELD, 'app/sign-up.jsx': SIGN_UP });
  const src = g.nodesOf('Source', (n) => n.kind === 'form' && n.file === 'app/sign-up.jsx');
  assert.equal(src.length, 1, 'call-site form recorded');
  const els = collected(g, src[0].id);
  assert.ok(els.includes('email'), `email collected: ${els}`);
  assert.ok(els.includes('username'), `username collected: ${els}`);
});

test('forms: a third-party component with a change prop is not a wrapper input', async () => {
  const { g } = await graphOf({
    'package.json': RN_PKG,
    'app/x.jsx': `import { View } from "react-native";\nimport { Slider } from "some-ui-lib";\nexport default function X({ s, setEmail }) { return <View><Slider value={s.email} onValueChange={setEmail} /></View>; }\n`,
  });
  assert.equal(g.nodesOf('Source', (n) => n.kind === 'form' && n.file === 'app/x.jsx').length, 0);
});

test('forms: web wrapper inside <form> named by its bound value', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'w', dependencies: { react: '18' } }),
    'src/Signup.jsx': `export default function Signup({ form, setForm }) {\n  return <form onSubmit={() => {}}>\n    <TextField label="Phone" value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} />\n  </form>;\n}\n`,
  });
  const src = g.nodesOf('Source', (n) => n.kind === 'form' && n.file === 'src/Signup.jsx');
  assert.equal(src.length, 1);
  assert.ok(collected(g, src[0].id).includes('phone'));
});

// ---------------------------------------------------------------------------
// (2) Appwrite / PocketBase

const APPWRITE_LIB = `import { Account, Client, Databases, Storage, ID } from "react-native-appwrite";
export const config = { endpoint: "https://cloud.appwrite.io/v1", databaseId: "660d14b2b809e838959a", userCollectionId: "660d14c0e8ae0ea842b8" };
const client = new Client();
client.setEndpoint(config.endpoint);
const account = new Account(client);
const databases = new Databases(client);
const storage = new Storage(client);
export async function createUser(email, password, username) {
  const acc = await account.create(ID.unique(), email, password, username);
  return databases.createDocument(config.databaseId, config.userCollectionId, ID.unique(), {
    accountId: acc.$id,
    email: email,
    username: username,
  });
}
export async function signOut() { return account.deleteSession("current"); }
export async function upload(file) { return storage.createFile("avatars", ID.unique(), file); }
`;

test('appwrite: createDocument → collection store named from the config property, account.create → auth store', async () => {
  const { g, warnings } = await graphOf({ 'package.json': JSON.stringify({ name: 'a', dependencies: { 'react-native-appwrite': '0.2', expo: '50' } }), 'lib/appwrite.js': APPWRITE_LIB });
  assert.deepEqual(warnings.filter((w) => /appwrite/.test(w)), []);
  const store = g.node('store:table:user');
  assert.ok(store, 'user collection store');
  assert.equal(store.kind, 'collection');
  assert.equal(store.file, 'lib/appwrite.js');
  assert.equal(store.source, 'appwrite');
  assert.ok(represents(g, 'user.email').includes('email'));
  assert.ok(edges(g, 'flowsTo', (e) => e.from === 'data:email' && e.to === 'store:column:user.email').length, 'email written');
  const auth = g.node('store:table:appwrite.auth.users');
  assert.ok(auth && auth.managed === 'appwrite');
  assert.ok(represents(g, 'appwrite.auth.users.password').includes('password'));
  assert.deepEqual(g.node('store:bucket:appwrite-storage')?.buckets, ['avatars'], 'storage bucket');
  // A logout is not a deletion flow.
  assert.equal(edges(g, 'deletes').length, 0);
  assert.ok(g.node('sink:vendor:appwrite'), 'Appwrite Cloud host');
});

test('appwrite: deleteDocument and account deletion → deletion flows', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'a', dependencies: { appwrite: '14' } }),
    'src/api.js': `import { Client, Databases, Users } from "node-appwrite";\nconst db = new Databases(new Client());\nconst users = new Users(new Client());\nexport async function removeProfile(id) {\n  await db.createDocument("main", "profiles", id, { email: "x", name: "y" });\n  await db.deleteDocument("main", "profiles", id);\n  await users.delete(id);\n}\n`,
  });
  const del = edges(g, 'deletes');
  assert.ok(del.some((e) => e.to === 'store:table:profiles'));
  assert.ok(del.some((e) => e.to === 'store:table:appwrite.auth.users'));
});

test('pocketbase: pb.collection(x).create / delete', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'p', dependencies: { pocketbase: '0.21' } }),
    'src/pb.js': `import PocketBase from "pocketbase";\nconst pb = new PocketBase("http://127.0.0.1:8090");\nexport const add = (data) => pb.collection("patients").create({ name: data.name, phone: data.phone });\nexport const drop = (id) => pb.collection("patients").delete(id);\n`,
  });
  const t = g.node('store:table:patients');
  assert.ok(t);
  assert.equal(t.source, 'pocketbase');
  assert.ok(represents(g, 'patients.phone').includes('phone'));
  assert.ok(edges(g, 'deletes', (e) => e.to === 'store:table:patients').length);
});

test('appwrite: readable names from config / env ids', () => {
  assert.equal(collectionNameFrom('userCollectionId'), 'user');
  assert.equal(collectionNameFrom('EXPO_PUBLIC_APPWRITE_USERS_COLLECTION_ID'), 'users');
  assert.equal(collectionNameFrom('databaseId'), null);
});

// ---------------------------------------------------------------------------
// (3) Laravel

const USERS_MIG = `<?php
use Illuminate\\Database\\Migrations\\Migration;
use Illuminate\\Database\\Schema\\Blueprint;
use Illuminate\\Support\\Facades\\Schema;
class CreateUsersTable extends Migration {
    public function up() {
        Schema::create('users', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password', 60);
            $table->text('address')->nullable();
            $table->string('primary_number')->nullable();
            $table->softDeletes();
            $table->timestamps();
        });
    }
    public function down() { Schema::drop('users'); }
}
`;
const ABS_MIG = `<?php
class CreateAbsencesTable extends Migration {
    public function up() {
        Schema::create('absences', static function (Blueprint $table) {
            $table->bigIncrements('id');
            $table->string('reason');
            $table->text('comment')->nullable();
            $table->integer('user_id')->unsigned()->nullable();
            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->timestamps();
        });
    }
    public function down() { Schema::dropIfExists('absences'); }
}
`;
const ENUM = `<?php
namespace App\\Enums;
class AbsenceReason {
    private const VACATION = 'vacation';
    private const SICK_LEAVE = 'sick_leave';
    private const OTHER = 'other';
}
`;
const USER_MODEL = `<?php
namespace App\\Models;
use Illuminate\\Database\\Eloquent\\SoftDeletes;
use Illuminate\\Foundation\\Auth\\User as Authenticatable;
class User extends Authenticatable {
    use SoftDeletes;
    protected $fillable = ['name', 'email', 'password', 'address', 'vat'];
    protected $hidden = ['password'];
    protected $casts = ['address' => 'encrypted'];
}
`;
const CONTROLLER = `<?php
namespace App\\Http\\Controllers;
use App\\Models\\User;
class UsersController extends Controller {
    public function destroy($id) {
        $user = User::findOrFail($id);
        $user->delete();
    }
    public function purge($id) {
        User::withTrashed()->find($id)->forceDelete();
    }
}
`;

test('laravel: migrations → tables / columns / FKs, model casts and fillable', async () => {
  const { g } = await graphOf({
    'composer.json': JSON.stringify({ require: { 'laravel/framework': '^10.0' } }),
    'database/migrations/2014_10_12_000000_create_users_table.php': USERS_MIG,
    'database/migrations/2020_04_08_070242_create_absences_table.php': ABS_MIG,
    'app/Models/User.php': USER_MODEL,
  });
  const users = g.node('store:table:users');
  assert.ok(users && users.source === 'eloquent');
  assert.ok(represents(g, 'users.email').includes('email'));
  assert.ok(represents(g, 'users.address').includes('address'));
  assert.ok(represents(g, 'users.primary_number').includes('phone'), 'qualified number of a person record is a phone');
  assert.ok(g.node('store:column:users.vat'), 'fillable-only column added');
  assert.ok(g.node('store:column:users.address').encrypted, 'encrypted cast');
  assert.ok(users.softDelete, 'soft deletes');
});

test('laravel: enum health value on a person-linked column → health (special category)', async () => {
  const { g } = await graphOf({
    'composer.json': JSON.stringify({ require: { 'laravel/framework': '^10.0' } }),
    'database/migrations/2014_10_12_000000_create_users_table.php': USERS_MIG,
    'database/migrations/2020_04_08_070242_create_absences_table.php': ABS_MIG,
    'app/Enums/AbsenceReason.php': ENUM,
  });
  const r = edges(g, 'represents', (e) => e.from === 'store:column:absences.reason' && e.to === 'data:health');
  assert.equal(r.length, 1);
  assert.equal(r[0].evidence[0].file, 'app/Enums/AbsenceReason.php');
  assert.equal(r[0].evidence[0].line, 5);
  assert.equal(g.node('data:health').sensitivity, 'special');
});

test('laravel: enum values on a table not about a person stay unclassified', async () => {
  const { g } = await graphOf({
    'composer.json': JSON.stringify({ require: { 'laravel/framework': '^10.0' } }),
    'database/migrations/2020_01_01_000000_create_products_table.php': `<?php\nclass X extends Migration { public function up() { Schema::create('products', function (Blueprint $table) { $table->id(); $table->string('category'); }); } }\n`,
    'app/Enums/ProductCategory.php': `<?php\nenum ProductCategory: string { case Medical = 'medical'; case Toys = 'toys'; }\n`,
  });
  assert.deepEqual(represents(g, 'products.category').filter((x) => x === 'health'), []);
});

test('laravel: Eloquent delete / forceDelete → deletion flows (soft vs hard)', async () => {
  const { g } = await graphOf({
    'composer.json': JSON.stringify({ require: { 'laravel/framework': '^10.0' } }),
    'database/migrations/2014_10_12_000000_create_users_table.php': USERS_MIG,
    'app/Models/User.php': USER_MODEL,
    'app/Http/Controllers/UsersController.php': CONTROLLER,
  });
  const del = edges(g, 'deletes', (e) => e.to === 'store:table:users');
  const soft = del.find((e) => e.from.endsWith('#destroy'));
  const hard = del.find((e) => e.from.endsWith('#purge'));
  assert.ok(soft && soft.soft === true, 'SoftDeletes model: delete() is soft');
  assert.ok(hard && !hard.soft, 'forceDelete is a hard delete');
});

test('laravel: parsers handle Schema::table alterations and PHP 8.1 enums', () => {
  const t = parseMigrations([
    { rel: 'database/migrations/1_create.php', content: USERS_MIG },
    { rel: 'database/migrations/2_alter.php', content: `<?php\nclass A extends Migration { public function up() { Schema::table('users', function (Blueprint $table) { $table->string('city')->nullable(); $table->dropColumn('address'); }); } }\n` },
  ]);
  assert.ok(t.get('users').columns.has('city'));
  assert.ok(!t.get('users').columns.has('address'));
  const e = parseEnums([{ rel: 'app/Enums/LeaveType.php', content: `<?php\nenum LeaveType: string {\n  case Sick = 'sick';\n  case Annual = 'annual';\n}\n` }]);
  assert.deepEqual(e[0].values.map((v) => v.value), ['sick', 'annual']);
});

// ---------------------------------------------------------------------------
// (4) Firestore whole-profile copies

const TYPES = `export interface Profile { id: string; displayName: string; photoURL: string; job: string; age: number; }\n`;
const HOME = `import firestore from "@react-native-firebase/firestore";
import { Profile } from "../lib/types";
import { useState } from "react";
export default function Home({ user }) {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const swipeLeft = (i: number) => {
    const userSwiped = profiles[i];
    firestore().collection("Users").doc(user.uid).collection("Passes").doc(userSwiped.id).set(userSwiped);
  };
  const match = async (i: number) => {
    const other = profiles[i];
    const me = (await firestore().collection("Users").doc(user.uid).get().then((s) => s.data())) as Profile;
    firestore().collection("Matches").doc(user.uid + other.id).set({ users: { [user.uid]: me, [other.id]: other }, usersMatched: [user.uid, other.id] });
  };
  const own = (p: Profile) => firestore().collection("Users").doc(user.uid).set(p);
  return null;
}
`;
const MSG = `import firestore from "@react-native-firebase/firestore";
export function send(user, matchId, text) {
  firestore().collection("Matches").doc(matchId).collection("Messages").add({ userId: user.uid, displayName: user.displayName, photoURL: user.photoURL, message: text });
}
`;

test('firestore: whole profile objects copied into relation collections → flowsTo whole/copy; own collection is not a copy', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'f', dependencies: { '@react-native-firebase/firestore': '18', 'react-native': '0.73' } }),
    'lib/types.ts': TYPES, 'screens/Home.tsx': HOME, 'screens/Msg.tsx': MSG,
  });
  const whole = (to) => edges(g, 'flowsTo', (e) => e.to === to && e.whole && e.copy);
  assert.ok(whole('store:table:Users/Passes').some((e) => e.from === 'data:full_name'), 'Passes copy');
  assert.ok(whole('store:table:Users/Passes').some((e) => e.from === 'data:photo'));
  const m = whole('store:table:Matches');
  assert.ok(m.length, 'embedded profiles in Matches.users');
  assert.ok(m.some((e) => e.copyFrom === 'Users'), 'source collection recorded');
  assert.equal(whole('store:table:Users').length, 0, 'writing a profile into Users is not a copy');
  const fc = edges(g, 'flowsTo', (e) => e.to === 'store:column:Matches/Messages.displayName' && e.fieldCopy);
  assert.equal(fc.length, 1, 'displayName copied into messages is a field copy');
  assert.ok(!fc[0].whole && !fc[0].copy);
});

// ---------------------------------------------------------------------------
// (5) mobile: push tokens, camera permission vs picker calls

test('mobile: Expo push token → device source, element and the Firestore column storing it', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'm', dependencies: { expo: '50', 'expo-notifications': '0.27', firebase: '10', 'react-native': '0.73' } }),
    'src/firebase.js': `import { initializeApp } from "firebase/app";\nimport { getFirestore } from "firebase/firestore";\nexport const firestore = getFirestore(initializeApp({}));\n`,
    'src/Root.js': `import * as Notifications from "expo-notifications";\nimport { setDoc, doc } from "firebase/firestore";\nimport { firestore } from "./firebase";\nexport async function register(userId) {\n  const token = await Notifications.getExpoPushTokenAsync({ projectId: "p" });\n  const ref = doc(firestore, "tokens", userId);\n  await setDoc(ref, { token: token.data, id: userId });\n}\n`,
  });
  assert.ok(g.node('source:device:push-token'));
  assert.ok(collected(g, 'source:device:push-token').includes('push_token'));
  assert.ok(edges(g, 'flowsTo', (e) => e.from === 'data:push_token' && e.to === 'store:column:tokens.token').length, 'token stored');
  assert.ok(edges(g, 'usedBy', (e) => e.from === 'data:push_token' && e.to === 'sink:vendor:push').length, 'token used for push delivery');
});

test('mobile: camera permission with only launchImageLibraryAsync is unused; launchCameraAsync uses it', async () => {
  const appJson = JSON.stringify({ expo: { ios: { infoPlist: { NSCameraUsageDescription: 'take photos' } }, android: { permissions: ['CAMERA'] }, plugins: ['expo-image-picker'] } }, null, 2);
  const pkg = JSON.stringify({ name: 'm', dependencies: { expo: '50', 'expo-image-picker': '15', 'react-native': '0.73' } });
  const picker = (fn) => `import * as ImagePicker from "expo-image-picker";\nexport async function pick() { return ImagePicker.${fn}({ quality: 1 }); }\n`;
  const a = await graphOf({ 'package.json': pkg, 'app.json': appJson, 'app/index.js': `import { pick } from "../lib/pick";\nexport default pick;\n`, 'lib/pick.js': picker('launchImageLibraryAsync') });
  const cam = a.g.node('source:device:camera');
  assert.equal(cam.unused, true);
  assert.ok(collected(a.g, 'source:device:camera:declared').includes('camera_access'), 'declared-only access element');
  assert.ok(edges(a.g, 'collects', (e) => e.from === 'source:device:camera' && e.to === 'data:photo').every((e) => e.declaredOnly), 'photo only declared, not captured');
  const b = await graphOf({ 'package.json': pkg, 'app.json': appJson, 'app/index.js': `import { pick } from "../lib/pick";\nexport default pick;\n`, 'lib/pick.js': picker('launchCameraAsync') });
  assert.equal(b.g.node('source:device:camera').unused, false);
  assert.ok(collected(b.g, 'source:device:camera').includes('photo'));
});
