/**
 * Firestore / Storage security rules → per-collection Store nodes with rule analysis, plus
 * user-identity stamps embedded in Firestore documents (derived stores).
 *
 * Policy props: {name, cmd, roles, using, ownerCheck, public, authOnly, testMode, roleCheck, docVar, matchPath, file, line, snippet}
 *   ownerCheck  the condition (or a rules function it calls) compares request.auth.uid with a path / data value
 *   roleCheck   the condition gates on custom claims / role helper functions (admin-only writes are not "auth only")
 *   docVar      the document wildcard of the enclosing match (`userId` in /users/{userId})
 *
 * Derived store (kind 'collection', source 'firestore-user-stamp'): a helper that copies the signed-in user's
 * identity (displayName / email / photoURL / phoneNumber) into an object that is written into Firestore
 * documents (`_createdBy: stampUser(currentUser)`). Those copies are personal data outside the user profile
 * and survive account deletion unless purged.
 *
 * Code-derived collections (kind 'collection', source 'firestore-code'): every Firestore SDK addresses data with the same
 * collection / doc path, so writes and reads through the modular API (setDoc(doc(db,'users',uid), …)), the namespaced
 * web v8 / compat API, React Native Firebase (firestore().collection('Users').doc(uid).set(…)), the Admin SDK and
 * WriteBatch / Transaction calls become Store nodes keyed like the rules parser keys literal match paths
 * ('users', 'users/posts'), with the written field names as columns. Collections that also have rules merge into the
 * rules store. Extra props: codeOps [op…], subcollectionOf (parent key), groupRead (read through collectionGroup).
 *
 * Rules are OR'ed: every allow statement whose match path covers a document grants access to it, nested and recursive
 * ({document=**}) matches included. Each collection store gets inheritedPolicies (policies of other match paths that
 * cover it, {…policy, inherited:true, fromPath}) and effectiveRead {level:'public'|'auth'|'conditional'|'role'|'owner',
 * policy, file, line, inherited}. When an owner-only read is widened by another read grant (public, any signed-in user,
 * or a non-admin role from an ancestor match), a Weakness {kind:'firestore-broad-read', collection, level, file, line,
 * snippet, ownerRule:{file,line}, inherited, condition} is added.
 *
 * Pre-pass for flow.js (node hints, see _sinks.js): identifiers bound to Firestore references, to OAuth credentials
 * (GoogleAuthProvider.credential(idToken)) and to storage-hook setters are marked so matchCall can resolve them.
 *
 * Realtime Database (scanRtdb): every RTDB SDK addresses one JSON tree by path — modular ref(db, `users/${uid}`) / child /
 * push, namespaced / Admin / React Native db.ref('users').child(uid), AngularFire list() / object(). The literal head of
 * the path is the store (kind 'collection', provider 'firebase-rtdb', source 'firebase-rtdb'); a literal below a dynamic
 * segment is a sub-collection when more keys follow or the value is pushed ('rooms/messages'), otherwise a column.
 * Columns come from the written object (literals, spreads, TS types of variables / parameters, fan-out updates
 * { [`posts/${id}`]: data }); writes / flowsTo / usedBy / deletes edges follow the Dart extractor's shapes. A path that
 * cannot be resolved creates nothing and is reported as not parsed. `ref` of firebase/storage is never matched.
 *
 * Configuration-level sinks (no call chain to match): Python logging handlers (FileHandler / RotatingFileHandler /
 * TimedRotatingFileHandler / SMTPHandler, dictConfig 'class' entries, basicConfig(filename=…)) and web-server access
 * logs (nginx access_log, Apache CustomLog, Caddy log output file) — see configSinkFacts in _sinks.js.
 * Facts: store:log:file:<path> {kind:'log', name, persisted:'file', handler, rotation}; access logs
 * store:log:access:<path> with implied ip_address / user_agent flows (confidence 0.6) and a retention-job control when
 * a logrotate rule in the repository covers the path; SMTPHandler → the smtp vendor sink (log records emailed).
 * Implied vendors: a file importing a Firebase package implies the Firebase / Google Cloud vendor.
 */
import fs from 'node:fs';
import path from 'node:path';
import { newTable, emitTables } from './_schema.js';
import { getAst, jsFiles, walk, memberChain, unwrap, propName, lineOf, resolveStrPrefix, moduleInfo, originOf, resolveFunction, resolveMemberFunction } from './ast.js';
import {
  FIRESTORE_PKG_RE, firestoreOp, firestorePath, firestoreCollectionKey, setNodeHint, storageHookStore, credentialProvider, configSinkFacts,
} from './_sinks.js';

export const name = 'firestore';
export const order = 15;

const OWNER_RE = /request\.auth\.uid\s*==\s*[\w.[\]()]+|[\w.[\]()]+\s*==\s*request\.auth\.uid/;
const ROLE_RE = /request\.auth\.token\.(?!email_verified\b)\w+|\b(?:hasAnyRole|hasRole|isAdmin|isOwner|isStaff|isEditor|isModerator|hasPermission|get\(|exists\()/;

/** `function name(args) { return …; }` blocks of a rules file → Map(name → body). */
export function ruleFunctions(content) {
  const fns = new Map();
  const re = /function\s+(\w+)\s*\(([^)]*)\)\s*\{/g;
  let m;
  while ((m = re.exec(content))) {
    let depth = 1;
    let i = re.lastIndex;
    for (; i < content.length && depth > 0; i++) {
      if (content[i] === '{') depth++;
      else if (content[i] === '}') depth--;
    }
    fns.set(m[1], content.slice(re.lastIndex, i - 1).replace(/\/\/.*$/gm, ''));
  }
  return fns;
}

/** Inline called rule functions (one level deeper per pass, max 3) so helper-based checks are seen. */
function expand(cond, fns) {
  let out = cond || '';
  for (let pass = 0; pass < 3; pass++) {
    let changed = false;
    out = out.replace(/\b(\w+)\s*\(([^()]*)\)/g, (all, fn) => {
      if (!fns.has(fn)) return all;
      changed = true;
      return `(${fns.get(fn).replace(/\breturn\b/g, '').replace(/;/g, ' ')})`;
    });
    if (!changed) break;
  }
  return out;
}

function analyseCondition(cond, fns = new Map()) {
  const c = (cond || '').trim();
  const pub = c === '' || /^true$/.test(c);
  const full = expand(c, fns);
  const ownerCheck = OWNER_RE.test(full);
  const roleCheck = !ownerCheck && ROLE_RE.test(full);
  const authOnly = !ownerCheck && /request\.auth\s*!=\s*null|request\.auth\.uid\s*!=\s*null/.test(full);
  const testMode = /request\.time\s*<\s*timestamp\.date\(/.test(c);
  return { public: pub || testMode, ownerCheck, authOnly, testMode, roleCheck };
}

export function parseRules(file) {
  const tables = new Map();
  const lines = file.content.split(/\r?\n/);
  const stack = []; // {path, depth}
  let depth = 0;
  const isStorage = /service\s+firebase\.storage/.test(file.content);
  const fns = ruleFunctions(file.content);
  lines.forEach((raw, i) => {
    const ln = raw.replace(/\/\/.*$/, '');
    const mm = ln.match(/match\s+(\/\S+)\s*\{\s*$/);
    if (mm) stack.push({ path: mm[1], depth: depth + 1 });
    const allow = ln.match(/allow\s+([\w\s,]+?)\s*(?::\s*if\s+(.+?))?\s*;/);
    if (allow && stack.length) {
      const full = stack.map((s) => s.path).join('');
      if (/^\/databases\/\{[^}]+\}\/documents$/.test(full) || /^\/b\/\{[^}]+\}\/o$/.test(full)) return;
      const segs = full.replace(/^\/databases\/\{[^}]+\}\/documents/, '').replace(/^\/b\/\{[^}]+\}\/o/, '').split('/').filter(Boolean);
      const literal = segs.filter((s) => !s.startsWith('{'));
      const coll = literal.length ? literal.join('/') : '*';
      const key = (isStorage ? 'storage:' : '') + coll;
      if (!tables.has(key)) tables.set(key, newTable(key, { name: coll, kind: isStorage ? 'bucket-path' : 'collection', file: file.rel, line: i + 1, snippet: raw.trim(), source: 'firebase-rules', rls: null, extra: { path: full } }));
      const t = tables.get(key);
      const ops = allow[1].split(',').map((s) => s.trim());
      const a = analyseCondition(allow[2], fns);
      const last = segs[segs.length - 1] || '';
      const docVar = /^\{(\w+)\}$/.test(last) ? last.slice(1, -1) : null;
      const pname = `${ops.join(',')}@${i + 1}`;
      t.policies.set(pname, {
        name: pname, cmd: ops.join(','), roles: ['public'], using: allow[2] || 'true', check: null, ownerCheck: a.ownerCheck, public: a.public,
        authOnly: a.authOnly, testMode: a.testMode, roleCheck: a.roleCheck, docVar, matchPath: full, file: file.rel, line: i + 1, snippet: raw.trim(),
      });
      t.extra = { ...t.extra, public: [...t.policies.values()].some((p) => p.public), ownerCheck: [...t.policies.values()].every((p) => p.ownerCheck) };
    }
    // Path wildcards like {userId} / {document=**} are not blocks.
    for (const ch of ln.replace(/\{[\w=*]+\}/g, '')) {
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        while (stack.length && stack[stack.length - 1].depth > depth) stack.pop();
      }
    }
  });
  return tables;
}

// ---- user-identity stamps embedded in documents ----
const IDENTITY_FIELDS = { displayName: 'full_name', email: 'email', photoURL: 'photo', phoneNumber: 'phone' };
const STAMP_PKG_RE = /from\s+['"](?:firebase\/firestore|@firebase\/firestore|firebase-admin\/firestore|firebase\/compat\/firestore)['"]|require\(\s*['"](?:firebase-admin|firebase\/firestore)['"]\s*\)/;
const FIRESTORE_WRITE_RE = /\b(?:setDoc|updateDoc|addDoc)\s*\(|\.(?:set|update|add)\s*\(\s*(?:doc\(|\w+Ref\b|ref\b|\{)|\bbatch\.(?:set|update)\s*\(|\btransaction\.(?:set|update)\s*\(/;

/**
 * Exported helpers that build an object from the signed-in user's identity:
 *   export const stampUser = (currentUser) => { const { displayName, email, uid, photoURL } = currentUser; return { displayName, email, … } }
 * → [{name, rel, line, fields:[displayName,…]}]
 */
export function findUserStampHelpers(files) {
  const out = [];
  for (const f of files) {
    if (!/\.[cm]?[jt]sx?$/.test(f.rel) || typeof f.content !== 'string') continue;
    const c = f.content;
    const re = /export\s+(?:const\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*(?::[^=]+)?=>|(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\))/g;
    let m;
    while ((m = re.exec(c))) {
      const fname = m[1] || m[3];
      const param = (m[2] || m[4] || '').split(',')[0].split(':')[0].trim();
      if (!fname || !/^\w+$/.test(param)) continue;
      const body = c.slice(re.lastIndex, re.lastIndex + 1500);
      // Identity fields destructured from / read off the user parameter, then returned in an object.
      const destr = new RegExp(String.raw`\{([^{}]+)\}\s*=\s*${param}\b`).exec(body);
      const fromParam = new Set();
      if (destr) for (const k of destr[1].split(',')) fromParam.add(k.trim().split(/[:\s]/)[0]);
      for (const k of Object.keys(IDENTITY_FIELDS)) if (new RegExp(String.raw`\b${param}\s*\??\.\s*${k}\b`).test(body)) fromParam.add(k);
      const ret = /\breturn\s*\{([\s\S]{0,600}?)\}|=>\s*\(\s*\{([\s\S]{0,600}?)\}\s*\)/.exec(body);
      if (!ret) continue;
      const retText = ret[1] || ret[2] || '';
      const fields = Object.keys(IDENTITY_FIELDS).filter((k) => fromParam.has(k) && new RegExp(String.raw`\b${k}\b`).test(retText));
      if (fields.length < 2 || !fields.some((k) => k === 'email' || k === 'displayName')) continue;
      out.push({ name: fname, rel: f.rel, line: c.slice(0, m.index).split('\n').length, fields });
    }
  }
  return out;
}

function userStampStores(ctx) {
  const files = (ctx.files || []).filter((f) => typeof f.content === 'string' && !f.test);
  if (!files.some((f) => STAMP_PKG_RE.test(f.content))) return null;
  const helpers = findUserStampHelpers(files);
  if (!helpers.length) return null;
  const tables = new Map();
  for (const h of helpers) {
    // Call sites in modules that write Firestore documents.
    const sites = [];
    for (const f of files) {
      if (!/\.[cm]?[jt]sx?$/.test(f.rel) || !FIRESTORE_WRITE_RE.test(f.content)) continue;
      const re = new RegExp(String.raw`\b${h.name}\s*\(`, 'g');
      let m;
      while ((m = re.exec(f.content))) {
        const pre = f.content.slice(Math.max(0, m.index - 80), m.index);
        if (f.rel === h.rel && /(?:const|function)\s*$/.test(pre)) continue;
        // Embedded copies only: the result is assigned to a property / variable (`_createdBy: stamp(u)`,
        // `const audit = stamp(u)`), not written as the user's own document (`setDoc(ref, stamp(u))`).
        if (!/(?<![=!<>])[:=]\s*(?:await\s+)?(?:[\w.!?]+\s*&&\s*)?$/.test(pre)) continue;
        sites.push({ rel: f.rel, line: f.content.slice(0, m.index).split('\n').length, snippet: f.content.split(/\r?\n/)[f.content.slice(0, m.index).split('\n').length - 1]?.trim() });
      }
    }
    if (!sites.length) continue;
    const key = `${h.name}() user stamp in documents`;
    const t = newTable(key, { name: `${h.name}() user stamp (embedded in documents)`, kind: 'collection', file: sites[0].rel, line: sites[0].line, snippet: sites[0].snippet, source: 'firestore-user-stamp', rls: null, extra: { derived: true, embedded: true, helper: { name: h.name, file: h.rel, line: h.line }, writeSites: sites.slice(0, 10) } });
    for (const fld of h.fields) t.columns.set(fld, { name: fld, type: 'string', file: h.rel, line: h.line });
    tables.set(key, t);
  }
  return tables.size ? tables : null;
}

// ---- rules are OR'ed across every match path that covers a document ----
function ruleSegs(matchPath) {
  return String(matchPath || '').replace(/^\/databases\/\{[^}]+\}\/documents/, '').replace(/^\/b\/\{[^}]+\}\/o/, '').split('/').filter(Boolean);
}
const isMulti = (s) => /^\{\w+=\*\*\}$/.test(s);
const isWild = (s) => /^\{\w+\}$/.test(s);

/** Does rules pattern p (segments) cover every document addressed by target path t? */
export function matchCovers(p, t, i = 0, j = 0) {
  if (i === p.length) return j === t.length;
  const ps = p[i];
  if (isMulti(ps)) return true;
  if (j === t.length) return false;
  const ts = t[j];
  if (isMulti(ts)) return false;
  if (isWild(ps)) return matchCovers(p, t, i + 1, j + 1);
  if (isWild(ts)) return false;
  return ps === ts && matchCovers(p, t, i + 1, j + 1);
}

const READ_RE = /\b(read|get|list)\b/;
const LEVEL_RANK = { public: 5, auth: 4, conditional: 3, role: 2, owner: 1 };
const ADMIN_RE = /admin|superuser|super_user|staff|moderator/i;
function policyLevel(p) {
  // analyseCondition marks role gates that also test request.auth != null as authOnly; the role is the real gate.
  return p.public ? 'public' : p.ownerCheck ? 'owner' : p.roleCheck ? 'role' : p.authOnly ? 'auth' : 'conditional';
}

/**
 * Adds inheritedPolicies / effectiveRead to every Firestore collection table of one rules file and returns
 * 'firestore-broad-read' weaknesses (owner-only reads widened by another grant).
 */
export function applyRuleInheritance(tables) {
  const weaknesses = [];
  const list = [...tables.values()].filter((t) => t.kind === 'collection');
  for (const t of list) {
    const own = [...t.policies.values()];
    const ownPaths = [...new Set(own.map((p) => p.matchPath).filter(Boolean))].map(ruleSegs);
    const inherited = [];
    for (const u of list) {
      if (u === t) continue;
      for (const p of u.policies.values()) {
        const ps = ruleSegs(p.matchPath);
        if (ownPaths.some((tp) => matchCovers(ps, tp) && ps.join('/') !== tp.join('/'))) inherited.push({ ...p, inherited: true, fromPath: p.matchPath, fromTable: u.key });
      }
    }
    const reads = [...own, ...inherited].filter((p) => READ_RE.test(String(p.cmd || '')));
    let eff = null;
    for (const p of reads) {
      const level = policyLevel(p);
      if (!eff || LEVEL_RANK[level] > LEVEL_RANK[eff.level]) eff = { level, policy: p.name, file: p.file, line: p.line, inherited: !!p.inherited };
    }
    t.extra = { ...t.extra, ...(inherited.length ? { inheritedPolicies: inherited } : {}), ...(eff ? { effectiveRead: eff } : {}) };
    // An owner-only read that another grant widens: rules are OR'ed, so the owner condition protects nothing.
    const ownerRead = own.find((p) => READ_RE.test(String(p.cmd || '')) && p.ownerCheck);
    if (!ownerRead) continue;
    const widening = reads
      .filter((p) => p !== ownerRead && !p.ownerCheck)
      .filter((p) => {
        const level = policyLevel(p);
        if (level === 'public' || level === 'auth') return !p.testMode;
        // Role gates count only when an ancestor match grants them and they are not admin-only.
        return level === 'role' && p.inherited && !ADMIN_RE.test(String(p.using || ''));
      })
      .sort((a, b) => LEVEL_RANK[policyLevel(b)] - LEVEL_RANK[policyLevel(a)])[0];
    if (!widening) continue;
    weaknesses.push({
      kind: 'firestore-broad-read', collection: t.key, level: policyLevel(widening), inherited: !!widening.inherited, fromPath: widening.matchPath,
      condition: String(widening.using || '').slice(0, 160), file: widening.file, line: widening.line, snippet: widening.snippet,
      ownerRule: { file: ownerRead.file, line: ownerRead.line, snippet: ownerRead.snippet },
    });
  }
  return weaknesses;
}

// ---- code-level Firestore use (all SDK flavours) + node hints for flow.js ----
const FS_TEXT_RE = /\b(collection|doc|collectionGroup|setDoc|addDoc|updateDoc|deleteDoc|getDocs?|onSnapshot)\s*\(|\.(collection|doc|collectionGroup)\s*\(/;
const FIREBASE_ANY_PKG = /^(firebase|firebase\/.+|@firebase\/.+|firebase-admin(\/.+)?|@react-native-firebase\/.+|@google-cloud\/firestore)$/;

function pkgOf(ctx, rel, name) {
  if (!name) return null;
  try {
    const o = originOf(ctx, rel, name);
    return o && !String(o).startsWith('local:') ? o : null;
  } catch {
    return null;
  }
}

function objProp(obj, key) {
  obj = unwrap(obj);
  if (!obj || obj.type !== 'ObjectExpression') return null;
  const p = obj.properties.find((pp) => pp.type === 'ObjectProperty' && propName(pp.key, pp.computed) === key);
  return p ? p.value : null;
}

/** Per-file declaration index: name → [{start, init, id}] (nearest preceding declaration wins). */
function declIndex(rec) {
  const decls = new Map();
  const add = (name, start, init, id) => {
    if (!decls.has(name)) decls.set(name, []);
    decls.get(name).push({ start, init, id });
  };
  walk(rec.ast.program, (n) => {
    if (n.type === 'VariableDeclarator' && n.init) {
      if (n.id?.type === 'Identifier') add(n.id.name, n.start ?? 0, n.init, n.id);
      else if (n.id?.type === 'ArrayPattern') n.id.elements.forEach((el, idx) => el?.type === 'Identifier' && add(el.name, n.start ?? 0, { __arrayOf: n.init, index: idx }, el));
    } else if (n.type === 'AssignmentExpression' && n.operator === '=' && n.left?.type === 'Identifier') add(n.left.name, n.start ?? 0, n.right, null);
  });
  return decls;
}
function nearestDecl(decls, node) {
  const list = decls.get(node?.name);
  if (!list) return null;
  let best = null;
  for (const d of list) if (d.id !== node && d.start <= (node.start ?? Infinity) && (!best || d.start >= best.start)) best = d;
  return best || (list.length === 1 && list[0].id !== node ? list[0] : null);
}

function strOf(ctx, rel, n) {
  const u = unwrap(n);
  if (!u) return null;
  if (u.type === 'StringLiteral') return u.value;
  if (u.type === 'TemplateLiteral' && !u.expressions.length) return u.quasis.map((q) => q.value.cooked).join('');
  if (u.type === 'Identifier' || u.type === 'MemberExpression' || u.type === 'OptionalMemberExpression' || u.type === 'TemplateLiteral' || u.type === 'BinaryExpression') {
    try {
      return resolveStrPrefix(ctx, rel, u) || null;
    } catch {
      return null;
    }
  }
  return null;
}

/** Field names written by a data argument (object literal, or a variable bound to one; spreads one level). */
function writtenFields(dataArg, ident, depth = 0) {
  let d = unwrap(dataArg);
  if (d?.type === 'Identifier' && depth < 2) d = unwrap(ident(d));
  if (!d || d.type !== 'ObjectExpression') return [];
  const out = [];
  for (const p of d.properties) {
    if (p.type === 'SpreadElement') out.push(...writtenFields(p.argument, ident, depth + 1));
    else if (p.type === 'ObjectProperty' || p.type === 'ObjectMethod') {
      const k = propName(p.key, p.computed);
      if (k) out.push({ name: k.split('.').pop(), node: p });
    }
  }
  return out;
}

// ---- copies of person records into other collections (whole objects and copied profile fields) ----
// A collection whose last segment names people is the record's own home: writing a profile there is not a copy.
const PERSON_HOME_RE = /^(users?|profiles?|accounts?|members?|people|persons?|customers?|employees?|students?|patients?|kullanicilar|uyeler)$/i;
const IDENTIFYING = new Set(['full_name', 'first_name', 'last_name', 'username', 'nickname', 'photo', 'email', 'phone']);
// Firebase Auth User properties (documented shape of auth.currentUser / onAuthStateChanged user).
const AUTH_USER_PROPS = new Set(['displayName', 'photoURL', 'email', 'phoneNumber']);

/** Project TS interface / object type alias keys: name → [key]. Cached on ctx.shared. */
function typeKeyIndex(ctx) {
  if (ctx.shared._fsTypeKeys) return ctx.shared._fsTypeKeys;
  const idx = new Map();
  for (const f of jsFiles(ctx)) {
    if (!/\.(tsx?|mts|cts)$/.test(f.rel) || !/\b(interface|type)\s+\w+/.test(f.content || '')) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    walk(rec.ast.program, (n) => {
      let members = null;
      if (n.type === 'TSInterfaceDeclaration') members = n.body?.body;
      else if (n.type === 'TSTypeAliasDeclaration' && n.typeAnnotation?.type === 'TSTypeLiteral') members = n.typeAnnotation.members;
      if (!members || !n.id?.name || idx.has(n.id.name)) return;
      idx.set(n.id.name, members.filter((m) => m.type === 'TSPropertySignature').map((m) => propName(m.key, m.computed)).filter(Boolean));
    });
  }
  ctx.shared._fsTypeKeys = idx;
  return idx;
}

/** Name of a TS type reference (Profile, Profile[], Array<Profile>, Promise<Profile>) → 'Profile'. */
function typeRefName(t) {
  if (!t) return null;
  if (t.type === 'TSTypeAnnotation') return typeRefName(t.typeAnnotation);
  if (t.type === 'TSArrayType') return typeRefName(t.elementType);
  if (t.type === 'TSTypeReference') {
    const nm = t.typeName?.type === 'Identifier' ? t.typeName.name : null;
    if (/^(Array|Promise|ReadonlyArray)$/.test(nm || '') && t.typeParameters?.params?.[0]) return typeRefName(t.typeParameters.params[0]);
    return nm;
  }
  if (t.type === 'TSUnionType') return t.types.map(typeRefName).find(Boolean) || null;
  return null;
}

/** Last literal collection('X') / collection(db, 'X') name in an expression's source text (where a record was read). */
function readCollectionOf(rec, node) {
  const text = rec.content.slice(node.start, node.end);
  if (!/\.(get|data)\s*\(|getDoc\s*\(|onSnapshot\s*\(/.test(text)) return null;
  const all = [...text.matchAll(/\bcollection\s*\(\s*(?:[\w$.]+\s*,\s*)?['"`]([\w-]+)['"`]/g)];
  return all.length ? all[all.length - 1][1] : null;
}

/**
 * What a whole object written into Firestore is, when it is a person record: its type (TS annotation / `as T` /
 * element of a useState<T[]> or T[] array) and keys, or the collection it was read from plus the members code reads.
 * → {name, typeName, keys:[...], sourceCollection} | null
 */
function personObject(ctx, rec, decls, node, depth = 0) {
  const n = unwrap(node);
  if (!n || n.type !== 'Identifier' || depth > 3) return null;
  const d = nearestDecl(decls, n);
  let typeName = null;
  let sourceCollection = null;
  if (d) {
    typeName = typeRefName(d.id?.typeAnnotation);
    let init = d.init;
    if (init?.__arrayOf) {
      // const [profiles, setProfiles] = useState<Profile[]>([])
      const call = unwrap(init.__arrayOf);
      if (!typeName && init.index === 0 && call?.typeParameters?.params?.[0]) typeName = typeRefName(call.typeParameters.params[0]);
      init = null;
    }
    if (init && !typeName) {
      for (let cur = init; cur && !typeName; ) {
        if (cur.type === 'TSAsExpression' || cur.type === 'TSTypeAssertion' || cur.type === 'TSSatisfiesExpression') typeName = typeRefName(cur.typeAnnotation);
        if (/^(TSAsExpression|TSTypeAssertion|TSSatisfiesExpression|AwaitExpression|ParenthesizedExpression|TSNonNullExpression)$/.test(cur.type)) cur = cur.expression || cur.argument;
        else break;
      }
    }
    const u = unwrap(init);
    if (u && !typeName && (u.type === 'MemberExpression' || u.type === 'OptionalMemberExpression') && u.computed && unwrap(u.object)?.type === 'Identifier') {
      // const picked = profiles[i]: an element of a typed array
      const inner = personObject(ctx, rec, decls, u.object, depth + 1);
      if (inner) {
        typeName = inner.typeName;
        sourceCollection = inner.sourceCollection;
      }
    }
    if (u && !sourceCollection) sourceCollection = readCollectionOf(rec, u);
  }
  const typeKeys = typeName ? typeKeyIndex(ctx).get(typeName) || null : null;
  // Members the code reads on the object (picked.displayName, picked.photoURL).
  const used = new Set();
  walk(rec.ast.program, (m) => {
    if ((m.type === 'MemberExpression' || m.type === 'OptionalMemberExpression') && !m.computed && unwrap(m.object)?.type === 'Identifier' && unwrap(m.object).name === n.name) {
      const p = propName(m.property, false);
      if (p) used.add(p);
    }
  });
  const keys = typeKeys?.length ? typeKeys : [...used];
  if (!keys.length) return null;
  return { name: n.name, typeName, keys, sourceCollection };
}

/** Classified identifying elements of a person object; null when it does not read as a person record. */
function personElements(ctx, po) {
  const container = po.typeName || po.sourceCollection || po.name;
  const out = [];
  for (const k of po.keys) {
    const cls = ctx.classify(k, { table: container, siblings: po.keys });
    if (cls && !out.some((x) => x.cls.element === cls.element)) out.push({ key: k, cls });
  }
  return out.some((x) => IDENTIFYING.has(x.cls.element)) ? out : null;
}

/**
 * Whole person objects and copied profile fields in a Firestore write's data argument.
 * → [{kind:'whole'|'field', key, column?, elements:[{key, cls}], object, typeName, sourceCollection, line, snippet}]
 */
function personCopies(ctx, rec, decls, dataArg, key, line, snippet) {
  const out = [];
  const lastSeg = key.split('/').pop();
  const seen = new Set();
  const consider = (valueNode, column, at) => {
    const v = unwrap(valueNode);
    if (!v) return;
    if (v.type === 'Identifier') {
      if (seen.has(v.name)) return;
      const po = personObject(ctx, rec, decls, v);
      if (!po) return;
      // Writing the record back into its own collection is not a copy.
      if (po.sourceCollection ? po.sourceCollection.toLowerCase() === lastSeg.toLowerCase() : PERSON_HOME_RE.test(lastSeg)) return;
      const els = personElements(ctx, po);
      if (!els) return;
      seen.add(v.name);
      out.push({ kind: 'whole', key, column, elements: els, object: v.name, typeName: po.typeName, sourceCollection: po.sourceCollection, line: lineOf(at) || line, snippet: (rec.lines[(lineOf(at) || line) - 1] || '').trim().slice(0, 200) || snippet });
      return;
    }
    if (v.type === 'ObjectExpression') {
      for (const p of v.properties) {
        if (p.type === 'ObjectProperty') consider(p.value, column || propName(p.key, p.computed), p);
        else if (p.type === 'SpreadElement') consider(p.argument, column, p);
      }
      return;
    }
    if (v.type === 'ArrayExpression') {
      for (const el of v.elements) consider(el, column, el || at);
      return;
    }
    // A profile field copied from a person object / the signed-in user: { displayName: user.displayName }.
    if ((v.type === 'MemberExpression' || v.type === 'OptionalMemberExpression') && !v.computed && column && !PERSON_HOME_RE.test(lastSeg)) {
      const prop = propName(v.property, false);
      const obj = unwrap(v.object);
      if (!prop) return;
      let po = null;
      if (obj?.type === 'Identifier') po = personObject(ctx, rec, decls, obj);
      const authUser = AUTH_USER_PROPS.has(prop) && (/^(user|currentUser|authUser|me|profile|loggedInUser)$/i.test(obj?.name || '') || (obj?.type === 'MemberExpression' && propName(obj.property, false) === 'currentUser'));
      if (!authUser && !(po && personElements(ctx, po))) return;
      const cls = ctx.classify(prop, { table: po?.typeName || key, siblings: po?.keys || [...AUTH_USER_PROPS] });
      if (!cls || !IDENTIFYING.has(cls.element)) return;
      out.push({ kind: 'field', key, column, elements: [{ key: prop, cls }], object: obj?.name || 'currentUser', line: lineOf(at) || line, snippet: (rec.lines[(lineOf(at) || line) - 1] || '').trim().slice(0, 200) || snippet });
    }
  };
  const d = unwrap(dataArg);
  if (d?.type === 'Identifier') consider(d, null, dataArg);
  else if (d?.type === 'ObjectExpression') for (const p of d.properties) {
    if (p.type === 'ObjectProperty') consider(p.value, propName(p.key, p.computed), p);
    else if (p.type === 'SpreadElement') consider(p.argument, null, p);
  }
  return out;
}

/** flowsTo edges for person copies: whole objects → the collection store (whole/copy), copied fields → the column (fieldCopy). */
function emitPersonCopies(ctx, rel, copies) {
  const { graph, ev } = ctx;
  for (const c of copies) {
    const tid = `store:table:${c.key}`;
    if (!graph.has(tid)) continue;
    const cid = c.column ? `store:column:${c.key}.${c.column}` : null;
    for (const { key, cls } of c.elements) {
      const note = c.kind === 'whole'
        ? `whole ${c.typeName || 'person'} object '${c.object}' copied into ${c.key}${c.column ? '.' + c.column : ''}${c.sourceCollection ? ` (read from ${c.sourceCollection})` : ''}`
        : `${c.object}.${key} copied into ${c.key}.${c.column}`;
      const e = ev(rel, c.line, c.snippet, 'static', c.kind === 'whole' ? 0.7 : 0.75, note);
      const did = graph.dataElement(cls, `${c.key}.${c.column || key}`, e);
      if (c.kind === 'whole') {
        graph.addEdge({ from: did, to: tid, type: 'flowsTo', whole: true, copy: true, copyKind: 'whole', copyOf: c.object, ...(c.sourceCollection ? { copyFrom: c.sourceCollection } : {}), field: key, evidence: [e] });
      } else if (cid && graph.has(cid)) {
        graph.addEdge({ from: did, to: cid, type: 'flowsTo', fieldCopy: true, copyKind: 'field', copyOf: c.object, field: key, evidence: [e] });
      }
    }
  }
}

/**
 * Scan JS/TS files for Firestore operations and hint-worthy bindings.
 * → { tables: Map(key → table), groupReads: [{id, rel, line}], firebaseImport: {rel, line, snippet} | null }
 */
export function scanFirestoreCode(ctx) {
  const tables = new Map();
  const groupReads = [];
  const copies = [];
  let firebaseImport = null;
  const files = jsFiles(ctx).filter((f) => typeof f.content === 'string' && !f.test);
  // Does the project use Firestore at all (any SDK)? Files that only import a local db handle count then.
  let projectFs = false;
  for (const f of files) {
    if (!/firebase|firestore/.test(f.content)) continue;
    const info = moduleInfo(ctx, f.rel);
    for (const imp of info.imports.values()) {
      if (!imp?.source) continue;
      if (FIREBASE_ANY_PKG.test(imp.source) && !firebaseImport) {
        const lines = f.content.split(/\r?\n/);
        const line = lines.findIndex((l) => l.includes(imp.source)) + 1;
        firebaseImport = { rel: f.rel, line: line || 1, snippet: line ? lines[line - 1].trim() : imp.source };
      }
      if (FIRESTORE_PKG_RE.test(imp.source)) projectFs = true;
    }
    if (/require\(\s*['"](firebase-admin|firebase|@google-cloud\/firestore)['"]\s*\)/.test(f.content)) projectFs = true;
  }
  for (const f of files) {
    const fsHere = projectFs && FS_TEXT_RE.test(f.content);
    const hooksHere = /Storage|useMMKV/.test(f.content);
    const credHere = /AuthProvider/.test(f.content);
    if (!fsHere && !hooksHere && !credHere) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    const decls = declIndex(rec);
    const ident = (node) => {
      const d = nearestDecl(decls, node);
      return d && !d.init?.__arrayOf ? d.init : null;
    };
    const h = { str: (n) => strOf(ctx, f.rel, n), prefix: (n) => strOf(ctx, f.rel, n), ident };
    const info = moduleInfo(ctx, f.rel);

    // Storage-hook setters: const [draft, setDraft] = useLocalStorage('draft', '')
    const setters = new Map(); // declaring Identifier node → hint
    if (hooksHere) {
      for (const list of decls.values()) {
        for (const d of list) {
          const ao = d.init?.__arrayOf;
          if (!ao || d.init.index !== 1) continue;
          const call = unwrap(ao);
          if (!/CallExpression$/.test(call?.type || '') || call.callee?.type !== 'Identifier') continue;
          const imp = info.imports.get(call.callee.name);
          if (!imp?.source || imp.source.startsWith('.')) continue;
          const store = storageHookStore(imp.source, imp.imported === 'default' ? 'default' : imp.imported);
          if (!store) continue;
          const keyArg = unwrap(call.arguments?.[0]);
          const key = keyArg?.type === 'ObjectExpression' ? strOf(ctx, f.rel, objProp(keyArg, 'key')) : strOf(ctx, f.rel, keyArg);
          setters.set(d.id, { kind: 'storage-setter', store, key: key || null, hook: call.callee.name });
        }
      }
    }
    // Credential bindings: const cred = auth.GoogleAuthProvider.credential(idToken)
    const creds = new Map();
    if (credHere) {
      for (const list of decls.values()) {
        for (const d of list) {
          if (!d.id || d.init?.__arrayOf) continue;
          const provider = credentialProvider({ strValue: (n) => strOf(ctx, f.rel, n) }, d.init);
          if (provider) creds.set(d.id, { kind: 'credential', provider });
        }
      }
    }
    // Firestore reference bindings: names whose initialiser is a collection / doc / query chain.
    const refNames = new Set();
    if (fsHere) {
      for (const [name, list] of decls) {
        if (list.some((d) => !d.init?.__arrayOf && /CallExpression$/.test(unwrap(d.init)?.type || '') && /\b(collection|doc|collectionGroup|query)\s*\(/.test(rec.content.slice(d.init.start, d.init.end)))) refNames.add(name);
      }
    }

    const seenOps = new Set();
    walk(rec.ast.program, (node, parent) => {
      if (node.type === 'Identifier') {
        const isDeclId = parent?.type === 'VariableDeclarator' && parent.id === node;
        const isProp = (parent?.type === 'MemberExpression' || parent?.type === 'OptionalMemberExpression') && parent.property === node && !parent.computed;
        const isKey = (parent?.type === 'ObjectProperty' || parent?.type === 'ObjectMethod') && parent.key === node && !parent.computed;
        if (isDeclId || isProp || isKey) return;
        if (refNames.has(node.name)) {
          try {
            const p = firestorePath(node, h);
            if (p && firestoreCollectionKey(p)) setNodeHint(node, { kind: 'firestore-ref', path: p });
          } catch {
            /* unresolvable */
          }
        }
        if (setters.size || creds.size) {
          const d = nearestDecl(decls, node);
          if (d?.id && setters.has(d.id) && parent && /CallExpression$/.test(parent.type) && parent.callee === node) setNodeHint(node, setters.get(d.id));
          if (d?.id && creds.has(d.id)) setNodeHint(node, creds.get(d.id));
        }
        return;
      }
      if (!fsHere || !/^(CallExpression|OptionalCallExpression)$/.test(node.type)) return;
      const ch = memberChain(node);
      const cl = { root: ch.root, rootNode: ch.rootNode, rootArgs: ch.rootArgs, segments: ch.segments, pkg: pkgOf(ctx, f.rel, ch.root), objProp };
      let op = null;
      try {
        op = firestoreOp(cl, h);
      } catch {
        op = null;
      }
      if (!op) return;
      const k = ch.segments.find((s) => s.args && /^(set|add|update|delete|create|get|onSnapshot|listDocuments)$/.test(s.name || ''));
      const sig = k?.args || ch.rootArgs;
      if (seenOps.has(sig)) return;
      seenOps.add(sig);
      const line = lineOf(node);
      const snippet = (rec.lines[(line || 1) - 1] || '').trim().slice(0, 200);
      if (op.path.group) {
        groupReads.push({ id: op.path.segs[0], rel: f.rel, line, snippet });
        return;
      }
      const key = op.key;
      if (!key) return;
      if (!tables.has(key)) {
        const parentKey = key.includes('/') ? key.split('/').slice(0, -1).join('/') : null;
        tables.set(key, newTable(key, {
          name: key, kind: 'collection', file: f.rel, line, snippet, source: 'firestore-code', rls: null,
          extra: { inferred: true, codeOps: [], ...(parentKey ? { subcollectionOf: parentKey } : {}) },
        }));
      }
      const t = tables.get(key);
      // Point the store at the first write (where the data enters), not at an earlier read.
      if (op.kind === 'write' && !t.extra.codeOps.some((o) => !/^(get|getDoc|getDocs|onSnapshot|listDocuments|deleteDoc|delete)/.test(o))) Object.assign(t, { file: f.rel, line, snippet });
      if (!t.extra.codeOps.includes(op.op)) t.extra.codeOps.push(op.op);
      if (op.kind === 'write' && op.dataArg) {
        for (const fld of writtenFields(op.dataArg, ident)) {
          if (t.columns.has(fld.name)) continue;
          const fl = lineOf(fld.node) || line;
          t.columns.set(fld.name, { name: fld.name, type: 'any', file: f.rel, line: fl, snippet: (rec.lines[fl - 1] || '').trim().slice(0, 200) });
        }
        if (op.op !== 'delete' && op.op !== 'deleteDoc') {
          try {
            for (const c of personCopies(ctx, rec, decls, op.dataArg, key, line, snippet)) copies.push({ ...c, rel: f.rel });
          } catch {
            /* unresolvable data argument */
          }
        }
      }
    });
  }
  // collectionGroup('posts') reads every 'posts' subcollection.
  for (const g of groupReads) {
    for (const t of tables.values()) if (t.key === g.id || t.key.endsWith('/' + g.id)) t.extra.groupRead = true;
  }
  return { tables, groupReads, firebaseImport, copies };
}

// ---- Realtime Database (JS/TS) ----
const RTDB_PKG_RE = /^(firebase\/database|@firebase\/database|@react-native-firebase\/database|firebase-admin\/database|@angular\/fire\/(compat\/)?database)$/;
const RTDB_TEXT_RE = /firebase\/database|fire\/(?:compat\/)?database|firebase-admin|\bdatabase\s*\(\s*\)\s*\.\s*ref\b|\bgetDatabase\s*\(/;
const RTDB_QUERY = /^(orderBy\w*|limitTo\w*|startAt|startAfter|endAt|endBefore|equalTo)$/;
const RTDB_READ = /^(get|once|on|onValue|onChild\w+|valueChanges|snapshotChanges|stateChanges)$/;
const RTDB_WRITE = /^(set|setWithPriority|update|push|transaction|runTransaction)$/;
const RTDB_MODULAR = /^(ref|refFromURL|child|push|query|set|setWithPriority|update|remove|get|onValue|onChildAdded|onChildChanged|onChildRemoved|runTransaction)$/;
const AUTH_PROFILE_UPDATE = /\bupdate(?:Profile|Email|PhoneNumber|User)\s*\(/;
const RTDB_MAINTENANCE = /(^|\/)(scripts?|seeds?|seeders?|migrations?)\//i;

/**
 * Store key and column of an RTDB path. segs: string | null (dynamic) per level.
 *   ['users', null] → users        ['rooms', null, 'messages', null] → rooms/messages
 *   ['users', null, 'email'] → users, column email      ['app', 'users', null] → app/users
 */
export function rtdbKey(segs, { push = false } = {}) {
  const list = push ? [...segs, null] : [...segs];
  while (list.length && list[0] === null) list.shift();
  if (!list.length) return null;
  const head = [];
  while (list.length && list[0] !== null) head.push(list.shift());
  let column = null;
  // Only literals: the first one is the node, the rest address a member of it.
  if (!list.length) {
    if (head.length > 1) column = head[head.length - 1];
    return { key: head[0], column };
  }
  const key = [head.join('/')];
  while (list.length) {
    while (list.length && list[0] === null) list.shift();
    const run = [];
    while (list.length && list[0] !== null) run.push(list.shift());
    if (!run.length) break;
    if (list.length) key.push(run.join('/'));
    else column = run[run.length - 1];
  }
  return { key: key.join('/'), column };
}

const RTDB_SEG = /^[\w$@.:-]+$/;

/** Type node → property names (Omit / Partial / Pick / Required / Readonly, intersections, arrays, imported names). */
function typeKeysOf(ctx, t, depth = 0) {
  if (!t || depth > 4) return [];
  if (t.type === 'TSTypeAnnotation') return typeKeysOf(ctx, t.typeAnnotation, depth);
  if (t.type === 'TSTypeLiteral') return t.members.filter((m) => m.type === 'TSPropertySignature').map((m) => propName(m.key, m.computed)).filter(Boolean);
  if (t.type === 'TSIntersectionType') return [...new Set(t.types.flatMap((x) => typeKeysOf(ctx, x, depth + 1)))];
  if (t.type === 'TSParenthesizedType') return typeKeysOf(ctx, t.typeAnnotation, depth + 1);
  if (t.type !== 'TSTypeReference') return [];
  const nm = t.typeName?.type === 'Identifier' ? t.typeName.name : null;
  const params = t.typeParameters?.params || t.typeArguments?.params || [];
  if (/^(Partial|Required|Readonly|NonNullable)$/.test(nm || '')) return typeKeysOf(ctx, params[0], depth + 1);
  if (/^(Omit|Pick)$/.test(nm || '')) {
    const keys = typeKeysOf(ctx, params[0], depth + 1);
    const lits = new Set((params[1]?.type === 'TSUnionType' ? params[1].types : [params[1]]).map((x) => x?.literal?.value).filter(Boolean));
    return keys.filter((k) => (nm === 'Omit' ? !lits.has(k) : lits.has(k)));
  }
  return nm ? typeKeyIndex(ctx).get(nm) || [] : [];
}

function returnExpr(fn) {
  if (!fn) return null;
  if (fn.body && fn.body.type !== 'BlockStatement') return fn.body;
  const rs = (fn.body?.body || []).filter((x) => x.type === 'ReturnStatement');
  return rs.length === 1 ? rs[0].argument : null;
}

function enclosingName(ancestors) {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const a = ancestors[i];
    if (!/Function|ObjectMethod|ClassMethod|ClassPrivateMethod/.test(a.type)) continue;
    if (a.id?.name) return a.id.name;
    if (a.key) return propName(a.key, a.computed);
    const p = ancestors[i - 1];
    if (p?.type === 'VariableDeclarator' && p.id?.name) return p.id.name;
    if (p && /^(ObjectProperty|ClassProperty|PropertyDefinition)$/.test(p.type)) return propName(p.key, p.computed);
    if (p?.type === 'AssignmentExpression') return propName(p.left?.property, p.left?.computed) || p.left?.name || null;
  }
  return null;
}

/**
 * Scan JS/TS files for Realtime Database operations.
 * → { tables, ops: [{kind, op, key, fields:[{name,line,file}], rel, line, snippet, fn}], unresolved: Set(rel) }
 */
export function scanRtdb(ctx) {
  const tables = new Map();
  const ops = [];
  const unresolved = new Set();
  const files = jsFiles(ctx).filter((f) => typeof f.content === 'string' && !f.test && RTDB_MAINTENANCE.test(f.rel) === false);
  if (!files.some((f) => RTDB_TEXT_RE.test(f.content))) return { tables, ops, unresolved };
  const ctxOf = new Map();
  const fileCtx = (rel) => {
    if (ctxOf.has(rel)) return ctxOf.get(rel);
    const rec = getAst(ctx, rel);
    if (!rec) {
      ctxOf.set(rel, null);
      return null;
    }
    const info = moduleInfo(ctx, rel);
    const modular = new Map(); // local name → SDK function
    const ns = new Set();
    let sdk = false;
    for (const [local, imp] of info.imports) {
      const src = imp?.source || '';
      if (!RTDB_PKG_RE.test(src)) continue;
      sdk = true;
      if (imp.imported === '*') ns.add(local);
      else if (RTDB_MODULAR.test(imp.imported)) modular.set(local, imp.imported);
    }
    // functions re-exported through a local module (export { ref, set } from 'firebase/database')
    for (const [local, imp] of info.imports) {
      if (!imp?.rel || modular.has(local) || !RTDB_MODULAR.test(imp.imported)) continue;
      if (RTDB_PKG_RE.test(pkgOf(ctx, rel, local) || '')) modular.set(local, imp.imported);
    }
    const params = [];
    walk(rec.ast.program, (n) => {
      if (!/Function|ObjectMethod|ClassMethod/.test(n.type) || !n.params) return;
      for (const p of n.params) {
        const id = p.type === 'AssignmentPattern' ? p.left : p;
        if (id?.type === 'Identifier') params.push({ name: id.name, start: n.start, end: n.end, type: id.typeAnnotation || null });
      }
    });
    const c = { rel, rec, info, modular, ns, sdk, decls: declIndex(rec), params, angular: [...info.imports.values()].some((i) => /^@angular\/fire\/(compat\/)?database$/.test(i?.source || '')) };
    ctxOf.set(rel, c);
    return c;
  };
  const DB_INIT = /\bgetDatabase\s*\(|\bdatabase\s*\(/;
  /** Is this expression / identifier a Realtime Database handle (getDatabase(), firebase.database(), an imported handle)? */
  const handleText = (fc, node) => fc.rec.content.slice(node.start, node.end);
  const isHandleName = (fc, idNode) => {
    const d = nearestDecl(fc.decls, idNode);
    if (d && !d.init?.__arrayOf) return DB_INIT.test(handleText(fc, d.init)) && !/\bref\s*\(/.test(handleText(fc, d.init));
    const imp = fc.info.imports.get(idNode.name);
    if (!imp?.rel) return false;
    const src = (ctx.files || []).find((f) => f.rel === imp.rel)?.content || '';
    const nm = imp.imported === 'default' ? (/export\s+default\s+(\w+)/.exec(src)?.[1] || null) : imp.imported;
    return !!nm && new RegExp(String.raw`\b${nm.replace(/\$/g, '\\$')}\b\s*(?::[^=;\n]+)?=\s*[^;\n]*\b(?:getDatabase|database)\s*\(`).test(src);
  };

  /** String expression → parts (string | null for a dynamic piece). */
  const parts = (fc, node, depth = 0) => {
    const n = unwrap(node);
    if (!n || depth > 6) return [null];
    if (n.type === 'StringLiteral') return [n.value];
    if (n.type === 'NumericLiteral') return [String(n.value)];
    if (n.type === 'TemplateLiteral') {
      const out = [];
      n.quasis.forEach((q, i) => {
        out.push(q.value.cooked ?? '');
        if (i < n.expressions.length) out.push(...parts(fc, n.expressions[i], depth + 1));
      });
      return out;
    }
    if (n.type === 'BinaryExpression' && n.operator === '+') return [...parts(fc, n.left, depth + 1), ...parts(fc, n.right, depth + 1)];
    if (n.type === 'Identifier') {
      // a parameter shadows a constant of the same name
      const inParam = fc.params.some((p) => p.name === n.name && p.start <= n.start && n.start <= p.end);
      const d = inParam ? null : nearestDecl(fc.decls, n);
      if (d && !d.init?.__arrayOf) {
        const u = unwrap(d.init);
        if (u && /^(StringLiteral|TemplateLiteral|BinaryExpression)$/.test(u.type)) return parts(fc, u, depth + 1);
        return [null];
      }
      const s = inParam ? null : strOf(ctx, fc.rel, n);
      return [s];
    }
    if (n.type === 'MemberExpression') return [strOf(ctx, fc.rel, n)];
    if (/CallExpression$/.test(n.type)) {
      const t = helperOf(fc, n);
      const r = t && returnExpr(t.node);
      const tc = r && fileCtx(t.rel);
      if (tc) return parts(tc, r, depth + 1);
    }
    return [null];
  };
  const pathSegs = (fc, node) => {
    if (!node) return [];
    const ps = parts(fc, node);
    const segs = [];
    let cur = '';
    let dyn = false;
    const flush = () => {
      if (dyn) segs.push(null);
      else if (cur) segs.push(RTDB_SEG.test(cur) ? cur : null);
      cur = '';
      dyn = false;
    };
    for (const p of ps) {
      if (p === null) {
        dyn = true;
        continue;
      }
      const bits = p.split('/');
      bits.forEach((b, i) => {
        if (i) flush();
        cur += b;
      });
    }
    flush();
    return segs;
  };
  const helperOf = (fc, call) => {
    const cal = unwrap(call.callee);
    try {
      if (cal?.type === 'Identifier') return resolveFunction(ctx, fc.rel, cal.name);
      if (cal?.type === 'MemberExpression' && unwrap(cal.object)?.type === 'Identifier') return resolveMemberFunction(ctx, fc.rel, unwrap(cal.object).name, propName(cal.property, cal.computed));
    } catch {
      /* not resolvable */
    }
    return null;
  };

  /** Reference expression → { segs, rest } (rest: the segments after the reference) | null. `undefined` base path = root. */
  const refOf = (fc, node, depth = 0) => {
    const n = unwrap(node);
    if (!n || depth > 6) return null;
    if (n.type === 'Identifier') {
      if (fc.params.some((p) => p.name === n.name && p.start <= n.start && n.start <= p.end)) return null;
      const d = nearestDecl(fc.decls, n);
      return d && !d.init?.__arrayOf ? refOf(fc, d.init, depth + 1) : null;
    }
    if (!/CallExpression$/.test(n.type)) return null;
    const ch = memberChain(n);
    let segs = ch.segments;
    let base = null;
    const modularBase = (fn, args) => {
      if (fn === 'ref') return pathSegs(fc, args[1]);
      if (fn === 'child') {
        const b = refOf(fc, args[0], depth + 1);
        return b && !b.rest.length ? [...b.segs, ...pathSegs(fc, args[1])] : null;
      }
      if (fn === 'push') {
        const b = refOf(fc, args[0], depth + 1);
        return b && !b.rest.length ? [...b.segs, null] : null;
      }
      if (fn === 'query') {
        const b = refOf(fc, args[0], depth + 1);
        return b && !b.rest.length ? b.segs : null;
      }
      return null;
    };
    if (ch.root && ch.rootArgs && fc.modular.has(ch.root)) base = modularBase(fc.modular.get(ch.root), ch.rootArgs);
    else if (ch.root && !ch.rootArgs && fc.ns.has(ch.root) && segs[0]?.args) {
      base = modularBase(segs[0].name, segs[0].args);
      segs = segs.slice(1);
    } else {
      const i = segs.findIndex((s) => s.name === 'ref' && s.args);
      if (i >= 0) {
        const before = segs.slice(0, i);
        const viaCall = before.some((s) => s.name === 'database' && s.args) || (ch.rootArgs && /^(getDatabase|database)$/.test(ch.root || '') && (RTDB_PKG_RE.test(pkgOf(ctx, fc.rel, ch.root) || '') || ch.root === 'getDatabase'));
        const viaName = !ch.rootArgs && ch.rootNode?.type === 'Identifier' && before.length === 0 && isHandleName(fc, ch.rootNode);
        const viaThis = ch.root === 'this' && fc.sdk && before.length === 1 && !/storage|bucket/i.test(before[0].name || '');
        if (!viaCall && !viaName && !viaThis) return null;
        base = pathSegs(fc, segs[i].args[0]);
        segs = segs.slice(i + 1);
      } else if (fc.angular && segs.some((s) => /^(list|object)$/.test(s.name || '') && s.args)) {
        const j = segs.findIndex((s) => /^(list|object)$/.test(s.name || '') && s.args);
        base = pathSegs(fc, segs[j].args[0]);
        segs = segs.slice(j + 1);
      } else if (!ch.rootArgs && ch.rootNode?.type === 'Identifier' && refOf(fc, ch.rootNode, depth + 1)?.rest.length === 0) {
        base = refOf(fc, ch.rootNode, depth + 1).segs;
      } else {
        // userRef(uid).set(…) / refs.userRef(uid).update(…): a project helper that returns a reference
        let t = null;
        let skip = 0;
        try {
          if (ch.root && ch.rootArgs) t = resolveFunction(ctx, fc.rel, ch.root);
          else if (ch.root && segs[0]?.args) {
            t = resolveMemberFunction(ctx, fc.rel, ch.root, segs[0].name);
            skip = 1;
          }
        } catch {
          /* not resolvable */
        }
        const r = t && returnExpr(t.node);
        const tc = r && fileCtx(t.rel);
        const b = tc ? refOf(tc, r, depth + 1) : null;
        if (!b || b.rest.length) return null;
        base = b.segs;
        segs = segs.slice(skip);
      }
    }
    if (!base) return null;
    const out = [...base];
    let k = 0;
    for (; k < segs.length; k++) {
      const s = segs[k];
      if (s.name === 'child' && s.args) out.push(...pathSegs(fc, s.args[0]));
      else if (s.name === 'push' && s.args && !s.args.length) out.push(null);
      else if (!(RTDB_QUERY.test(s.name || '') && s.args)) break;
    }
    return { segs: out, rest: segs.slice(k) };
  };

  /** Written fields of a data argument. → {fields:[{name,line}], object:boolean} */
  const dataFields = (fc, node, depth = 0) => {
    let d = unwrap(node);
    if (!d || depth > 4) return { fields: [], object: false };
    if (/CallExpression$/.test(d.type) && d.arguments?.[0] && /^JSON\.parse$|^(serialize|clean|removeUndefined|omitBy|pickBy|stripUndefined)$/.test(fc.rec.content.slice(d.callee.start, d.callee.end))) {
      const inner = unwrap(d.arguments[0]);
      d = /CallExpression$/.test(inner?.type || '') ? unwrap(inner.arguments?.[0]) : inner;
    }
    if (d?.type === 'TSAsExpression') d = unwrap(d);
    const line = lineOf(d);
    const typed = (t) => typeKeysOf(ctx, t).map((name) => ({ name, line }));
    if (d?.type === 'Identifier') {
      const p = fc.params.filter((x) => x.name === d.name && x.start <= d.start && d.start <= x.end).sort((a, b) => b.start - a.start)[0];
      if (p) {
        const f = typed(p.type);
        return { fields: f, object: f.length > 0 };
      }
      const decl = nearestDecl(fc.decls, d);
      const out = [];
      if (decl?.id?.typeAnnotation) out.push(...typed(decl.id.typeAnnotation));
      let obj = out.length > 0;
      if (decl && !decl.init?.__arrayOf) {
        const r = dataFields(fc, decl.init, depth + 1);
        obj ||= r.object;
        for (const x of r.fields) if (!out.some((y) => y.name === x.name)) out.push(x);
      }
      return { fields: out, object: obj };
    }
    if (d?.type === 'ObjectExpression') {
      const out = [];
      for (const pr of d.properties) {
        if (pr.type === 'SpreadElement') out.push(...dataFields(fc, pr.argument, depth + 1).fields);
        else if (pr.type === 'ObjectProperty' || pr.type === 'ObjectMethod') {
          const k = propName(pr.key, pr.computed);
          if (k) out.push({ name: k.split('/').pop(), line: lineOf(pr) });
        }
      }
      return { fields: out, object: true };
    }
    return { fields: [], object: false };
  };

  const addOp = (fc, o) => {
    const k = rtdbKey(o.segs, { push: o.push });
    if (!k) {
      unresolved.add(fc.rel);
      return;
    }
    const line = o.line;
    const snippet = (fc.rec.lines[(line || 1) - 1] || '').trim().slice(0, 200);
    if (!tables.has(k.key)) {
      const parent = k.key.includes('/') ? k.key.split('/').slice(0, -1).join('/') : null;
      tables.set(k.key, newTable(k.key, {
        name: k.key.split('/').pop(), kind: 'collection', file: fc.rel, line, snippet, source: 'firebase-rtdb', rls: null,
        extra: { inferred: true, codeOps: [], tech: 'firebase-rtdb', provider: 'firebase-rtdb', ...(parent ? { subcollectionOf: parent } : {}) },
      }));
    }
    const t = tables.get(k.key);
    if (o.kind === 'write' && !t.extra.codeOps.some((x) => RTDB_WRITE.test(x))) Object.assign(t, { file: fc.rel, line, snippet });
    if (!t.extra.codeOps.includes(o.op) && t.extra.codeOps.length < 20) t.extra.codeOps.push(o.op);
    let fields = [];
    if (o.kind === 'write') {
      const r = o.data ? dataFields(fc, o.data) : { fields: [], object: false };
      fields = r.fields;
      if (k.column && !r.object) fields = [{ name: k.column, line }];
      for (const fld of fields) {
        if (t.columns.has(fld.name) || !/^[A-Za-z_][\w-]*$/.test(fld.name)) continue;
        const fl = fld.line || line;
        t.columns.set(fld.name, { name: fld.name, type: 'any', file: fc.rel, line: fl, snippet: (fc.rec.lines[fl - 1] || '').trim().slice(0, 200) });
      }
    }
    ops.push({ kind: o.kind, op: o.op, key: k.key, partial: !!k.column, fields, rel: fc.rel, line, snippet, fn: o.fn, ...(o.sync ? { sync: true } : {}) });
  };
  const isNull = (n) => unwrap(n)?.type === 'NullLiteral';

  for (const f of files) {
    if (!/\b(ref|child|push|list|object|set|update|remove|onValue)\s*\(/.test(f.content)) continue;
    if (!RTDB_TEXT_RE.test(f.content) && !/\.\s*ref\s*\(|\bref\s*\(/.test(f.content)) continue;
    const fc = fileCtx(f.rel);
    if (!fc) continue;
    if (!fc.modular.size && !fc.ns.size && !fc.sdk && !fc.angular && !/\bref\s*\(/.test(f.content)) continue;
    walk(fc.rec.ast.program, (node, parent, ancestors) => {
      if (!/^(CallExpression|OptionalCallExpression)$/.test(node.type)) return;
      const ch = memberChain(node);
      let op = null;
      let target = null;
      let args = null;
      if (ch.root && ch.rootArgs && !ch.segments.length && fc.modular.has(ch.root)) {
        op = fc.modular.get(ch.root);
        args = ch.rootArgs.slice(1);
        if (!RTDB_READ.test(op) && !RTDB_WRITE.test(op) && op !== 'remove') return;
        if (op === 'push' && !args.length) return;
        target = refOf(fc, ch.rootArgs[0]);
      } else if (ch.root && !ch.rootArgs && fc.ns.has(ch.root) && ch.segments.length === 1) {
        op = ch.segments[0].name;
        args = (ch.segments[0].args || []).slice(1);
        if (!RTDB_READ.test(op) && !RTDB_WRITE.test(op) && op !== 'remove') return;
        if (op === 'push' && !args.length) return;
        target = refOf(fc, ch.segments[0].args?.[0]);
      } else {
        const last = ch.segments[ch.segments.length - 1];
        op = last?.name;
        args = last?.args || [];
        if (!op || !last.args || (!RTDB_READ.test(op) && !RTDB_WRITE.test(op) && op !== 'remove')) return;
        if (op === 'push' && !args.length) return;
        if (!fc.sdk && !/database|getDatabase/.test(f.content) && !/\bref\s*\(/.test(f.content)) return;
        const r = refOf(fc, node);
        if (!r || r.rest.length !== 1 || r.rest[0].name !== op) return;
        target = { segs: r.segs, rest: [] };
        if (fc.angular && op === 'update' && args.length === 2) args = args.slice(1);
      }
      const line = lineOf(node);
      const fn = enclosingName(ancestors);
      // The same function also changes the auth provider's profile: both copies are written together.
      const outer = [...ancestors].reverse().find((a) => /Function|ObjectMethod|ClassMethod/.test(a.type));
      const sync = !!outer && AUTH_PROFILE_UPDATE.test(f.content.slice(outer.start, outer.end));
      if (!target || target.rest.length) {
        if (!RTDB_READ.test(op)) unresolved.add(f.rel);
        return;
      }
      const kind = RTDB_READ.test(op) ? 'read' : op === 'remove' || (op === 'set' && isNull(args[0])) ? 'delete' : 'write';
      // Fan-out update: keys are paths below the reference.
      if (op === 'update') {
        const entries = fanOut(fc, args[0]);
        if (entries.length) {
          for (const e of entries) addOp(fc, { segs: [...target.segs, ...pathSegs(fc, e.key)], kind: isNull(e.value) ? 'delete' : 'write', op, data: e.value, line: lineOf(e.node) || line, fn, sync });
          return;
        }
      }
      addOp(fc, { segs: target.segs, kind, op, push: op === 'push', data: kind === 'write' ? args[0] : null, line, fn, sync });
    });
  }
  return { tables, ops, unresolved };

  /** [{key, value, node}] of a multi-path update object ({ ['posts/' + id]: x } or updates['posts/' + id] = x). */
  function fanOut(fc, dataArg) {
    const d = unwrap(dataArg);
    const out = [];
    const pathLike = (key) => {
      const p = parts(fc, key);
      return p.some((x) => typeof x === 'string' && x.includes('/'));
    };
    const fromObject = (o) => {
      for (const pr of o.properties || []) {
        if (pr.type !== 'ObjectProperty') continue;
        const key = pr.computed || pr.key.type === 'StringLiteral' ? pr.key : null;
        if (key && pathLike(key)) out.push({ key, value: pr.value, node: pr });
      }
    };
    if (d?.type === 'ObjectExpression') fromObject(d);
    else if (d?.type === 'Identifier') {
      const decl = nearestDecl(fc.decls, d);
      const init = decl && !decl.init?.__arrayOf ? unwrap(decl.init) : null;
      if (init?.type === 'ObjectExpression') fromObject(init);
      walk(fc.rec.ast.program, (n) => {
        if (n.type !== 'AssignmentExpression' || n.operator !== '=') return;
        const l = n.left;
        if (l?.type !== 'MemberExpression' || !l.computed || unwrap(l.object)?.name !== d.name) return;
        if (decl && (n.start < decl.start || n.start > d.start)) return;
        if (pathLike(l.property)) out.push({ key: l.property, value: n.right, node: n });
      });
    }
    return out;
  }
}

/** Write / read / delete edges of the RTDB operations (same shapes as the Dart extractor and flow.js recordStoreOp). */
function emitRtdb(ctx, scan) {
  const { graph, ev } = ctx;
  const consumer = (o) => {
    const id = `consumer:${o.rel}#${o.fn || 'top'}`;
    if (!graph.has(id)) graph.addNode({ id, type: 'Consumer', name: `${o.rel}#${o.fn || 'top'}`, file: o.rel, fn: o.fn || 'top', line: o.line, evidence: [ev(o.rel, o.line, o.snippet, 'static', 0.7)] });
    return id;
  };
  const readKeys = new Map();
  for (const o of scan.ops) {
    const tid = `store:table:${o.key}`;
    if (!graph.has(tid)) continue;
    const e = ev(o.rel, o.line, o.snippet, 'static', 0.85);
    if (o.kind === 'read') {
      if (!readKeys.has(o.key)) readKeys.set(o.key, o);
      continue;
    }
    const we = graph.addEdge({ from: consumer(o), to: tid, type: 'writes', op: o.kind === 'delete' ? 'delete' : o.op, file: o.rel, line: o.line, evidence: [e] });
    we.ops ||= [];
    const opName = o.kind === 'delete' ? 'delete' : o.op;
    if (!we.ops.includes(opName) && we.ops.length < 10) we.ops.push(opName);
    if (o.kind === 'delete') {
      if (o.partial) continue; // one member of the record is cleared, not the record
      const cid = `control:deletion-flow:${o.rel}#${o.fn || 'anonymous'}`;
      graph.addNode({ id: cid, type: 'Control', kind: 'deletion-flow', endpoint: null, file: o.rel, line: o.line, ...(o.fn ? { name: o.fn } : {}), evidence: [e] });
      graph.addEdge({ from: cid, to: tid, type: 'deletes', evidence: [e] });
      continue;
    }
    for (const fl of o.fields) {
      const cid = `store:column:${o.key}.${fl.name}`;
      if (!graph.has(cid)) continue;
      const fe = ev(o.rel, fl.line || o.line, o.snippet, 'static', 0.8);
      const op2 = o.op === 'update' ? 'update' : o.sync ? 'upsert' : null;
      for (const rep of graph.edgesFrom(cid, 'represents')) {
        const edge = graph.addEdge({ from: rep.to, to: cid, type: 'flowsTo', field: fl.name, ...(op2 ? { op: op2 } : {}), evidence: [fe] });
        if (op2 && !edge.op) edge.op = op2;
      }
    }
  }
  // Usage: a record that is read somewhere and whose field names the code accesses. Deliberately lenient (an
  // "unused" conclusion must not rest on a value that travels through snapshot.val() untyped).
  if (readKeys.size) {
    const code = jsFiles(ctx).filter((f) => !f.test && typeof f.content === 'string');
    const uses = new Map();
    for (const [key, o] of readKeys) {
      for (const c of scan.tables.get(key)?.columns.keys() || []) {
        const cid = `store:column:${key}.${c}`;
        if (!graph.has(cid) || !graph.edgesFrom(cid, 'represents').length) continue;
        if (!uses.has(c)) uses.set(c, code.some((f) => new RegExp(String.raw`[.?]\s*${c}\b(?!\s*[:=(](?!=))|\{[^{}=;]*\b${c}\b[^{}=;]*\}\s*=\s*`).test(f.content)));
        if (!uses.get(c)) continue;
        const e = ev(o.rel, o.line, o.snippet, 'static', 0.5, `${key} is read here; ${c} is accessed in code`);
        const to = consumer(o);
        graph.addEdge({ from: cid, to, type: 'usedBy', column: c, store: key, table: key, evidence: [e] });
        for (const rep of graph.edgesFrom(cid, 'represents')) graph.addEdge({ from: rep.to, to, type: 'usedBy', column: c, store: key, table: key, evidence: [e] });
      }
    }
  }
}

// ---- configuration-level sinks (Python logging handlers, web-server access logs) ----
const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', '.next', '.nuxt', 'vendor', 'venv', '.venv', '__pycache__', 'coverage', '.cache']);
const SERVER_CONF_PATH = /(^|\/)(nginx|apache2?|httpd|caddy|logrotate(\.d)?|sites-(available|enabled)|conf\.d)(\/|$)|\.conf$|(^|\/)Caddyfile[\w.-]*$|(^|\/)(nginx|httpd|apache2?|logrotate)[\w.-]*$/i;

/**
 * Web-server / logrotate configuration files the source walker skips (extension-less nginx sites, *.conf, Caddyfile).
 * Bounded read-only walk of ctx.root: depth ≤ 6, ≤ 3000 entries, files ≤ 256 KB. → [{rel, content}]
 */
function serverConfigFiles(root) {
  const out = [];
  if (!root) return out;
  let budget = 3000;
  const visit = (dir, rel, depth) => {
    if (depth > 6 || budget <= 0) return;
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (--budget <= 0) return;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) visit(path.join(dir, e.name), r, depth + 1);
        continue;
      }
      if (!e.isFile() || !SERVER_CONF_PATH.test(r) || /\.(m?[jt]sx?|py|rb|go|php|json|ya?ml|toml|md|lock)$/i.test(e.name)) continue;
      try {
        const p = path.join(dir, e.name);
        if (fs.statSync(p).size > 256 * 1024) continue;
        out.push({ rel: r, content: fs.readFileSync(p, 'utf8') });
      } catch {
        /* unreadable */
      }
    }
  };
  visit(root, '', 0);
  return out;
}

function emitConfigSinks(ctx) {
  const known = new Set((ctx.files || []).map((f) => f.rel));
  const extra = serverConfigFiles(ctx.root).filter((f) => !known.has(f.rel));
  const facts = configSinkFacts([...(ctx.files || []), ...extra]);
  if (!facts.length) return;
  const { graph, ev } = ctx;
  for (const f of facts) {
    const e = ev(f.rel, f.line, f.snippet, 'static', f.kind === 'access-log' ? 0.8 : 0.75, f.note);
    if (f.kind === 'log-email') {
      const v = ctx.vendors?.vendorById?.('smtp');
      if (v) graph.vendorSink(v, e);
      continue;
    }
    if (f.kind === 'log-file') {
      const id = `store:log:file:${f.file || 'unknown'}`;
      graph.addNode({ id, type: 'Store', kind: 'log', name: f.file || 'log file', persisted: 'file', handler: f.handler, ...(f.rotation ? { rotation: f.rotation } : {}), file: f.rel, line: f.line, evidence: [e] });
      continue;
    }
    if (f.kind === 'access-log') {
      const id = `store:log:access:${f.file || f.server}`;
      graph.addNode({ id, type: 'Store', kind: 'log', name: f.file || `${f.server} access log`, persisted: 'file', server: f.server, accessLog: true, file: f.rel, line: f.line, evidence: [e] });
      // Default access-log formats (nginx/Apache "combined", Caddy JSON) record the client IP and the User-Agent.
      for (const nm of f.fields || []) {
        const cls = ctx.classify?.(nm);
        if (!cls) continue;
        const note = `${f.server} access log records the client ${nm}`;
        const capped = { ...cls, confidence: Math.min(cls.confidence ?? 0.6, 0.6) };
        const did = graph.dataElement(capped, `${f.server}.access_log`, ev(f.rel, f.line, f.snippet, 'inferred', 0.6, note));
        // The log format is the store's schema: the store represents the element (a standing record kept for retention review),
        // not an app-level flow of a variable into a logger (which AUD-SEC-04 is about).
        graph.addEdge({ from: id, to: did, type: 'represents', implied: true, evidence: [ev(f.rel, f.line, f.snippet, 'inferred', 0.6, note)] });
      }
      if (f.rotation) {
        const cid = `control:retention-job:logrotate:${f.file || f.server}`;
        graph.addNode({ id: cid, type: 'Control', kind: 'retention-job', mechanism: 'logrotate', file: f.rotation.rel, line: f.rotation.line, evidence: [ev(f.rotation.rel, f.rotation.line, f.rotation.snippet, 'static', 0.8, 'logrotate rule covers the access log')] });
        graph.addEdge({ from: cid, to: id, type: 'expires', evidence: [ev(f.rotation.rel, f.rotation.line, f.rotation.snippet, 'static', 0.8)] });
      }
    }
  }
}

export function extract(ctx) {
  const all = new Map();
  const ruleWeaknesses = [];
  for (const f of ctx.files.filter((x) => /(^|\/)(firestore|storage)\.rules$|\.rules$/.test(x.rel) && /rules_version|service\s+(cloud\.firestore|firebase\.storage)/.test(x.content))) {
    const tables = parseRules(f);
    try {
      ruleWeaknesses.push(...applyRuleInheritance(tables));
    } catch (e) {
      ctx.warn?.(`firestore: rule inheritance: ${e.message}`);
    }
    for (const [k, t] of tables) all.set(k, t);
  }
  // Code-level collections (any SDK flavour); rules stores absorb the written fields of the same collection.
  let code = null;
  try {
    code = scanFirestoreCode(ctx);
  } catch (e) {
    ctx.warn?.(`firestore: code scan: ${e.message}`);
  }
  const codeOnly = new Map();
  if (code) {
    for (const [k, t] of code.tables) {
      const r = all.get(k);
      if (r) {
        for (const [cn, col] of t.columns) if (!r.columns.has(cn)) r.columns.set(cn, col);
        r.extra = { ...r.extra, codeOps: t.extra.codeOps, ...(t.extra.groupRead ? { groupRead: true } : {}) };
      } else codeOnly.set(k, t);
    }
  }
  if (all.size) emitTables(ctx, all, 'firebase-rules');
  if (codeOnly.size) emitTables(ctx, codeOnly, 'firestore-code');
  if (code?.copies?.length) {
    try {
      for (const c of code.copies) emitPersonCopies(ctx, c.rel, [c]);
    } catch (e) {
      ctx.warn?.(`firestore: person copies: ${e.message}`);
    }
  }
  // Realtime Database: a second document store next to (or instead of) Firestore.
  try {
    const rt = scanRtdb(ctx);
    if (rt.tables.size) {
      // Firestore and RTDB collections of the same name are different stores.
      const taken = new Set([...all.keys(), ...codeOnly.keys()]);
      for (const [k, t] of [...rt.tables]) {
        if (!taken.has(k)) continue;
        rt.tables.delete(k);
        const nk = `rtdb:${k}`;
        t.key = nk;
        rt.tables.set(nk, t);
        for (const o of rt.ops) if (o.key === k) o.key = nk;
      }
      emitTables(ctx, rt.tables, 'firebase-rtdb');
      emitRtdb(ctx, rt);
    }
    if (rt.unresolved.size) {
      (ctx.shared.unparsed ||= []).push({ layer: 'dbWrites', kind: 'firebase-rtdb', label: { tr: 'Firebase Realtime Database yolları (çözümlenemedi)', en: 'Firebase Realtime Database paths (not resolved)' }, files: [...rt.unresolved].slice(0, 20), count: rt.unresolved.size, reason: 'not-parsed' });
    }
    (ctx.shared.dataLayers ||= {});
    if (rt.tables.size || rt.unresolved.size) ctx.shared.dataLayers['firebase-rtdb'] = { detected: true, stores: rt.tables.size, writes: rt.ops.filter((o) => o.kind === 'write').length, deletes: rt.ops.filter((o) => o.kind === 'delete').length };
  } catch (e) {
    ctx.warn?.(`firestore: rtdb: ${e.message}`);
    if (process.env.KVKK_DEBUG) console.error(e);
  }
  for (const w of ruleWeaknesses) {
    const id = `weakness:firestore-broad-read:${w.collection}:${w.line}`;
    ctx.graph.addNode({ id, type: 'Weakness', ...w, evidence: [ctx.ev(w.file, w.line, w.snippet, 'static', 0.8, `rules are OR'ed: this ${w.level} read also applies to ${w.collection}`)] });
  }
  // Implied hosting vendor: the app talks to Firebase / Google Cloud.
  if (code?.firebaseImport) {
    const v = ctx.vendors?.vendorById?.('firebase');
    if (v) ctx.graph.vendorSink(v, ctx.ev(code.firebaseImport.rel, code.firebaseImport.line, code.firebaseImport.snippet, 'static', 0.85, 'Firebase SDK imported'));
  }
  try {
    emitConfigSinks(ctx);
  } catch (e) {
    ctx.warn?.(`firestore: config sinks: ${e.message}`);
  }
  try {
    const stamps = userStampStores(ctx);
    if (stamps) emitTables(ctx, stamps, 'firestore-user-stamp');
  } catch (e) {
    ctx.warn?.(`firestore: user stamps: ${e.message}`);
  }
}
