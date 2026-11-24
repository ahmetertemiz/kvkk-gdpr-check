/**
 * Dart / Flutter extractor (order 16): the documented FlutterFire and supabase_flutter client APIs, read with a small
 * lexer (no Dart toolchain is ever run).
 *
 *   cloud_firestore    FirebaseFirestore.instance (or a field / variable / getter holding it, a CollectionReference /
 *                      DocumentReference held in a variable) .collection('c').doc(id)[.collection('s').doc(id)]
 *                        .set(map[, SetOptions]) | .update(map) | .add(map)          → write, the map's keys are columns
 *                        .delete()                                                  → deletion flow → collection
 *                        .get() | .snapshots() | .where(…) …                       → read (store referenced)
 *                      WriteBatch / Transaction: batch.set(ref, map) / tx.update(ref, map) / batch.delete(ref)
 *                      map = map literal, `x.toJson()` / `toMap()` / `toFirestore()` of a model class (its returned map
 *                      literal, or its fields for json_serializable `_$XToJson(this)`), a variable holding either,
 *                      withConverter<T>(…).add(obj). Model.fromJson / fromMap / fromSnap(snapshot of collection c) adds
 *                      the keys the factory reads (snapshot['email']) to collection c.
 *                      Paths and map keys may be constants: class-scoped (`Paths.users`), enum values, getters, top-level
 *                      constants, interpolations ('$root/users', 'users/$uid/posts'). A dynamic sub-collection is
 *                      `<parent>/{dynamic}` and keeps the last literal collection as its record name.
 *                      Maps may be built up (`data['k'] = v`, addAll, spreads, `if (x) 'k': v`).
 *                      Wrapper methods that take the path and / or the map as parameters are summarised and
 *                      instantiated at their call sites across files (depth 3): the write belongs to the caller.
 *   firebase_database  FirebaseDatabase.instance.ref('users/$uid') / .child() / .push() .set | .update | .remove, held
 *                      DatabaseReferences, the same wrappers  → store {provider:'firebase-rtdb'} (key: rtdbKey, firestore.js)
 *   firebase_auth      createUserWithEmailAndPassword(email:, password:)            → managed auth store + Firebase sink
 *                      signInWith* (email / phone / credential / provider)          → Firebase sink
 *                      updateEmail / verifyBeforeUpdateEmail / updatePhoneNumber / updateDisplayName / updatePhotoURL
 *                      currentUser.delete() / user.delete()                         → account deletion flow
 *   firebase_storage   FirebaseStorage.instance.ref(…).child(…).putData | putFile | putString → bucket firebase-storage
 *                      ….delete() / refFromURL(url).delete()                        → deletion flow → bucket
 *   supabase_flutter   supabase.from('t').insert | upsert | update(map) / .delete()  → table store (existing SQL table or
 *                      a new code-derived one), columns, deletion flow
 *   TextEditingController fields whose name classifies (an `_emailController`) → form Source collecting that element,
 *                      when the element is also written / sent by this extractor.
 *
 * Writes (same shapes as the JS extractors so checks need nothing Dart-specific):
 *   Store store:table:<collection path> {kind:'collection', source:'firestore-code', tech:'firestore', provider:'firestore',
 *         language:'dart', inferred:true, codeOps:[…]} + columns (emitTables) — merged into a rules store of the same key
 *   Store store:table:firebase.auth.users (id shared with _sinks.js), store:bucket:firebase-storage
 *   flowsTo DataElement → column (written field), DataElement → auth store / Firebase sink
 *   writes  consumer:<file>#<fn> → Store {op, file, line}  (contract C1, same as flow.js recordStoreOp)
 *   Control deletion-flow + deletes edges; Sink sink:vendor:firebase / supabase for the imported SDK
 *   ctx.shared.unparsed {layer:'dbWrites'|'schema', kind:'dart', files} for Firestore / Supabase calls whose collection
 *   or data could not be resolved (contract C2).
 */
import path from 'node:path';
import { newTable, emitTables } from './_schema.js';
import { rtdbKey } from './firestore.js';

export const name = 'dart';
export const order = 16;

const FIREBASE_AUTH_USERS = { id: 'store:table:firebase.auth.users', props: { kind: 'table', table: 'firebase.auth.users', external: true, managed: 'firebase' } };
const STORAGE_BUCKET = { id: 'store:bucket:firebase-storage', props: { kind: 'bucket', name: 'firebase-storage', external: true, managed: 'firebase', source: 'firebase-storage' } };
const KEYWORDS = new Set(['if', 'for', 'while', 'switch', 'catch', 'return', 'await', 'new', 'const', 'final', 'var', 'else', 'try', 'super', 'this', 'throw', 'assert', 'print', 'setState']);

// ---------------------------------------------------------------------------
// Lexing

/**
 * Dart source → { code, mask }: `code` has comments blanked (offsets and newlines kept); `mask` additionally blanks the
 * contents of string literals (quotes kept) so parentheses / braces can be balanced and identifiers searched safely.
 */
export function lexDart(src) {
  const code = src.split('');
  const mask = src.split('');
  const n = src.length;
  let i = 0;
  const blank = (arr, a, b) => {
    for (let k = a; k < b; k++) if (arr[k] !== '\n') arr[k] = ' ';
  };
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === '/' && d === '/') {
      let j = src.indexOf('\n', i);
      if (j < 0) j = n;
      blank(code, i, j);
      blank(mask, i, j);
      i = j;
      continue;
    }
    if (c === '/' && d === '*') {
      let j = src.indexOf('*/', i + 2);
      j = j < 0 ? n : j + 2;
      blank(code, i, j);
      blank(mask, i, j);
      i = j;
      continue;
    }
    if (c === "'" || c === '"') {
      const raw = src[i - 1] === 'r' && !/\w/.test(src[i - 2] || '');
      const triple = src.slice(i, i + 3) === c.repeat(3);
      const q = triple ? c.repeat(3) : c;
      let j = i + q.length;
      while (j < n) {
        if (!raw && src[j] === '\\') {
          j += 2;
          continue;
        }
        if (src.startsWith(q, j)) break;
        if (!triple && src[j] === '\n') break;
        j++;
      }
      const end = Math.min(n, j + q.length);
      blank(mask, i + q.length, Math.min(j, n));
      i = end;
      continue;
    }
    i++;
  }
  return { code: code.join(''), mask: mask.join('') };
}

/** Index of the bracket closing the one at `open` (mask text, strings blanked). */
function closeOf(mask, open) {
  const pairs = { '(': ')', '{': '}', '[': ']', '<': '>' };
  const o = mask[open];
  const cl = pairs[o];
  let depth = 0;
  for (let k = open; k < mask.length; k++) {
    const ch = mask[k];
    if (ch === o) depth++;
    else if (ch === cl) {
      depth--;
      if (depth === 0) return k;
    } else if (o === '<' && /[;{}()]/.test(ch)) return -1;
  }
  return -1;
}

/** Top-level comma-separated parts of an argument list (text between the parentheses). */
function splitArgs(code, mask, a, b) {
  const out = [];
  let depth = 0;
  let start = a;
  for (let k = a; k < b; k++) {
    const ch = mask[k];
    if (ch === '<') {
      // type arguments: Map<String, dynamic>
      const g = closeOf(mask, k);
      if (g > 0 && g < b) k = g;
      continue;
    }
    if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch)) depth--;
    else if (ch === ',' && depth === 0) {
      out.push({ text: code.slice(start, k).trim(), start, end: k });
      start = k + 1;
    }
  }
  if (code.slice(start, b).trim()) out.push({ text: code.slice(start, b).trim(), start, end: b });
  return out;
}

/** A plain string literal ('users', "users", no interpolation) → its value. */
function strLit(text) {
  const m = /^r?(['"])([^'"$\\]*)\1$/.exec(String(text || '').trim());
  return m ? m[2] : null;
}

/** 1-based line of an offset. */
function lineAt(src, off) {
  let n = 1;
  for (let k = 0; k < off && k < src.length; k++) if (src.charCodeAt(k) === 10) n++;
  return n;
}

/**
 * Parse a member chain starting at `start` (an identifier): root(.seg(args)?)* with Dart's `!`, `?.` and generics.
 * → { root, segs:[{name, args:[{text,start,end}], argA, argB, generic}], end } or null. A cascade (`..`) ends it.
 */
function parseChain(code, mask, start) {
  const id = /^[A-Za-z_$][\w$]*/.exec(mask.slice(start, start + 80));
  if (!id) return null;
  let k = start + id[0].length;
  const segs = [];
  const skipWs = () => {
    while (k < mask.length && /[\s!]/.test(mask[k])) k++;
  };
  const readCall = (seg) => {
    skipWs();
    if (mask[k] === '<') {
      const g = closeOf(mask, k);
      if (g > 0) {
        seg.generic = code.slice(k + 1, g).trim();
        k = g + 1;
        skipWs();
      }
    }
    if (mask[k] === '(') {
      const c = closeOf(mask, k);
      if (c < 0) return false;
      seg.argA = k + 1;
      seg.argB = c;
      seg.args = splitArgs(code, mask, k + 1, c);
      k = c + 1;
    }
    return true;
  };
  const root = { name: id[0] };
  if (!readCall(root)) return null;
  for (;;) {
    const save = k;
    skipWs();
    if (mask[k] === '?' && mask[k + 1] === '.') k += 2;
    else if (mask[k] === '.' && mask[k + 1] !== '.') k += 1;
    else {
      k = save;
      break;
    }
    while (k < mask.length && /\s/.test(mask[k])) k++;
    const m = /^[A-Za-z_$][\w$]*/.exec(mask.slice(k, k + 80));
    if (!m) {
      k = save;
      break;
    }
    k += m[0].length;
    const seg = { name: m[0] };
    if (!readCall(seg)) break;
    segs.push(seg);
  }
  return { root, segs, end: k };
}

/** Name of the function / method enclosing an offset (best effort). */
function enclosingFn(mask, off) {
  const head = mask.slice(Math.max(0, off - 6000), off);
  const re = /(?:^|[\s;{}])([A-Za-z_]\w*)\s*\(([^;{}]|\{[^{}]*\})*?\)\s*(?:async\*?|sync\*)?\s*(?:\{|=>)/g;
  let best = null;
  let m;
  while ((m = re.exec(head))) if (!KEYWORDS.has(m[1])) best = m[1];
  return best;
}

/** Text of the statement holding an offset (from the previous `;`/`{`/`}` to the next `;`). */
function statementAt(code, mask, off) {
  let a = off;
  while (a > 0 && !/[;{}]/.test(mask[a - 1])) a--;
  let b = off;
  let depth = 0;
  while (b < mask.length) {
    const ch = mask[b];
    if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch)) {
      if (depth === 0) break;
      depth--;
    } else if (ch === ';' && depth === 0) break;
    b++;
  }
  return { text: code.slice(a, b), start: a, end: b };
}

// ---------------------------------------------------------------------------
// Project index: model classes, string constants, Firebase handles

function importsOf(code) {
  return [...code.matchAll(/^\s*import\s+['"]package:([\w]+)\//gm)].map((m) => m[1]);
}

/** Entries of a map literal starting at `open` ('{'). → {keys:[{name, off}], spreads:[{text, start}]}; keyOf resolves constant keys. */
function mapEntries(code, mask, open, keyOf = null) {
  const close = closeOf(mask, open);
  const keys = [];
  const spreads = [];
  if (close < 0) return { keys, spreads };
  const entry = (text, start) => {
    const lead = text.length - text.trimStart().length;
    let t = text.trim();
    let off = start + lead;
    // collection-if / collection-for: `if (cond) 'k': v`
    const cond = /^(?:if|for)\s*\(/.exec(t);
    if (cond) {
      const c = closeOf(mask, off + cond[0].length - 1);
      if (c < 0) return;
      const rest = code.slice(c + 1, start + text.length);
      const els = rest.split(/\belse\b/);
      let at = c + 1;
      for (const part of els) {
        entry(part, at);
        at += part.length + 4;
      }
      return;
    }
    const spread = /^\.\.\.\??\s*/.exec(t);
    if (spread) {
      off += spread[0].length;
      t = t.slice(spread[0].length);
      if (t.startsWith('{') || /^<[^>]*>\s*\{/.test(t)) {
        const inner = mapEntries(code, mask, mask.indexOf('{', off), keyOf);
        keys.push(...inner.keys);
        spreads.push(...inner.spreads);
      } else spreads.push({ text: t, start: off });
      return;
    }
    const lit = /^r?(['"])([^'"$\\]*)\1\s*:/.exec(t);
    if (lit) {
      keys.push({ name: lit[2], off });
      return;
    }
    const id = /^([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*){0,3})\s*:(?!:)/.exec(t);
    if (id && keyOf) {
      const name = keyOf(id[1].replace(/\s+/g, ''), off);
      if (name) keys.push({ name, off });
    }
  };
  for (const a of splitRaw(mask, open + 1, close)) entry(code.slice(a.start, a.end), a.start);
  return { keys, spreads };
}
/** Top-level comma-separated ranges (untrimmed). */
function splitRaw(mask, a, b) {
  const out = [];
  let depth = 0;
  let start = a;
  for (let k = a; k < b; k++) {
    const ch = mask[k];
    if (ch === '<') {
      // type arguments: Map<String, dynamic>
      const g = closeOf(mask, k);
      if (g > 0 && g < b) k = g;
      continue;
    }
    if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch)) depth--;
    else if (ch === ',' && depth === 0) {
      out.push({ start, end: k });
      start = k + 1;
    }
  }
  if (mask.slice(start, b).trim()) out.push({ start, end: b });
  return out;
}

/** Model classes of one file: name → {file, line, toMap:[{name,line}], fromMap:[…], fields:[…], jsonSerializable}. */
function indexClasses(f, code, mask, classes, keyOf) {
  const re = /\bclass\s+([A-Z]\w*)\b[^{;]*\{/g;
  let m;
  while ((m = re.exec(mask))) {
    const open = m.index + m[0].length - 1;
    const close = closeOf(mask, open);
    if (close < 0) continue;
    const body = { a: open + 1, b: close };
    const cls = { name: m[1], file: f.rel, line: lineAt(code, m.index), toMap: [], fromMap: [], fields: [], jsonSerializable: false };
    const bodyMask = mask.slice(body.a, body.b);
    // toJson / toMap / toFirestore / toDocument: the returned map literal and `data['k'] = …` assignments
    const toRe = /\b(toJson|toMap|toFirestore|toDocument|toFirebase|toFireStore|toJSON|toData)\s*\([^)]*\)\s*(?:async\s*)?(=>|\{)/g;
    let t;
    while ((t = toRe.exec(bodyMask))) {
      const at = body.a + t.index + t[0].length - 1;
      let from = at + 1;
      let end = body.b;
      if (mask[at] === '{') end = closeOf(mask, at);
      else {
        from = at + 1;
        const semi = mask.indexOf(';', from);
        let depth = 0;
        end = semi < 0 ? body.b : semi;
        for (let k = from; k < body.b; k++) {
          if ('([{'.includes(mask[k])) depth++;
          else if (')]}'.includes(mask[k])) depth--;
          else if (mask[k] === ';' && depth === 0) { end = k; break; }
        }
      }
      if (end < 0) continue;
      const add = (name, off) => { if (!cls.toMap.some((x) => x.name === name)) cls.toMap.push({ name, line: lineAt(code, off) }); };
      const segMask = mask.slice(from, end);
      for (const lm of segMask.matchAll(/(?:\breturn|=|=>|^)\s*(?:const\s+)?(?:<[^<>{}]*(?:<[^<>]*>)?[^<>{}]*>\s*)?\{/g)) {
        const open = from + lm.index + lm[0].length - 1;
        for (const k of mapEntries(code, mask, open, keyOf).keys) add(k.name, k.off);
      }
      for (const am of indexAssignments(code, mask, from, end, null, keyOf)) add(am.name, am.off);
    }
    if (/_\$\w+ToJson\s*\(\s*this\s*\)/.test(bodyMask)) cls.jsonSerializable = true;
    // fromJson / fromMap / fromSnap / fromFirestore / fromDocument: keys the factory reads
    const fromRe = /\b(?:factory\s+\w+\.|static\s+\w+\s+|\w+\.)?(from\w*)\s*\(([^()]|\([^()]*\))*\)\s*(?:async\s*)?(?:=>|\{)/g;
    let fr;
    while ((fr = fromRe.exec(bodyMask))) {
      if (!/^from(Json|Map|Snap|Snapshot|Firestore|Document|Doc|Data|Firebase|DocumentSnapshot|JSON)\w*$/i.test(fr[1])) continue;
      const startAt = body.a + fr.index + fr[0].length;
      const end = Math.min(body.b, startAt + 3000);
      const seg = code.slice(startAt, end);
      const stop = (() => {
        // until the end of this member (balanced braces)
        let depth = 1;
        for (let k = startAt; k < end; k++) {
          if (mask[k] === '{' || mask[k] === '(') depth++;
          else if (mask[k] === '}' || mask[k] === ')') {
            depth--;
            if (depth <= 0) return k - startAt;
          } else if (mask[k] === ';' && depth === 1 && fr[0].trim().endsWith('=>')) return k - startAt;
        }
        return seg.length;
      })();
      const member = seg.slice(0, stop);
      for (const km of member.matchAll(/\b\w+(?:\(\))?\s*[!?]?\s*\[\s*(['"])([A-Za-z_][\w]*)\1\s*\]/g)) {
        cls.fromMap.push({ name: km[2], line: lineAt(code, startAt + km.index) });
      }
      // doc.get('k') / doc.get(Fields.k) / map[Fields.k]
      for (const km of member.matchAll(/\.\s*get\s*\(\s*(?:(['"])([A-Za-z_]\w*)\1|([A-Z]\w*(?:\.\w+)+))\s*\)|\b\w+\s*[!?]?\s*\[\s*([A-Z]\w*(?:\.\w+)+)\s*\]/g)) {
        const nm = km[2] || (keyOf && keyOf(km[3] || km[4], startAt + km.index));
        if (nm) cls.fromMap.push({ name: nm, line: lineAt(code, startAt + km.index) });
      }
    }
    // fields (json_serializable / freezed models)
    for (const fm of code.slice(body.a, body.b).matchAll(/(?:^|[;{}\n])\s*(?:@JsonKey\s*\(\s*name\s*:\s*(['"])(\w+)\1[^)]*\)\s*)?(?:late\s+)?final\s+[\w<>?,\s]+?\s+([a-z_]\w*)\s*;/g)) {
      cls.fields.push({ name: fm[2] || fm[3], line: lineAt(code, body.a + fm.index) });
    }
    if (!classes.has(cls.name) || (!classes.get(cls.name).toMap.length && cls.toMap.length)) classes.set(cls.name, cls);
  }
}

/** `v['k'] = x` assignments in a range. name: only this variable (null: any). */
function indexAssignments(code, mask, from, end, name, keyOf) {
  const out = [];
  const re = new RegExp(String.raw`(?:^|[^\w.$])(${name || '[A-Za-z_]\\w*'})\s*\[`, 'g');
  const seg = mask.slice(from, end);
  let m;
  while ((m = re.exec(seg))) {
    const open = from + m.index + m[0].length - 1;
    const close = closeOf(mask, open);
    if (close < 0 || !/^\s*(?:\?\?)?=(?!=)/.test(mask.slice(close + 1, close + 12))) continue;
    const key = code.slice(open + 1, close).trim();
    const lit = strLit(key);
    const nm = lit || (keyOf && /^[A-Za-z_]\w*(?:\.\w+)*$/.test(key) ? keyOf(key, open) : null);
    if (nm && /^[\w.$-]+$/.test(nm)) out.push({ name: nm, off: open });
  }
  return out;
}

/** Class-like blocks of a file: {kind, name, a, b, bases}. */
function indexBlocks(mask) {
  const out = [];
  const re = /\b(class|mixin|enum|extension)\s+([A-Za-z_]\w*)?([^{};()]*)\{/g;
  let m;
  while ((m = re.exec(mask))) {
    const open = m.index + m[0].length - 1;
    const close = closeOf(mask, open);
    if (close < 0) continue;
    const bases = [...m[3].matchAll(/\b([A-Z]\w*)/g)].map((x) => x[1]);
    out.push({ kind: m[1], name: m[2] || (m[1] === 'extension' ? bases[0] : null), a: open + 1, b: close, bases });
    re.lastIndex = open + 1;
  }
  return out;
}

const blockAt = (blocks, off) => {
  let best = null;
  for (const b of blocks) if (b.a <= off && off < b.b && (!best || b.a > best.a)) best = b;
  return best;
};
/** Prefix bracket depth of a file (braces and parentheses): depth between two offsets is d[b] - d[a]. */
function depthIndex(mask) {
  const d = new Int32Array(mask.length + 1);
  let cur = 0;
  for (let k = 0; k < mask.length; k++) {
    d[k] = cur;
    if (mask[k] === '{' || mask[k] === '(') cur++;
    else if (mask[k] === '}' || mask[k] === ')') cur--;
  }
  d[mask.length] = cur;
  return d;
}

/** Functions / methods of a file: {name, cls, nameOff, a, b, params:[{name, type, index, named}]} (a..b: body range). */
function indexFunctions(code, mask, blocks) {
  const out = [];
  const re = /(^|[^\w.$])([A-Za-z_]\w*)\s*(?:<[^<>(){};]*>\s*)?\(/g;
  let m;
  while ((m = re.exec(mask))) {
    if (KEYWORDS.has(m[2])) continue;
    const open = m.index + m[0].length - 1;
    const close = closeOf(mask, open);
    if (close < 0) continue;
    const tail = /^\s*(?:async\*?|sync\*)?\s*(\{|=>)/.exec(mask.slice(close + 1, close + 60));
    if (!tail) continue;
    // `x ? foo(a) : …` / map entries never reach here: a call is not followed by `{` or `=>`
    const at = close + 1 + tail[0].length;
    let end;
    if (tail[1] === '{') end = closeOf(mask, at - 1);
    else {
      end = at;
      let depth = 0;
      for (; end < mask.length; end++) {
        const ch = mask[end];
        if ('([{'.includes(ch)) depth++;
        else if (')]}'.includes(ch)) { if (--depth < 0) break; } else if ((ch === ';' || ch === ',') && depth === 0) break;
      }
    }
    if (end < 0) continue;
    const params = [];
    let index = 0;
    const addParam = (raw, named) => {
      let t = raw.trim().replace(/^@\w+(?:\([^)]*\))?\s*/, '');
      t = t.replace(/\s*(?:=|:)(?![^<]*>).*$/s, '').replace(/\b(required|final|covariant|late|const|var)\s+/g, '').trim();
      const pm = /^(.*?)\s*\b([A-Za-z_]\w*)\s*$/s.exec(t.replace(/\([^)]*\)\s*$/, ''));
      if (!pm) return;
      params.push({ name: pm[2], type: pm[1].trim() || null, index: named ? -1 : index, named });
      if (!named) index++;
    };
    for (const part of splitArgs(code, mask, open + 1, close)) {
      const g = /^([{[])([\s\S]*)[}\]]$/.exec(part.text);
      if (!g) addParam(part.text, false);
      else {
        const bo = mask.indexOf(g[1], part.start);
        const bc = closeOf(mask, bo);
        if (bc > 0) for (const x of splitArgs(code, mask, bo + 1, bc)) addParam(x.text, g[1] === '{');
      }
    }
    const nameOff = m.index + m[1].length;
    out.push({ name: m[2], cls: blockAt(blocks, nameOff)?.name || null, nameOff, open, a: at, b: end, params, ret: mask.slice(Math.max(0, nameOff - 60), nameOff) });
    re.lastIndex = open + 1;
  }
  return out;
}

const fnAt = (fns, off) => {
  let best = null;
  for (const f of fns) if (f.a <= off && off < f.b && (!best || f.a > best.a)) best = f;
  return best;
};

/**
 * Project constants: qual 'Class.member' → [{text, rec, off}] (raw initialiser, resolved lazily), top-level names, and a
 * bare-name index used only when every class agrees on the value.
 */
function indexConstants(rec, index) {
  const { code, mask, blocks } = rec;
  const depths = depthIndex(mask);
  const add = (name, text, off) => {
    const b = blockAt(blocks, off);
    // class members sit at depth 0 of their block, top-level constants at depth 0 of the file; locals are not indexed
    if (depths[off] - depths[b ? b.a : 0] !== 0) return;
    const key = b?.name ? `${b.name}.${name}` : name;
    if (!index.qual.has(key)) index.qual.set(key, { text: text.trim(), rec, off, cls: b?.name || null });
    if (!index.bare.has(name)) index.bare.set(name, []);
    index.bare.get(name).push(key);
  };
  for (const m of code.matchAll(/\b(?:(?:static|late)\s+)*(?:const|final)\s+(?:String\??\s+)?([A-Za-z_]\w*)\s*=\s*(r?(?:'[^'\n]*'|"[^"\n]*")|[A-Z]\w*(?:\.\w+)+)\s*;/g)) add(m[1], m[2], m.index);
  for (const m of code.matchAll(/\b(?:static\s+)?String\s+get\s+([A-Za-z_]\w*)\s*=>\s*(r?(?:'[^'\n]*'|"[^"\n]*"))\s*;/g)) add(m[1], m[2], m.index);
  for (const m of code.matchAll(/\bstatic\s+(?:late\s+)?String\s+([A-Za-z_]\w*)\s*=\s*(r?(?:'[^'\n]*'|"[^"\n]*"))\s*;/g)) add(m[1], m[2], m.index);
  for (const b of blocks) {
    if (b.kind !== 'enum' || !b.name) continue;
    // enum Coll { users('users'), posts('posts'); … }  |  enum Coll { users, posts }
    const semi = mask.slice(b.a, b.b).indexOf(';');
    const end = semi < 0 ? b.b : b.a + semi;
    for (const part of splitArgs(code, mask, b.a, end)) {
      const em = /^([A-Za-z_]\w*)\s*(?:\(\s*(?:\w+\s*:\s*)?(r?(?:'[^']*'|"[^"]*"))[\s\S]*\))?$/.exec(part.text.trim());
      if (em) index.enums.set(`${b.name}.${em[1]}`, { name: em[1], value: em[2] ? strLit(em[2]) : null });
    }
  }
}

/** Identifiers bound to a FlutterFire / Supabase handle: `final FirebaseFirestore _db = FirebaseFirestore.instance;`. */
function handleNames(mask, typeRe, instRe) {
  const out = new Set();
  for (const m of mask.matchAll(new RegExp(`\\b(?:${typeRe})\\??\\s+(?:get\\s+)?([A-Za-z_]\\w*)\\s*(?:[=;,)]|=>)`, 'g'))) out.add(m[1]);
  for (const m of mask.matchAll(new RegExp(`\\b([A-Za-z_]\\w*)\\s*(?:=|=>)\\s*(?:${instRe})`, 'g'))) out.add(m[1]);
  for (const m of mask.matchAll(new RegExp(`\\bget\\s+([A-Za-z_]\\w*)\\s*=>\\s*(?:${instRe})`, 'g'))) out.add(m[1]);
  return out;
}

// ---------------------------------------------------------------------------

const DYN = null;
const isParam = (x) => !!x && typeof x === 'object';
const PATH_SEG = /^[\w$@.:-]+$/;

/**
 * Resolver over the project index.
 *   parts(text, env)  string expression → [string | null | {param}]
 *   segs(text, env)   path expression → path segments, same element types
 *   str(text, env)    constant string or null
 * env = { rec, off, fn } (where the expression stands).
 */
function makeResolver(index) {
  const localInit = (name, env) => {
    const { rec, off, fn } = env;
    if (!fn) return null;
    const from = fn.a;
    const before = rec.mask.slice(from, off);
    const re = new RegExp(String.raw`(?:^|[^\w.$])${name}\s*(?:\?\?)?=(?!=|>)\s*`, 'g');
    let last = null;
    let m;
    while ((m = re.exec(before))) last = m;
    if (!last) return null;
    const at = from + last.index + last[0].length;
    const st = statementAt(rec.code, rec.mask, at);
    return { text: rec.code.slice(at, st.end), at };
  };
  const ofKey = (key, depth) => {
    const c = index.qual.get(key);
    if (!c || depth > 4) return undefined;
    return parts(c.text, { rec: c.rec, off: c.off, fn: null, cls: c.cls }, depth + 1);
  };
  const single = (ps) => (ps && ps.every((x) => typeof x === 'string') ? ps.join('') : null);
  function ident(chain, env, depth) {
    const bits = chain.replace(/\s+/g, '').replace(/^this\./, '').split('.');
    const cls = env.cls ?? env.fn?.cls ?? null;
    if (bits.length === 1) {
      const n = bits[0];
      // innermost function first, then the enclosing ones
      const fns = env.fn ? env.rec.fns.filter((f) => f.a <= env.off && env.off < f.b).sort((a, b) => b.a - a.a) : [];
      for (const f of fns) {
        const li = localInit(n, { ...env, fn: f });
        if (li && /^\s*(?:r?['"]|[A-Za-z_][\w.]*\s*;?\s*$)/.test(li.text) && depth < 4) return parts(li.text, { ...env, off: li.at, fn: f }, depth + 1);
        if (li) return [DYN];
        if (f.params.some((p) => p.name === n)) return [{ param: n, fn: f }];
      }
      const own = cls ? ofKey(`${cls}.${n}`, depth) : undefined;
      if (own) return own;
      const top = ofKey(n, depth);
      if (top) return top;
      return [DYN];
    }
    for (let k = bits.length; k >= 2; k--) {
      const en = index.enums.get(bits.slice(k - 2, k).join('.'));
      if (!en) continue;
      const tail = bits[k];
      if (tail === 'name') return [en.name];
      if (tail) return [en.value ?? DYN];
    }
    const key = bits.slice(-2).join('.');
    const q = ofKey(key, depth);
    if (q) return q;
    const last = bits[bits.length - 1];
    if (last === 'toString') return [DYN];
    // A member of something else (an instance, a prefix import): only when the name is unambiguous in the project.
    const keys = index.bare.get(last) || [];
    const vals = [...new Set(keys.map((k) => single(ofKey(k, depth + 1))).filter((x) => x != null))];
    if (keys.length && vals.length === 1 && !index.classNames.has(bits[bits.length - 2])) return [vals[0]];
    return [DYN];
  }
  function parts(text, env, depth = 0) {
    let t = String(text || '').trim().replace(/;$/, '').trim();
    if (!t || depth > 6) return [DYN];
    if (/^\(.*\)$/s.test(t) && closeOf(lexDart(t).mask, 0) === t.length - 1) t = t.slice(1, -1).trim();
    const lx = lexDart(t);
    // concatenation
    const plus = [];
    let depthB = 0;
    let start = 0;
    for (let k = 0; k < lx.mask.length; k++) {
      const ch = lx.mask[k];
      if ('([{'.includes(ch)) depthB++;
      else if (')]}'.includes(ch)) depthB--;
      else if (ch === '+' && depthB === 0) {
        plus.push(t.slice(start, k));
        start = k + 1;
      }
    }
    if (plus.length) return [...plus, t.slice(start)].flatMap((x) => parts(x, env, depth + 1));
    const raw = /^r(['"])/.test(t);
    const sm = /^r?(['"])([\s\S]*)\1$/.exec(t);
    if (sm && lx.mask.replace(/^r/, '').slice(1, -1).trim() === '') {
      if (raw) return [sm[2]];
      const body = sm[2];
      const out = [];
      let k = 0;
      let buf = '';
      while (k < body.length) {
        if (body[k] === '\\') {
          buf += body[k + 1] || '';
          k += 2;
          continue;
        }
        if (body[k] === '$') {
          let expr = null;
          if (body[k + 1] === '{') {
            let d = 0;
            let j = k + 1;
            for (; j < body.length; j++) {
              if (body[j] === '{') d++;
              else if (body[j] === '}' && --d === 0) break;
            }
            expr = body.slice(k + 2, j);
            k = j + 1;
          } else {
            const im = /^[A-Za-z_]\w*/.exec(body.slice(k + 1));
            if (!im) {
              buf += '$';
              k++;
              continue;
            }
            expr = im[0];
            k += 1 + im[0].length;
          }
          out.push(buf);
          buf = '';
          out.push(...parts(expr, env, depth + 1));
          continue;
        }
        buf += body[k++];
      }
      out.push(buf);
      return out;
    }
    const id = /^[A-Za-z_]\w*(?:\s*[!?]?\.\s*[A-Za-z_]\w*)*$/.exec(t);
    if (id) return ident(t.replace(/[!?]/g, ''), env, depth);
    return [DYN];
  }
  function segs(text, env) {
    const out = [];
    let cur = '';
    let dyn = null; // null | 'dyn' | {param}
    let mixed = false;
    const flush = () => {
      if (dyn) out.push(isParam(dyn) && !mixed && !cur ? dyn : DYN);
      else if (cur) out.push(PATH_SEG.test(cur) ? cur : DYN);
      cur = '';
      dyn = null;
      mixed = false;
    };
    for (const p of parts(text, env)) {
      if (typeof p !== 'string') {
        if (dyn) mixed = true;
        dyn = isParam(p) ? p : 'dyn';
        continue;
      }
      p.split('/').forEach((b, i) => {
        if (i) flush();
        cur += b;
      });
    }
    flush();
    return out;
  }
  const str = (text, env) => {
    const ps = parts(text, env);
    const v = single(ps);
    return v && v.length ? v : null;
  };
  return { parts, segs, str };
}

/**
 * Path of a Firestore chain's segments (+ base path from a held reference): alternating collection / document segments
 * (string | null | {param}). → { path, rest, converter, group }
 */
function chainPath(base, segs, R, env) {
  const path = base ? base.slice() : [];
  let group = false;
  let i = 0;
  for (; i < segs.length; i++) {
    const s = segs[i];
    const arg = s.args?.[0];
    const at = arg ? { ...env, off: arg.start } : env;
    if (s.name === 'collection' || s.name === 'collectionGroup') {
      if (path.length % 2 === 1) path.push(DYN); // a missing document step cannot be addressed
      path.push(...(arg ? R.segs(arg.text, at) : [DYN]));
      if (s.name === 'collectionGroup') group = true;
    } else if (s.name === 'doc') {
      if (!arg || path.length % 2 === 1) {
        // .doc(): auto id; .doc('a/b') under a collection addresses a deeper document
        const d = arg ? R.segs(arg.text, at) : [DYN];
        path.push(...(d.length % 2 === 1 ? d : [DYN]));
      } else path.push(...R.segs(arg.text, at));
    } else if (!/^(where|orderBy|limit|limitToLast|startAt|startAtDocument|startAfter|startAfterDocument|endAt|endBefore|withConverter)$/.test(s.name)) break;
  }
  return { path, group, rest: segs.slice(i), converter: segs.slice(0, i).find((s) => s.name === 'withConverter')?.generic || null };
}

/** Store key of a Firestore path: the collection ids; a dynamic sub-collection is '{dynamic}'. null: first collection unknown. */
function collectionKey(path) {
  const colls = path.filter((_, i) => i % 2 === 0);
  if (!colls.length || typeof colls[0] !== 'string') return null;
  return colls.map((c) => (typeof c === 'string' ? c : '{dynamic}')).join('/');
}
const recordName = (key) => {
  const lits = key.split('/').filter((x) => x !== '{dynamic}');
  return key.includes('{dynamic}') ? lits[lits.length - 1] : key;
};
const isDocPath = (path) => path.length > 0 && path.length % 2 === 0;

export function extract(ctx) {
  const dartFiles = (ctx.files || []).filter((f) => !f.test && /\.dart$/i.test(f.rel) && !/\.(g|freezed|mocks)\.dart$/.test(f.rel) && !/(^|\/)firebase_options\.dart$/.test(f.rel));
  if (!dartFiles.length) return;
  const { graph, ev } = ctx;
  const recs = dartFiles.map((f) => {
    const src = f.content.replace(/\r\n?/g, '\n');
    const { code, mask } = lexDart(src);
    const blocks = indexBlocks(mask);
    return { f, src, code, mask, imports: importsOf(code), blocks, fns: indexFunctions(code, mask, blocks) };
  });
  const classes = new Map();
  const index = { qual: new Map(), bare: new Map(), enums: new Map(), classNames: new Set(), bases: new Map() };
  for (const r of recs) {
    for (const b of r.blocks) {
      if (!b.name) continue;
      index.classNames.add(b.name);
      if (!index.bases.has(b.name)) index.bases.set(b.name, b.bases);
    }
    indexConstants(r, index);
  }
  const R = makeResolver(index);
  const keyOfIn = (r) => (text, off) => {
    const v = R.str(text, { rec: r, off, fn: fnAt(r.fns, off) });
    return v && /^[\w.$-]+$/.test(v) ? v : null;
  };
  for (const r of recs) {
    try {
      indexClasses(r.f, r.code, r.mask, classes, keyOfIn(r));
    } catch (e) {
      ctx.warn?.(`dart: ${r.f.rel}: ${e.message}`);
    }
  }
  // Handles: names project-wide (fields are often declared in a service and used through it).
  const fsNames = new Set();
  const authNames = new Set();
  const storageNames = new Set();
  const sbNames = new Set();
  for (const r of recs) {
    for (const n of handleNames(r.mask, 'FirebaseFirestore', 'FirebaseFirestore\\s*\\.\\s*instance')) fsNames.add(n);
    for (const n of handleNames(r.mask, 'FirebaseAuth', 'FirebaseAuth\\s*\\.\\s*instance')) authNames.add(n);
    for (const n of handleNames(r.mask, 'FirebaseStorage', 'FirebaseStorage\\s*\\.\\s*instance')) storageNames.add(n);
    for (const n of handleNames(r.mask, 'SupabaseClient', 'Supabase\\s*\\.\\s*instance\\s*\\.\\s*client')) sbNames.add(n);
  }

  const tables = new Map();
  const writes = []; // {key, fields:[{name,line,file}], rel, line, snippet, fn, op}
  const deletions = []; // {target, rel, line, snippet, fn, account}
  const authFlows = []; // {names, rel, line, snippet, store:boolean}
  const uploads = [];
  const unparsed = new Map(); // layer -> Set(rel)
  const summaries = []; // wrapper methods: {fn, rec, kind, segs, op, data, converter}
  const globalRefs = new Map(); // top-level / static references: name or Class.name → {path, kind}
  const refFns = new Map(); // method returning a reference: name → [{path, kind, fn, rec}]
  const sdkImport = { firebase: null, supabase: null };
  const writtenElements = new Set();
  const addUnparsed = (layer, rel) => {
    if (!unparsed.has(layer)) unparsed.set(layer, new Set());
    unparsed.get(layer).add(rel);
  };
  const ensureTable = (key, props) => {
    if (!tables.has(key)) {
      const parentKey = key.includes('/') ? key.split('/').slice(0, -1).join('/') : null;
      const tech = props?.tech || 'firestore';
      const { tech: _t, ...rest } = props || {};
      tables.set(key, newTable(key, { name: recordName(key), kind: 'collection', rls: null, source: tech === 'firestore' ? 'firestore-code' : tech, ...rest, extra: { inferred: true, codeOps: [], tech, provider: tech, language: 'dart', ...(parentKey ? { subcollectionOf: parentKey } : {}) } }));
    }
    return tables.get(key);
  };
  const addCols = (t, fields, rel) => {
    for (const fl of fields) {
      if (!fl.name || t.columns.has(fl.name)) continue;
      t.columns.set(fl.name, { name: fl.name, type: 'any', file: fl.file || rel, line: fl.line, snippet: fl.snippet });
    }
  };

  /** Fields of a write's data argument. → {fields, resolved, param?} (param: the enclosing function's parameter holding the map) */
  const dataFields = (r, argText, argStart, converter, depth = 0) => {
    if (!argText || depth > 4) return { fields: [], resolved: false };
    const t = argText.trim();
    const off = argStart + (argText.length - argText.trimStart().length);
    const keyOf = keyOfIn(r);
    const lineSnip = (o) => ({ line: lineAt(r.src, o), file: r.f.rel, snippet: r.src.split('\n')[lineAt(r.src, o) - 1]?.trim() });
    if (t.startsWith('{') || /^(?:const\s+)?<[^{}]*>\s*\{/.test(t)) {
      const open = r.mask.indexOf('{', off);
      const { keys, spreads } = mapEntries(r.code, r.mask, open, keyOf);
      const fields = keys.map((k) => ({ name: k.name, ...lineSnip(k.off) }));
      let param = null;
      for (const sp of spreads) {
        const x = dataFields(r, sp.text, sp.start, null, depth + 1);
        param ||= x.param || null;
        for (const fl of x.fields) if (!fields.some((y) => y.name === fl.name)) fields.push(fl);
      }
      return { fields, resolved: true, ...(param ? { param } : {}) };
    }
    if (/^(?:Map|LinkedHashMap|HashMap)(?:<[^{}()]*>)?\s*(?:\.\s*(?:from|of)\s*)?\(/.test(t) && t.endsWith(')')) {
      const open = r.mask.indexOf('(', off);
      const a = splitArgs(r.code, r.mask, open + 1, closeOf(r.mask, open))[0];
      return a ? dataFields(r, a.text, a.start, null, depth + 1) : { fields: [], resolved: true };
    }
    const fromClass = (clsName) => {
      const c = classes.get(String(clsName || '').replace(/^.*\./, '').replace(/[?<].*$/, ''));
      if (!c) return null;
      const list = c.toMap.length ? c.toMap : c.jsonSerializable || c.fields.length ? c.fields : c.fromMap;
      return list.length ? list.map((x) => ({ name: x.name, line: x.line, file: c.file })) : null;
    };
    // x.toJson() / Model(...).toMap()
    const call = /^(.*?)\s*[!?]?\.\s*(toJson|toMap|toFirestore|toDocument|toFirebase|toFireStore|toJSON|toData)\s*\(\s*\)$/s.exec(t);
    const typeOfVar = (v) => {
      const before = r.code.slice(Math.max(0, argStart - 8000), argStart);
      const last = v;
      const decl = [...before.matchAll(new RegExp(`\\b((?:[A-Za-z_]\\w*\\.)?[A-Z]\\w*)\\??\\s+${v}\\s*(?:=|[,)])`, 'g'))].pop();
      if (decl) return decl[1];
      const ctor = [...before.matchAll(new RegExp(`\\b(?:final|var|const)\\s+${v}\\s*=\\s*(?:new\\s+|const\\s+)?((?:[A-Za-z_]\\w*\\.)?[A-Z]\\w*)\\s*[(.]`, 'g'))].pop();
      if (ctor) return ctor[1];
      // a field of the class / widget: `final Member member;`
      const field = new RegExp(`\\b(?:final|late|required)\\s+((?:[A-Za-z_]\\w*\\.)?[A-Z]\\w*)\\??\\s+${last}\\s*[;=]`).exec(r.code);
      return field ? field[1] : null;
    };
    if (call) {
      const recv = call[1].trim();
      const ctorM = /^(?:new\s+|const\s+)?((?:[A-Za-z_]\w*\.)?[A-Z]\w*)\s*\(/.exec(recv);
      const cls = ctorM ? ctorM[1] : /^(?:\w+[!?]?\.)*_?[a-z]\w*$/.test(recv) ? typeOfVar(recv.split('.').pop()) : null;
      const fl = cls ? fromClass(cls) : null;
      return fl ? { fields: fl, resolved: true } : { fields: [], resolved: false };
    }
    if (/^[A-Za-z_]\w*[!]?$/.test(t)) {
      const v = t.replace('!', '');
      if (converter) {
        const fl = fromClass(converter);
        if (fl) return { fields: fl, resolved: true };
      }
      // a variable of the same function: map literal, toJson() result, and the keys assigned to it afterwards
      const fn = fnAt(r.fns, argStart);
      const a = fn ? fn.a : Math.max(0, argStart - 6000);
      const before = r.mask.slice(a, argStart);
      const re = new RegExp(`(?:^|[^\\w.$])${v}\\s*=(?!=|>)\\s*`, 'g');
      let last = null;
      let mm;
      while ((mm = re.exec(before))) last = mm;
      const assigned = indexAssignments(r.code, r.mask, a, argStart, v, keyOf).map((k) => ({ name: k.name, ...lineSnip(k.off) }));
      for (const am of r.mask.slice(a, argStart).matchAll(new RegExp(`(?:^|[^\\w.$])${v}\\s*\\.\\s*addAll\\s*\\(`, 'g'))) {
        const open = a + am.index + am[0].length - 1;
        const arg = splitArgs(r.code, r.mask, open + 1, closeOf(r.mask, open))[0];
        if (arg) assigned.push(...dataFields(r, arg.text, arg.start, null, depth + 1).fields);
      }
      const merge = (x) => {
        const fields = [...x.fields];
        for (const fl of assigned) if (!fields.some((y) => y.name === fl.name)) fields.push(fl);
        return { ...x, fields, resolved: x.resolved || assigned.length > 0 };
      };
      if (last) {
        const at = a + last.index + last[0].length;
        const st = statementAt(r.code, r.mask, at);
        const rhs = r.code.slice(at, st.end);
        const x = dataFields(r, rhs, at, null, depth + 1);
        if (x.resolved || x.fields.length || x.param) return merge(x);
      }
      const p = r.fns.filter((x) => x.a <= argStart && argStart < x.b).find((x) => x.params.some((y) => y.name === v));
      const pType = p?.params.find((y) => y.name === v)?.type || '';
      if (p && (!pType || /^(?:Map\b|dynamic\b|Object\b|var\b|final\b)/.test(pType))) return merge({ fields: [], resolved: assigned.length > 0, param: { param: v, fn: p } });
      const cls = typeOfVar(v);
      const fl = cls ? fromClass(cls) : null;
      if (fl) return merge({ fields: fl, resolved: true });
      if (assigned.length) return merge({ fields: [], resolved: true });
    }
    // a helper of the project returning the map: `_toPayload(user)` / `user.payload()`
    const helper = /(?:^|\.)([a-z_]\w*)\s*\([\s\S]*\)$/.exec(t);
    if (helper) {
      const hits = recs.flatMap((x) => x.fns.filter((y) => y.name === helper[1] && /\bMap\b[^;{}]*$/.test(y.ret)).map((y) => ({ rec: x, fn: y })));
      if (hits.length === 1) {
        const { rec, fn } = hits[0];
        const fields = [];
        for (const lm of rec.mask.slice(fn.a, fn.b).matchAll(/(?:\breturn|=|=>|^)\s*(?:<[^<>{}]*>\s*)?\{/g)) {
          const open = fn.a + lm.index + lm[0].length - 1;
          for (const k of mapEntries(rec.code, rec.mask, open, keyOfIn(rec)).keys) if (!fields.some((y) => y.name === k.name)) fields.push({ name: k.name, line: lineAt(rec.src, k.off), file: rec.f.rel });
        }
        if (fields.length) return { fields, resolved: true };
      }
    }
    return { fields: [], resolved: false };
  };

  const DB_NAMES = ['_firestore', 'firestore', '_db', 'db', '_fireStore', 'fireStore', 'firebaseFirestore', '_firebaseFirestore'];
  /** Held reference visible at an offset: same function (latest before), the file's fields / top level, shared refs. */
  const lookupRef = (r, name, off) => {
    const fns = r.fns.filter((x) => x.a <= off && off < x.b).sort((a, b) => b.a - a.a);
    const all = r.refs || [];
    for (const fn of fns) {
      const c = all.filter((x) => x.name === name && x.fn === fn && x.start < off).pop();
      if (c) return c;
      if (fn.params.some((p) => p.name === name)) return null; // a parameter shadows fields
    }
    return all.filter((x) => x.name === name && !x.fn).pop() || globalRefs.get(name) || null;
  };
  /** Does a shared (top-level / static) reference or a reference-returning method appear in this file? */
  function hasSharedRef(mask) {
    for (const n of globalRefs.keys()) if (new RegExp(`\\b${n.replace('.', '\\s*\\.\\s*')}\\b`).test(mask)) return true;
    for (const n of refFns.keys()) if (new RegExp(`\\b${n}\\s*\\(`).test(mask)) return true;
    return false;
  }
  /** Realtime Database reference segments: path of ref()/child()/push() + the remaining segments. */
  const rtdbChain = (base, segs, env) => {
    const path = base.slice();
    let i = 0;
    for (; i < segs.length; i++) {
      const s = segs[i];
      const arg = s.args?.[0];
      if (/^(ref|reference|child)$/.test(s.name) && s.args) {
        if (arg && !/^path\s*:/.test(arg.text)) path.push(...R.segs(arg.text, { ...env, off: arg.start }));
      } else if (s.name === 'push' && s.args && !s.args.length) path.push(DYN);
      else if (!/^(orderBy\w*|limitTo\w*|equalTo|startAt|startAfter|endAt|endBefore)$/.test(s.name)) break;
    }
    return { path, rest: segs.slice(i) };
  };
  /** A reference expression starting at `start`. → {kind, path, rest, converter, group, end} | null */
  function refOfExpr(r, start, localFs, depth = 0) {
    const { code, mask } = r;
    if (depth > 4) return null;
    let at = start;
    const pre = /^(?:await\s+|this\s*\.\s*)+/.exec(mask.slice(at, at + 60));
    if (pre) at += pre[0].length;
    const chain = parseChain(code, mask, at);
    if (!chain) return null;
    const env = { rec: r, off: at, fn: fnAt(r.fns, at) };
    const root = chain.root;
    let segs = chain.segs;
    const fire = (base, rest) => ({ kind: 'firestore', ...chainPath(base, rest, R, env), end: chain.end });
    const rtdb = (base, rest) => ({ kind: 'rtdb', ...rtdbChain(base, rest, env), end: chain.end });
    if (root.name === 'FirebaseFirestore' && !root.args) return fire(null, segs.slice(/^instance(For)?$/.test(segs[0]?.name || '') ? 1 : 0));
    if (root.name === 'FirebaseDatabase' && !root.args) return rtdb([], segs.slice(/^instance(For)?$/.test(segs[0]?.name || '') ? 1 : 0));
    if (!root.args) {
      const held = lookupRef(r, root.name, at) || (segs[0] && !segs[0].args ? globalRefs.get(`${root.name}.${segs[0].name}`) : null);
      if (held) {
        const rest = held.name && held.name.includes('.') ? segs.slice(1) : segs;
        return held.kind === 'firestore' ? fire(held.path, rest) : rtdb(held.path, rest);
      }
    }
    // a handle, possibly behind another object: `_service.firestore.collection('x')`
    const h = [root, ...segs].findIndex((x) => !x.args && localFs.has(x.name));
    const hd = [root, ...segs].findIndex((x) => !x.args && rtdbNames.has(x.name));
    const after = (i) => [root, ...segs].slice(i + 1);
    if (h >= 0 && /^(collection|doc|collectionGroup)$/.test(after(h)[0]?.name || '') && (h === 0 || fsNames.has([root, ...segs][h].name))) return fire(null, after(h));
    if (hd >= 0 && /^(ref|reference|child)$/.test(after(hd)[0]?.name || '')) return rtdb([], after(hd));
    if (!root.args && r.imports.includes('cloud_firestore') && /^(collection|doc)$/.test(segs[0]?.name || '') && segs[0].args && /^(_?\w*(firestore|Firestore|db|Db|DB)\w*)$/.test(root.name)) return fire(null, segs);
    // a method that returns a reference: userDoc(uid).set(…) / repo.userDoc(uid)
    const list = [root, ...segs];
    const j = list.findIndex((x) => x.args && refFns.has(x.name));
    if (j >= 0) {
      const cands = refFns.get(list[j].name);
      const c = cands.length === 1 ? cands[0] : null;
      if (c) {
        const path = substitute(c.path, c.fn, list[j], r, at);
        return c.kind === 'firestore' ? fire(path, list.slice(j + 1)) : rtdb(path, list.slice(j + 1));
      }
    }
    return null;
  }
  /** Argument of a call for a parameter. */
  const argFor = (param, seg) => {
    const args = seg.args || [];
    if (param.named) {
      const a = args.find((x) => new RegExp(`^${param.name}\\s*:`).test(x.text));
      if (!a) return null;
      const m = /^\w+\s*:\s*/.exec(a.text);
      return { text: a.text.slice(m[0].length), start: a.start + (a.text.length ? a.end - a.start - a.text.length : 0) + m[0].length };
    }
    const pos = args.filter((x) => !/^[A-Za-z_]\w*\s*:(?!:)/.test(x.text) || /^['"]/.test(x.text));
    return pos[param.index] || null;
  };
  /** Path with the parameters of `fn` replaced by the arguments of a call. */
  function substitute(path, fn, seg, rec, at) {
    return path.flatMap((x) => {
      if (!isParam(x)) return [x];
      if (x.fn !== fn) return [DYN];
      const p = fn.params.find((y) => y.name === x.param);
      const a = p && argFor(p, seg);
      if (!a) return [DYN];
      const out = R.segs(a.text, { rec, off: a.start ?? at, fn: fnAt(rec.fns, a.start ?? at) });
      return out.length ? out : [DYN];
    });
  }
  const trimStart = (r, a, b) => a + (r.code.slice(a, b).length - r.code.slice(a, b).trimStart().length);
  /** Reference expressions of a file: {start, kind, path, rest, converter, group}. */
  function refChains(r, localFs) {
    const { mask } = r;
    const starts = new Set();
    const push = (re, g = 1) => {
      for (const m of mask.matchAll(re)) {
        const st = m.index + (m[0].length - m[0].trimStart().length);
        void g;
        starts.add(st);
      }
    };
    push(/\bFirebaseFirestore\b|\bFirebaseDatabase\b/g);
    push(/\b[A-Za-z_]\w*\s*[!?]?\s*\??\.\s*(?:collection|collectionGroup|doc|ref|reference)\s*\(/g);
    for (const x of r.refs || []) push(new RegExp(`\\b${x.name.split('.').pop()}\\s*[!?]?\\s*\\??\\.\\s*[A-Za-z_]`, 'g'));
    for (const n of globalRefs.keys()) push(new RegExp(`\\b${n.replace('.', '\\s*\\.\\s*')}\\s*[!?]?\\s*\\.\\s*[A-Za-z_]`, 'g'));
    for (const n of refFns.keys()) push(new RegExp(`\\b(?:[A-Za-z_]\\w*(?:\\(\\))?\\s*[!?]?\\.\\s*)?${n}\\s*\\(`, 'g'));
    const out = [];
    for (const st of [...starts].sort((a, b) => a - b)) {
      // middle of a longer chain (`x.y.collection`): only a known handle / `this.` field starts one there
      const head = mask.slice(Math.max(0, st - 12), st);
      const nm = /^[A-Za-z_]\w*/.exec(mask.slice(st, st + 80))?.[0];
      if (/\.\s*$/.test(head) && !/\bthis\s*\.\s*$/.test(head) && !fsNames.has(nm) && !rtdbNames.has(nm)) continue;
      if (/[\w$]$/.test(head)) continue;
      const ref = refOfExpr(r, st, localFs);
      if (ref) out.push({ start: st, ...ref });
    }
    // drop chains that start inside another one's receiver (`_db` of `service._db.collection`)
    return out.filter((c) => !out.some((o) => o !== c && o.start < c.start && c.start < o.end && o.end === c.end));
  }
  /** Bindings: held references, reference getters / methods, shared references. */
  function scanRefs(r, localFs) {
    r.refs ||= [];
    const { code, mask } = r;
    for (let pass = 0; pass < 2; pass++) {
      for (const c of refChains(r, localFs)) {
        if (c.rest.length || c.group || (!c.path.length && c.kind !== 'rtdb')) continue;
        const st = statementAt(code, mask, c.start);
        const lead = code.slice(st.start, c.start);
        const fn = fnAt(r.fns, c.start);
        const getter = /\bget\s+([A-Za-z_]\w*)\s*=>\s*(?:this\s*\.\s*)?$/.exec(code.slice(Math.max(0, c.start - 160), c.start)) || /\bget\s+([A-Za-z_]\w*)\s*\{\s*return\s+(?:this\s*\.\s*)?$/.exec(code.slice(Math.max(0, c.start - 160), c.start));
        const assign = /(?:^|[\s(])(?:[\w<>,?\s]+\s+)?([A-Za-z_]\w*)\s*=\s*(?:await\s+)?(?:this\s*\.\s*)?$/.exec(lead);
        const name = getter?.[1] || assign?.[1];
        if (name) {
          const b = blockAt(r.blocks, c.start);
          const scope = getter ? null : fn;
          const entry = { name, path: c.path, kind: c.kind, start: c.start, fn: scope, converter: c.converter };
          if (!r.refs.some((x) => x.name === name && x.start === c.start)) r.refs.push(entry);
          if (!scope && !b && !globalRefs.has(name)) globalRefs.set(name, { ...entry, name });
          if (!scope && b?.name && (getter || /\bstatic\b/.test(lead)) && !globalRefs.has(`${b.name}.${name}`) && /\bstatic\b/.test(code.slice(Math.max(0, c.start - 200), c.start).split(/[;{}]/).pop())) globalRefs.set(`${b.name}.${name}`, { ...entry, name: `${b.name}.${name}` });
          continue;
        }
        // `DocumentReference userDoc(String uid) => _db.collection('users').doc(uid);`
        if (fn && !/^(main|build)$/.test(fn.name)) {
          const body = mask.slice(fn.a, c.start).trim();
          const after = mask.slice(c.end, fn.b).trim();
          if (/^(return(\s+this\s*\.)?)?$/.test(body) && /^;?$/.test(after)) {
            const list = refFns.get(fn.name) || [];
            if (!list.some((x) => x.rec === r && x.fn === fn)) list.push({ path: c.path, kind: c.kind, fn, rec: r });
            refFns.set(fn.name, list);
          }
        }
      }
    }
  }
  const visitOp = (r, c) => {
    const seg = c.rest[0];
    const op = seg?.name;
    if (!op || !seg.args) return;
    if (c.kind === 'firestore') {
      if (c.group || !c.path.length) return;
      if (/^(set|update|add|delete|get|snapshots)$/.test(op)) applyOp({ rec: r, kind: 'firestore', path: c.path, op, data: seg.args[0] || null, converter: c.converter, at: c.start });
      else if (c.path.length) applyOp({ rec: r, kind: 'firestore', path: c.path, op: 'ref', at: c.start });
    } else if (/^(set|setWithPriority|update|remove|push|get|once|onValue|onChild\w+)$/.test(op)) {
      if (op === 'push') return;
      const isDel = op === 'remove' || (op === 'set' && /^null$/.test(seg.args[0]?.text || ''));
      applyOp({ rec: r, kind: 'rtdb', path: c.path, op: isDel ? 'delete' : /^(get|once|on)/.test(op) ? 'get' : op, data: seg.args[0] || null, at: c.start });
    }
  };
  /**
   * One operation on a resolved path: emits the store and the write, or — when the path's head or the data map is a
   * parameter of the enclosing method — a summary that is instantiated at its call sites.
   */
  function applyOp(o) {
    const { rec: r, kind, op } = o;
    const line = lineAt(r.src, o.at);
    const snippet = (r.src.split('\n')[line - 1] || '').trim().slice(0, 200);
    const fnRec = fnAt(r.fns, o.at);
    const fn = fnRec?.name || enclosingFn(r.mask, o.at);
    const write = /^(set|setWithPriority|update|add)$/.test(op);
    const isDelete = op === 'delete';
    let data = { fields: [], resolved: !write };
    if (write) data = o.fields ? { fields: o.fields, resolved: true } : dataFields(r, o.data?.text, o.data?.start ?? 0, o.converter);
    const headParam = kind === 'firestore' ? isParam(o.path[0]) : o.path.length > 0 && !o.path.some((x) => typeof x === 'string') && o.path.some(isParam);
    const dataParam = write && data.param && data.param.fn === fnRec;
    const depth = o.depth || 0;
    if ((headParam || dataParam) && (write || isDelete) && fnRec && depth < 3) {
      summaries.push({ rec: r, fn: fnRec, kind, path: o.path, op, batch: o.batch, dataParam: dataParam ? data.param.param : null, fields: data.fields, resolved: data.resolved, depth, done: false, hit: false, origin: o.origin || r.f.rel });
      if (headParam) return;
    } else if (headParam) {
      if (write || isDelete) addUnparsed('dbWrites', r.f.rel);
      return;
    }
    let key = null;
    let column = null;
    if (kind === 'firestore') key = collectionKey(o.path);
    else {
      const k = rtdbKey(o.path.map((x) => (isParam(x) ? null : x)));
      key = k?.key || null;
      column = k?.column || null;
    }
    if (!key) {
      if (write || isDelete) addUnparsed('dbWrites', r.f.rel);
      return;
    }
    const tech = kind === 'rtdb' ? 'firebase-rtdb' : 'firestore';
    if (kind === 'rtdb' && tables.get(key)?.extra?.tech === 'firestore') key = `rtdb:${key}`;
    const t = ensureTable(key, { file: r.f.rel, line, snippet, tech });
    const opName = o.batch ? `batch.${op}` : op;
    if (op !== 'ref' && !t.extra.codeOps.includes(opName)) t.extra.codeOps.push(opName);
    if (write) {
      let fields = data.fields;
      if (kind === 'rtdb' && column && !fields.length) fields = [{ name: column, line, file: r.f.rel }];
      if (!data.resolved && !dataParam && !fields.length) addUnparsed('dbWrites', r.f.rel);
      if (!t._firstWrite && !o.batch) {
        t._firstWrite = true;
        Object.assign(t, { file: r.f.rel, line, snippet });
      }
      fields = fields.map((x) => (x.name.includes('.') ? { ...x, name: x.name.split('.')[0] } : x)); // 'address.city' updates a nested member
      addCols(t, fields, r.f.rel);
      writes.push({ key, fields, rel: r.f.rel, line, snippet, fn, op: opName.replace(/^batch\./, '') });
    } else if (isDelete) {
      if (kind === 'firestore' && !isDocPath(o.path)) return;
      if (kind === 'rtdb' && column) return;
      deletions.push({ target: `store:table:${key}`, key, rel: r.f.rel, line, snippet, fn });
      writes.push({ key, fields: [], rel: r.f.rel, line, snippet, fn, op: 'delete' });
    } else if (op === 'get' || op === 'snapshots') {
      // Model.fromX(<snapshot of this collection>) in the same statement or through the variable it is assigned to
      const { code, mask } = r;
      const stmt = statementAt(code, mask, o.at);
      const assign = /(?:^|[\s(])(?:[\w<>,?\s]+\s+)?([A-Za-z_]\w*)\s*=\s*(?:await\s+)?$/.exec(code.slice(stmt.start, o.at));
      const after = code.slice(stmt.start, Math.min(code.length, stmt.end + 1500));
      const v = assign ? assign[1] : null;
      const re = /\b([A-Z]\w*)\s*\.\s*(from\w*)\s*\(\s*([^),]*)/g;
      let m;
      while ((m = re.exec(after))) {
        if (!/^from(Json|Map|Snap|Snapshot|Firestore|Document|Doc|Data|Firebase|DocumentSnapshot)/i.test(m[2])) continue;
        if (stmt.start + m.index > stmt.end && !(v && new RegExp(`\\b${v}\\b`).test(m[3]))) continue;
        const c = classes.get(m[1]);
        if (c) addCols(t, (c.fromMap.length ? c.fromMap : c.toMap).map((x) => ({ name: x.name, line: x.line, file: c.file })), r.f.rel);
      }
    }
  }
  /** Class of a call's receiver: declared field / variable type, `context.read<T>()`, `T(…)`, `T.instance`, `Get.find<T>()`. */
  const receiverClass = (r, at) => {
    const head = r.mask.slice(Math.max(0, at - 220), at).replace(/\s+$/, '');
    if (!/\.$/.test(head)) return { bare: true };
    const recv = /([A-Za-z_]\w*)\s*(?:<\s*([A-Z]\w*)\s*>\s*)?(?:\([^()]*(?:\([^()]*\)[^()]*)*\))?\s*(?:\.\s*(instance|I|notifier))?\s*[!?]*\.{1,2}$/.exec(head);
    if (!recv) return { unknown: true };
    if (recv[2]) return { cls: recv[2] };
    if (recv[1] === 'this') return { bare: true };
    if (/^[A-Z]/.test(recv[1])) return { cls: recv[1], name: recv[1] };
    const v = recv[1];
    const ty = new RegExp(`\\b(?!return\\b|final\\b|late\\b|var\\b)([A-Z]\\w*)(?:<[^<>;=]*>)?\\??\\s+${v}\\s*[;=,)}]`).exec(r.mask) || new RegExp(`\\b${v}\\s*=\\s*(?:const\\s+|new\\s+)?([A-Z]\\w*)\\s*[(.]`).exec(r.mask) || new RegExp(`\\b${v}\\s*=\\s*[^;]*?(?:read|watch|find|of|get|put|call|locator|getIt|sl)\\s*<\\s*([A-Z]\\w*)\\s*>`).exec(r.mask);
    return ty ? { cls: ty[1], name: v } : { unknown: true, name: v };
  };
  const related = (a, b, seen = new Set()) => {
    if (!a || !b) return false;
    if (a === b) return true;
    if (seen.has(a)) return false;
    seen.add(a);
    return (index.bases.get(a) || []).some((x) => related(x, b, seen));
  };
  const loose = (recvName, cls) => {
    const n = String(recvName || '').replace(/^_+/, '').toLowerCase();
    const c = String(cls || '').toLowerCase();
    return n.length > 2 && (c.includes(n) || n.includes(c));
  };
  /** Instantiate wrapper summaries at their call sites (depth 3). */
  const instantiate = () => {
    for (let i = 0; i < summaries.length && i < 400; i++) {
      const s0 = summaries[i];
      const declared = recs.flatMap((x) => x.fns.filter((y) => y.name === s0.fn.name).map((y) => ({ rec: x, fn: y })));
      const summarised = new Set(summaries.map((x) => x.fn));
      const needed = [...new Set([...s0.path.filter((x) => isParam(x) && x.fn === s0.fn).map((x) => x.param), ...(s0.dataParam ? [s0.dataParam] : [])])];
      for (const r of recs) {
        if (!r.mask.includes(s0.fn.name)) continue;
        const re = new RegExp(`(?:^|[^\\w$])(${s0.fn.name})\\s*(?:<[^<>(){};]*>\\s*)?\\(`, 'g');
        let m;
        while ((m = re.exec(r.mask))) {
          const at = m.index + m[0].indexOf(s0.fn.name);
          if (r.fns.some((x) => x.nameOff === at)) continue; // the declaration itself
          const open = m.index + m[0].length - 1;
          const close = closeOf(r.mask, open);
          if (close < 0) continue;
          const seg = { name: s0.fn.name, args: splitArgs(r.code, r.mask, open + 1, close) };
          const rc = receiverClass(r, at);
          if (rc.bare) {
            if (s0.fn.cls ? blockAt(r.blocks, at)?.name !== s0.fn.cls && !related(blockAt(r.blocks, at)?.name, s0.fn.cls) : false) continue;
          } else if (!s0.fn.cls) continue;
          else if (rc.cls && index.classNames.has(rc.cls)) {
            if (!related(rc.cls, s0.fn.cls) && !related(s0.fn.cls, rc.cls)) continue;
          } else if (!declared.every((d) => summarised.has(d.fn) && d.fn.params.length === s0.fn.params.length) && !loose(rc.name, s0.fn.cls)) continue;
          else if (declared.length > 1 && rc.name && declared.some((d) => d.fn !== s0.fn && loose(rc.name, d.fn.cls)) && !loose(rc.name, s0.fn.cls)) continue;
          const argOf = (n) => {
            const p = s0.fn.params.find((x) => x.name === n);
            return p ? argFor(p, seg) : null;
          };
          if (needed.some((n) => !argOf(n)) && s0.path.some((x) => isParam(x) && x.fn === s0.fn && !argOf(x.param) && x === s0.path[0])) continue;
          const path = s0.kind === 'firestore' || s0.path.some(isParam) ? substitute(s0.path, s0.fn, seg, r, at) : s0.path;
          const d = s0.dataParam ? argOf(s0.dataParam) : null;
          let fields = null;
          let data = null;
          if (s0.dataParam) data = d ? { text: d.text, start: d.start } : null;
          else fields = s0.fields;
          const before = summaries.length;
          applyOp({ rec: r, kind: s0.kind, path, op: s0.op, batch: s0.batch, data, ...(fields ? { fields } : {}), converter: null, at, depth: s0.depth + 1, origin: s0.origin });
          // fields the wrapper itself sets next to the parameter (data['updatedAt'] = …)
          if (s0.dataParam && s0.fields.length && summaries.length === before) {
            const key = s0.kind === 'firestore' ? collectionKey(path) : rtdbKey(path.map((x) => (isParam(x) ? null : x)))?.key;
            if (key && tables.has(key)) addCols(tables.get(key), s0.fields, r.f.rel);
          }
          s0.hit = true;
        }
      }
    }
    // A wrapper nobody calls with a resolvable path stays a gap of its file.
    for (const s0 of summaries) if (!s0.hit && s0.depth === 0) addUnparsed('dbWrites', s0.rec.f.rel);
  };

  // Reference bindings of every file first: shared references and reference-returning methods are used across files.
  const rtdbNames = new Set();
  for (const r of recs) for (const n of handleNames(r.mask, 'FirebaseDatabase', 'FirebaseDatabase\\s*\\.\\s*instance(?!\\s*\\.\\s*(?:ref|reference)\\b)')) rtdbNames.add(n);
  for (const r of recs) {
    const localFs = new Set(fsNames);
    if (r.imports.includes('cloud_firestore')) for (const n of DB_NAMES) localFs.add(n);
    r.localFs = localFs;
    if (/\b(collection|doc|ref|reference)\s*\(/.test(r.mask)) scanRefs(r, localFs);
  }

  for (const r of recs) {
    const { f, code, mask, src } = r;
    const lines = src.split('\n');
    const usesFirestore = r.imports.includes('cloud_firestore');
    const usesAuth = r.imports.includes('firebase_auth');
    const usesStorage = r.imports.includes('firebase_storage');
    const usesRtdb = r.imports.includes('firebase_database');
    const usesSupabase = r.imports.includes('supabase_flutter') || r.imports.includes('supabase');
    for (const [pkgs, key] of [[/^(firebase_core|cloud_firestore|firebase_auth|firebase_storage|firebase_database|cloud_functions)$/, 'firebase'], [/^(supabase_flutter|supabase)$/, 'supabase']]) {
      if (sdkImport[key]) continue;
      const m = new RegExp(`^\\s*import\\s+['"]package:(${pkgs.source.slice(2, -2)})\\/`, 'm').exec(code);
      if (m) sdkImport[key] = { rel: f.rel, line: lineAt(src, m.index), snippet: lines[lineAt(src, m.index) - 1]?.trim(), pkg: m[1] };
    }
    if (!usesFirestore && !usesAuth && !usesStorage && !usesSupabase && !usesRtdb && !/FirebaseFirestore|FirebaseAuth|FirebaseStorage|FirebaseDatabase|Supabase\s*\.\s*instance/.test(mask) && ![...fsNames].some((n) => n.length > 2 && new RegExp(`\\b${n}\\s*\\.\\s*(?:collection|doc)\\s*\\(`).test(mask)) && !hasSharedRef(mask)) continue;
    const snippetAt = (off) => (lines[lineAt(src, off) - 1] || '').trim().slice(0, 200);
    const localFs = r.localFs;
    const batchNames = new Set();
    for (const m of mask.matchAll(/\b([A-Za-z_]\w*)\s*=\s*[\w.]+\s*\.\s*batch\s*\(\s*\)/g)) batchNames.add(m[1]);
    for (const m of mask.matchAll(/\bWriteBatch\s+([A-Za-z_]\w*)/g)) batchNames.add(m[1]);
    for (const m of mask.matchAll(/\brunTransaction\s*\(\s*\(\s*(?:Transaction\s+)?([A-Za-z_]\w*)\s*\)/g)) batchNames.add(m[1]);

    // ---- Firestore / Realtime Database chains ----
    const seenAt = new Set();
    for (const c of refChains(r, localFs)) {
      if (seenAt.has(c.start)) continue;
      seenAt.add(c.start);
      visitOp(r, c);
    }
    // WriteBatch / Transaction: batch.set(ref, map) / tx.update(ref, map) / batch.delete(ref); cascades `..set(ref, map)`
    const batchOps = [];
    for (const b of batchNames) for (const bm of mask.matchAll(new RegExp(`\\b${b}\\s*\\.{1,2}\\s*(set|update|delete)\\s*\\(`, 'g'))) batchOps.push({ op: bm[1], at: bm.index, open: bm.index + bm[0].length - 1 });
    for (const bm of mask.matchAll(/\.\.\s*(set|update|delete)\s*\(/g)) batchOps.push({ op: bm[1], at: bm.index, open: bm.index + bm[0].length - 1 });
    const seenOpen = new Set();
    for (const bo of batchOps) {
      if (seenOpen.has(bo.open)) continue;
      seenOpen.add(bo.open);
      const close = closeOf(mask, bo.open);
      if (close < 0) continue;
      const args = splitArgs(code, mask, bo.open + 1, close);
      if (!args.length) continue;
      const target = refOfExpr(r, args[0].start + (code.slice(args[0].start, args[0].end).length - code.slice(args[0].start, args[0].end).trimStart().length), localFs);
      if (!target || target.kind !== 'firestore' || target.rest.length) continue;
      applyOp({ rec: r, kind: 'firestore', path: target.path, op: bo.op, batch: true, data: args[1] || null, converter: null, at: bo.at });
    }

    // ---- FirebaseAuth ----
    const authHere = usesAuth || /FirebaseAuth\s*\.\s*instance/.test(mask);
    if (authHere) {
      const AUTH_CALL = /\.\s*(createUserWithEmailAndPassword|signInWithEmailAndPassword|signInWithPhoneNumber|verifyPhoneNumber|signInWithCredential|signInWithProvider|signInWithPopup|signInWithRedirect|signInWithEmailLink|sendSignInLinkToEmail|sendPasswordResetEmail|updateEmail|verifyBeforeUpdateEmail|updatePhoneNumber|updateDisplayName|updatePhotoURL|updatePassword|updateProfile)\s*\(/g;
      let am;
      while ((am = AUTH_CALL.exec(mask))) {
        const open = am.index + am[0].length - 1;
        const close = closeOf(mask, open);
        if (close < 0) continue;
        const args = splitArgs(code, mask, open + 1, close);
        const fnName = am[1];
        const names = new Set();
        for (const a of args) {
          const named = /^([A-Za-z_]\w*)\s*:\s*([\s\S]*)$/.exec(a.text);
          if (named) names.add(named[1]);
          const val = named ? named[2] : a.text;
          for (const idm of val.matchAll(/\b([A-Za-z_]\w*)\b/g)) names.add(idm[1].replace(/^_/, '').replace(/(Controller|Ctrl|TextController|Field)$/, ''));
        }
        if (/Email/.test(fnName) && !/Link$|Reset/.test(fnName)) names.add('email');
        if (/sendPasswordResetEmail|sendSignInLinkToEmail|signInWithEmailLink/.test(fnName)) names.add('email');
        if (/Password/.test(fnName) && !/Reset/.test(fnName)) names.add('password');
        if (/Phone/.test(fnName)) names.add('phone');
        if (fnName === 'updateDisplayName') names.add('display_name');
        if (fnName === 'updatePhotoURL') names.add('photo_url');
        const store = /^(createUserWithEmailAndPassword|updateEmail|verifyBeforeUpdateEmail|updatePhoneNumber|updateDisplayName|updatePhotoURL|updatePassword|updateProfile|signInWithPhoneNumber|verifyPhoneNumber|signInWithCredential|signInWithProvider|signInWithPopup|signInWithRedirect|signInWithEmailLink)$/.test(fnName);
        authFlows.push({ names: [...names], rel: f.rel, line: lineAt(src, am.index), snippet: snippetAt(am.index), store, fn: fnName });
      }
      // account deletion: currentUser!.delete(), user.delete() where user = …currentUser / cred.user
      const userVars = new Set();
      for (const um of mask.matchAll(/\b([A-Za-z_]\w*)\s*=\s*(?:await\s+)?[\w.!?\s]*?\.\s*currentUser\b/g)) userVars.add(um[1]);
      for (const um of mask.matchAll(/\bUser\??\s+([A-Za-z_]\w*)\s*[=;,)]/g)) userVars.add(um[1]);
      const DEL = /(?:\bcurrentUser|\.\s*user|\b([A-Za-z_]\w*))\s*[!?]?\s*\.\s*delete\s*\(\s*\)/g;
      let dm;
      while ((dm = DEL.exec(mask))) {
        if (dm[1] && !userVars.has(dm[1])) continue;
        deletions.push({ target: FIREBASE_AUTH_USERS.id, auth: true, rel: f.rel, line: lineAt(src, dm.index), snippet: snippetAt(dm.index), fn: enclosingFn(mask, dm.index), account: true });
      }
    }

    // ---- Firebase Storage ----
    const stHere = usesStorage || /FirebaseStorage\s*\.\s*instance/.test(mask);
    if (stHere) {
      const localSt = new Set(storageNames);
      for (const n of ['_storage', 'storage', 'firebaseStorage', '_firebaseStorage']) localSt.add(n);
      const refNames = new Set();
      const refPaths = new Map(); // ref variable → text of the ref()/child() arguments it was built from
      for (const rm of mask.matchAll(/\b(?:Reference\s+|final\s+|var\s+)?([A-Za-z_]\w*)\s*=\s*((?:FirebaseStorage\s*\.\s*instance|[A-Za-z_]\w*)\s*\.\s*(?:ref|refFromURL|child)\s*\()/g)) {
        refNames.add(rm[1]);
        const rc = parseChain(code, mask, rm.index + rm[0].length - rm[2].length);
        const txt = (rc?.segs || []).filter((s) => /^(ref|child)$/.test(s.name)).map((s) => s.args?.[0]?.text || '').join(' ');
        refPaths.set(rm[1], `${refPaths.get(rm[1]) || ''} ${txt}`.trim());
      }
      for (const rm of mask.matchAll(/\bReference\??\s+([A-Za-z_]\w*)/g)) refNames.add(rm[1]);
      const ST = /\b(FirebaseStorage|[A-Za-z_]\w*)\s*[!?]?\s*\.\s*(instance|ref|refFromURL|child|putData|putFile|putString|delete)\b/g;
      let sm;
      while ((sm = ST.exec(mask))) {
        const start = sm.index;
        if (/\.\s*$/.test(mask.slice(Math.max(0, start - 3), start))) continue;
        const rn = sm[1];
        if (!(rn === 'FirebaseStorage' || localSt.has(rn) || refNames.has(rn))) continue;
        const chain = parseChain(code, mask, start);
        if (!chain) continue;
        ST.lastIndex = Math.max(ST.lastIndex, chain.end);
        const op = chain.segs.find((s) => /^(putData|putFile|putString|delete)$/.test(s.name));
        if (!op) continue;
        if (op.name === 'delete' && !chain.segs.some((s) => /^(ref|refFromURL|child)$/.test(s.name)) && !refNames.has(rn)) continue;
        const pathText = `${refPaths.get(rn) || ''} ${chain.segs.filter((s) => /^(ref|child)$/.test(s.name)).map((s) => s.args?.[0]?.text || '').join(' ')}`.trim();
        const line = lineAt(src, start);
        const entry = { rel: f.rel, line, snippet: snippetAt(start), fn: enclosingFn(mask, start), pathText, args: (op.args || []).map((a) => a.text).join(' ') };
        if (op.name === 'delete') deletions.push({ target: STORAGE_BUCKET.id, bucket: true, ...entry });
        else uploads.push(entry);
      }
    }

    // ---- supabase_flutter ----
    if (usesSupabase) {
      const localSb = new Set(sbNames);
      for (const n of ['supabase', '_supabase', 'client', '_client', 'supabaseClient', '_supabaseClient', 'db', '_db']) localSb.add(n);
      const SB = /\b(Supabase\s*\.\s*instance\s*\.\s*client|[A-Za-z_]\w*)\s*[!?]?\s*\.\s*from\s*\(/g;
      let bm;
      while ((bm = SB.exec(mask))) {
        const start = bm.index;
        if (/\.\s*$/.test(mask.slice(Math.max(0, start - 3), start))) continue;
        const rn = bm[1].replace(/\s+/g, '');
        if (!(rn.startsWith('Supabase.') || localSb.has(rn))) continue;
        const chain = parseChain(code, mask, start);
        if (!chain) continue;
        let segs = chain.segs;
        if (rn.startsWith('Supabase.')) segs = segs.slice(2);
        const fromSeg = segs.find((s) => s.name === 'from');
        if (!fromSeg) continue;
        const tbl = R.str(fromSeg.args?.[0]?.text, { rec: r, off: fromSeg.args?.[0]?.start ?? start, fn: fnAt(r.fns, start) });
        const op = segs.slice(segs.indexOf(fromSeg) + 1).find((s) => /^(insert|upsert|update|delete|select)$/.test(s.name));
        if (!op) continue;
        if (!tbl) {
          if (op.name !== 'select') addUnparsed('dbWrites', f.rel);
          continue;
        }
        const line = lineAt(src, start);
        const snippet = snippetAt(start);
        const fn = enclosingFn(mask, start);
        const key = graph.has(`store:table:public.${tbl}`) && !graph.has(`store:table:${tbl}`) ? `public.${tbl}` : tbl;
        if (op.name === 'delete') {
          deletions.push({ target: `store:table:${key}`, key, sb: true, rel: f.rel, line, snippet, fn });
          writes.push({ key, fields: [], rel: f.rel, line, snippet, fn, op: 'delete', sb: true });
        } else if (op.name !== 'select') {
          const a0 = op.args?.[0];
          const { fields, resolved } = dataFields(r, a0?.text, a0?.start ?? 0, null);
          if (!resolved) addUnparsed('dbWrites', f.rel);
          writes.push({ key, fields, rel: f.rel, line, snippet, fn, op: op.name, sb: true });
        }
      }
    }
  }

  instantiate();

  // ---- emit Firestore collections (merging into rules / JS stores of the same key) ----
  const sbTables = new Map();
  for (const w of writes.filter((x) => x.sb)) {
    if (graph.has(`store:table:${w.key}`)) continue;
    if (!sbTables.has(w.key)) sbTables.set(w.key, newTable(w.key, { name: w.key, kind: 'table', rls: null, source: 'supabase-dart', file: w.rel, line: w.line, snippet: w.snippet, extra: { inferred: true, tech: 'supabase', provider: 'supabase', language: 'dart' } }));
    addCols(sbTables.get(w.key), w.fields, w.rel);
  }
  const keep = new Map();
  for (const t of [...tables.values(), ...sbTables.values()]) {
    delete t._firstWrite;
    const id = `store:table:${t.key}`;
    const prev = graph.node(id);
    if (prev) keep.set(id, { source: prev.source, file: prev.file, line: prev.line, kind: prev.kind });
  }
  try {
    if (tables.size) {
      for (const t of tables.values()) t.extra.codeOps = t.extra.codeOps.slice(0, 20);
      const fsT = new Map([...tables].filter(([, t]) => t.extra.tech !== 'firebase-rtdb'));
      const rtT = new Map([...tables].filter(([, t]) => t.extra.tech === 'firebase-rtdb'));
      if (fsT.size) emitTables(ctx, fsT, 'firestore-code');
      if (rtT.size) emitTables(ctx, rtT, 'firebase-rtdb');
    }
    if (sbTables.size) emitTables(ctx, sbTables, 'supabase-dart');
  } catch (e) {
    ctx.warn?.(`dart: emit: ${e.message}`);
  }
  for (const [id, p] of keep) {
    const n = graph.node(id);
    if (n) Object.assign(n, p);
  }
  // Supabase writes to existing SQL tables: columns already modelled.
  const consumer = (rel, fn, line, snippet) => {
    const id = `consumer:${rel}#${fn || 'top'}`;
    if (!graph.has(id)) graph.addNode({ id, type: 'Consumer', name: `${rel}#${fn || 'top'}`, file: rel, fn: fn || 'top', line, evidence: [ev(rel, line, snippet, 'static', 0.7)] });
    return id;
  };
  for (const w of writes) {
    const tid = `store:table:${w.key}`;
    if (!graph.has(tid)) continue;
    const e = ev(w.rel, w.line, w.snippet, 'static', 0.85);
    try {
      const we = graph.addEdge({ from: consumer(w.rel, w.fn, w.line, w.snippet), to: tid, type: 'writes', op: w.op, file: w.rel, line: w.line, evidence: [e] });
      we.ops ||= [];
      if (!we.ops.includes(w.op) && we.ops.length < 10) we.ops.push(w.op);
    } catch {
      /* missing node */
    }
    for (const fl of w.fields) {
      const cid = `store:column:${w.key}.${fl.name}`;
      if (!graph.has(cid)) continue;
      for (const rep of graph.edgesFrom(cid, 'represents')) {
        // an update of an existing document rectifies the field
        const fe = graph.addEdge({ from: rep.to, to: cid, type: 'flowsTo', field: fl.name, ...(w.op === 'update' ? { op: 'update' } : {}), evidence: [e] });
        if (w.op === 'update' && !/update|upsert/.test(fe.op || '')) fe.op = 'update';
        writtenElements.add(rep.to);
      }
    }
  }

  // ---- Firebase Auth / Storage ----
  const fb = ctx.vendors?.vendorById?.('firebase');
  const fbSink = (e) => (fb ? graph.vendorSink(fb, e) : null);
  for (const a of authFlows) {
    const e = ev(a.rel, a.line, a.snippet, 'static', 0.8, `FirebaseAuth.${a.fn}`);
    const sid = fbSink(e);
    if (a.store) graph.addNode({ id: FIREBASE_AUTH_USERS.id, type: 'Store', ...FIREBASE_AUTH_USERS.props, source: 'firebase-auth', evidence: [e] });
    for (const nm of a.names) {
      const cls = ctx.classify(nm);
      if (!cls || cls.category === 'technical') continue;
      const did = graph.dataElement(cls, nm, e);
      if (sid) graph.addEdge({ from: did, to: sid, type: 'flowsTo', evidence: [e] });
      if (a.store) graph.addEdge({ from: did, to: FIREBASE_AUTH_USERS.id, type: 'flowsTo', evidence: [e] });
      writtenElements.add(did);
    }
  }
  for (const u of uploads) {
    const e = ev(u.rel, u.line, u.snippet, 'static', 0.8, 'Firebase Storage upload');
    const userLinked = /\b(uid|userId|user_id|currentUser|userUid|ownerId)\b/.test(u.pathText);
    graph.addNode({ id: STORAGE_BUCKET.id, type: 'Store', ...STORAGE_BUCKET.props, public: null, ...(userLinked ? { userLinkedKey: true } : {}), evidence: [e] });
    fbSink(e);
    const names = new Set();
    for (const s of `${u.pathText} ${u.args}`.matchAll(/['"]([A-Za-z_][\w]*)['"]|\b([A-Za-z_]\w*)\b/g)) names.add(s[1] || s[2]);
    for (const nm of names) {
      const cls = ctx.classify(nm);
      if (!cls || !['audiovisual', 'user-content', 'identity', 'contact', 'health', 'biometric'].includes(cls.category)) continue;
      const did = graph.dataElement(cls, nm, e);
      graph.addEdge({ from: did, to: STORAGE_BUCKET.id, type: 'flowsTo', evidence: [e] });
    }
  }
  if (sdkImport.firebase && fb) graph.vendorSink(fb, ev(sdkImport.firebase.rel, sdkImport.firebase.line, sdkImport.firebase.snippet, 'static', 0.85, `Firebase SDK imported (package:${sdkImport.firebase.pkg})`));
  const sbV = ctx.vendors?.vendorById?.('supabase');
  if (sdkImport.supabase && sbV) graph.vendorSink(sbV, ev(sdkImport.supabase.rel, sdkImport.supabase.line, sdkImport.supabase.snippet, 'static', 0.85, 'Supabase SDK imported (package:supabase_flutter)'));

  // ---- deletions ----
  for (const d of deletions) {
    if (!graph.has(d.target)) {
      if (d.auth) graph.addNode({ id: FIREBASE_AUTH_USERS.id, type: 'Store', ...FIREBASE_AUTH_USERS.props, source: 'firebase-auth' });
      else if (d.bucket) graph.addNode({ id: STORAGE_BUCKET.id, type: 'Store', ...STORAGE_BUCKET.props, public: null });
      else continue;
    }
    const cid = `control:deletion-flow:${d.rel}#${d.fn || 'anonymous'}`;
    const e = ev(d.rel, d.line, d.snippet, 'static', 0.85);
    graph.addNode({ id: cid, type: 'Control', kind: 'deletion-flow', endpoint: null, file: d.rel, line: d.line, ...(d.fn ? { name: d.fn } : {}), ...(d.account ? { accountDeletion: true } : {}), language: 'dart', evidence: [e] });
    graph.addEdge({ from: cid, to: d.target, type: 'deletes', evidence: [e] });
  }

  // ---- TextEditingController form sources ----
  for (const r of recs) {
    const ctrls = new Map();
    for (const cm of r.mask.matchAll(/\b([A-Za-z_]\w*)\s*=\s*(?:new\s+)?TextEditingController\s*\(|\bTextEditingController\??\s+([A-Za-z_]\w*)\s*[=;]/g)) {
      const nm = cm[1] || cm[2];
      if (!ctrls.has(nm)) ctrls.set(nm, cm.index);
    }
    if (!ctrls.size) continue;
    const srcId = `source:form:${path.posix.basename(r.f.rel, '.dart')}`;
    for (const [nm, off] of ctrls) {
      if (!new RegExp(`\\b${nm}\\s*[!?]?\\s*\\.\\s*text\\b`).test(r.mask)) continue;
      const base = nm.replace(/^_+/, '').replace(/(TextEditingController|TextController|Controller|Ctrl|Ctl)$/, '');
      const cls = base ? ctx.classify(base) : null;
      if (!cls) continue;
      const did = `data:${cls.element}`;
      if (!writtenElements.has(did)) continue;
      const line = lineAt(r.src, off);
      const e = ev(r.f.rel, line, (r.src.split('\n')[line - 1] || '').trim(), 'static', Math.min(cls.confidence, 0.75), 'TextEditingController input');
      graph.addNode({ id: srcId, type: 'Source', kind: 'form', name: path.posix.basename(r.f.rel, '.dart'), file: r.f.rel, line, evidence: [e] });
      graph.dataElement(cls, base, e);
      graph.addEdge({ from: srcId, to: did, type: 'collects', evidence: [e] });
    }
  }

  if (unparsed.size) {
    ctx.shared.unparsed ||= [];
    for (const [layer, rels] of unparsed) ctx.shared.unparsed.push({ layer, kind: 'dart', label: { tr: 'Dart veri erişimi (çözümlenemedi)', en: 'Dart data access (not resolved)' }, files: [...rels].slice(0, 20), count: rels.size, reason: 'not-parsed' });
  }
  ctx.shared.dataLayers ||= {};
  ctx.shared.dataLayers.dart = { stores: tables.size + sbTables.size, writes: writes.length, deletes: deletions.length, auth: authFlows.length, uploads: uploads.length };
}
