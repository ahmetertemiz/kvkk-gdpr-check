/**
 * Python ORM schemas (regex/bracket level, no Python parser):
 *  - Django models (models.Model)
 *  - SQLAlchemy declarative models, 1.x (`x = Column(...)`) and 2.x (`x: Mapped[T] = mapped_column(...)`, annotation-only `x: Mapped[T]`),
 *    with or without `__tablename__` (Flask-SQLAlchemy derives CamelCase → snake_case)
 *  - SQLModel: `class User(UserBase, table=True)` with the fields of its SQLModel bases; foreign_key / ondelete of Field()
 *  - SQLAlchemy Core `Table('name', metadata, Column('c', ...))`
 *  - Alembic migrations (op.create_table / add_column / drop_column / drop_table / rename_table / alter_column, batch_alter_table),
 *    replayed in revision order.
 * Precedence when the same table appears in several places: ORM model > Core Table > Alembic.
 * pythonOrmOps(ctx) (second pass, after the routes are known; called by the order-22 extractor): session writes and deletes
 * of mapped models (`session.add(Model(…))`, `Model.model_validate(dto, update={…})`, `obj.sqlmodel_update(data)`,
 * `Model(**dto.model_dump())`, setattr loops, insert / update / delete statements, `session.delete(obj)`) → `writes` edges,
 * flowsTo edges for the written columns and deletion-flow Controls (endpoint of the enclosing route, as flow.js does for
 * JS). Objects that are not derived from a mapped model are ignored.
 * Sets ctx.shared.pythonModelsUnparsed = number of model classes that declare columns we could not read (coverage warning, IDX-2).
 */
import { newTable, emitTables, lineOf } from './_schema.js';

export const name = 'orm-python';
export const order = 14;

const DJ_ON_DELETE = { CASCADE: 'cascade', SET_NULL: 'set null', SET_DEFAULT: 'set default', PROTECT: 'restrict', RESTRICT: 'restrict', DO_NOTHING: 'no action' };
const SA_TYPES = /\b(String|Text|Unicode|UnicodeText|Integer|SmallInteger|BigInteger|Boolean|DateTime|Date|Time|Interval|JSON|JSONB|LargeBinary|Float|Numeric|Uuid|UUID|Enum|ARRAY|INET|Vector)\b/;
const PY_TYPES = {
  str: 'string', int: 'integer', float: 'float', bool: 'boolean', bytes: 'largebinary', datetime: 'datetime', date: 'date', time: 'time',
  timedelta: 'interval', Decimal: 'numeric', dict: 'json', list: 'json', UUID: 'uuid', uuid: 'uuid', Any: 'unknown',
};
const SNIPPET_MAX = 160;

// ───────────────────────── bracket-aware scanning helpers ─────────────────────────

/** Index just past the string literal starting at s[i] (handles ''' / """ and escapes). */
function skipString(s, i) {
  const q = s[i];
  const end = s.startsWith(q + q + q, i) ? q + q + q : q;
  let j = i + end.length;
  while (j < s.length) {
    if (s[j] === '\\') { j += 2; continue; }
    if (s.startsWith(end, j)) return j + end.length;
    if (end.length === 1 && s[j] === '\n') return j;
    j++;
  }
  return s.length;
}

/** Index just past the bracket that closes s[open]; -1 when unbalanced. Strings and # comments are skipped. */
function closeIndex(s, open) {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    const ch = s[i];
    if (ch === '#') { while (i < s.length && s[i] !== '\n') i++; continue; }
    if (ch === '"' || ch === "'") { i = skipString(s, i) - 1; continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if ((ch === ')' || ch === ']' || ch === '}') && --depth === 0) return i + 1;
  }
  return -1;
}

/** Net bracket depth change of a code fragment, and the fragment without its trailing # comment. */
function scanLine(s) {
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '#') return { depth, code: s.slice(0, i) };
    if (ch === '"' || ch === "'") { i = skipString(s, i) - 1; continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
  }
  return { depth, code: s };
}

/** Split s[start, end) at top-level commas → [{text, start}] (trimmed, empty parts dropped). */
function splitTop(s, start, end) {
  const out = [];
  let depth = 0;
  let from = start;
  const push = (to) => {
    const raw = s.slice(from, to);
    const text = raw.trim();
    if (text) out.push({ text, start: from + raw.indexOf(text) });
  };
  for (let i = start; i < end; i++) {
    const ch = s[i];
    if (ch === '#') { while (i < end && s[i] !== '\n') i++; continue; }
    if (ch === '"' || ch === "'") { i = skipString(s, i) - 1; continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (ch === ',' && depth === 0) { push(i); from = i + 1; }
  }
  push(end);
  return out;
}

/** Arguments of the call whose '(' is at s[open] → [{text, start}], or null when unbalanced. */
function callArgs(s, open) {
  const close = closeIndex(s, open);
  return close < 0 ? null : splitTop(s, open + 1, close - 1);
}

/** Position of the first top-level single '=' (assignment, not ==, <=, >=, !=), or -1. */
function assignIndex(s) {
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '"' || ch === "'") { i = skipString(s, i) - 1; continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (ch === '=' && depth === 0 && s[i + 1] !== '=' && !'=<>!'.includes(s[i - 1])) return i;
  }
  return -1;
}

const strLit = (text) => text?.match(/^[rbuRBU]?(['"])(.*)\1$/s)?.[2] ?? null;
const kwArg = (args, k) => args.find((a) => new RegExp(`^${k}\\s*=`).test(a.text))?.text.replace(/^\w+\s*=\s*/, '');
const stripStrings = (s) => s.replace(/(['"])(?:\\.|(?!\1)[^\\\n])*\1/g, "''");
const snip = (s) => {
  const t = s.replace(/\s+/g, ' ').trim();
  return t.length > SNIPPET_MAX ? `${t.slice(0, SNIPPET_MAX - 1)}…` : t;
};
const snakeCase = (n) => n.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2').toLowerCase();

/** Classes at module level: {name, bases:[string], basesText, startLine, header, body:[{text,line}], logical:[{text,line,snippet}]}. */
function classBlocks(content) {
  const lines = content.split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/^class\s+\w+\s*[(:]/.test(lines[i])) continue;
    // Header may span lines: class User(\n    UserMixin, db.Model):
    let header = lines[i];
    let hEnd = i;
    while (scanLine(header).depth > 0 && hEnd + 1 < lines.length) header += ` ${lines[++hEnd].trim()}`;
    const m = header.match(/^class\s+(\w+)\s*([(:])/);
    let basesText = '';
    if (m[2] === '(') {
      const open = header.indexOf('(');
      const close = closeIndex(header, open);
      if (close < 0 || !/^\s*:/.test(header.slice(close))) continue;
      basesText = header.slice(open + 1, close - 1);
    }
    const bases = splitTop(basesText, 0, basesText.length).map((b) => b.text);
    const body = [];
    let depth = 0;
    for (let j = hEnd + 1; j < lines.length; j++) {
      const ln = lines[j];
      // A non-indented line ends the class, unless we are inside an open bracket or it is a comment.
      if (depth <= 0 && /^\S/.test(ln) && !/^#/.test(ln)) break;
      body.push({ text: ln, line: j + 1 });
      depth += scanLine(ln).depth;
    }
    out.push({ name: m[1], bases, basesText, startLine: i + 1, header: snip(header), body, logical: logicalLines(body) });
    i = hEnd;
  }
  return out;
}

/** Join physical lines into logical lines (until brackets balance); comments removed. */
function logicalLines(body) {
  const out = [];
  for (let i = 0; i < body.length; i++) {
    const first = scanLine(body[i].text);
    let text = first.code.replace(/\s+$/, '');
    let depth = first.depth;
    const line = body[i].line;
    while (depth > 0 && i + 1 < body.length) {
      const next = scanLine(body[++i].text);
      text += ` ${next.code.trim()}`;
      depth += next.depth;
    }
    if (text.trim()) out.push({ text, line, snippet: snip(text) });
  }
  return out;
}

// ───────────────────────── Django ─────────────────────────
//
// Project-level resolver (Django docs, "Model inheritance"): a class is a model when one of its bases is
// django.db.models.Model, a django.contrib.auth abstract base, or (transitively, across files) another model class.
// `class Meta: abstract = True` → no table, its fields are inherited by children; `proxy = True` → the parent's
// table; a concrete parent (multi-table inheritance) gives the child a `<parent>_ptr_id` one-to-one key.
// The real table name is `<app_label>_<model>` unless Meta.db_table is set; the graph key stays the lowercase model
// name (findTable / FK aliases; app_label_model only on a name clash), with the conventional name in `name`.

// Fields contributed by django.contrib.auth bases (django/contrib/auth/base_user.py and models.py). The framework-maintained
// timestamps (last_login, date_joined) are left out: Django writes them itself, so they say nothing about the app's own use.
const DJ_USER_FIELDS = [['password', 'char'], ['is_superuser', 'boolean'], ['username', 'char'], ['first_name', 'char'], ['last_name', 'char'], ['email', 'email'], ['is_staff', 'boolean'], ['is_active', 'boolean']];
const DJ_OPTIONAL_BUILTIN = new Set(['first_name', 'last_name']);
const DJ_AUTH_BASES = {
  AbstractBaseUser: [['password', 'char']],
  PermissionsMixin: [['is_superuser', 'boolean']],
  AbstractUser: DJ_USER_FIELDS,
  User: DJ_USER_FIELDS,
};
const DJ_FIELD_RE = /^(\s+)(\w+)\s*(?::[^=]+)?=\s*((?:\w+\.)*)(\w*Field|ForeignKey|OneToOneField|ManyToManyField|ParentalKey)\s*\(([\s\S]*)\)\s*$/;
const DJ_NOT_COLUMN = /^(?:GenericForeignKey|GenericRelation|ManyToManyField|TaggableManager)$/;

const modOf = (rel) => rel.replace(/\.py$/, '').replace(/\/__init__$/, '').split('/').join('.');
const sameModule = (a, b) => !!a && !!b && (a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`));

/** localName → {mod, name|null} for `from m import a as b` (relative imports resolved) and `import m.n as z`. */
export function importsOf(content, rel) {
  const out = new Map();
  const text = content.replace(/\(\s*([^()]*?)\s*\)/gs, (m, inner) => (/^[\w\s,]+$/.test(inner) ? inner.replace(/\s*\n\s*/g, ' ') : m));
  const abs = (mod) => {
    if (!mod.startsWith('.')) return mod;
    const dots = mod.match(/^\.+/)[0].length;
    const pkg = rel.replace(/\.py$/, '').split('/');
    pkg.pop();
    for (let i = 1; i < dots; i++) pkg.pop();
    const rest = mod.slice(dots);
    return [...pkg, ...(rest ? rest.split('.') : [])].join('.');
  };
  for (const m of text.matchAll(/^[ \t]*from\s+([.\w]+)\s+import\s+([^\n#]+)/gm)) {
    const mod = abs(m[1]);
    for (const part of m[2].replace(/\\\s*$/, '').split(',')) {
      const mm = part.trim().match(/^(\w+)(?:\s+as\s+(\w+))?$/);
      if (mm) out.set(mm[2] || mm[1], { mod, name: mm[1] });
    }
  }
  for (const m of text.matchAll(/^[ \t]*import\s+([\w.]+)(?:\s+as\s+(\w+))?\s*$/gm)) out.set(m[2] || m[1].split('.')[0], { mod: m[2] ? m[1] : m[1].split('.')[0], name: null });
  return out;
}

const indentOf = (s) => s.match(/^[ \t]*/)[0].replace(/\t/g, '    ').length;

/** Split a class body into its own statements and its `class Meta:` options. */
function djangoBody(c) {
  const lines = c.logical.filter((b) => b.text.trim() && !/^\s*[rbuRBU]?(?:'''|""")/.test(b.text));
  const bodyIndent = lines.length ? Math.min(...lines.map((b) => indentOf(b.text))) : 0;
  const own = [];
  const meta = { abstract: false, proxy: false, dbTable: null, appLabel: null };
  let inMeta = false;
  for (const b of lines) {
    const ind = indentOf(b.text);
    if (ind <= bodyIndent) {
      inMeta = /^\s*class\s+Meta\b/.test(b.text);
      if (!inMeta && !/^\s*(?:class|def|async\s+def|@)/.test(b.text)) own.push(b);
      continue;
    }
    if (!inMeta) continue;
    if (/^\s*abstract\s*=\s*True\b/.test(b.text)) meta.abstract = true;
    if (/^\s*proxy\s*=\s*True\b/.test(b.text)) meta.proxy = true;
    const dt = b.text.match(/^\s*db_table\s*=\s*[rbu]?['"]([^'"]+)['"]/);
    if (dt) meta.dbTable = dt[1];
    const al = b.text.match(/^\s*app_label\s*=\s*['"]([^'"]+)['"]/);
    if (al) meta.appLabel = al[1];
  }
  return { own, meta };
}

/** App label from the file path: <app>/models.py, <app>/models/<x>.py. */
function appLabelOf(rel) {
  const dirs = rel.split('/').slice(0, -1);
  if (dirs.at(-1) === 'models') dirs.pop();
  return dirs.at(-1) || 'app';
}

/**
 * Every Django model in the project.
 * @param {{rel:string, content:string}[]} files  .py files
 * @param {{unparsed:number, items?:object[]}} stats
 * @returns {{tables: Map, proxies: Map<string,string>, modelKeys: Map<string,string>}}
 */
export function parseDjangoProject(files, stats = { unparsed: 0 }) {
  const classes = [];
  const byMod = new Map();
  let authUserModel = null;
  for (const f of files) {
    if (/(?:^|\/)migrations\//.test(f.rel)) continue;
    const au = f.content.match(/^AUTH_USER_MODEL\s*=\s*['"]([\w.]+)['"]/m);
    if (au) authUserModel = au[1];
    if (!/^class\s+\w+\s*\(/m.test(f.content)) continue;
    const mod = modOf(f.rel);
    const imports = importsOf(f.content, f.rel);
    const djangoFile = /\bdjango\b/.test(f.content) || /\bmodels\.\w+\(/.test(f.content);
    for (const c of classBlocks(f.content)) {
      const entry = { c, file: f, mod, imports, djangoFile, ...djangoBody(c) };
      classes.push(entry);
      if (!byMod.has(mod)) byMod.set(mod, []);
      byMod.get(mod).push(entry);
    }
  }
  const byName = new Map();
  for (const e of classes) byName.set(e.c.name, [...(byName.get(e.c.name) || []), e]);
  const findClass = (mod, name) => {
    const local = byMod.get(mod)?.find((e) => e.c.name === name);
    if (local) return local;
    for (const [m, list] of byMod) {
      if (!sameModule(m, mod)) continue;
      const hit = list.find((e) => e.c.name === name);
      if (hit) return hit;
    }
    return null;
  };
  const baseMemo = new Map();
  /** One base expression → {root} | {cls} | {external} | {skip} | null. */
  const resolveBase = (e, raw) => {
    const mk = `${e.mod}|${e.c.name}|${raw}`;
    if (baseMemo.has(mk)) return baseMemo.get(mk);
    const r = resolveBase0(e, raw);
    baseMemo.set(mk, r);
    return r;
  };
  const resolveBase0 = (e, raw) => {
    const b = raw.replace(/\[[\s\S]*\]$/, '').trim();
    if (/^\w+\s*=/.test(b) || /^object$/.test(b)) return { skip: true }; // metaclass=..., object
    const parts = b.split('.');
    const last = parts.pop();
    const head = parts[0];
    const imp = e.imports.get(head || last);
    const impMod = imp ? (head ? (imp.name ? `${imp.mod}.${imp.name}` : imp.mod) : imp.mod) : null;
    const fromDjango = (impMod && /^django\b/.test(impMod)) || (!imp && /^(?:models|django)$/.test(head || ''));
    if (last === 'Model' && (fromDjango || head === 'models')) return { root: 'Model' };
    if (last === 'User') {
      if (impMod && /^django\.contrib\.auth/.test(impMod)) return { root: 'User' };
    } else if (DJ_AUTH_BASES[last] && (fromDjango || !findClass(e.mod, last))) return { root: last };
    // A project class: same module, imported name, or `module.Class`.
    let target = null;
    if (!head) target = (byMod.get(e.mod) || []).find((x) => x.c.name === last && x !== e) || (imp?.name ? findClass(imp.mod, imp.name) : null);
    else if (impMod) target = findClass(impMod, last);
    if (!target && (!impMod || !/^django\b/.test(impMod))) {
      const same = (byName.get(imp?.name || last) || []).filter((x) => x !== e);
      if (same.length === 1) target = same[0];
    }
    if (target) return { cls: target };
    // A model base from an installed package (django-model-utils, django-extensions, polymorphic …).
    if (impMod && !/^django\b/.test(impMod) && /Model$/.test(imp?.name || last)) return { external: true };
    return null;
  };
  // Optional built-in user fields (first_name / last_name) count only when the project's code or templates touch them.
  const mentionMemo = new Map();
  const mentioned = (n) => {
    if (!mentionMemo.has(n)) mentionMemo.set(n, files.some((f) => !/(?:^|\/)migrations\//.test(f.rel) && new RegExp(`['".]${n}\\b`).test(f.content)));
    return mentionMemo.get(n);
  };
  const memo = new Map();
  const isModel = (e, seen = new Set()) => {
    if (memo.has(e)) return memo.get(e);
    if (seen.has(e)) return false;
    seen.add(e);
    let yes = false;
    for (const b of e.c.bases) {
      const r = resolveBase(e, b);
      if (!r || r.skip) continue;
      if (r.root || (r.cls && isModel(r.cls, seen)) || (r.external && e.own.some((s) => DJ_FIELD_RE.test(s.text)))) { yes = true; break; }
    }
    memo.set(e, yes);
    return yes;
  };

  const ownFields = (e) => {
    const cols = [];
    for (const b of e.own) {
      const m = b.text.match(DJ_FIELD_RE);
      if (!m) continue;
      const [, , field, , type, args] = m;
      cols.push({ field, type, args, where: { file: e.file.rel, line: b.line, snippet: b.snippet } });
    }
    return cols;
  };
  /** Columns inherited from abstract ancestors and auth bases. */
  const inherited = (e, seen = new Set()) => {
    const out = [];
    if (seen.has(e)) return out;
    seen.add(e);
    for (const b of e.c.bases) {
      const r = resolveBase(e, b);
      if (!r) continue;
      if (r.root && DJ_AUTH_BASES[r.root]) {
        for (const [name, type] of DJ_AUTH_BASES[r.root]) if (!DJ_OPTIONAL_BUILTIN.has(name) || mentioned(name)) out.push({ builtin: true, field: name, type, where: { file: e.file.rel, line: e.c.startLine, snippet: e.c.header } });
      } else if (r.cls && isModel(r.cls) && r.cls.meta.abstract) {
        out.push(...inherited(r.cls, seen), ...ownFields(r.cls));
      }
    }
    return out;
  };
  const concreteParent = (e) => {
    for (const b of e.c.bases) {
      const r = resolveBase(e, b);
      if (r?.cls && isModel(r.cls) && !r.cls.meta.abstract) return r.cls;
    }
    return null;
  };

  const models = classes.filter((e) => isModel(e));
  const keyOf = new Map();
  const used = new Set();
  for (const e of models) {
    if (e.meta.abstract || e.meta.proxy) continue;
    const app = e.meta.appLabel || appLabelOf(e.file.rel);
    let key = e.meta.dbTable || e.c.name.toLowerCase();
    if (used.has(key)) key = `${app}_${e.c.name.toLowerCase()}`;
    used.add(key);
    keyOf.set(e, { key, name: e.meta.dbTable || `${app}_${e.c.name.toLowerCase()}`, app });
  }
  const tableOfModel = (e, depth = 0) => {
    if (!e || depth > 8) return null;
    if (keyOf.has(e)) return keyOf.get(e).key;
    return e.meta.proxy ? tableOfModel(concreteParent(e), depth + 1) : null;
  };
  const proxies = new Map();
  for (const e of models) {
    if (!e.meta.proxy) continue;
    const k = tableOfModel(e);
    if (k) proxies.set(e.c.name, k);
  }
  const modelKeys = new Map();
  for (const [e, k] of keyOf) {
    modelKeys.set(e.c.name, k.key);
    modelKeys.set(`${k.app}.${e.c.name}`, k.key);
  }
  for (const [n, k] of proxies) if (!modelKeys.has(n)) modelKeys.set(n, k);
  const refKey = (ref, self) => {
    if (ref === 'self') return self;
    if (/AUTH_USER_MODEL|get_user_model/.test(ref)) {
      if (!authUserModel) return 'auth_user';
      return modelKeys.get(authUserModel) || modelKeys.get(authUserModel.split('.').pop()) || authUserModel.split('.').pop().toLowerCase();
    }
    return modelKeys.get(ref) || modelKeys.get(ref.split('.').pop()) || ref.split('.').pop().toLowerCase();
  };

  const tables = new Map();
  for (const [e, k] of keyOf) {
    const c = e.c;
    const t = newTable(k.key, { name: k.name, kind: 'table', model: c.name, file: e.file.rel, line: c.startLine, snippet: c.header, source: 'django' });
    const proxyNames = [...proxies].filter(([, key]) => key === k.key).map(([n]) => n);
    if (proxyNames.length) t.extra = { proxies: proxyNames };
    const own = ownFields(e);
    const parent = concreteParent(e);
    if (parent) {
      const pk = tableOfModel(parent);
      const col = `${parent.c.name.toLowerCase()}_ptr_id`;
      t.columns.set(col, { name: col, type: 'fk', notNull: true, file: e.file.rel, line: c.startLine, snippet: c.header });
      if (pk) t.fks.push({ column: col, refTable: pk, refColumn: 'id', onDelete: 'cascade', file: e.file.rel, line: c.startLine, snippet: c.header });
    }
    for (const col of [...inherited(e), ...own]) {
      if (col.builtin) {
        if (!t.columns.has(col.field)) t.columns.set(col.field, { name: col.field, type: col.type, notNull: true, ...col.where });
        continue;
      }
      const { field, type, args, where } = col;
      if (DJ_NOT_COLUMN.test(type)) continue;
      if (/^(?:ForeignKey|OneToOneField|ParentalKey)$/.test(type)) {
        const toKw = args.match(/\bto\s*=\s*(?:[rbu]?['"]([\w.]+)['"]|([\w.]+))/);
        const pos = args.match(/^\s*(?:[rbu]?['"]([\w.]+)['"]|([\w.]+(?:\(\))?))\s*(?:,|$)/);
        const ref = toKw ? toKw[1] || toKw[2] : pos ? pos[1] || pos[2] : null;
        const od = args.match(/on_delete\s*=\s*(?:models\.)?(\w+)/)?.[1];
        const colName = `${field}_id`;
        t.columns.set(colName, { name: colName, type: 'fk', notNull: !/null\s*=\s*True/.test(args), ...where });
        if (ref) t.fks.push({ column: colName, refTable: refKey(ref, k.key), refColumn: 'id', onDelete: od ? DJ_ON_DELETE[od] || od.toLowerCase() : null, ...where });
        continue;
      }
      t.columns.set(field, {
        name: field, type: type.replace(/Field$/, '').toLowerCase() || 'unknown', notNull: !/null\s*=\s*True/.test(args),
        default: args.match(/default\s*=\s*([^,)]+)/)?.[1]?.trim(), ...where,
        ...(/Encrypted/.test(type) ? { encrypted: true } : {}),
      });
    }
    // Body-level `x = something(...)` that is not a recognisable field (a field factory, a third-party field
    // with an unusual name) while no own field was read: the model's own columns are unknown → partial coverage.
    const opaque = e.own.filter((s) => /^\s+\w+\s*=\s*[\w.]+\s*\(/.test(s.text) && !DJ_FIELD_RE.test(s.text)
      && !/^\s*(?:objects|\w*manager|_\w+)\s*=|Manager\s*\(|as_manager\s*\(|^\s*(?:USERNAME_FIELD|EMAIL_FIELD|REQUIRED_FIELDS)\b|^\s*\w+\s*=\s*(?:property|staticmethod|classmethod|cached_property|_|gettext\w*|ugettext\w*)\s*\(/.test(s.text));
    if ((own.length && !t.columns.size) || (!own.length && opaque.length)) {
      stats.unparsed++;
      stats.items?.push({ file: e.file.rel, line: c.startLine, name: c.name, kind: 'django-model', reason: own.length ? 'fields declared but none parsed' : `field declaration not recognised (${opaque[0].text.trim().slice(0, 60)})` });
    }
    tables.set(k.key, t);
  }
  // Classes that declare Django model fields but could not be tied to models.Model (unknown base): partial coverage.
  for (const e of classes) {
    if (!e.djangoFile || memo.get(e)) continue;
    if (!e.own.some((s) => /^\s+\w+\s*=\s*models\.\w*(?:Field|ForeignKey)\s*\(/.test(s.text))) continue;
    stats.unparsed++;
    stats.items?.push({ file: e.file.rel, line: e.c.startLine, name: e.c.name, kind: 'django-model', reason: 'model base class not resolved' });
  }
  // Per-model facts for other extractors: table, unique fields (DRF / ModelForm generate "already exists" validators
  // for them), and whether the model is the user model (auth base class or AUTH_USER_MODEL).
  const authRoot = (e, seen = new Set()) => {
    if (seen.has(e)) return null;
    seen.add(e);
    for (const b of e.c.bases) {
      const r = resolveBase(e, b);
      if (r?.root && r.root !== 'PermissionsMixin' && DJ_AUTH_BASES[r.root]) return r.root;
      if (r?.cls) { const x = authRoot(r.cls, seen); if (x) return x; }
    }
    return null;
  };
  const info = {};
  for (const e of models) {
    const table = tableOfModel(e);
    if (!table) continue;
    const root = authRoot(e);
    const unique = new Set(root === 'AbstractUser' || root === 'User' ? ['username'] : []);
    for (const col of [...inherited(e), ...ownFields(e)]) if (!col.builtin && /\b(?:unique|primary_key)\s*=\s*True\b/.test(col.args)) unique.add(col.field);
    for (const b of e.own) {
      const uf = b.text.match(/^\s*USERNAME_FIELD\s*=\s*['"](\w+)['"]/);
      if (uf) unique.add(uf[1]);
    }
    const isUser = !!root || (!!authUserModel && authUserModel.split('.').pop() === e.c.name);
    info[e.c.name] = { table, file: e.file.rel, line: e.c.startLine, unique: [...unique], user: isUser };
  }
  return { tables, proxies, modelKeys, info, authUserModel, models: new Set(models.map((e) => `${e.mod}.${e.c.name}`)) };
}

/** Single-file convenience wrapper (kept for callers/tests that parse one models.py). */
export function parseDjango(file, stats = { unparsed: 0 }) {
  return parseDjangoProject([file], stats).tables;
}

// ───────────────────────── SQLAlchemy column arguments ─────────────────────────

/** `Optional[str]` / `str | None` / `"datetime"` → {type, optional, known}. */
function pyType(inner) {
  let t = inner.trim().replace(/^(['"])(.*)\1$/s, '$2').trim();
  let optional = false;
  const opt = t.match(/^(?:\w+\.)*Optional\[([\s\S]*)\]$/);
  if (opt) { optional = true; t = opt[1].trim(); }
  if (/\|\s*None\b|\bNone\s*\|/.test(t)) { optional = true; t = t.replace(/\|\s*None\b|\bNone\s*\|/g, '').trim(); }
  t = t.replace(/^(['"])(.*)\1$/s, '$2').trim();
  const base = t.split('[')[0].split('.').pop();
  return { type: PY_TYPES[base] || base.toLowerCase(), optional, known: base in PY_TYPES };
}

/** Parse the arguments of Column(...) / mapped_column(...). */
function columnArgs(args) {
  const positional = args.filter((a) => !/^\w+\s*=/.test(a.text));
  const all = args.map((a) => a.text).join(', ');
  const noStr = stripStrings(all);
  const saType = noStr.match(SA_TYPES)?.[1];
  const nullable = kwArg(args, 'nullable');
  // ForeignKey('user.id', ondelete='CASCADE') or ForeignKey(User.id) (model attribute, resolved to a table in extract()).
  const fk = all.match(/\bForeignKey\(\s*(?:['"]([\w.]+)['"]|([A-Z]\w*)\.(\w+))([^)]*)\)/);
  let ref = null;
  if (fk) {
    const od = fk[4].match(/ondelete\s*=\s*['"]([\w ]+)['"]/i)?.[1];
    const onDelete = od ? od.toLowerCase() : null;
    if (fk[1]) {
      const parts = fk[1].split('.');
      ref = { refTable: parts.length > 1 ? parts.at(-2) : parts[0], refColumn: parts.length > 1 ? parts.at(-1) : 'id', onDelete };
    } else {
      ref = { refTable: snakeCase(fk[2]), refModel: fk[2], refColumn: fk[3], onDelete };
    }
  }
  return {
    name: strLit(positional[0]?.text),
    saType,
    nullable: nullable === 'True' ? true : nullable === 'False' ? false : null,
    primaryKey: /^True$/.test(kwArg(args, 'primary_key') || ''),
    default: kwArg(args, 'default')?.trim(),
    fk: ref,
  };
}

function columnModel(field, info, mapped, where) {
  const type = info.saType || mapped?.type || 'unknown';
  const notNull = info.nullable !== null ? !info.nullable : info.primaryKey || (mapped ? !mapped.optional : false);
  return { name: field, type: type.toLowerCase(), notNull, default: info.default, ...where, ...(info.saType === 'Vector' ? { vector: true } : {}) };
}

/** One class-body logical line → {column, fk} | null. */
function parseOrmAttr(text) {
  const m = text.match(/^\s+(\w+)\s*([:=])([\s\S]*)$/);
  if (!m || m[1].startsWith('__')) return null;
  let ann = null;
  let value = null;
  if (m[2] === ':') {
    const eq = assignIndex(m[3]);
    ann = (eq < 0 ? m[3] : m[3].slice(0, eq)).trim();
    value = eq < 0 ? null : m[3].slice(eq + 1).trim();
  } else {
    if (m[3].startsWith('=')) return null; // `x == y` is not an assignment
    value = m[3].trim();
  }
  let mapped = null;
  if (ann) {
    const am = ann.match(/^(?:\w+\.)*(Mapped|WriteOnlyMapped|DynamicMapped)\[([\s\S]*)\]$/);
    if (am && am[1] !== 'Mapped') return null; // relationship collections
    if (am) mapped = pyType(am[2]);
  }
  if (value) {
    const vm = value.match(/^(?:\w+\.)*(Column|mapped_column)\s*\(/);
    if (!vm) return null; // relationship(), column_property(), constants, ...
    const open = vm[0].length - 1;
    if (closeIndex(value, open) !== value.length) return null;
    const info = columnArgs(splitTop(value, open + 1, value.length - 1));
    return { field: info.name || m[1], info, mapped };
  }
  // Annotation-only `x: Mapped[T]` is a column when T is a plain scalar (Mapped['Post'] needs relationship()).
  if (mapped?.known) return { field: m[1], info: { saType: null, nullable: null, primaryKey: false, default: undefined, fk: null }, mapped };
  return null;
}

const COLUMNISH = /\b(?:Column|mapped_column)\s*\(|\bMapped\[/;

/** Names of declarative bases defined in the file: `class Base(DeclarativeBase)`, `Base = declarative_base()`, abstract parents. */
function localBases(content, classes) {
  const out = new Set();
  for (const m of content.matchAll(/^(\w+)\s*(?::[^=\n]+)?=\s*(?:\w+\.)*(?:declarative_base|as_declarative)\s*\(/gm)) out.add(m[1]);
  for (const c of classes) {
    if (c.bases.some((b) => /^(?:\w+\.)*(?:DeclarativeBase|DeclarativeBaseNoMeta)$/.test(b))) out.add(c.name);
  }
  return out;
}

const isAbstract = (c) => c.logical.some((b) => /^\s+__abstract__\s*=\s*True\b/.test(b.text));

/** Columns a SQLAlchemy class body declares: `x = Column(...)`, `x: Mapped[T]`, and `@declared_attr def x(cls): return Column(...)`. */
function saClassAttrs(c) {
  const out = [];
  for (let i = 0; i < c.logical.length; i++) {
    const b = c.logical[i];
    let attr = parseOrmAttr(b.text);
    if (!attr && /^\s+@(?:\w+\.)*declared_attr\b/.test(b.text)) {
      const def = c.logical[i + 1]?.text.match(/^\s+def\s+(\w+)\s*\(/);
      const ret = c.logical[i + 2]?.text.match(/^\s+return\s+((?:\w+\.)*(?:Column|mapped_column)\s*\([\s\S]*\))\s*$/);
      if (def && ret && !def[1].startsWith('__')) attr = parseOrmAttr(`    ${def[1]} = ${ret[1]}`);
    }
    if (attr) out.push({ attr, b });
  }
  return out;
}

/**
 * Project-wide SQLAlchemy column mixins and abstract model bases (SQLAlchemy docs, "Composing Mapped Hierarchies with
 * Mixins"): `class TimestampMixin: created_at = Column(...)` and `class Base(db.Model): __abstract__ = True` in one
 * module contribute their columns to models declared in other modules.
 * @returns {Map<string, {abstract:boolean, attrs:object[], file:string}>}
 */
export function sqlAlchemyMixins(files) {
  const out = new Map();
  for (const f of files) {
    if (!/\bsqlalchemy\b|flask_sqlalchemy|\bdb\.Model\b/.test(f.content)) continue;
    for (const c of classBlocks(f.content)) {
      const explicit = c.logical.some((b) => /^\s+__tablename__\s*(?::\s*\w+\s*)?=/.test(b.text));
      const abstract = isAbstract(c);
      const plain = !c.bases.length || c.bases.every((b) => /^(?:object|ABC|abc\.ABC)$/.test(b) || out.has(b.split('.').pop()));
      if (explicit || (!abstract && !plain)) continue;
      const attrs = saClassAttrs(c);
      if (!attrs.length && !abstract) continue;
      out.set(c.name, { abstract, attrs, file: f.rel, bases: c.bases });
    }
  }
  return out;
}

export function parseSqlAlchemy(file, stats = { unparsed: 0 }, { mixins = new Map(), skip = new Set() } = {}) {
  const tables = new Map();
  const classes = classBlocks(file.content);
  const bases = localBases(file.content, classes);
  // Abstract model parents (`class TimestampModel(db.Model): __abstract__ = True`) are bases for their children.
  const isModelBase = (b) => bases.has(b) || b === 'Base' || (/^(?:\w+\.)?Model$/.test(b) && b !== 'models.Model') || !!mixins.get(b.split('.').pop())?.abstract;
  /** Columns inherited from mixins / abstract parents (depth-first, base order). */
  const inheritedAttrs = (c, seen = new Set()) => {
    const out = [];
    for (const b of c.bases) {
      const n = b.split('.').pop();
      if (seen.has(n)) continue;
      seen.add(n);
      // Plain column mixins only (`class TimestampMixin: created_at = Column(...)`); __abstract__ parents mark the child
      // as a model but their columns are not copied here (kept conservative, as before).
      const mx = mixins.get(n);
      if (mx && !mx.abstract) out.push(...inheritedAttrs({ bases: mx.bases || [] }, seen), ...mx.attrs.map((x) => ({ ...x, file: mx.file })));
    }
    return out;
  };
  for (const c of classes) {
    if (bases.has(c.name) && !c.bases.some(isModelBase)) continue; // the declarative base itself
    if (c.bases.includes('models.Model')) continue; // Django
    if (skip.has(`${file.rel.replace(/\.py$/, '').replace(/\/__init__$/, '').split('/').join('.')}.${c.name}`)) continue;
    const explicit = c.logical.map((b) => b.text.match(/^\s+__tablename__\s*(?::\s*\w+\s*)?=\s*['"]([^'"]+)['"]/)?.[1]).find(Boolean);
    const modelLike = explicit || c.bases.some(isModelBase);
    if (!modelLike) continue;
    if (isAbstract(c)) {
      bases.add(c.name);
      continue;
    }
    const tn = explicit || snakeCase(c.name);
    const t = newTable(tn, { name: tn, kind: 'table', model: c.name, file: file.rel, line: c.startLine, snippet: c.header, source: 'sqlalchemy' });
    let columnish = 0;
    for (const { attr, b, file: from } of inheritedAttrs(c)) {
      const where = { file: from || file.rel, line: b.line, snippet: b.snippet };
      t.columns.set(attr.field, columnModel(attr.field, attr.info, attr.mapped, where));
      if (attr.info.fk) t.fks.push({ column: attr.field, ...attr.info.fk, ...where });
    }
    for (const b of c.logical) {
      if (COLUMNISH.test(b.text) && !/\brelationship\s*\(|WriteOnlyMapped|DynamicMapped/.test(b.text)) columnish++;
    }
    const ownAttrs = saClassAttrs(c);
    for (const { attr, b } of ownAttrs) {
      const where = { file: file.rel, line: b.line, snippet: b.snippet };
      t.columns.set(attr.field, columnModel(attr.field, attr.info, attr.mapped, where));
      if (attr.info.fk) t.fks.push({ column: attr.field, ...attr.info.fk, ...where });
    }
    if (columnish && !ownAttrs.length) stats.unparsed++;
    // An implicit table name is only trusted when the class really declares columns.
    if (!explicit && !t.columns.size) continue;
    tables.set(tn, t);
  }
  return tables;
}

// ───────────────────────── SQLAlchemy Core + Alembic ─────────────────────────

/** Column('name', Type, ...) / ForeignKeyConstraint([...], [...]) items of a Table()/create_table() argument list. */
function tableItems(file, t, items) {
  const content = file.content;
  for (const a of items) {
    const where = { file: file.rel, line: lineOf(content, a.start), snippet: snip(a.text) };
    const cm = a.text.match(/^(?:\w+\.)*Column\s*\(/);
    if (cm) {
      const info = columnArgs(callArgs(content, a.start + cm[0].length - 1) || []);
      if (!info.name) continue;
      t.columns.set(info.name, columnModel(info.name, info, null, where));
      if (info.fk) t.fks.push({ column: info.name, ...info.fk, ...where });
      continue;
    }
    const fm = a.text.match(/^(?:\w+\.)*ForeignKeyConstraint\s*\(/);
    if (fm) {
      const args = callArgs(content, a.start + fm[0].length - 1) || [];
      const list = (x) => [...(x?.text || '').matchAll(/['"]([\w.]+)['"]/g)].map((m) => m[1]);
      const cols = list(args[0]);
      const refs = list(args[1]);
      const od = strLit(kwArg(args, 'ondelete') || '');
      cols.forEach((col, i) => {
        const parts = (refs[i] || refs[0] || '').split('.');
        if (!parts[0]) return;
        t.fks.push({ column: col, refTable: parts.length > 1 ? parts.at(-2) : parts[0], refColumn: parts.length > 1 ? parts.at(-1) : 'id', onDelete: od ? od.toLowerCase() : null, ...where });
      });
    }
  }
}

/** Parse the Table()/op.create_table() call whose '(' is at `open` → table or null. */
function coreTable(file, open, { skipMeta, source }) {
  const args = callArgs(file.content, open);
  const tn = strLit(args?.[0]?.text);
  if (!tn) return null;
  const lineEnd = file.content.indexOf('\n', open);
  const snippet = snip(file.content.slice(file.content.lastIndexOf('\n', open) + 1, lineEnd < 0 ? undefined : lineEnd));
  const t = newTable(tn, { name: tn, kind: 'table', file: file.rel, line: lineOf(file.content, open), snippet, source });
  tableItems(file, t, args.slice(skipMeta ? 2 : 1));
  return t;
}

/** SQLAlchemy Core `x = sa.Table('name', metadata, sa.Column('c', ...))` in application code. */
export function parseCoreTables(file) {
  const tables = new Map();
  if (!/\bsqlalchemy\b|flask_sqlalchemy/.test(file.content)) return tables;
  for (const m of file.content.matchAll(/(?<![\w.])(?:(?:sa|db|sqlalchemy)\.)?Table\s*\(/g)) {
    const t = coreTable(file, m.index + m[0].length - 1, { skipMeta: true, source: 'sqlalchemy-core' });
    if (t?.columns.size) tables.set(t.key, t);
  }
  return tables;
}

const ALEMBIC_OPS = /\bop\.(?:create_table|add_column|drop_table|drop_column|batch_alter_table|rename_table|alter_column)\s*\(/;

/** Alembic revision metadata → {revision, parents[]}. */
function revisionInfo(content) {
  const revision = content.match(/^revision\s*(?::[^=\n]+)?=\s*['"]([\w-]+)['"]/m)?.[1] || null;
  const down = content.match(/^down_revision\s*(?::[^=\n]+)?=\s*(.+)$/m)?.[1] || '';
  return { revision, parents: [...down.matchAll(/['"]([\w-]+)['"]/g)].map((m) => m[1]) };
}

/** Order migration files parent-first (Kahn), ties and unlinked files by path. */
export function orderMigrations(files) {
  const info = new Map(files.map((f) => [f, revisionInfo(f.content)]));
  const byRev = new Map();
  for (const [f, i] of info) if (i.revision) byRev.set(i.revision, f);
  const pending = new Map(files.map((f) => [f, info.get(f).parents.filter((p) => byRev.has(p) && byRev.get(p) !== f).length]));
  const out = [];
  const byPath = (a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0);
  let ready = files.filter((f) => !pending.get(f)).sort(byPath);
  while (ready.length) {
    const f = ready.shift();
    out.push(f);
    const rev = info.get(f).revision;
    if (!rev) continue;
    for (const [g, n] of pending) {
      if (n > 0 && info.get(g).parents.includes(rev)) {
        pending.set(g, n - 1);
        if (n - 1 === 0) ready = [...ready, g].sort(byPath);
      }
    }
  }
  for (const f of files.slice().sort(byPath)) if (!out.includes(f)) out.push(f); // cycles
  return out;
}

/** Operations in a migration's upgrade() body, in source order. */
function migrationOps(file) {
  const content = file.content;
  const up = content.match(/^def\s+upgrade\s*\(/m);
  const start = up ? up.index : 0;
  const nextDef = up ? content.slice(start + up[0].length).search(/^def\s/m) : -1;
  const end = up && nextDef >= 0 ? start + up[0].length + nextDef : content.length;
  const region = (re) => [...content.matchAll(re)].filter((m) => m.index >= start && m.index < end);
  const aliases = region(/\bwith\s+op\.batch_alter_table\s*\(\s*['"](\w+)['"][^\n]*?\bas\s+(\w+)/g).map((m) => ({ at: m.index, table: m[1], alias: m[2] }));
  const tableOf = (alias, at) => aliases.filter((a) => a.alias === alias && a.at < at).at(-1)?.table || null;
  const ops = [];
  for (const m of region(/\bop\.create_table\s*\(/g)) ops.push({ at: m.index, op: 'create', open: m.index + m[0].length - 1 });
  for (const m of region(/\bop\.drop_table\s*\(\s*['"](\w+)['"]/g)) ops.push({ at: m.index, op: 'drop', table: m[1] });
  for (const m of region(/\bop\.rename_table\s*\(\s*['"](\w+)['"]\s*,\s*['"](\w+)['"]/g)) ops.push({ at: m.index, op: 'rename', table: m[1], to: m[2] });
  for (const m of region(/\b(\w+)\.(add_column|drop_column|alter_column)\s*\(/g)) {
    const args = callArgs(content, m.index + m[0].length - 1);
    if (!args) continue;
    let table;
    let rest;
    if (m[1] === 'op') {
      table = strLit(args[0]?.text);
      rest = args.slice(1);
    } else {
      table = tableOf(m[1], m.index);
      rest = args;
    }
    if (!table) continue;
    ops.push({ at: m.index, op: m[2], table, args: rest });
  }
  return ops.sort((a, b) => a.at - b.at);
}

/** Replay Alembic migrations (revision order) into a table map. */
export function parseAlembic(files) {
  const tables = new Map();
  for (const file of orderMigrations(files)) {
    for (const o of migrationOps(file)) {
      if (o.op === 'create') {
        const t = coreTable(file, o.open, { skipMeta: false, source: 'alembic' });
        if (t) tables.set(t.key, t);
      } else if (o.op === 'drop') {
        tables.delete(o.table);
      } else if (o.op === 'rename') {
        const t = tables.get(o.table);
        if (!t) continue;
        tables.delete(o.table);
        Object.assign(t, { key: o.to, name: o.to });
        tables.set(o.to, t);
      } else {
        const t = tables.get(o.table);
        if (!t) continue;
        if (o.op === 'add_column') tableItems(file, t, o.args.slice(0, 1));
        else if (o.op === 'drop_column') {
          const col = strLit(o.args[0]?.text);
          t.columns.delete(col);
          t.fks = t.fks.filter((f) => f.column !== col);
        } else if (o.op === 'alter_column') {
          const col = strLit(o.args[0]?.text);
          const to = strLit(kwArg(o.args, 'new_column_name') || '');
          const c = t.columns.get(col);
          if (!c || !to) continue;
          t.columns.delete(col);
          t.columns.set(to, { ...c, name: to });
          for (const f of t.fks) if (f.column === col) f.column = to;
        }
      }
    }
  }
  return tables;
}

// ───────────────────────── SQLModel / pydantic classes ─────────────────────────

const DTO_ROOT = /^(?:\w+\.)*(?:SQLModel|BaseModel|BaseSchema)$/;
const PY_SCALAR = new Set(['EmailStr', 'SecretStr', 'HttpUrl', 'AnyUrl', 'AnyHttpUrl', 'NameEmail', 'constr', 'conint', 'PositiveInt', 'NonNegativeInt', 'UUID4', 'IPvAnyAddress']);

/**
 * Annotated classes of the project (SQLModel and pydantic): name → {name, bases, file, line, header, table, fields, sqlmodel}.
 * fields: [{name, type, notNull, fk, relation, where, vector}] declared in the class body.
 */
export function annotatedClasses(files) {
  const out = new Map();
  for (const f of files) {
    if (!/^class\s+\w+\s*\(/m.test(f.content)) continue;
    for (const c of classBlocks(f.content)) {
      if (!c.bases.length) continue;
      const bases = c.bases.filter((b) => !/^\w+\s*=/.test(b));
      const table = c.bases.some((b) => /^table\s*=\s*True$/.test(b.trim()));
      const lines = c.logical.filter((b) => b.text.trim() && !/^\s*[rbuRBU]?(?:'''|""")/.test(b.text));
      const indent = lines.length ? Math.min(...lines.map((b) => indentOf(b.text))) : 0;
      const fields = [];
      let tablename = null;
      for (const b of lines) {
        if (indentOf(b.text) !== indent) continue;
        const tn = b.text.match(/^\s+__tablename__\s*(?::[^=]+)?=\s*['"]([^'"]+)['"]/);
        if (tn) tablename = tn[1];
        const m = b.text.match(/^\s+([A-Za-z]\w*)\s*:\s*([\s\S]+)$/);
        if (!m || m[1] === 'model_config') continue;
        const eq = assignIndex(m[2]);
        const ann = (eq < 0 ? m[2] : m[2].slice(0, eq)).trim();
        const value = eq < 0 ? null : m[2].slice(eq + 1).trim();
        if (/^(?:\w+\.)*ClassVar\b/.test(ann) || /^(?:def|class|return)\b/.test(m[1])) continue;
        const where = { file: f.rel, line: b.line, snippet: b.snippet };
        const relation = !!value && /^(?:\w+\.)*(?:Relationship|relationship|PrivateAttr|computed_field)\s*\(/.test(value);
        const inner = ann.replace(/^(?:\w+\.)*Annotated\[\s*/, '').replace(/,[\s\S]*\]$/, (x) => (/Annotated\[/.test(ann) ? '' : x));
        const ty = pyType(inner);
        const bare = inner.replace(/^(?:\w+\.)*Optional\[([\s\S]*)\]$/, '$1').replace(/\|\s*None\b|\bNone\s*\|/g, '').trim().replace(/^['"]|['"]$/g, '');
        const scalarName = bare.split('[')[0].split('.').pop();
        const type = PY_SCALAR.has(scalarName) ? 'string' : /^(?:list|List|set|Set|tuple|dict|Dict|Json)$/.test(scalarName) ? 'json' : ty.type;
        const fld = { name: m[1], type, notNull: !ty.optional, where, relation, ref: ty.known || PY_SCALAR.has(scalarName) ? null : bare, fk: null };
        const fm = value && value.match(/^(?:\w+\.)*(Field|Column|mapped_column)\s*\(/);
        if (fm) {
          const args = splitTop(value, fm[0].length, closeIndex(value, fm[0].length - 1) - 1);
          const ref = strLit(kwArg(args, 'foreign_key') || '');
          const od = strLit(kwArg(args, 'ondelete') || '');
          if (ref) {
            const parts = ref.split('.');
            fld.fk = { refTable: parts.length > 1 ? parts.at(-2) : parts[0], refColumn: parts.length > 1 ? parts.at(-1) : 'id', onDelete: od ? od.toLowerCase() : null };
          }
          const nullable = kwArg(args, 'nullable');
          if (nullable) fld.notNull = nullable !== 'True';
          const sa = kwArg(args, 'sa_column');
          const sm = sa && sa.match(/^(?:\w+\.)*Column\s*\(/);
          if (sm) {
            const info = columnArgs(splitTop(sa, sm[0].length, closeIndex(sa, sm[0].length - 1) - 1));
            if (info.fk) fld.fk = info.fk;
            if (info.saType) fld.type = info.saType.toLowerCase();
            if (info.saType === 'Vector') fld.vector = true;
            if (info.name) fld.name = info.name;
          }
        }
        fields.push(fld);
      }
      const entry = { name: c.name, bases, file: f.rel, line: c.startLine, header: c.header, table, tablename, fields };
      // Two classes of one name: keep the mapped one.
      const prev = out.get(c.name);
      if (!prev || (table && !prev.table)) out.set(c.name, entry);
    }
  }
  return out;
}

/** Is the class a SQLModel / pydantic class (transitively)? */
function dtoClass(classes, name, seen = new Set()) {
  if (seen.has(name)) return false;
  seen.add(name);
  const c = classes.get(name);
  return !!c && c.bases.some((b) => DTO_ROOT.test(b.replace(/\[[\s\S]*\]$/, '')) || dtoClass(classes, b.replace(/\[[\s\S]*\]$/, '').split('.').pop(), seen));
}
/** Fields including inherited ones (base first, overridden by the class). */
function allFields(classes, name, seen = new Set()) {
  if (seen.has(name) || !classes.has(name)) return [];
  seen.add(name);
  const c = classes.get(name);
  const out = new Map();
  for (const b of c.bases) for (const f of allFields(classes, b.replace(/\[[\s\S]*\]$/, '').split('.').pop(), seen)) out.set(f.name, f);
  for (const f of c.fields) out.set(f.name, f);
  return [...out.values()];
}

/** SQLModel tables: `class X(Base, table=True)`. */
export function parseSqlModels(classes) {
  const tables = new Map();
  for (const c of classes.values()) {
    if (!c.table || !dtoClass(classes, c.name)) continue;
    const key = c.tablename || c.name.toLowerCase();
    const t = newTable(key, { name: key, kind: 'table', model: c.name, file: c.file, line: c.line, snippet: c.header, source: 'sqlmodel' });
    for (const f of allFields(classes, c.name)) {
      if (f.relation) continue;
      // An attribute typed with another mapped class is a relation, not a column.
      const refClass = f.ref && classes.get(f.ref.replace(/^(?:list|List|set|Set|Optional)\[|\]$/g, '').replace(/^['"]|['"]$/g, ''));
      if (refClass?.table) continue;
      t.columns.set(f.name, { name: f.name, type: f.type, notNull: f.notNull, ...f.where, ...(f.vector ? { vector: true } : {}) });
      if (f.fk) t.fks.push({ column: f.name, ...f.fk, ...f.where });
    }
    if (t.columns.size) tables.set(key, t);
  }
  return tables;
}

// ───────────────────────── session writes and deletes ─────────────────────────

const PY_NON_APP = /(^|\/)tests?\.py$|(^|\/)(?:migrations|alembic|versions|scripts?|seeds?|fixtures|management\/commands)\//i;
const SESSION = String.raw`(?:\b(?:\w+\.)*(?:db_session|async_session|dbsession|session|sess|db|_session|_db))`;
// A column that stores the digest by name: the value written is the output of the hash function, not the password.
const HASHED_COLUMN = /(^|_)(hash(ed)?|digest)(_|$)|passwordhash|hashedpassword/i;
// … unless the code visibly assigns the raw password to it.
const rawInto = (body, col) => new RegExp(String.raw`\b${col}['"]?\s*[=:]\s*(?:\w+\.)*(?:plain_?|raw_?)?password\s*[,)}\n]`).test(body);
const SESSION_READ = String.raw`(?:get|get_one|scalar|scalars|exec|execute|query|first|one|one_or_none)`;

/** Text of the bracket group opening at src[open]; '' when unbalanced. */
const group = (src, open) => {
  const c = closeIndex(src, open);
  return c < 0 ? '' : src.slice(open + 1, c - 1);
};

export function pythonOrmOps(ctx) {
  const { graph, ev } = ctx;
  const models = new Map(); // class name → table key
  for (const [k, t] of Object.entries(ctx.shared.tables || {})) {
    const m = t?.model && String(t.model).split('.').pop();
    if (m && /\.py$/.test(t.file || '') && /python-orm/.test(t.source || '') && graph.node(`store:table:${k}`)) models.set(m, k);
  }
  if (!models.size) return { writes: 0, deletes: 0 };
  const files = ctx.files.filter((f) => f.rel.endsWith('.py') && !f.test && typeof f.content === 'string' && !PY_NON_APP.test(f.rel) && f.content.length < 600000);
  if (!files.some((f) => /\bsqlalchemy\b|\bsqlmodel\b|flask_sqlalchemy/.test(f.content))) return { writes: 0, deletes: 0 };
  const classes = annotatedClasses(files);
  const alt = [...models.keys()].sort((a, b) => b.length - a.length).join('|');
  const modelIn = (text) => (text ? new RegExp(String.raw`\b(${alt})\b`).exec(text)?.[1] || null : null);
  /** Model / DTO named by an annotation: `User | None`, Optional["User"], Annotated alias. */
  const aliases = new Map();
  for (const f of files) {
    for (const m of f.content.matchAll(/^(\w+)\s*(?::\s*TypeAlias\s*)?=\s*(?:\w+\.)*Annotated\[\s*(?:["']?)([\w.]+)/gm)) aliases.set(m[1], m[2].split('.').pop());
  }
  const annName = (ann) => {
    const t = String(ann || '').replace(/["']/g, '').replace(/\|\s*None\b|\bNone\s*\|/g, '').replace(/^(?:\w+\.)*(?:Optional|Annotated|Awaitable)\[\s*/, '').trim();
    const id = /^([\w.]+)/.exec(t)?.[1]?.split('.').pop() || null;
    return id ? aliases.get(id) || id : null;
  };
  // functions returning a model: `def get_user(...) -> User | None`
  const returns = new Map();
  const defsOf = new Map();
  for (const f of files) {
    const list = [];
    const re = /^([ \t]*)(?:async\s+)?def\s+(\w+)\s*\(/gm;
    let m;
    while ((m = re.exec(f.content))) {
      const open = m.index + m[0].length - 1;
      const close = closeIndex(f.content, open);
      if (close < 0) continue;
      const ret = /^\s*->\s*([^:\n]+):/.exec(f.content.slice(close, close + 200))?.[1]?.trim() || null;
      const params = splitTop(f.content, open + 1, close - 1).map((a) => {
        const pm = /^\*{0,2}(\w+)\s*(?::\s*([\s\S]+?))?(?:\s*=(?!=)[\s\S]*)?$/.exec(a.text);
        return pm ? { name: pm[1], ann: pm[2]?.trim() || null } : null;
      }).filter(Boolean);
      list.push({ indent: m[1].length, name: m[2], at: m.index, body: close, params, ret });
    }
    list.forEach((d, i) => {
      let end = f.content.length;
      for (const e of list.slice(i + 1)) if (e.indent <= d.indent) { end = e.at; break; }
      d.end = end;
      const rn = annName(d.ret);
      if (rn && models.has(rn)) {
        if (!returns.has(d.name)) returns.set(d.name, new Set());
        returns.get(d.name).add(rn);
      }
    });
    defsOf.set(f.rel, list);
  }
  const returnOf = (fn) => (returns.get(fn)?.size === 1 ? [...returns.get(fn)][0] : null);
  const routesByFile = new Map();
  for (const [id, r] of Object.entries(ctx.shared.routes || {})) {
    if (!r?.file?.endsWith('.py') || !r.line || !graph.has(id)) continue;
    if (!routesByFile.has(r.file)) routesByFile.set(r.file, []);
    routesByFile.get(r.file).push({ id, line: r.line });
  }
  const lineNo = (src, off) => lineOf(src, off);
  const routeOf = (f, d) => {
    const start = lineNo(f.content, d.at);
    return (routesByFile.get(f.rel) || []).filter((r) => r.line <= start + 1 && r.line >= start - 12).sort((a, b) => b.line - a.line)[0]?.id || null;
  };
  const columnsOf = (key) => new Set(ctx.shared.tables[key]?.columns || []);
  let writes = 0;
  let deletes = 0;
  const flows = []; // deletes: {f, d, endpoint, targets:[{key, line, snippet}]}
  for (const f of files) {
    const src = f.content;
    if (!new RegExp(SESSION + String.raw`\.(?:add|add_all|merge|delete|exec|execute|scalar|scalars|query|commit|flush)\s*\(`).test(src)) continue;
    const lines = src.split('\n');
    for (const d of defsOf.get(f.rel) || []) {
      // own body only: nested defs are visited on their own
      let body = src.slice(d.body, d.end);
      for (const e of defsOf.get(f.rel)) if (e !== d && e.at > d.at && e.end <= d.end) body = body.slice(0, e.at - d.body) + body.slice(e.at - d.body, e.end - d.body).replace(/[^\n]/g, ' ') + body.slice(e.end - d.body);
      const off = d.body;
      const endpoint = routeOf(f, d);
      const at = (o) => ({ line: lineNo(src, off + o), snippet: (lines[lineNo(src, off + o) - 1] || '').trim().slice(0, 200) });
      // ---- what the names of this function hold ----
      const modelVar = new Map(); // var → {model, fresh}
      const dtoVar = new Map(); // var → class name
      for (const p of d.params) {
        const n = annName(p.ann);
        if (n && models.has(n)) modelVar.set(p.name, { model: n, fresh: false });
        else if (n && classes.has(n)) dtoVar.set(p.name, n);
      }
      const stmtVar = new Map(); // statement = select(Model)…
      const dataVar = new Map(); // data = dto.model_dump(…) | {…}
      const fieldsOfExpr = (text) => {
        const t = String(text || '').trim();
        const dump = /^(\w+)\.(?:model_dump|dict)\s*\(/.exec(t);
        if (dump) return dtoVar.has(dump[1]) ? allFields(classes, dtoVar.get(dump[1])).map((x) => x.name) : [];
        if (/^\{/.test(t)) return [...t.matchAll(/['"](\w+)['"]\s*:/g)].map((x) => x[1]);
        if (/^\w+$/.test(t)) return dtoVar.has(t) ? allFields(classes, dtoVar.get(t)).map((x) => x.name) : dataVar.get(t) || [];
        return [];
      };
      for (const m of body.matchAll(/^[ \t]*(\w+)\s*(?::\s*([^=\n]+?))?\s*=(?!=)\s*(?:await\s+)?/gm)) {
        const rhsAt = m.index + m[0].length;
        let rhs = body.slice(rhsAt, rhsAt + 600);
        rhs = logicalRhs(rhs);
        const v = m[1];
        const ann = annName(m[2]);
        const ctor = new RegExp(String.raw`^(${alt})\s*(?:\.\s*(?:model_validate|from_orm|parse_obj|construct)\s*)?\(`).exec(rhs);
        const call = /^(?:self\.)?(?:\w+\.)*(\w+)\s*\(/.exec(rhs);
        if (ctor) modelVar.set(v, { model: ctor[1], fresh: true });
        else if (/^(?:\w+\.)*select\s*\(/.test(rhs) || /^\w+\.(?:where|filter|options|order_by)\s*\(/.test(rhs) && stmtVar.has(/^\w+/.exec(rhs)[0])) stmtVar.set(v, modelIn(rhs.slice(0, 200)) || stmtVar.get(/^\w+/.exec(rhs)[0]));
        else if (new RegExp(String.raw`^${SESSION}\.${SESSION_READ}\s*\(`).test(rhs) || /^(\w+)\.(?:scalar|scalars|first|one)/.test(rhs)) {
          const inner = modelIn(rhs) || [...stmtVar.entries()].find(([s]) => new RegExp(String.raw`\(\s*${s}\s*[),]`).test(rhs))?.[1];
          if (inner) modelVar.set(v, { model: inner, fresh: false });
        } else if (ann && models.has(ann)) modelVar.set(v, { model: ann, fresh: false });
        else if (call && returnOf(call[1])) modelVar.set(v, { model: returnOf(call[1]), fresh: false });
        else if (/^(\w+)\.(?:model_dump|dict)\s*\(/.test(rhs) || /^\{/.test(rhs)) dataVar.set(v, fieldsOfExpr(rhs));
        else {
          const dc = /^(\w+)\s*(?:\.\s*model_validate\s*)?\(/.exec(rhs)?.[1];
          if (dc && classes.has(dc) && !models.has(dc)) dtoVar.set(v, dc);
        }
      }
      for (const m of body.matchAll(/\bfor\s+(\w+)\s+in\s+([^\n:]+):/g)) {
        const mv = /^\w+$/.exec(m[2].trim()) && modelVar.get(m[2].trim());
        if (mv) modelVar.set(m[1], { ...mv });
      }
      for (const m of body.matchAll(/(?<![\w.])(\w+)\[\s*['"](\w+)['"]\s*\]\s*=(?!=)/g)) if (dataVar.has(m[1])) dataVar.set(m[1], [...dataVar.get(m[1]), m[2]]);
      const write = (model, op, o, cols, text = null) => {
        const key = models.get(model);
        const tid = `store:table:${key}`;
        if (!graph.has(tid)) return;
        const { line, snippet: ln } = at(o);
        const snippet = text ? text.replace(/\s+/g, ' ').slice(0, 200) : ln;
        const e = ev(f.rel, line, snippet, 'static', 0.8, 'Python ORM write');
        // The function, not the endpoint, is the writer: which endpoint a write serves stays flow.js' conclusion (`via`).
        const from = `consumer:${f.rel}#${d.name}`;
        if (!graph.has(from)) graph.addNode({ id: from, type: 'Consumer', name: `${f.rel}#${d.name}`, file: f.rel, fn: d.name, line, evidence: [ev(f.rel, line, snippet, 'static', 0.7)] });
        const we = graph.addEdge({ from, to: tid, type: 'writes', op, file: f.rel, line, evidence: [e] });
        we.ops ||= [];
        if (!we.ops.includes(op) && we.ops.length < 10) we.ops.push(op);
        writes++;
        const known = columnsOf(key);
        for (const c of new Set(cols || [])) {
          const cid = `store:column:${key}.${c}`;
          if (!known.has(c) || !graph.has(cid)) continue;
          for (const r of graph.edgesFrom(cid, 'represents')) graph.addEdge({ from: r.to, to: cid, type: 'flowsTo', column: c, viaColumnMapping: true, python: true, ...(HASHED_COLUMN.test(c) && !rawInto(body, c) ? { transformed: 'hash' } : {}), ...(op === 'update' ? { op } : {}), evidence: [e] });
        }
      };
      const persists = new RegExp(SESSION + String.raw`\.(?:add|add_all|merge|commit|flush|bulk_save_objects)\s*\(`).test(body);
      const kwCols = (args) => splitTop(args, 0, args.length).flatMap((a) => {
        const k = /^(\w+)\s*=(?!=)/.exec(a.text);
        if (k) return k[1] === 'update' ? [] : [k[1]];
        const sp = /^\*\*\s*([\s\S]+)$/.exec(a.text);
        return sp ? fieldsOfExpr(sp[1]) : [];
      });
      const updateKw = (args) => {
        const u = splitTop(args, 0, args.length).find((a) => /^update\s*=/.test(a.text));
        return u ? fieldsOfExpr(u.text.replace(/^update\s*=\s*/, '')) : [];
      };
      if (persists) {
        for (const m of body.matchAll(new RegExp(String.raw`(?<![\w.])(${alt})\s*(\.\s*(?:model_validate|from_orm|parse_obj)\s*)?\(`, 'g'))) {
          const open = m.index + m[0].length - 1;
          const args = group(body, open);
          if (m[2]) {
            const first = splitTop(args, 0, args.length)[0]?.text || '';
            write(m[1], 'create', m.index, [...fieldsOfExpr(first), ...updateKw(args)], `${m[0]}${args})`);
          } else if (new RegExp(String.raw`(?:${SESSION}\.(?:add|merge)\s*\(\s*|=\s*)$`).test(body.slice(0, m.index)) || /\[\s*$/.test(body.slice(0, m.index))) write(m[1], 'create', m.index, kwCols(args), `${m[0]}${args})`);
        }
        for (const m of body.matchAll(/(?<![\w.])([\w.]+)\.sqlmodel_update\s*\(/g)) {
          const mv = modelVar.get(m[1]);
          if (!mv) continue;
          const args = group(body, m.index + m[0].length - 1);
          write(mv.model, 'update', m.index, [...fieldsOfExpr(splitTop(args, 0, args.length)[0]?.text || ''), ...updateKw(args)]);
        }
        for (const m of body.matchAll(/\bsetattr\s*\(\s*(\w+)\s*,/g)) {
          const mv = modelVar.get(m[1]);
          if (mv) write(mv.model, 'update', m.index, [...dtoVar.values()].flatMap((n) => allFields(classes, n).map((x) => x.name)));
        }
        for (const m of body.matchAll(/(?:^|[^\w.])(\w+)\.(\w+)\s*=(?!=)/gm)) {
          const mv = modelVar.get(m[1]);
          if (mv && columnsOf(models.get(mv.model)).has(m[2])) write(mv.model, mv.fresh ? 'create' : 'update', m.index, [m[2]]);
        }
        for (const m of body.matchAll(new RegExp(SESSION + String.raw`\.(?:add|merge)\s*\(\s*(\w+)\s*[,)]`, 'g'))) {
          const mv = modelVar.get(m[1]);
          if (mv) write(mv.model, mv.fresh ? 'create' : 'update', m.index, []);
        }
      }
      // Core statements: insert(Model).values(a=…), update(Model).values(…)
      for (const m of body.matchAll(new RegExp(String.raw`(?<![\w.])(?:sa\.|sqlalchemy\.)?(insert|update|delete)\s*\(\s*(${alt})\s*\)`, 'g'))) {
        if (m[1] === 'delete') continue;
        const rest = body.slice(m.index, m.index + 600);
        const vm = /\.values\s*\(/.exec(rest);
        const args = vm ? group(body, m.index + vm.index + vm[0].length - 1) : '';
        write(m[2], m[1] === 'insert' ? 'create' : 'update', m.index, [...kwCols(args), ...fieldsOfExpr(args)]);
      }
      for (const m of body.matchAll(new RegExp(SESSION + String.raw`\.query\s*\(\s*(${alt})\s*\)[^\n]*?\.update\s*\(`, 'g'))) {
        const args = group(body, m.index + m[0].length - 1);
        write(m[1], 'update', m.index, [...fieldsOfExpr(args), ...[...args.matchAll(new RegExp(String.raw`\b${m[1]}\.(\w+)\s*:`, 'g'))].map((x) => x[1])]);
      }
      // ---- deletes ----
      const targets = [];
      const del = (model, o) => {
        const key = models.get(model);
        if (key) targets.push({ key, ...at(o) });
      };
      for (const m of body.matchAll(new RegExp(SESSION + String.raw`\.delete\s*\(\s*(\w+)\s*\)`, 'g'))) {
        const mv = modelVar.get(m[1]);
        if (mv && !mv.fresh) del(mv.model, m.index);
      }
      for (const m of body.matchAll(new RegExp(String.raw`(?<![\w.])(?:sa\.|sqlalchemy\.)?delete\s*\(\s*(${alt})\s*\)`, 'g'))) del(m[1], m.index);
      for (const m of body.matchAll(new RegExp(SESSION + String.raw`\.query\s*\(\s*(${alt})\s*\)[^\n]*?\.delete\s*\(`, 'g'))) del(m[1], m.index);
      if (targets.length) {
        deletes += targets.length;
        for (const t of targets) write([...models].find(([, k]) => k === t.key)[0], 'delete', body.indexOf(t.snippet.slice(0, 20)) >= 0 ? body.indexOf(t.snippet.slice(0, 20)) : 0, []);
        flows.push({ f, d, endpoint, targets });
      }
    }
  }
  // A helper (crud.remove_item) reached from routes is the routes' deletion flow.
  for (const x of flows) {
    let endpoints = x.endpoint ? [x.endpoint] : [];
    if (!endpoints.length && !/^__/.test(x.d.name)) {
      const sameName = [...defsOf.values()].flat().filter((d) => d.name === x.d.name).length;
      if (sameName === 1) {
        const callRe = new RegExp(String.raw`(?<!def )\b${x.d.name}\s*\(`);
        for (const f of files) for (const d of defsOf.get(f.rel) || []) if (d !== x.d && callRe.test(f.content.slice(d.body, d.end))) {
          const ep = routeOf(f, d);
          if (ep && !endpoints.includes(ep)) endpoints.push(ep);
        }
      }
    }
    const first = x.targets[0];
    const id = endpoints.length === 1 ? `control:deletion-flow:${endpoints[0]}` : `control:deletion-flow:${x.f.rel}#${x.d.name}`;
    const e = ev(x.f.rel, first.line, first.snippet, 'static', 0.8);
    if (!graph.has(id)) graph.addNode({ id, type: 'Control', kind: 'deletion-flow', endpoint: endpoints[0] || null, file: x.f.rel, line: first.line, name: x.d.name, ...(endpoints.length > 1 ? { endpoints } : {}), evidence: [e] });
    for (const t of x.targets) if (graph.has(`store:table:${t.key}`)) graph.addEdge({ from: id, to: `store:table:${t.key}`, type: 'deletes', evidence: [ev(x.f.rel, t.line, t.snippet, 'static', 0.8)] });
  }
  return { writes, deletes };
}

/** The right-hand side of an assignment: up to the end of its line, or of its open brackets. */
function logicalRhs(text) {
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"' || ch === "'") { i = skipString(text, i) - 1; continue; }
    if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch)) depth--;
    else if (ch === '\n' && depth <= 0) return text.slice(0, i).replace(/\s+/g, ' ').trim();
  }
  return text.replace(/\s+/g, ' ').trim();
}

// ───────────────────────── extractor ─────────────────────────

export function extract(ctx) {
  const stats = { unparsed: 0, items: [] };
  const orm = new Map();
  const core = new Map();
  const migrations = [];
  const pyFiles = ctx.files.filter((x) => x.rel.endsWith('.py') && typeof x.content === 'string');
  // Django: one project-wide pass (models inherit from project base classes defined in other files).
  let djangoModels = new Set();
  if (pyFiles.some((f) => /\bfrom\s+django\b|\bimport\s+django\b|models\.Model\b/.test(f.content))) {
    const dj = parseDjangoProject(pyFiles.filter((f) => !(/alembic/.test(f.content) && ALEMBIC_OPS.test(f.content))), stats);
    for (const [k, t] of dj.tables) orm.set(k, t);
    djangoModels = dj.models;
    ctx.shared.djangoModels = Object.fromEntries(dj.modelKeys);
    ctx.shared.djangoModelInfo = dj.info;
    if (dj.authUserModel) ctx.shared.djangoAuthUserModel = dj.authUserModel;
  }
  const saMixins = sqlAlchemyMixins(pyFiles);
  for (const f of pyFiles) {
    if (/alembic/.test(f.content) && ALEMBIC_OPS.test(f.content)) {
      migrations.push(f);
      continue;
    }
    if (/__tablename__|db\.Model|DeclarativeBase|declarative_base|mapped_column|db\.Column/.test(f.content)) {
      for (const [k, t] of parseSqlAlchemy(f, stats, { mixins: saMixins, skip: djangoModels })) orm.set(k, t);
    }
    if (/\bTable\s*\(/.test(f.content)) for (const [k, t] of parseCoreTables(f)) core.set(k, t);
  }
  // SQLModel: a project-wide pass (a table class inherits the fields of SQLModel bases declared in other files).
  if (pyFiles.some((f) => /\bsqlmodel\b/.test(f.content))) {
    try {
      for (const [k, t] of parseSqlModels(annotatedClasses(pyFiles.filter((f) => !migrations.includes(f))))) orm.set(k, t);
    } catch (e) {
      ctx.warn?.(`orm-python: sqlmodel: ${e.message}`);
    }
  }
  ctx.shared.pythonModelsUnparsed = (Number(ctx.shared.pythonModelsUnparsed) || 0) + stats.unparsed;
  // Contract C2: unparsed constructs are listed for partial-coverage reporting.
  if (stats.items.length) {
    if (ctx.shared.unparsed === undefined) ctx.shared.unparsed = [];
    if (Array.isArray(ctx.shared.unparsed)) for (const it of stats.items) ctx.shared.unparsed.push({ extractor: name, ...it });
  }
  // Precedence: ORM model > Core Table > Alembic migration.
  const all = new Map([...(migrations.length ? parseAlembic(migrations) : []), ...core, ...orm]);
  // ForeignKey(User.id) → the table that model User maps to.
  const modelTable = new Map([...orm.values()].map((t) => [t.model, t.key]));
  for (const t of all.values()) {
    for (const fk of t.fks) {
      if (fk.refModel && modelTable.has(fk.refModel)) fk.refTable = modelTable.get(fk.refModel);
      delete fk.refModel;
    }
  }
  if (all.size) emitTables(ctx, all, 'python-orm');
}
