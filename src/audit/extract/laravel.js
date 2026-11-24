/**
 * Laravel / Eloquent extractor (order 12, schema layer): PHP migrations, Eloquent models, enum classes and deletes.
 *
 *   database/migrations/*.php   Schema::create('t', fn (Blueprint $table) { $table->string('phone'); … })
 *                               Schema::table('t', …) adds / drops / renames columns; $table->softDeletes() marks soft
 *                               delete; $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade') and
 *                               $table->foreignId('user_id')->constrained()->cascadeOnDelete() are foreign keys.
 *   Eloquent models             class X extends Model|Authenticatable: $table, $fillable (columns the app writes),
 *                               $hidden (not serialised), $casts ('encrypted' / 'encrypted:*' casts → encrypted columns,
 *                               an enum class cast names the column's value set), `use SoftDeletes`.
 *   Enum classes                PHP 8.1 `enum X: string { case A = 'a'; }` and constant classes (`const SICK_LEAVE = 'sick_leave'`,
 *                               app/Enums, BenSampo / spatie enums): the values a column takes. When the column is in a table
 *                               about a person (FK to users / employees, or a person entity) and a value names a health state
 *                               (sick leave, medical, disability, injury, pregnancy …), the column holds health data
 *                               (KVKK md.6 / GDPR Art.9): the column represents data:health with the enum line as evidence.
 *   Deletes                     $model->delete() / ->forceDelete() / Model::destroy($ids) / Model::where(…)->delete() in
 *                               controllers, services, jobs → Control deletion-flow (per method) → deletes → table
 *                               (soft: true when the model uses SoftDeletes and the call is not forceDelete).
 *
 * Classification goes through ctx.classify (classify/pii.js) with the table and sibling columns as context.
 * Stores carry source 'eloquent' (layer attribution, legal/stack.js). Writes ctx.shared.dataLayers.eloquent.
 */
import { newTable, emitTables } from './_schema.js';

export const name = 'laravel';
export const order = 12;

const COL_TYPES = {
  string: 'varchar', char: 'char', text: 'text', mediumText: 'text', longText: 'text', tinyText: 'text',
  integer: 'integer', bigInteger: 'bigint', smallInteger: 'smallint', tinyInteger: 'smallint', mediumInteger: 'integer',
  unsignedInteger: 'integer', unsignedBigInteger: 'bigint', unsignedSmallInteger: 'smallint', unsignedTinyInteger: 'smallint',
  boolean: 'boolean', date: 'date', dateTime: 'timestamp', dateTimeTz: 'timestamptz', timestamp: 'timestamp', timestampTz: 'timestamptz',
  time: 'time', timeTz: 'time', year: 'integer', decimal: 'numeric', float: 'float', double: 'float', unsignedDecimal: 'numeric',
  json: 'json', jsonb: 'jsonb', enum: 'enum', set: 'enum', uuid: 'uuid', ulid: 'text', ipAddress: 'inet', macAddress: 'text',
  binary: 'bytea', foreignId: 'bigint', foreignUuid: 'uuid', foreignUlid: 'text', geometry: 'geometry', point: 'point',
};
const ID_TYPES = /^(increments|bigIncrements|smallIncrements|tinyIncrements|mediumIncrements|id)$/;
// Enum / constant values that name a health state (sick leave, medical leave, disability …).
const HEALTH_VALUE = /^(sick|sickness|ill|illness|ill_health|medical|medical_leave|disability|disabled|handicap\w*|injury|injured|accident_at_work|work_accident|pregnan\w*|maternity|maternity_leave|hospital\w*|quarantine|diagnos\w*|treatment|therapy|rehab\w*|mental_health|burnout)$/;
const HEALTH_TOKEN = /^(sick|sickness|illness|medical|disability|disabled|injury|pregnancy|pregnant|maternity|hospital|hospitalization|hospitalisation|quarantine|diagnosis|therapy|rehabilitation)$/;
const PHONE_QUALIFIED = /^(primary|secondary|home|work|mobile|cell|office|alt|alternate|alternative|other|contact|business|private|personal)_?(number|no|nr|num)$/i;
const PERSON_FK =/^(user|employee|staff|member|person|customer|patient|student|worker|driver|client_contact|contact)_?id$/i;

const lineAt = (content, idx) => content.slice(0, idx).split('\n').length;
const lineText = (content, line) => (content.split(/\r?\n/)[line - 1] || '').trim().slice(0, 200);

/** Strip PHP comments (keeps offsets: comment text becomes spaces). */
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' ')).replace(/(^|[^:'"\\])(\/\/|#(?!\[))[^\n]*/g, (m, p) => p + ' '.repeat(m.length - p.length));
}

/** Index of the brace closing the one at `open`. */
function matchBrace(src, open) {
  let depth = 0;
  let q = null;
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    if (q) {
      if (ch === '\\') i++;
      else if (ch === q) q = null;
      continue;
    }
    if (ch === '"' || ch === "'") q = ch;
    else if (ch === '{') depth++;
    else if (ch === '}' && --depth === 0) return i;
  }
  return src.length;
}

const snake = (s) => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
function plural(s) {
  if (/(s|x|z|ch|sh)$/.test(s)) return `${s}es`;
  if (/[^aeiou]y$/.test(s)) return `${s.slice(0, -1)}ies`;
  return `${s}s`;
}
function singular(s) {
  if (/ies$/.test(s)) return `${s.slice(0, -3)}y`;
  if (/(ses|xes|zes|ches|shes)$/.test(s)) return s.slice(0, -2);
  if (/s$/.test(s) && !/ss$/.test(s)) return s.slice(0, -1);
  return s;
}
const strList = (s) => [...String(s || '').matchAll(/['"]([\w.-]+)['"]/g)].map((m) => m[1]);

// ---------------------------------------------------------------------------
// Migrations

/** Parse migration files into table models. → Map(key → table) */
export function parseMigrations(files) {
  const tables = new Map();
  const ordered = [...files].sort((a, b) => a.rel.localeCompare(b.rel));
  for (const f of ordered) {
    const src = stripComments(f.content);
    // Only the up() part: down() reverses it.
    const downAt = src.search(/function\s+down\s*\(/);
    const re = /Schema::(?:connection\([^)]*\)->)?(create|table)\s*\(\s*['"]([\w.]+)['"]\s*,\s*(?:static\s+)?(?:function|fn)\s*\([^)]*\)\s*(?:use\s*\([^)]*\)\s*)?(?::\s*\w+\s*)?(\{|=>)/g;
    let m;
    while ((m = re.exec(src))) {
      if (downAt >= 0 && m.index > downAt) {
        // down() may come first in odd files; stop only when the up() function precedes it.
        const upAt = src.search(/function\s+up\s*\(/);
        if (upAt >= 0 && upAt < downAt) break;
      }
      const [, op, tname] = m;
      const bodyStart = m.index + m[0].length - 1;
      const bodyEnd = m[3] === '{' ? matchBrace(src, bodyStart) : src.indexOf(';', bodyStart);
      const body = src.slice(bodyStart, bodyEnd);
      const tLine = lineAt(src, m.index);
      if (!tables.has(tname)) {
        if (op === 'table' && !tables.size) { /* altering a table created elsewhere: still model it */ }
        tables.set(tname, newTable(tname, { name: tname, kind: 'table', file: f.rel, line: tLine, snippet: lineText(f.content, tLine), source: 'eloquent', extra: { orm: 'eloquent' } }));
      }
      const t = tables.get(tname);
      const stmtRe = /\$\w+\s*->\s*(\w+)\s*\(([^;]*?)\)\s*((?:->\s*\w+\s*\([^;]*?\)\s*)*);/g;
      let s;
      while ((s = stmtRe.exec(body))) {
        const [, method, argText, chain] = s;
        const at = bodyStart + s.index;
        const line = lineAt(src, at);
        const args = strList(argText);
        const where = { file: f.rel, line, snippet: lineText(f.content, line) };
        if (method === 'softDeletes' || method === 'softDeletesTz') {
          t.extra.softDeletes = true;
          t.columns.set(args[0] || 'deleted_at', { name: args[0] || 'deleted_at', type: 'timestamp', ...where });
          continue;
        }
        if (method === 'dropSoftDeletes') {
          t.extra.softDeletes = false;
          continue;
        }
        if (method === 'rememberToken') {
          t.columns.set('remember_token', { name: 'remember_token', type: 'varchar', ...where });
          continue;
        }
        if (method === 'dropColumn') {
          for (const c of args) t.columns.delete(c);
          continue;
        }
        if (method === 'renameColumn' && args.length >= 2) {
          const c = t.columns.get(args[0]);
          if (c) {
            t.columns.delete(args[0]);
            t.columns.set(args[1], { ...c, name: args[1] });
          }
          continue;
        }
        if (method === 'foreign' && args[0]) {
          const ref = /->\s*on\s*\(\s*['"]([\w.]+)['"]/.exec(chain);
          const refCol = /->\s*references\s*\(\s*['"](\w+)['"]/.exec(chain);
          const del = /->\s*onDelete\s*\(\s*['"]([\w ]+)['"]/.exec(chain) || (/->\s*cascadeOnDelete\s*\(/.test(chain) ? [null, 'cascade'] : null) || (/->\s*nullOnDelete\s*\(/.test(chain) ? [null, 'set null'] : null);
          if (ref) t.fks.push({ column: args[0], refTable: ref[1], refColumn: refCol?.[1] || 'id', onDelete: del ? del[1].toUpperCase() : null, ...where });
          continue;
        }
        if (ID_TYPES.test(method)) continue;
        if (method === 'timestamps' || method === 'timestampsTz' || method === 'nullableTimestamps') continue;
        if (/^(morphs|nullableMorphs|uuidMorphs|nullableUuidMorphs)$/.test(method) && args[0]) {
          t.columns.set(`${args[0]}_id`, { name: `${args[0]}_id`, type: 'bigint', ...where });
          t.columns.set(`${args[0]}_type`, { name: `${args[0]}_type`, type: 'varchar', ...where });
          continue;
        }
        const type = COL_TYPES[method];
        if (!type || !args[0]) continue;
        const col = args[0];
        t.columns.set(col, { name: col, type, notNull: !/->\s*nullable\s*\(\s*\)/.test(chain), ...where, ...(method === 'enum' ? { enumValues: strList(argText.slice(argText.indexOf('['))) } : {}) });
        if (/^foreign(Id|Uuid|Ulid)$/.test(method) && /->\s*constrained\s*\(/.test(chain)) {
          const ct = /->\s*constrained\s*\(\s*['"]([\w.]+)['"]/.exec(chain);
          const refTable = ct ? ct[1] : plural(col.replace(/_id$/, ''));
          const del = /->\s*cascadeOnDelete\s*\(/.test(chain) ? 'CASCADE' : /->\s*nullOnDelete\s*\(/.test(chain) ? 'SET NULL' : (/->\s*onDelete\s*\(\s*['"]([\w ]+)['"]/.exec(chain) || [])[1]?.toUpperCase() || null;
          t.fks.push({ column: col, refTable, refColumn: 'id', onDelete: del, ...where });
        }
      }
      // Schema::drop / dropIfExists in up(): table gone.
    }
    const dropRe = /Schema::(?:drop|dropIfExists)\s*\(\s*['"]([\w.]+)['"]/g;
    let d;
    while ((d = dropRe.exec(src))) {
      if (downAt >= 0 && d.index > downAt && src.search(/function\s+up\s*\(/) < downAt) continue;
      tables.delete(d[1]);
    }
  }
  return tables;
}

// ---------------------------------------------------------------------------
// Models

/** Eloquent model facts per class. → [{rel, className, table, fillable, hidden, casts:{col: cast}, softDeletes, line}] */
export function parseModels(files) {
  const out = [];
  for (const f of files) {
    const src = stripComments(f.content);
    const cm = /\bclass\s+(\w+)\s+extends\s+(\\?[\w\\]*?(Model|Authenticatable|Pivot|User))\b/.exec(src);
    if (!cm) continue;
    const className = cm[1];
    const tableM = /\$table\s*=\s*['"]([\w.]+)['"]/.exec(src);
    const arr = (prop) => {
      const m = new RegExp(`\\$${prop}\\s*=\\s*(?:\\[|array\\s*\\()([\\s\\S]*?)(?:\\]|\\))\\s*;`).exec(src);
      return m ? { text: m[1], line: lineAt(src, m.index) } : null;
    };
    const fillable = arr('fillable');
    const hidden = arr('hidden');
    const casts = arr('casts');
    const castMap = {};
    if (casts) for (const m of casts.text.matchAll(/['"](\w+)['"]\s*=>\s*(?:['"]([^'"]+)['"]|([\w\\]+)::class)/g)) castMap[m[1]] = m[2] || m[3];
    // Laravel 11 casts(): return ['x' => 'encrypted'];
    const castsFn = /function\s+casts\s*\(\s*\)\s*(?::\s*array\s*)?\{([\s\S]*?)\}/.exec(src);
    if (castsFn) for (const m of castsFn[1].matchAll(/['"](\w+)['"]\s*=>\s*(?:['"]([^'"]+)['"]|([\w\\]+)::class)/g)) castMap[m[1]] = m[2] || m[3];
    out.push({
      rel: f.rel, className, line: lineAt(src, cm.index),
      table: tableM ? tableM[1] : plural(snake(className)),
      fillable: fillable ? strList(fillable.text) : [], fillableLine: fillable?.line,
      hidden: hidden ? strList(hidden.text) : [],
      casts: castMap,
      softDeletes: /\buse\s+[\w\\,\s]*\bSoftDeletes\b/.test(src),
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Enums

/** Enum / constant classes. → [{rel, className, values:[{value, name, line}]}] */
export function parseEnums(files) {
  const out = [];
  for (const f of files) {
    const src = stripComments(f.content);
    const em = /\benum\s+(\w+)\s*(?::\s*(?:string|int))?\s*(?:implements\s+[\w\\,\s]+)?\{/.exec(src);
    const cm = em || /\bclass\s+(\w+)\b[^{]*\{/.exec(src);
    if (!cm) continue;
    const values = [];
    const re = em ? /\bcase\s+(\w+)\s*(?:=\s*['"]([^'"]*)['"])?\s*;/g : /\bconst\s+(\w+)\s*=\s*['"]([^'"]*)['"]\s*;/g;
    let m;
    while ((m = re.exec(src))) values.push({ name: m[1], value: m[2] ?? m[1].toLowerCase(), line: lineAt(src, m.index) });
    if (!values.length) continue;
    // A constants class only counts when it is an enum by location / name / base class.
    if (!em && !/(^|\/)Enums?\//.test(f.rel) && !/extends\s+[\w\\]*Enum\b/.test(src) && !/(Type|Status|Reason|Kind|State|Category)$/.test(cm[1])) continue;
    out.push({ rel: f.rel, className: cm[1], values });
  }
  return out;
}

function healthValue(ctx, v, table) {
  const raw = String(v.value || v.name);
  const norm = snake(raw).replace(/[\s-]+/g, '_').toLowerCase();
  const byName = snake(v.name).toLowerCase();
  for (const cand of [norm, byName]) {
    const cls = ctx.classify(cand, { table });
    if (cls && cls.category === 'health') return cls;
  }
  if (HEALTH_VALUE.test(norm) || HEALTH_VALUE.test(byName) || norm.split('_').some((t) => HEALTH_TOKEN.test(t))) return ctx.classify('health', { table });
  return null;
}

/** Does the table describe something about a person (FK to a person table, person-ish key, or a person entity)? */
function aboutPerson(t, personTables) {
  if (t.fks.some((fk) => personTables.has(fk.refTable) || PERSON_FK.test(fk.column))) return true;
  return [...t.columns.keys()].some((c) => PERSON_FK.test(c));
}

// ---------------------------------------------------------------------------
// Deletes

const DELETE_CALL = /(\$\w+)(?:\s*->\s*\w+\s*\([^;]*?\))*\s*->\s*(delete|forceDelete)\s*\(\s*\)|\b([A-Z]\w*)\s*::\s*(\w+)\s*\(([^;]*?)\)\s*(?:->\s*\w+\s*\([^;]*?\)\s*)*?(?:->\s*(delete|forceDelete)\s*\(\s*\))?(?=\s*;)/g;

/** Deletion sites per PHP method. → [{rel, fn, line, snippet, table, force}] */
export function findDeletes(files, models, tables) {
  const byClass = new Map(models.map((m) => [m.className, m]));
  const tableNames = new Set(tables.keys());
  const out = [];
  for (const f of files) {
    if (/(^|\/)(database|tests?)\//.test(f.rel)) continue;
    const src = stripComments(f.content);
    if (!/->\s*(delete|forceDelete)\s*\(\s*\)|::\s*destroy\s*\(/.test(src)) continue;
    // Variable → model class: $user = User::findOrFail($id) / User $user (type-hinted parameter)
    const varModel = new Map();
    for (const m of src.matchAll(/(\$\w+)\s*=\s*([A-Z]\w*)\s*::\s*\w+\s*\(/g)) if (byClass.has(m[2])) varModel.set(m[1], m[2]);
    for (const m of src.matchAll(/\b([A-Z]\w*)\s+(\$\w+)\s*[,)]/g)) if (byClass.has(m[1])) varModel.set(m[2], m[1]);
    const fnAt = [...src.matchAll(/function\s+(\w+)\s*\(/g)].map((m) => ({ name: m[1], at: m.index }));
    DELETE_CALL.lastIndex = 0;
    let m;
    while ((m = DELETE_CALL.exec(src))) {
      let model = null;
      let force = false;
      if (m[1]) {
        if (m[1] === '$this' || m[1] === '$table') continue;
        model = varModel.get(m[1]) || null;
        force = m[2] === 'forceDelete';
        if (!model) {
          // $user->delete(): the variable name names the model.
          const v = m[1].slice(1);
          const guess = [...byClass.keys()].find((c) => c.toLowerCase() === v.toLowerCase());
          if (guess) model = guess;
          else if (tableNames.has(plural(snake(v)))) model = { table: plural(snake(v)) };
        }
      } else if (m[3]) {
        if (m[4] !== 'destroy' && !m[6]) continue;
        model = byClass.has(m[3]) ? m[3] : tableNames.has(plural(snake(m[3]))) ? { table: plural(snake(m[3])) } : null;
        force = m[6] === 'forceDelete';
      }
      if (!model) continue;
      const mm = typeof model === 'string' ? byClass.get(model) : null;
      const table = mm ? mm.table : model.table;
      if (!tableNames.has(table)) continue;
      const line = lineAt(src, m.index);
      const fn = fnAt.filter((x) => x.at < m.index).pop()?.name || null;
      out.push({ rel: f.rel, fn, line, snippet: lineText(f.content, line), table, force, soft: !force && !!(mm?.softDeletes || tables.get(table)?.extra?.softDeletes) });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------

export function extract(ctx) {
  const php = (ctx.files || []).filter((f) => !f.test && /\.php$/i.test(f.rel) && !/\.blade\.php$/i.test(f.rel) && typeof f.content === 'string');
  if (!php.length) return;
  const migrations = php.filter((f) => /(^|\/)database\/migrations\//.test(f.rel) || /Schema::create\s*\(/.test(f.content));
  const modelFiles = php.filter((f) => /\bextends\s+\\?[\w\\]*(Model|Authenticatable|Pivot)\b/.test(f.content) && /\bnamespace\b|<\?php/.test(f.content));
  if (!migrations.length && !modelFiles.length) return;
  const { graph, ev } = ctx;
  const tables = parseMigrations(migrations);
  const models = parseModels(modelFiles);

  // Models: $fillable columns missing from migrations (attribute-only schema), encrypted casts, hidden columns.
  for (const mdl of models) {
    let t = tables.get(mdl.table);
    if (!t && mdl.fillable.length) {
      t = newTable(mdl.table, { name: mdl.table, kind: 'table', file: mdl.rel, line: mdl.fillableLine || mdl.line, snippet: lineText(php.find((x) => x.rel === mdl.rel)?.content || '', mdl.fillableLine || mdl.line), source: 'eloquent', extra: { orm: 'eloquent', fromModel: true } });
      tables.set(mdl.table, t);
    }
    if (!t) continue;
    t.model = mdl.className;
    if (mdl.softDeletes) t.extra.softDeletes = true;
    for (const c of mdl.fillable) {
      if (!t.columns.has(c)) t.columns.set(c, { name: c, type: 'unknown', file: mdl.rel, line: mdl.fillableLine || mdl.line });
    }
    for (const [c, cast] of Object.entries(mdl.casts)) {
      const col = t.columns.get(c);
      if (col && /^encrypted/.test(cast)) col.encrypted = 'laravel-encrypted-cast';
      if (col && /\\|^[A-Z]/.test(cast) && !/^(date|datetime|array|json|boolean|integer|float|string|object|collection|timestamp|decimal)/i.test(cast)) col.enumClass = cast.split('\\').pop();
    }
    for (const c of mdl.hidden) {
      const col = t.columns.get(c);
      if (col) col.hidden = true;
    }
  }
  if (!tables.size) return;
  emitTables(ctx, tables, 'eloquent');
  for (const t of tables.values()) {
    graph.addNode({ id: `store:table:${t.key}`, type: 'Store', orm: 'eloquent', ...(t.extra.softDeletes ? { softDelete: true } : {}) });
    for (const c of t.columns.values()) if (c.hidden) graph.addNode({ id: `store:column:${t.key}.${c.name}`, type: 'Store', hidden: true });
  }

  // Qualified number columns of a person / contact record (primary_number, secondary_number, home_no …) are phone
  // numbers: the bare qualifier says which of the person's numbers it is.
  for (const t of tables.values()) {
    const cols = [...t.columns.keys()];
    const personShaped = cols.some((c) => /^(e_?mail|email_address)$/i.test(c)) && cols.some((c) => /^(name|first_?name|last_?name|full_?name|contact_?name)$/i.test(c));
    if (!personShaped) continue;
    for (const c of t.columns.values()) {
      if (!PHONE_QUALIFIED.test(c.name)) continue;
      const cid = `store:column:${t.key}.${c.name}`;
      if (!graph.has(cid) || graph.edgesFrom(cid, 'represents').length) continue;
      const cls = ctx.classify('phone', { table: t.key, siblings: cols });
      if (!cls) continue;
      const e = ev(c.file || t.file, c.line || t.line, c.snippet, 'static', Math.min(0.7, cls.confidence), `${c.name}: a qualified number of a person record (name + e-mail) is a phone number`);
      graph.addEdge({ from: cid, to: graph.dataElement(cls, `${t.key}.${c.name}`, e), type: 'represents', evidence: [e] });
    }
  }

  // Enums: a column taking health-state values in a table about a person holds health data.
  const enums = parseEnums(php.filter((f) => /\benum\s+\w+|\bconst\s+\w+\s*=/.test(f.content)));
  const personTables = new Set([...tables.keys()].filter((k) => /^(users|employees|staff|members|people|persons|customers|patients|students|contacts)$/i.test(k)));
  for (const en of enums) {
    const toks = snake(en.className).split('_');
    for (const t of tables.values()) {
      const tSing = singular(t.key.split('.').pop());
      let col = [...t.columns.values()].find((c) => c.enumClass === en.className);
      if (!col) {
        // AbsenceReason → absences.reason; LeaveType → leaves.type; or a column named after the whole enum (absence_reason).
        const full = toks.join('_');
        col = t.columns.get(full) || null;
        if (!col && toks.length > 1 && toks.slice(0, -1).join('_') === tSing) col = t.columns.get(toks[toks.length - 1]) || null;
        if (!col && toks.length > 1 && toks[0] === tSing) col = t.columns.get(toks.slice(1).join('_')) || null;
      }
      if (!col || !/^(varchar|char|text|enum|unknown|integer|smallint)$/.test(col.type || 'unknown')) continue;
      if (!aboutPerson(t, personTables)) continue;
      const hit = en.values.map((v) => ({ v, cls: healthValue(ctx, v, t.key) })).find((x) => x.cls);
      if (!hit) continue;
      const cid = `store:column:${t.key}.${col.name}`;
      if (!graph.has(cid)) continue;
      const src = php.find((x) => x.rel === en.rel)?.content || '';
      const e = ev(en.rel, hit.v.line, lineText(src, hit.v.line), 'static', Math.min(0.8, hit.cls.confidence), `${en.className}::${hit.v.name} ('${hit.v.value}') is a value of ${t.key}.${col.name}: the column records a health state of the person`);
      const did = graph.dataElement(hit.cls, `${t.key}.${col.name}`, e);
      graph.addEdge({ from: cid, to: did, type: 'represents', viaEnum: en.className, evidence: [e, ev(col.file, col.line, col.snippet, 'static', 0.9)] });
    }
  }

  // Deletes.
  let deletes = [];
  try {
    deletes = findDeletes(php, models, tables);
  } catch (e) {
    ctx.warn?.(`laravel: deletes: ${e.message}`);
  }
  for (const d of deletes) {
    const id = `control:deletion-flow:${d.rel}#${d.fn || 'anonymous'}`;
    const e = ev(d.rel, d.line, d.snippet, 'static', 0.85, d.soft ? 'soft delete (SoftDeletes): the row is kept with deleted_at set' : undefined);
    graph.addNode({ id, type: 'Control', kind: 'deletion-flow', endpoint: null, file: d.rel, line: d.line, ...(d.fn ? { name: d.fn } : {}), ...(d.soft ? { softDelete: true } : {}), evidence: [e] });
    graph.addEdge({ from: id, to: `store:table:${d.table}`, type: 'deletes', ...(d.soft ? { soft: true } : {}), evidence: [e] });
  }
  ctx.shared.dataLayers ||= {};
  ctx.shared.dataLayers.eloquent = { detected: true, tables: tables.size, models: models.length, enums: enums.length, deletes: deletes.length };
}
