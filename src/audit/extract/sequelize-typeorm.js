/**
 * SQL ORM models (order 15, after the .sql / knex schema sources): Sequelize, sequelize-typescript, TypeORM,
 * MikroORM, Objection.js.
 *
 *   Sequelize      sequelize.define('User', { email: DataTypes.STRING }, { tableName }), User.init({...}, { sequelize, tableName }),
 *                  associations (Post.belongsTo(User, { foreignKey: 'userId', onDelete: 'CASCADE' }), User.hasMany(Post, {...})),
 *                  migrations (queryInterface.createTable('Users', { email: { type: Sequelize.STRING } }) / addColumn)
 *   sequelize-ts   @Table({ tableName }) class User extends Model { @Column email; @ForeignKey(() => Org) @Column orgId; @BelongsTo(() => Org, { onDelete }) }
 *   TypeORM        @Entity('users') class User { @Column() email; @Column({ name: 'first_name' }) firstName; @ManyToOne(() => Org, { onDelete: 'CASCADE' }) org }
 *                  new EntitySchema({ name, tableName, columns, relations })
 *   MikroORM       @Entity({ tableName }) class User { @Property() email; @ManyToOne(() => Org, { deleteRule: 'cascade' }) org }
 *   Objection      class User extends Model { static tableName = 'users' } (columns from class fields / jsonSchema)
 *
 * Contract produced: ctx.shared.ormModels = Map<ClassName, {table, orm, file, line}>; flow.js exposes it to matchers as
 * c.ormModel(name) (store writes: Model.create / update / destroy, repository.save / delete, manager.save(Entity, …),
 * Objection Model.query().insert(…)). Tables already modelled by another source get the ORM's extra columns merged in.
 */
import { newTable, emitTables } from './_schema.js';
import { getAst, jsFiles, walk, lineOf, strValue, unwrap, propName } from './ast.js';
import { constStr } from './rawsql.js';

export const name = 'sequelize-typeorm';
export const order = 15;

const snake = (s) => String(s).replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Z])([A-Z][a-z])/g, '$1_$2').toLowerCase();
const plural = (s) => (/(s|x|z|ch|sh)$/i.test(s) ? `${s}es` : /[^aeiou]y$/i.test(s) ? `${s.slice(0, -1)}ies` : `${s}s`);

function objGet(obj, key) {
  const o = unwrap(obj);
  if (o?.type !== 'ObjectExpression') return null;
  const p = o.properties.find((q) => q.type === 'ObjectProperty' && propName(q.key, q.computed) === key);
  return p ? p.value : null;
}
function boolOf(n) {
  const u = unwrap(n);
  return u?.type === 'BooleanLiteral' ? u.value : null;
}
function decoratorsOf(node) {
  return (node.decorators || []).map((d) => {
    const e = unwrap(d.expression);
    if (e?.type === 'CallExpression') return { name: unwrap(e.callee)?.name || propName(unwrap(e.callee)?.property), args: e.arguments || [], node: d };
    if (e?.type === 'Identifier') return { name: e.name, args: [], node: d };
    return { name: null, args: [], node: d };
  });
}
/** Type name of a Sequelize attribute: DataTypes.STRING / Sequelize.STRING(255) / DataType.TEXT / { type: … } / 'string'. */
function seqType(n) {
  let u = unwrap(n);
  if (u?.type === 'ObjectExpression') u = unwrap(objGet(u, 'type'));
  if (u?.type === 'CallExpression') u = unwrap(u.callee);
  if (u?.type === 'MemberExpression') return String(propName(u.property, u.computed) || 'unknown').toLowerCase();
  const s = strValue(u);
  return s ? s.toLowerCase() : 'unknown';
}
/** Arrow returning a class: () => Org → 'Org'. */
function classRef(n) {
  const u = unwrap(n);
  if (u?.type === 'ArrowFunctionExpression') {
    const b = unwrap(u.body);
    if (b?.type === 'Identifier') return b.name;
  }
  if (u?.type === 'Identifier') return u.name;
  return strValue(u);
}
/** TS type name of a class property annotation (string / Date / Org[]). */
function tsTypeName(prop) {
  const t = prop.typeAnnotation?.typeAnnotation;
  if (!t) return null;
  if (t.type === 'TSStringKeyword') return 'string';
  if (t.type === 'TSNumberKeyword') return 'number';
  if (t.type === 'TSBooleanKeyword') return 'boolean';
  if (t.type === 'TSTypeReference') return t.typeName?.name || null;
  if (t.type === 'TSArrayType') return 'array';
  return null;
}

function where(rec, rel, node) {
  const line = lineOf(node);
  return { file: rel, line, snippet: (rec.lines[line - 1] || '').trim() };
}

/**
 * Fields a toJSON method / serialiser removes: `delete values.password`, `values.password = undefined`,
 * `const { password, ...rest } = this.get()`, `omit(obj, ['password'])`. A field set to null / undefined counts.
 */
function strippedFields(fn) {
  const out = new Set();
  const f = unwrap(fn);
  if (!f?.body) return out;
  walk(f.body, (n) => {
    if (n.type === 'UnaryExpression' && n.operator === 'delete') {
      const a = unwrap(n.argument);
      const k = a && propName(a.property, a.computed);
      if (k) out.add(k);
    } else if (n.type === 'AssignmentExpression' && unwrap(n.left)?.type === 'MemberExpression') {
      const r = unwrap(n.right);
      const k = propName(unwrap(n.left).property, unwrap(n.left).computed);
      if (k && (r?.type === 'NullLiteral' || (r?.type === 'Identifier' && r.name === 'undefined'))) out.add(k);
    } else if (n.type === 'ObjectPattern' && n.properties.some((p) => p.type === 'RestElement')) {
      for (const p of n.properties) if (p.type !== 'RestElement' && propName(p.key, p.computed)) out.add(propName(p.key, p.computed));
    } else if (n.type === 'CallExpression' && /^omit$/.test(unwrap(n.callee)?.name || propName(unwrap(n.callee)?.property) || '')) {
      for (const a of n.arguments.slice(1)) {
        const u = unwrap(a);
        for (const e of u?.type === 'ArrayExpression' ? u.elements : [u]) if (strValue(e)) out.add(strValue(e));
      }
    }
  });
  return out;
}

function parseFile(ctx, f, models, tables, pendingAssoc, pendingJoins = [], pendingStrips = []) {
  const rec = getAst(ctx, f.rel);
  if (!rec) return;
  const rel = f.rel;
  const content = f.content || '';
  const addTable = (key, props) => {
    if (!tables.has(key)) tables.set(key, newTable(key, { name: key, kind: 'table', source: props.source, ...props }));
    const t = tables.get(key);
    if (props.file && !t.file) Object.assign(t, { file: props.file, line: props.line, snippet: props.snippet });
    return t;
  };
  const addCol = (t, col, type, w, extra = {}) => {
    if (!col || t.columns.has(col)) return;
    t.columns.set(col, { name: col, type: String(type || 'unknown').toLowerCase(), notNull: !!extra.notNull, ...w, ...(extra.encrypted ? { encrypted: true } : {}) });
  };

  walk(rec.ast, (n) => {
    // ---------- Classes: TypeORM / MikroORM / sequelize-typescript / Objection ----------
    if ((n.type === 'ClassDeclaration' || n.type === 'ClassExpression') && n.id?.name) {
      const cls = n.id.name;
      const decs = decoratorsOf(n);
      const entity = decs.find((d) => /^(Entity|Table|ViewEntity|ChildEntity)$/.test(d.name || ''));
      const superName = unwrap(n.superClass)?.type === 'Identifier' ? n.superClass.name : unwrap(n.superClass)?.type === 'MemberExpression' ? propName(n.superClass.property) : null;
      const body = n.body?.body || [];
      let orm = null;
      let table = null;
      if (entity) {
        const a0 = entity.args[0];
        const explicit = constStr(ctx, rel, a0) || constStr(ctx, rel, objGet(a0, 'name')) || constStr(ctx, rel, objGet(a0, 'tableName'));
        if (entity.name === 'Table') {
          orm = 'sequelize';
          table = explicit || (boolOf(objGet(a0, 'freezeTableName')) ? cls : plural(cls));
        } else {
          orm = /@mikro-orm\//.test(content) ? 'mikro-orm' : 'typeorm';
          table = explicit || snake(cls);
        }
      } else if (superName === 'Model' && /from\s+['"]objection['"]|require\(\s*['"]objection['"]\s*\)/.test(content)) {
        orm = 'objection';
        for (const m of body) {
          const k = propName(m.key, m.computed);
          if (!m.static || k !== 'tableName') continue;
          if (m.type === 'ClassProperty') table = constStr(ctx, rel, m.value);
          else if (m.type === 'ClassMethod') {
            const ret = m.body?.body?.find((s) => s.type === 'ReturnStatement');
            table = constStr(ctx, rel, ret?.argument);
          }
        }
        if (!table) return;
      } else return;
      if (!table) return;
      const key = table;
      const w = where(rec, rel, n);
      const t = addTable(key, { file: rel, line: w.line, snippet: w.snippet, source: orm, model: cls });
      t.model = cls;
      let relations = null;
      models.set(cls, { table: key, orm, file: rel, line: w.line });
      for (const m of body) {
        if (m.type === 'ClassMethod' && !m.static && propName(m.key, m.computed) === 'toJSON') {
          pendingStrips.push({ cls, fields: strippedFields(m) });
          continue;
        }
        if (m.type !== 'ClassProperty' && m.type !== 'ClassAccessorProperty') continue;
        if (m.static) continue;
        const prop = propName(m.key, m.computed);
        if (!prop) continue;
        const pd = decoratorsOf(m);
        const mw = where(rec, rel, m);
        if (orm === 'objection') {
          if (/^(\$|id$|createdAt$|updatedAt$)/.test(prop)) continue;
          addCol(t, prop, tsTypeName(m) || 'unknown', mw);
          continue;
        }
        const colDec = pd.find((d) => /^(Column|PrimaryColumn|PrimaryGeneratedColumn|CreateDateColumn|UpdateDateColumn|DeleteDateColumn|Property|PrimaryKey|Enum|Formula|VersionColumn|ObjectIdColumn)$/.test(d.name || ''));
        const relDec = pd.find((d) => /^(ManyToOne|OneToOne|BelongsTo|HasOne|HasMany|OneToMany|ManyToMany|BelongsToMany)$/.test(d.name || ''));
        const fkDec = pd.find((d) => d.name === 'ForeignKey');
        // Relation properties (loaded with leftJoinAndSelect / relations: [...] / eager: true): prop → target class.
        if (relDec) {
          const ropts = relDec.args.find((a) => unwrap(a)?.type === 'ObjectExpression');
          const target = classRef(relDec.args[0]) || constStr(ctx, rel, relDec.args[0]);
          if (target) (relations ||= {})[prop] = { toClass: target, kind: relDec.name, ...(boolOf(objGet(ropts, 'eager')) === true ? { eager: true } : {}) };
        }
        if (colDec) {
          const a0 = colDec.args[0];
          const opts = unwrap(a0)?.type === 'ObjectExpression' ? a0 : colDec.args[1];
          const colName = constStr(ctx, rel, objGet(opts, 'name')) || constStr(ctx, rel, objGet(opts, 'fieldName')) || constStr(ctx, rel, objGet(opts, 'field')) || prop;
          const type = (unwrap(a0)?.type === 'StringLiteral' ? strValue(a0) : null) || constStr(ctx, rel, objGet(opts, 'type')) || (unwrap(a0)?.type === 'MemberExpression' ? seqType(a0) : null) || tsTypeName(m) || 'unknown';
          const hidden = boolOf(objGet(opts, 'select')) === false || boolOf(objGet(opts, 'hidden')) === true || boolOf(objGet(opts, 'lazy')) === true;
          addCol(t, colName, type, mw, { notNull: boolOf(objGet(opts, 'nullable')) === false });
          if (hidden) t.columns.get(colName).hidden = true;
          // class-transformer @Exclude() / @Exclude({ toPlainOnly: true }) and NestJS GraphQL @HideField() keep the column
          // out of serialised entities (the column is still loaded) (r8).
          if (pd.some((d) => d.name === 'HideField' || (d.name === 'Exclude' && boolOf(objGet(d.args[0], 'toClassOnly')) !== true))) t.columns.get(colName).private = true;
          if (fkDec) pendingAssoc.push({ from: key, column: colName, toClass: classRef(fkDec.args[0]), onDelete: null, w: mw });
        } else if (relDec && /^(ManyToOne|OneToOne|BelongsTo)$/.test(relDec.name)) {
          const target = classRef(relDec.args[0]);
          const opts = relDec.args.find((a) => unwrap(a)?.type === 'ObjectExpression');
          const od = constStr(ctx, rel, objGet(opts, 'onDelete')) || constStr(ctx, rel, objGet(opts, 'deleteRule'));
          const join = pd.find((d) => d.name === 'JoinColumn');
          const jn = join ? constStr(ctx, rel, objGet(join.args[0], 'name')) : null;
          const fkCol = constStr(ctx, rel, objGet(opts, 'foreignKey')) || jn || (relDec.name === 'BelongsTo' ? null : `${prop}Id`);
          if (relDec.name === 'OneToOne' && !join) continue; // inverse side carries no column
          if (fkCol) addCol(t, fkCol, 'fk', mw);
          pendingAssoc.push({ from: key, column: fkCol || `${prop}Id`, toClass: target, onDelete: od ? od.toLowerCase() : null, w: mw });
        } else if (relDec && /^(ManyToMany|BelongsToMany)$/.test(relDec.name)) {
          // Owning side of a many-to-many: TypeORM @ManyToMany + @JoinTable, MikroORM @ManyToMany({ owner: true } /
          // pivotTable), sequelize-typescript @BelongsToMany(() => B, () => Through) creates a join table holding
          // one FK per side (rows linking a user to other records are personal data too).
          const jt = pd.find((d) => d.name === 'JoinTable');
          const opts = relDec.args.find((a) => unwrap(a)?.type === 'ObjectExpression');
          const mikroOwner = orm === 'mikro-orm' && (boolOf(objGet(opts, 'owner')) === true || objGet(opts, 'pivotTable'));
          if (relDec.name === 'ManyToMany' && !jt && !mikroOwner) continue;
          const through = relDec.name === 'BelongsToMany' ? classRef(relDec.args[1]) : null;
          if (relDec.name === 'BelongsToMany' && !through) continue;
          const jtOpts = jt?.args?.[0];
          const name = constStr(ctx, rel, objGet(jtOpts, 'name')) || constStr(ctx, rel, objGet(opts, 'pivotTable'));
          const jc = constStr(ctx, rel, objGet(objGet(jtOpts, 'joinColumn'), 'name'));
          const ijc = constStr(ctx, rel, objGet(objGet(jtOpts, 'inverseJoinColumn'), 'name'));
          pendingJoins.push({ owner: key, prop, toClass: classRef(relDec.args[0]), name, through, joinColumn: jc, inverseJoinColumn: ijc, orm, file: rel, w: mw });
        } else if (!relDec && orm === 'sequelize' && pd.length === 0 && tsTypeName(m)) {
          // sequelize-typescript without decorators on the field: not a column.
        }
      }
      if (relations) models.get(cls).relations = relations;
      return;
    }

    // ---------- User.prototype.toJSON = function () { … delete values.password … } (Sequelize instances, r8) ----------
    if (n.type === 'AssignmentExpression') {
      const l = unwrap(n.left);
      if (l?.type === 'MemberExpression' && propName(l.property, l.computed) === 'toJSON') {
        const po = unwrap(l.object);
        if (po?.type === 'MemberExpression' && propName(po.property, po.computed) === 'prototype' && unwrap(po.object)?.type === 'Identifier') {
          pendingStrips.push({ cls: unwrap(po.object).name, fields: strippedFields(n.right) });
        }
      }
      return;
    }
    if (n.type !== 'CallExpression') return;
    const callee = unwrap(n.callee);
    // ---------- sequelize.define('User', attrs, opts) ----------
    if (callee?.type === 'MemberExpression' && propName(callee.property) === 'define' && n.arguments?.length >= 2 && unwrap(n.arguments[1])?.type === 'ObjectExpression') {
      const modelName = constStr(ctx, rel, n.arguments[0]);
      if (!modelName) return;
      const opts = n.arguments[2];
      const table = constStr(ctx, rel, objGet(opts, 'tableName')) || (boolOf(objGet(opts, 'freezeTableName')) ? modelName : plural(modelName));
      const w = where(rec, rel, n);
      const t = addTable(table, { file: rel, line: w.line, snippet: w.snippet, source: 'sequelize', model: modelName });
      t.model = modelName;
      models.set(modelName, { table, orm: 'sequelize', file: rel, line: w.line });
      // The variable the model is bound to (const User = sequelize.define('user', …)) is the model too.
      seqAttrs(ctx, rec, rel, n.arguments[1], t, pendingAssoc, addCol);
      return;
    }
    // ---------- User.init(attrs, { sequelize, tableName, modelName }) ----------
    if (callee?.type === 'MemberExpression' && propName(callee.property) === 'init' && unwrap(callee.object)?.type === 'Identifier' && n.arguments?.length >= 2 && objGet(n.arguments[1], 'sequelize')) {
      const cls = unwrap(callee.object).name;
      const opts = n.arguments[1];
      const modelName = constStr(ctx, rel, objGet(opts, 'modelName')) || cls;
      const table = constStr(ctx, rel, objGet(opts, 'tableName')) || (boolOf(objGet(opts, 'freezeTableName')) ? modelName : plural(modelName));
      const w = where(rec, rel, n);
      const t = addTable(table, { file: rel, line: w.line, snippet: w.snippet, source: 'sequelize', model: cls });
      t.model = cls;
      models.set(cls, { table, orm: 'sequelize', file: rel, line: w.line });
      if (modelName !== cls) models.set(modelName, { table, orm: 'sequelize', file: rel, line: w.line });
      seqAttrs(ctx, rec, rel, n.arguments[0], t, pendingAssoc, addCol);
      return;
    }
    // ---------- associations: Post.belongsTo(User, { foreignKey, onDelete }) / User.hasMany(Post, { onDelete }) ----------
    if (callee?.type === 'MemberExpression' && /^(belongsTo|hasMany|hasOne)$/.test(propName(callee.property) || '') && unwrap(callee.object)?.type === 'Identifier' && unwrap(n.arguments?.[0])?.type === 'Identifier') {
      const kind = propName(callee.property);
      const a = unwrap(callee.object).name;
      const b = unwrap(n.arguments[0]).name;
      const opts = n.arguments[1];
      const fkRaw = objGet(opts, 'foreignKey');
      const fk = constStr(ctx, rel, fkRaw) || constStr(ctx, rel, objGet(fkRaw, 'name'));
      const od = constStr(ctx, rel, objGet(opts, 'onDelete'));
      const w = where(rec, rel, n);
      // belongsTo: a holds the FK to b; hasMany/hasOne: b holds the FK to a.
      const as = constStr(ctx, rel, objGet(opts, 'as'));
      if (kind === 'belongsTo') pendingAssoc.push({ assoc: true, ...(as ? { as } : {}), fromClass: a, column: fk || `${b[0].toLowerCase()}${b.slice(1)}Id`, toClass: b, onDelete: od ? od.toLowerCase() : null, w });
      else pendingAssoc.push({ fromClass: b, column: fk || `${a[0].toLowerCase()}${a.slice(1)}Id`, toClass: a, onDelete: od ? od.toLowerCase() : null, w });
      return;
    }
    // ---------- Sequelize migrations: queryInterface.createTable('Users', {...}) / addColumn('Users', 'email', {...}) ----------
    if (callee?.type === 'MemberExpression' && /^(createTable|addColumn)$/.test(propName(callee.property) || '') && /^(queryInterface|qi|queryinterface)$/i.test(unwrap(callee.object)?.name || '')) {
      const table = constStr(ctx, rel, n.arguments?.[0]);
      if (!table) return;
      const w = where(rec, rel, n);
      const t = addTable(table, { file: rel, line: w.line, snippet: w.snippet, source: 'sequelize' });
      if (propName(callee.property) === 'createTable') seqAttrs(ctx, rec, rel, n.arguments[1], t, pendingAssoc, addCol, true);
      else {
        const col = constStr(ctx, rel, n.arguments[1]);
        if (col) addCol(t, col, seqType(n.arguments[2]), w);
      }
      return;
    }
    // ---------- TypeORM EntitySchema ----------
    if (n.type === 'CallExpression' || n.type === 'NewExpression') {
      /* handled below for NewExpression */
    }
  });
  // new EntitySchema({ name, tableName, columns, relations })
  walk(rec.ast, (n) => {
    if (n.type !== 'NewExpression' || unwrap(n.callee)?.name !== 'EntitySchema') return;
    const o = n.arguments?.[0];
    const nm = constStr(ctx, rel, objGet(o, 'name'));
    const table = constStr(ctx, rel, objGet(o, 'tableName')) || (nm ? snake(nm) : null);
    if (!table) return;
    const w = where(rec, rel, n);
    const t = addTable(table, { file: rel, line: w.line, snippet: w.snippet, source: 'typeorm', model: nm });
    if (nm) {
      t.model = nm;
      models.set(nm, { table, orm: 'typeorm', file: rel, line: w.line });
    }
    const cols = unwrap(objGet(o, 'columns'));
    if (cols?.type === 'ObjectExpression') {
      for (const p of cols.properties) {
        if (p.type !== 'ObjectProperty') continue;
        const k = propName(p.key, p.computed);
        const cn = constStr(ctx, rel, objGet(p.value, 'name')) || k;
        addCol(t, cn, constStr(ctx, rel, objGet(p.value, 'type')) || (unwrap(objGet(p.value, 'type'))?.name || 'unknown'), where(rec, rel, p));
      }
    }
    const rels = unwrap(objGet(o, 'relations'));
    if (rels?.type === 'ObjectExpression') {
      for (const p of rels.properties) {
        if (p.type !== 'ObjectProperty') continue;
        const type = constStr(ctx, rel, objGet(p.value, 'type'));
        if (!/^(many-to-one|one-to-one)$/.test(type || '')) continue;
        const target = constStr(ctx, rel, objGet(p.value, 'target'));
        const od = constStr(ctx, rel, objGet(p.value, 'onDelete'));
        const k = propName(p.key, p.computed);
        pendingAssoc.push({ from: table, column: `${k}Id`, toClass: target, onDelete: od ? od.toLowerCase() : null, w: where(rec, rel, p) });
      }
    }
  });
}

function seqAttrs(ctx, rec, rel, attrsNode, t, pendingAssoc, addCol, migration = false) {
  const o = unwrap(attrsNode);
  if (o?.type !== 'ObjectExpression') return;
  for (const p of o.properties) {
    if (p.type !== 'ObjectProperty') continue;
    const k = propName(p.key, p.computed);
    if (!k) continue;
    const v = p.value;
    const w = where(rec, rel, p);
    const col = constStr(ctx, rel, objGet(v, 'field')) || k;
    addCol(t, col, seqType(v), w, { notNull: boolOf(objGet(v, 'allowNull')) === false });
    const ref = objGet(v, 'references');
    if (ref) {
      const model = constStr(ctx, rel, objGet(ref, 'model')) || constStr(ctx, rel, objGet(objGet(ref, 'model'), 'tableName')) || (unwrap(objGet(ref, 'model'))?.type === 'Identifier' ? unwrap(objGet(ref, 'model')).name : null);
      const od = constStr(ctx, rel, objGet(v, 'onDelete'));
      if (model) pendingAssoc.push({ from: t.key, column: col, ...(migration ? { toTable: model } : { toClass: model, toTable: model }), refColumn: constStr(ctx, rel, objGet(ref, 'key')), onDelete: od ? od.toLowerCase() : null, w });
    }
  }
}

export function extract(ctx) {
  const files = jsFiles(ctx).filter((f) => /\b(sequelize|Sequelize|typeorm|@mikro-orm|objection|EntitySchema|queryInterface)\b/.test(f.content || ''));
  if (!files.length) return;
  const models = new Map();
  const tables = new Map();
  const pendingAssoc = [];
  const pendingJoins = [];
  const pendingStrips = [];
  for (const f of files) {
    try {
      parseFile(ctx, f, models, tables, pendingAssoc, pendingJoins, pendingStrips);
    } catch (e) {
      ctx.warn?.(`sequelize-typeorm: ${f.rel}: ${e.message}`);
    }
  }
  const tableOfClass = (c) => (c ? models.get(c)?.table || (tables.has(c) ? c : null) : null);
  // Join tables of many-to-many relations (TypeORM default naming: <owner>_<property>_<target>, columns <table>Id;
  // FKs ON DELETE CASCADE by default). A sequelize-typescript `through` model is already a table of its own.
  for (const j of pendingJoins) {
    const to = tableOfClass(j.toClass);
    if (!to || !tables.has(j.owner)) continue;
    if (j.through) continue;
    const camel = (x) => String(x).replace(/_([a-z0-9])/g, (_, ch) => ch.toUpperCase());
    const key = j.name || (j.orm === 'mikro-orm' ? `${j.owner}_${snake(j.prop)}` : `${j.owner}_${snake(j.prop)}_${to}`);
    if (tables.has(key)) continue;
    const t = newTable(key, { name: key, kind: 'table', source: j.orm, file: j.file, line: j.w.line, snippet: j.w.snippet, extra: { joinTable: true } });
    const c1 = j.joinColumn || camel(`${j.owner}_id`);
    const c2 = j.inverseJoinColumn || (to === j.owner ? camel(`${to}_id_2`) : camel(`${to}_id`));
    for (const [col, ref] of [[c1, j.owner], [c2, to]]) {
      t.columns.set(col, { name: col, type: 'fk', notNull: true, ...j.w });
      t.fks.push({ column: col, refTable: ref, refColumn: 'id', onDelete: j.orm === 'typeorm' ? 'cascade' : null, ...j.w });
    }
    tables.set(key, t);
  }
  // Columns that name a person role and hold a key (followerId, followingId, blockedUserId, senderId) without a declared
  // relation: an implicit reference to the user table (no FK constraint, so the rows survive the user's deletion).
  const userTable = [...tables.keys()].find((k) => /^(app_?)?users?$/i.test(k)) || [...models.entries()].find(([c]) => /^(App)?User(Entity|Model)?$/.test(c))?.[1]?.table;
  if (userTable && tables.has(userTable)) {
    const ROLE = /^(follower|following|followee|followed|blocker|blocked|blockedUser|blockingUser|friend|requester|addressee|inviter|invitee|sender|recipient|receiver|user|owner|author|creator|member)_?id$/i;
    for (const t of tables.values()) {
      if (t.key === userTable || t.extra?.joinTable) continue;
      for (const c of t.columns.values()) {
        if (!ROLE.test(c.name) || t.fks.some((fk) => fk.column === c.name)) continue;
        if (!/^(fk|number|int|integer|bigint|string|uuid|varchar|text|unknown)$/.test(String(c.type || '').toLowerCase())) continue;
        t.fks.push({ column: c.name, refTable: userTable, refColumn: 'id', onDelete: null, implicit: true, file: c.file, line: c.line, snippet: c.snippet });
      }
    }
  }
  for (const a of pendingAssoc) {
    const from = a.from || tableOfClass(a.fromClass);
    const to = tableOfClass(a.toClass) || a.toTable || null;
    if (!from || !to || !tables.has(from)) continue;
    const t = tables.get(from);
    // Sequelize belongsTo associations are relations an `include` loads (r8).
    const fm = a.assoc ? models.get(a.fromClass) : null;
    if (fm && models.has(a.toClass)) (fm.relations ||= {})[a.as || `${a.toClass[0].toLowerCase()}${a.toClass.slice(1)}`] ||= { toClass: a.toClass, kind: 'BelongsTo' };
    if (a.column && !t.columns.has(a.column)) t.columns.set(a.column, { name: a.column, type: 'fk', notNull: false, ...a.w });
    const prev = t.fks.find((x) => x.column === a.column && x.refTable === to);
    if (prev) {
      if (!prev.onDelete && a.onDelete) prev.onDelete = a.onDelete;
    } else t.fks.push({ column: a.column, refTable: to, refColumn: a.refColumn || 'id', onDelete: a.onDelete || null, ...a.w });
  }
  // Relation targets as table names: c.ormModel(name).relations[prop] = { table, eager }.
  for (const v of models.values()) {
    if (!v.relations) continue;
    for (const r of Object.values(v.relations)) r.table = tableOfClass(r.toClass);
  }
  ctx.shared.ormModels ||= new Map();
  for (const [k, v] of models) ctx.shared.ormModels.set(k, v);
  ctx.shared.dataLayers ||= {};
  const orms = [...new Set([...models.values()].map((m) => m.orm))];
  ctx.shared.dataLayers.orm = { ...(ctx.shared.dataLayers.orm || {}), detected: true, orms, models: models.size, schemaTables: tables.size, statements: ctx.shared.dataLayers.orm?.statements || 0 };
  if (!tables.size) return;
  // Tables already modelled by another source (knex / .sql migrations): add only the columns they lack.
  const existing = ctx.shared.tables || {};
  const fresh = new Map();
  const merged = [];
  for (const [k, t] of tables) {
    if (existing[k]) {
      const have = new Set(existing[k].columns || []);
      for (const cn of [...t.columns.keys()]) if (have.has(cn)) t.columns.delete(cn);
      merged.push([k, existing[k], t.model]);
    }
    fresh.set(k, t);
  }
  const keep = merged.map(([k, prev, model]) => [k, { ...prev, columns: [...prev.columns] }, model]);
  const bySource = new Map();
  for (const t of fresh.values()) {
    const src = t.source || 'orm';
    if (!bySource.has(src)) bySource.set(src, new Map());
    bySource.get(src).set(t.key, t);
  }
  for (const [src, ts] of bySource) emitTables(ctx, ts, src);
  // Columns the ORM never loads by default (hidden: select: false / lazy) or never serialises (private: @Exclude,
  // @HideField, toJSON): marked on the column nodes, which the schema emitter does not do (r8).
  for (const s of pendingStrips) {
    const t = tables.get(models.get(s.cls)?.table);
    for (const fld of s.fields) {
      const c = t?.columns.get(fld) || t?.columns.get(snake(fld));
      if (c) c.private = true;
    }
  }
  for (const t of tables.values()) {
    for (const c of t.columns.values()) {
      const cn = c.hidden || c.private ? ctx.graph.node(`store:column:${t.key}.${c.name}`) : null;
      if (!cn) continue;
      if (c.hidden) cn.hidden = true;
      if (c.private) cn.private = true;
    }
  }
  for (const [k, prev, model] of keep) {
    const now = ctx.shared.tables[k];
    // The table keeps the schema source that defined it (knex / sql migrations); the ORM only adds its model name.
    const tn = ctx.graph.node(`store:table:${k}`);
    if (tn && prev.source) {
      tn.source = prev.source;
      if (model) tn.model = model;
    }
    ctx.shared.tables[k] = { ...prev, columns: [...new Set([...prev.columns, ...(now?.columns || [])])], ...(model ? { model } : {}) };
  }
}
