// WS-D/E/F: prisma.js (PRI-1, PRI-2), orm-python.js (PY-1 … PY-4), mongoose.js (MGO-1, MGO-2).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';
import { PrivacyGraph } from '../src/audit/graph.js';
import { parsePrisma } from '../src/audit/extract/prisma.js';
import { parseSqlAlchemy, parseAlembic, extract as extractPython } from '../src/audit/extract/orm-python.js';
import { extract as extractMongoose } from '../src/audit/extract/mongoose.js';

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-wsdef-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}
const cols = (t) => [...t.columns.keys()];

/** Minimal extractor ctx over in-memory files (no walk), for extractor-level tests. */
function fakeCtx(files, extra = {}) {
  return {
    root: '/x', graph: new PrivacyGraph(), shared: {}, classify: () => null, warn: () => {},
    ev: (file, line, snippet) => ({ file, line, snippet }),
    files: Object.entries(files).map(([rel, content]) => ({ rel, content, kind: 'code', ...(/\.test\./.test(rel) ? { test: true } : {}) })),
    ...extra,
  };
}

// ── PRI-1 / PRI-2 ──
test('PRI-1: model line is the `model` keyword line (CRLF + blank lines)', () => {
  const content = ['// header', '', 'model A {', '  id Int @id', '}', '', '', 'model B {', '  id Int @id', '}'].join('\r\n');
  const t = parsePrisma({ rel: 'schema.prisma', content });
  assert.equal(t.get('A').line, 3);
  assert.equal(t.get('B').line, 8);
  const lf = parsePrisma({ rel: 's.prisma', content: 'a\n\nmodel X {\n  id Int @id\n}\n' });
  assert.equal(lf.get('X').line, 3);
});

test('PRI-2: named-argument @@map(name:) / @map(name:)', () => {
  const content = `model User {
  id        String   @id
  createdAt DateTime @map(name: "created_at")
  email     String   @map("email_address")
  @@map(name: "users")
}`;
  const t = parsePrisma({ rel: 'schema.prisma', content });
  assert.ok(t.has('users'));
  assert.deepEqual(cols(t.get('users')), ['id', 'created_at', 'email_address']);
});

// ── PY-1 / PY-2 ──
const MICROBLOG = `from typing import Optional
import sqlalchemy as sa
import sqlalchemy.orm as so
from flask_login import UserMixin
from app import db

class SearchableMixin:
    pass

class User(UserMixin, db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True,
                                                unique=True)
    email: so.Mapped[str] = so.mapped_column(sa.String(120), index=True,
                                             unique=True)
    password_hash: so.Mapped[Optional[str]] = so.mapped_column(sa.String(256))
    about_me: so.Mapped[Optional[str]] = so.mapped_column(sa.String(140))
    last_seen: so.Mapped[Optional[datetime]] = so.mapped_column(
        default=lambda: datetime.now(timezone.utc))
    token: so.Mapped[Optional[str]] = so.mapped_column(
        sa.String(32), index=True, unique=True)
    token_expiration: so.Mapped[Optional[datetime]]
    posts: so.WriteOnlyMapped['Post'] = so.relationship(
        back_populates='author')
    author: so.Mapped['User'] = so.relationship(back_populates='posts')

    def avatar(self, size):
        return self.email

class PostMessage(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    body: so.Mapped[str] = so.mapped_column(sa.String(140))
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(User.id), index=True)
`;

test('PY-1/PY-2: Flask-SQLAlchemy 2.x model without __tablename__', () => {
  const stats = { unparsed: 0 };
  const t = parseSqlAlchemy({ rel: 'app/models.py', content: MICROBLOG }, stats);
  assert.deepEqual([...t.keys()], ['user', 'post_message']);
  const u = t.get('user');
  assert.deepEqual(cols(u), ['id', 'username', 'email', 'password_hash', 'about_me', 'last_seen', 'token', 'token_expiration']);
  assert.equal(u.columns.get('email').type, 'string');
  assert.equal(u.columns.get('email').notNull, true);
  assert.equal(u.columns.get('password_hash').notNull, false);
  assert.equal(u.columns.get('token_expiration').type, 'datetime');
  assert.equal(u.columns.get('username').line, 12);
  assert.equal(stats.unparsed, 0);
  assert.equal(t.get('post_message').fks[0].refModel, 'User');
});

test('PY-1: declarative Base, abstract parents, non-model classes', () => {
  const content = `from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    pass

class Timestamped(Base):
    __abstract__ = True
    created: Mapped[datetime]

class Customer(Timestamped):
    __tablename__ = "customers"
    id = Column(Integer, primary_key=True)
    phone = Column("phone_number", String(20), nullable=False)

class Helper(object):
    email = Column(String)

class APIKey(Base):
    key: Mapped[str] = mapped_column(String(64))
`;
  const t = parseSqlAlchemy({ rel: 'm.py', content });
  assert.deepEqual([...t.keys()].sort(), ['api_key', 'customers']);
  assert.deepEqual(cols(t.get('customers')), ['id', 'phone_number']);
  assert.equal(t.get('customers').columns.get('phone_number').notNull, true);
});

// ── PY-3 ──
const MIG1 = `from alembic import op
import sqlalchemy as sa
revision = 'aaa111'
down_revision = None

def upgrade():
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('legacy', sa.String(length=10), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )

def downgrade():
    op.drop_table('user')
`;
const MIG2 = `from alembic import op
import sqlalchemy as sa
revision = 'bbb222'
down_revision = 'aaa111'

def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('phone', sa.String(length=20), nullable=True))
        batch_op.drop_column('legacy')
    op.create_table('address',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('street', sa.String(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
    )
    op.create_table('temp', sa.Column('x', sa.Integer()))
    op.drop_table('temp')

def downgrade():
    op.drop_table('address')
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('phone')
`;

test('PY-3: Alembic migrations replayed in revision order (filename order is reversed)', () => {
  const t = parseAlembic([
    { rel: 'migrations/versions/01_second.py', content: MIG2 },
    { rel: 'migrations/versions/02_first.py', content: MIG1 },
  ]);
  assert.deepEqual([...t.keys()].sort(), ['address', 'user']);
  assert.deepEqual(cols(t.get('user')), ['id', 'email', 'phone']);
  const fk = t.get('address').fks[0];
  assert.deepEqual([fk.column, fk.refTable, fk.refColumn, fk.onDelete], ['user_id', 'user', 'id', 'cascade']);
  assert.equal(t.get('user').columns.get('email').line, 9);
});

test('PY-3: migration-only project and Core Table; ORM wins on merge', async () => {
  const dir = tmpProject({
    'migrations/versions/a.py': MIG1,
    'migrations/versions/b.py': MIG2,
    'app/tables.py': `import sqlalchemy as sa
from app import db
followers = sa.Table(
    'followers',
    db.metadata,
    sa.Column('follower_id', sa.Integer, sa.ForeignKey('user.id', ondelete='CASCADE'),
              primary_key=True),
)
`,
  });
  const { graph } = await buildGraph(dir);
  assert.ok(graph.has('store:column:user.email'));
  assert.ok(graph.has('store:column:user.phone'));
  assert.ok(!graph.has('store:column:user.legacy'));
  assert.ok(!graph.has('store:table:temp'));
  const e = graph.edgesFrom('store:table:followers', 'references').find((x) => x.to === 'store:table:user');
  assert.equal(e.onDelete, 'cascade');

  // Add an ORM model for `user`: its columns replace the migration's.
  fs.writeFileSync(path.join(dir, 'app/models.py'), `from app import db
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))
    nickname = db.Column(db.String(30))
`);
  const { graph: g2 } = await buildGraph(dir);
  assert.ok(g2.has('store:column:user.nickname'));
  assert.ok(!g2.has('store:column:user.phone'));
  assert.equal(g2.node('store:table:user').model, 'User');
});

test('PY-3: rich-style Table() without sqlalchemy is ignored', () => {
  const ctx = fakeCtx({ 'cli.py': `from rich.table import Table\nt = Table('Name', 'Email')\n` });
  extractPython(ctx);
  assert.equal(ctx.graph.nodesOf('Store').length, 0);
});

// ── PY-4 ──
test('PY-4: pythonModelsUnparsed counts model classes whose columns could not be read', () => {
  const ctx = fakeCtx({
    'models.py': `from app import db
class Weird(db.Model):
    email = db.Column  # attribute alias, not a call
    data = custom(db.Column(db.String))
class Fine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
`,
  });
  extractPython(ctx);
  assert.equal(ctx.shared.pythonModelsUnparsed, 1);
  assert.ok(ctx.graph.has('store:table:fine'));
  assert.ok(!ctx.graph.has('store:table:weird'));

  const ok = fakeCtx({ 'models.py': MICROBLOG });
  extractPython(ok);
  assert.equal(ok.shared.pythonModelsUnparsed, 0);
  // ForeignKey(User.id) resolves to the model's table.
  assert.ok(ok.graph.edgesFrom('store:table:post_message', 'references').some((e) => e.to === 'store:table:user'));
});

// ── MGO-1 ──
const tokenModel = (ttl) => `const mongoose = require('mongoose');
const tokenSchema = mongoose.Schema({
  token: { type: String, required: true },
  user: { type: mongoose.SchemaTypes.ObjectId, ref: 'User' },
  expires: { type: Date, required: true },
});
${ttl}
module.exports = mongoose.model('Token', tokenSchema);`;

test('MGO-1: TTL index → retention-job expires edge; plain `expires` field is not a TTL', () => {
  for (const [label, ttl, want] of [
    ['schema.index expireAfterSeconds', "tokenSchema.index({ expires: 1 }, { expireAfterSeconds: 0 });", true],
    ['schema.index expires', "tokenSchema.index({ createdAt: 1 }, { expires: '7d' });", true],
    ['no TTL', '', false],
    ['non-TTL index', 'tokenSchema.index({ token: 1 }, { unique: true });', false],
  ]) {
    const ctx = fakeCtx({ 'src/models/token.model.js': tokenModel(ttl) });
    extractMongoose(ctx);
    const exp = ctx.graph.edgesTo ? ctx.graph.edgesTo('store:table:Token', 'expires') : ctx.graph.edges.filter((e) => e.to === 'store:table:Token' && e.type === 'expires');
    assert.equal(exp.length > 0, want, label);
    if (want) assert.equal(ctx.graph.node(exp[0].from).kind, 'retention-job');
  }
});

test('MGO-1: field-level expires / index.expires options', () => {
  const ctx = fakeCtx({
    'm.js': `const mongoose = require('mongoose');
const sessionSchema = new mongoose.Schema({
  createdAt: { type: Date, default: Date.now, expires: 3600 },
});
const otpSchema = new mongoose.Schema({
  code: String,
  expireAt: { type: Date, index: { expires: '10m' } },
});
const profileSchema = new mongoose.Schema({ session: { expires: Date } });
mongoose.model('Session', sessionSchema);
mongoose.model('Otp', otpSchema);
mongoose.model('Profile', profileSchema);`,
  });
  extractMongoose(ctx);
  const exp = (t) => ctx.graph.in(`store:table:${t}`, 'expires');
  assert.equal(exp('Session').length, 1);
  assert.equal(exp('Session')[0].ttl, '3600');
  assert.equal(exp('Otp').length, 1);
  assert.equal(exp('Profile').length, 0);
});

// ── MGO-2 ──
test('MGO-2: schemas in test files are skipped unless includeTests', () => {
  const files = {
    'tests/unit/paginate.plugin.test.js': `const mongoose = require('mongoose');
const projectSchema = mongoose.Schema({ name: { type: String } });
const Project = mongoose.model('Project', projectSchema);`,
  };
  const ctx = fakeCtx(files);
  extractMongoose(ctx);
  assert.ok(!ctx.graph.has('store:table:Project'));
  const inc = fakeCtx(files, { includeTests: true });
  extractMongoose(inc);
  assert.ok(inc.graph.has('store:table:Project'));
});
