// R5 WS4 (flow / ORM writes): TypeORM injected repositories and NestJS handler parameters, many-to-many join tables
// and implicit user references, eager relations in responses, projections before the response, log arguments
// (request-scoped credentials, whole rows, caught errors), reachability of script-only helpers, digest prefixes,
// promise continuations on Prisma writes, SQLAlchemy writes / deletes and OAuth provider literals in templates.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';

async function graphOf(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r5-ws4-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  const { graph, warnings, ctx } = await buildGraph(root);
  return { g: graph, warnings, ctx };
}
const edges = (g, type, pred = () => true) => g.edges.filter((e) => e.type === type && pred(e));
const flowsTo = (g, el, to) => edges(g, 'flowsTo', (e) => e.from === `data:${el}` && (typeof to === 'string' ? e.to === to : to.test(e.to)));
const flowWarnings = (warnings) => warnings.filter((w) => /^(flow|sequelize-typeorm|orm-python)\b/.test(w));

// ---------------------------------------------------------------------------------------------
// TypeORM + NestJS
// ---------------------------------------------------------------------------------------------
const NEST_PKG = JSON.stringify({ name: 'nest-fx', dependencies: { '@nestjs/common': '10', '@nestjs/core': '10', '@nestjs/typeorm': '10', typeorm: '0.3', argon2: '0.30' } });
const USER_ENTITY = `import { Entity, PrimaryGeneratedColumn, Column, BeforeInsert, ManyToMany, JoinTable, OneToMany } from 'typeorm';
import * as argon2 from 'argon2';
import { ArticleEntity } from '../article/article.entity';
@Entity('user')
export class UserEntity {
  @PrimaryGeneratedColumn() id: number;
  @Column() username: string;
  @Column() email: string;
  @Column({ default: '' }) bio: string;
  @Column() password: string;
  @BeforeInsert()
  async hashPassword() { this.password = await argon2.hash(this.password); }
  @ManyToMany(type => ArticleEntity)
  @JoinTable()
  favorites: ArticleEntity[];
  @OneToMany(type => ArticleEntity, article => article.author)
  articles: ArticleEntity[];
}
`;
const ARTICLE_ENTITY = `import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { UserEntity } from '../user/user.entity';
@Entity('article')
export class ArticleEntity {
  @PrimaryGeneratedColumn() id: number;
  @Column() title: string;
  @Column({ default: '' }) body: string;
  @ManyToOne(type => UserEntity, user => user.articles)
  author: UserEntity;
}
`;
const FOLLOWS_ENTITY = `import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';
@Entity('follows')
export class FollowsEntity {
  @PrimaryGeneratedColumn() id: number;
  @Column() followerId: number;
  @Column() followingId: number;
}
`;
const USER_SERVICE = `import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserEntity } from './user.entity';
@Injectable()
export class UserService {
  constructor(
    @InjectRepository(UserEntity)
    private readonly repo: Repository<UserEntity>
  ) {}
  async create(dto) {
    const { username, email, password } = dto;
    const user = new UserEntity();
    user.username = username;
    user.email = email;
    user.password = password;
    return await this.repo.save(user);
  }
  async remove(email: string) {
    return await this.repo.delete({ email });
  }
}
`;
const USER_CONTROLLER = `import { Controller, Post, Delete, Body, Param } from '@nestjs/common';
import { UserService } from './user.service';
@Controller()
export class UserController {
  constructor(private readonly userService: UserService) {}
  @Post('users')
  async create(@Body('user') userData) {
    return this.userService.create(userData);
  }
  @Delete('users/:email')
  async remove(@Param('email') email: string) {
    return this.userService.remove(email);
  }
}
`;
const ARTICLE_SERVICE = `import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, getRepository } from 'typeorm';
import { ArticleEntity } from './article.entity';
@Injectable()
export class ArticleService {
  constructor(@InjectRepository(ArticleEntity) private readonly articleRepository: Repository<ArticleEntity>) {}
  async findAll() {
    const qb = getRepository(ArticleEntity).createQueryBuilder('article').leftJoinAndSelect('article.author', 'author');
    qb.where('1 = 1');
    const articles = await qb.getMany();
    return { articles };
  }
  async findOne(id: number) {
    const article = await this.articleRepository.findOne({ where: { id }, relations: ['author'] });
    return { article };
  }
  async titles() {
    const rows = await this.articleRepository.find();
    return rows.map((r) => ({ id: r.id, title: r.title }));
  }
}
`;
const ARTICLE_CONTROLLER = `import { Controller, Get, Param } from '@nestjs/common';
import { ArticleService } from './article.service';
@Controller('articles')
export class ArticleController {
  constructor(private readonly articleService: ArticleService) {}
  @Get()
  async findAll() { return this.articleService.findAll(); }
  @Get(':id')
  async findOne(@Param('id') id: number) { return this.articleService.findOne(id); }
  @Get('titles')
  async titles() { return this.articleService.titles(); }
}
`;
const NEST_FILES = {
  'package.json': NEST_PKG,
  'src/user/user.entity.ts': USER_ENTITY,
  'src/user/user.service.ts': USER_SERVICE,
  'src/user/user.controller.ts': USER_CONTROLLER,
  'src/article/article.entity.ts': ARTICLE_ENTITY,
  'src/article/article.service.ts': ARTICLE_SERVICE,
  'src/article/article.controller.ts': ARTICLE_CONTROLLER,
  'src/profile/follows.entity.ts': FOLLOWS_ENTITY,
};

test('TypeORM: injected Repository<UserEntity> writes / deletes resolve through the class suffix; @Body feeds them; @BeforeInsert hashes', async () => {
  const { g, warnings } = await graphOf(NEST_FILES);
  assert.deepEqual(flowWarnings(warnings), []);
  const email = flowsTo(g, 'email', 'store:column:user.email');
  assert.ok(email.length, 'save(user) writes user.email');
  assert.ok(email[0].evidence.some((e) => e.file === 'src/user/user.service.ts'));
  const pw = flowsTo(g, 'password', 'store:column:user.password');
  assert.ok(pw.length && pw.every((e) => e.transformed === 'hash'), 'the entity hashes in @BeforeInsert');
  const del = edges(g, 'deletes', (e) => e.to === 'store:table:user');
  assert.ok(del.length, 'repo.delete({ email }) deletes from user');
});

test('TypeORM: @ManyToMany + @JoinTable creates the join table; person-role key columns reference the user table', async () => {
  const { g } = await graphOf(NEST_FILES);
  const jt = g.node('store:table:user_favorites_article');
  assert.ok(jt, 'join table modelled');
  const refs = edges(g, 'references', (e) => e.from === 'store:table:user_favorites_article').map((e) => e.to).sort();
  assert.deepEqual(refs, ['store:table:article', 'store:table:user']);
  const follows = edges(g, 'references', (e) => e.from === 'store:table:follows');
  // One references edge per table pair (graph edges are keyed by from|type|to): the first column names it.
  assert.equal(follows.length, 1);
  assert.equal(follows[0].column, 'followerId');
  assert.ok(follows[0].to === 'store:table:user' && follows[0].implicit);
});

test('eager relations: leftJoinAndSelect / relations: [...] expose the related entity; a row mapper limits the response', async () => {
  const { g } = await graphOf(NEST_FILES);
  const exposes = (ep) => edges(g, 'exposes', (e) => e.from === ep).map((e) => e.to.replace(/^data:/, ''));
  assert.ok(exposes('endpoint:GET /articles').includes('password'), 'author columns joined into GET /articles');
  assert.ok(exposes('endpoint:GET /articles/:id').includes('email'), 'relations: [author] on findOne');
  assert.ok(!exposes('endpoint:GET /articles/titles').includes('password'), 'rows.map(r => ({ id, title })) sends only the projection');
});

// ---------------------------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------------------------
const EXPRESS_PKG = JSON.stringify({ name: 'ex-fx', dependencies: { express: '4', winston: '3', pg: '8', 'better-auth': '1' } });

test('logs: request-scoped credentials (res.locals token, session cookie helpers) reach the log; err.message is not free text', async () => {
  const { g } = await graphOf({
    'package.json': EXPRESS_PKG,
    'src/app.js': `import express from 'express';
import { createLogger } from 'winston';
import { getSessionCookie } from 'better-auth/cookies';
const logger = createLogger({});
const app = express();
function authenticate(req, res, next) {
  res.locals.accessToken = String(req.headers.authorization).replace('Bearer ', '');
  logger.log('info', 'JWT: Verifying token - %s', res.locals.accessToken);
  next();
}
app.post('/refresh', authenticate, async (req, res) => {
  const sessionCookie = getSessionCookie(req);
  console.log('Session cookie: ', sessionCookie);
  try {
    await fetch('https://api.example.com/x', { method: 'POST', body: JSON.stringify({ email: req.body.email }) });
  } catch (err) {
    logger.error('failed - %s', err.message);
  }
  res.json({ ok: true });
});
app.listen(3000);
`,
  });
  const toLog = (el) => edges(g, 'flowsTo', (e) => e.from === `data:${el}` && e.to.startsWith('store:log'));
  const tok = toLog('auth_token');
  assert.ok(tok.some((e) => e.to === 'store:log:logger'), 'res.locals.accessToken logged through a format string');
  assert.ok(tok.some((e) => e.to === 'store:log:console'), 'sessionCookie logged by console.log');
  assert.ok(!toLog('free_text').length, 'err.message is program text');
});

test('logs: a whole DB row logged expands to its columns (minus hidden ones)', async () => {
  const { g } = await graphOf({
    'package.json': EXPRESS_PKG,
    'migrations/001.sql': 'CREATE TABLE users (id serial primary key, name text, email text, password text);',
    'src/app.js': `import express from 'express';
import pg from 'pg';
const pool = new pg.Pool();
const app = express();
app.get('/me', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.query.id]);
  console.log('user row', rows[0]);
  res.json({ ok: true });
});
app.listen(3000);
`,
  });
  const logged = edges(g, 'flowsTo', (e) => e.to === 'store:log:console').map((e) => e.from.replace(/^data:/, ''));
  assert.ok(logged.includes('email') && logged.includes('full_name'), `row columns logged: ${logged}`);
});

test('error causes: an error swallowed by the action (catch → status) does not reach the error class logger', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'n', dependencies: { next: '15', react: '19', 'drizzle-orm': '0.30' } }),
    'lib/errors.ts': `export class AppError extends Error {
  constructor(code: string, options?: ErrorOptions) { super(code, options); }
  toResponse() {
    const { cause } = this;
    console.error({ cause });
    return Response.json({ message: 'failed' }, { status: 500 });
  }
}
`,
    'lib/queries.ts': `import { AppError } from './errors';
export async function saveUser(db: any, email: string) {
  try {
    return await fetch('https://api.example.com/users', { method: 'POST', body: JSON.stringify({ email }) });
  } catch (error) {
    throw new AppError('bad_request:database', { cause: error });
  }
}
`,
    'app/actions.ts': `'use server';
import { saveUser } from '../lib/queries';
export async function register(_: unknown, formData: FormData) {
  try {
    await saveUser(null, formData.get('email') as string);
    return { status: 'success' };
  } catch {
    return { status: 'failed' };
  }
}
`,
  });
  const logged = edges(g, 'flowsTo', (e) => e.from === 'data:email' && e.to === 'store:log:console');
  assert.equal(logged.length, 0);
});

test('reachability: a helper only scripts import, and seed files, produce no log / provider flows', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'r', dependencies: { express: '4', nodemailer: '6' } }),
    'src/utils/mail.js': `import nodemailer from 'nodemailer';
const transporter = nodemailer.createTransport({});
export async function send(options) {
  console.log('sending', options.to, options.email);
  return transporter.sendMail({ to: options.email, subject: 'x' });
}
`,
    'scripts/mail-test.js': `import { send } from '../src/utils/mail.js';
send({ email: process.argv[2] });
`,
    'src/db/seed.server.js': `const email = 'demo@example.com';
console.log('seeded user', email);
`,
    'src/app.js': `import express from 'express';
const app = express();
app.post('/x', (req, res) => { console.log('email', req.body.email); res.json({}); });
app.listen(1);
`,
  });
  const flows = edges(g, 'flowsTo', (e) => e.evidence.some((v) => /mail\.js|seed\.server\.js/.test(v.file)));
  assert.equal(flows.length, 0, JSON.stringify(flows.map((e) => [e.from, e.to])));
  assert.ok(flowsTo(g, 'email', 'store:log:console').length, 'the app route still logs');
});

test('derived values: a short digest prefix (k-anonymity range query) is not the password', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'h', dependencies: { express: '4' } }),
    'src/app.js': `import crypto from 'crypto';
import express from 'express';
const app = express();
export function getPasswordHashParts(password) {
  const hash = crypto.createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
  return [hash.slice(0, 5), hash.slice(5)];
}
app.post('/pw', async (req, res) => {
  const [prefix] = getPasswordHashParts(req.body.password);
  await fetch(\`https://api.pwnedpasswords.com/range/\${prefix}\`);
  res.json({});
});
app.listen(1);
`,
  });
  assert.equal(flowsTo(g, 'password', /pwnedpasswords/).length, 0);
});

test('Prisma: writes chained with .then / .catch keep their write edges', async () => {
  const { g } = await graphOf({
    'package.json': JSON.stringify({ name: 'p', dependencies: { '@prisma/client': '5', '@remix-run/node': '2' } }),
    'prisma/schema.prisma': `model User {
  id    String @id
  email String @unique
}
`,
    'app/database/db.server.ts': `import { PrismaClient } from "@prisma/client";
let db: PrismaClient;
declare global { var __db__: PrismaClient; }
if (process.env.NODE_ENV === "production") { db = new PrismaClient(); } else { if (!global.__db__) { global.__db__ = new PrismaClient(); } db = global.__db__; }
export { db };
`,
    'app/database/index.ts': 'export * from "./db.server";\n',
    'app/routes/join.tsx': `import type { ActionFunctionArgs } from "@remix-run/node";
import { db } from "../database";
export async function action({ request }: ActionFunctionArgs) {
  const formData = await request.formData();
  const email = formData.get("email") as string;
  const user = await db.user.create({ data: { email, id: "x" } }).then((u) => u).catch(() => null);
  return { ok: !!user };
}
`,
  });
  assert.ok(flowsTo(g, 'email', /store:column:User\.email/).length, 'db.user.create(...).then().catch() writes User.email');
});

test('SQLAlchemy: Model(...) / obj.col = … with session.add/commit are writes; session.delete is a deletion flow', async () => {
  const { g } = await graphOf({
    'requirements.txt': 'flask\nflask-sqlalchemy\nflask-login\n',
    'app/models.py': `from app import db
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64))
    email = db.Column(db.String(120))
    about_me = db.Column(db.String(140))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
`,
    'app/routes.py': `from flask import Blueprint, request
from flask_login import current_user, login_required
from app import db
from app.models import User, Post
bp = Blueprint('main', __name__)

@bp.route('/register', methods=['POST'])
def register():
    user = User(username=request.form['username'], email=request.form['email'])
    db.session.add(user)
    db.session.commit()
    return 'ok'

@bp.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():
    current_user.about_me = request.form['about_me']
    db.session.commit()
    return 'ok'

@bp.route('/post/<int:id>/delete', methods=['POST'])
@login_required
def delete_post(id):
    post = db.get_or_404(Post, id)
    db.session.delete(post)
    db.session.commit()
    return 'ok'
`,
  });
  assert.ok(flowsTo(g, 'email', 'store:column:user.email').length, 'User(email=…) + session.add');
  assert.ok(flowsTo(g, 'free_text', 'store:column:user.about_me').length, 'current_user.about_me = … + commit');
  assert.ok(edges(g, 'deletes', (e) => e.to === 'store:table:post').length, 'session.delete(post)');
});

test('OAuth providers: template buttons and exported provider lists name the identity providers', async () => {
  const { g, ctx } = await graphOf({
    'package.json': JSON.stringify({ name: 'o', dependencies: { astro: '4', '@supabase/supabase-js': '2', '@supabase/auth-ui-svelte': '0.2', svelte: '4' } }),
    'src/pages/signin.astro': `---
---
<form action="/api/auth/signin" method="post">
  <button value="github" name="provider" type="submit">GitHub</button>
</form>
`,
    'src/pages/api/auth/signin.ts': `import type { APIRoute } from "astro";
import { createClient } from "@supabase/supabase-js";
const supabase = createClient("https://x.supabase.co", "anon");
export const POST: APIRoute = async ({ request, redirect }) => {
  const formData = await request.formData();
  const provider = formData.get("provider")?.toString();
  const { data } = await supabase.auth.signInWithOAuth({ provider: provider as any });
  return redirect(data.url);
};
`,
    'src/login/login_config.ts': 'export const oauthProviders = ["google"]\n',
    'src/login/Login.svelte': `<script>
  import { Auth } from "@supabase/auth-ui-svelte"
  import { oauthProviders } from "./login_config"
</script>
<Auth providers={oauthProviders} />
`,
  });
  assert.deepEqual(ctx.shared.oauthProviderLiterals, ['github', 'google']);
  assert.ok(g.node('source:oauth:github'), 'astro button value feeds signInWithOAuth');
  assert.ok(g.node('source:oauth:google'), 'Supabase Auth UI with an exported provider list');
});
