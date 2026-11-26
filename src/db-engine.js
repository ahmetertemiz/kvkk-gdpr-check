/**
 * Which database a SQL file belongs to, per file and folder, so a project with two databases (e.g. Supabase for one
 * part and Cloudflare D1 for accounts) does not get one database's rules applied to the other's tables.
 *
 *   'supabase'  under supabase/ or Supabase-specific SQL (auth.uid(), auth.users, TO authenticated / anon, policies …)
 *   'd1'        a Cloudflare D1 migrations folder named in wrangler (toml / json / jsonc) or a nitro / nuxt config
 *               (d1_databases[].migrations_dir; wrangler's default is migrations/)
 *   'other'     DDL of a database without Row Level Security (MySQL / MariaDB / SQLite syntax)
 *   'unknown'   none of the above: plain SQL that could be any Postgres (or anything else)
 */

import { stripComments } from './strip-comments.js';

// DDL of a database without Row Level Security (MySQL / MariaDB / SQLite).
export const NON_POSTGRES_SQL_RE = /\bENGINE\s*=\s*\w+|\bAUTO_INCREMENT\b|\bAUTOINCREMENT\b|\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?`|\bDEFAULT\s+CHARSET\b|\bunsigned\b/i;

// SQL only Supabase (PostgREST + GoTrue + Storage) gives meaning to.
export const SUPABASE_SQL_RE = /\bauth\s*\.\s*(?:uid|users|jwt|role|email)\b|\bto\s+(?:authenticated|anon)\b|\bstorage\s*\.\s*(?:buckets|objects)\b|\bcreate\s+policy\b|\b(?:enable|force)\s+row\s+level\s+security\b|\bservice_role\b|\bsupabase_\w+|\bsupabase\s*\.\s*\w+/i;

const SUPABASE_DIR_RE = /(^|\/)supabase\//;
const WRANGLER_RE = /(^|\/)wrangler\.(?:toml|json|jsonc)$/;
const NITRO_RE = /(^|\/)(?:nitro|nuxt)\.config\.[cm]?[jt]s$/;

const norm = (p) => String(p).replace(/\\/g, '/').replace(/\/+$/, '');

/** Folder of `rel` and a path written relative to it, as a project-relative path (null when it leaves the project). */
function joinRel(dir, p) {
  const parts = dir ? dir.split('/') : [];
  for (const seg of norm(p).split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') {
      if (!parts.length) return null;
      parts.pop();
    } else parts.push(seg);
  }
  return parts.join('/');
}

/** migrations_dir values (and whether a D1 database is declared at all) in one config file. */
function d1Declarations(f) {
  const c = f.content || '';
  if (!/d1_databases/.test(c)) return { declared: false, dirs: [] };
  const dirs = [];
  const re = /["']?migrations_dir["']?\s*[:=]\s*["'`]([^"'`]+)["'`]/g;
  let m;
  while ((m = re.exec(c))) dirs.push(m[1]);
  return { declared: true, dirs };
}

/**
 * Project-relative D1 migration folders. A migrations_dir that leaves the folder of its config (nitro writes the
 * wrangler config under .output/, so "../../db/migrations") is matched by its tail against the project's folders.
 */
export function d1MigrationDirs(files) {
  const folders = new Set();
  for (const f of files) {
    const parts = f.rel.split('/');
    for (let i = 1; i < parts.length; i++) folders.add(parts.slice(0, i).join('/'));
  }
  const out = new Set();
  const addDir = (configRel, p) => {
    const dir = configRel.includes('/') ? configRel.slice(0, configRel.lastIndexOf('/')) : '';
    const direct = joinRel(dir, p);
    if (direct !== null && folders.has(direct)) return out.add(direct);
    // Leaves the config's folder or the project: keep the part after the leading ../ and find it in the project.
    const tail = norm(p).replace(/^(?:\.{1,2}\/)+/, '');
    if (!tail) return null;
    for (const d of folders) if (d === tail || d.endsWith(`/${tail}`)) out.add(d);
    return null;
  };
  for (const f of files) {
    const wrangler = WRANGLER_RE.test(f.rel);
    if (!wrangler && !NITRO_RE.test(f.rel)) continue;
    const { declared, dirs } = d1Declarations(f);
    if (!declared) continue;
    for (const p of dirs) addDir(f.rel, p);
    if (wrangler && !dirs.length) addDir(f.rel, 'migrations'); // wrangler's default
  }
  return [...out];
}

/**
 * One database's migration history: the path up to its migrations folder (prisma/migrations/<ts>/migration.sql →
 * prisma/migrations), else the file's folder. A later ALTER TABLE file carries no dialect of its own; it belongs to the
 * database its folder's other files name.
 */
function migrationGroup(rel) {
  const parts = rel.split('/');
  parts.pop();
  const i = parts.lastIndexOf('migrations');
  return (i >= 0 ? parts.slice(0, i + 1) : parts).join('/');
}

// Prisma schema datasource provider without Row Level Security (MySQL, SQLite, SQL Server, CockroachDB, MongoDB).
const PRISMA_OTHER_PROVIDER_RE = /datasource\s+\w+\s*\{[^}]*\bprovider\s*=\s*["'](?:mysql|sqlite|sqlserver|cockroachdb|mongodb)["']/;

// The env variable a Prisma datasource reads its URL from (url = env("DATABASE_URL")).
const PRISMA_URL_ENV_RE = /datasource\s+\w+\s*\{[^}]*\burl\s*=\s*env\(\s*["'](\w+)["']\s*\)/;
const SUPABASE_DB_HOST_RE = /\.supabase\.(?:co|com)\b/;

/** Folders of the Prisma schemas whose database is Supabase (its URL variable points at a Supabase host in an env file). */
function prismaOnSupabase(files) {
  const envs = files.filter((f) => f.kind === 'env' || /(?:^|\/)\.env(?:\.[\w-]+)?$/.test(f.rel));
  const out = [];
  for (const f of files) {
    if (!/\.prisma$/.test(f.rel)) continue;
    const v = stripComments(f.content || '', f.rel).match(PRISMA_URL_ENV_RE)?.[1];
    if (!v) continue;
    const re = new RegExp(`^\\s*(?:export\\s+)?${v}\\s*=\\s*["']?([^"'\\s#]+)`, 'm');
    if (envs.some((e) => SUPABASE_DB_HOST_RE.test(String(e.content || '').match(re)?.[1] || ''))) out.push(f.rel.includes('/') ? f.rel.slice(0, f.rel.lastIndexOf('/')) : '');
  }
  return out;
}

const under = (dirs) => (rel) => dirs.some((d) => !d || rel.startsWith(`${d}/`));

/** Engine of each .sql file: Map rel → 'supabase' | 'd1' | 'other' | 'unknown'. */
export function sqlEngines(files) {
  const d1 = d1MigrationDirs(files);
  const inD1 = (rel) => d1.some((d) => rel === d || rel.startsWith(`${d}/`));
  // Folders under a Prisma schema whose datasource has no RLS, or whose database is Supabase.
  const underPrismaOther = under(files
    .filter((f) => /\.prisma$/.test(f.rel) && PRISMA_OTHER_PROVIDER_RE.test(stripComments(f.content || '', f.rel)))
    .map((f) => (f.rel.includes('/') ? f.rel.slice(0, f.rel.lastIndexOf('/')) : '')));
  const underPrismaSupabase = under(prismaOnSupabase(files));
  const out = new Map();
  for (const f of files) {
    if (!/\.sql$/i.test(f.rel)) continue;
    const c = stripComments(f.content || '', f.rel);
    let e = 'unknown';
    if (inD1(f.rel)) e = 'd1';
    else if (NON_POSTGRES_SQL_RE.test(c) || underPrismaOther(f.rel)) e = 'other';
    else if (SUPABASE_DIR_RE.test(f.rel) || SUPABASE_SQL_RE.test(c) || underPrismaSupabase(f.rel)) e = 'supabase';
    out.set(f.rel, e);
  }
  // A file whose own text names no database takes the one its migration folder names (when only one is named).
  const named = new Map();
  for (const [rel, e] of out) {
    if (e === 'unknown') continue;
    const g = migrationGroup(rel);
    if (!named.has(g)) named.set(g, new Set());
    named.get(g).add(e);
  }
  for (const [rel, e] of out) {
    if (e !== 'unknown') continue;
    const set = named.get(migrationGroup(rel));
    if (set && set.size === 1) out.set(rel, [...set][0]);
  }
  return out;
}
