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

/** Engine of each .sql file: Map rel → 'supabase' | 'd1' | 'other' | 'unknown'. */
export function sqlEngines(files) {
  const d1 = d1MigrationDirs(files);
  const inD1 = (rel) => d1.some((d) => rel === d || rel.startsWith(`${d}/`));
  const out = new Map();
  for (const f of files) {
    if (!/\.sql$/i.test(f.rel)) continue;
    const c = stripComments(f.content || '', f.rel);
    let e = 'unknown';
    if (inD1(f.rel)) e = 'd1';
    else if (NON_POSTGRES_SQL_RE.test(c)) e = 'other';
    else if (SUPABASE_DIR_RE.test(f.rel) || SUPABASE_SQL_RE.test(c)) e = 'supabase';
    out.set(f.rel, e);
  }
  return out;
}
