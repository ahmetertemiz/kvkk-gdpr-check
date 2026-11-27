// kvkk-ignore-file  (reads schema files; contains no personal data itself)
/**
 * Personal-data columns of the database schema, for the quick scan's inventory (PII001).
 *
 * The quick scan's field patterns only know a short word list (email, phone, address …), so a schema column such as
 * `nickname`, `avatar_url` or `user_agent` never reached the inventory. This reads the SQL migrations and Prisma
 * schemas with the deep audit's own parsers and classifies every column with its classifier (the table name and the
 * sibling columns as context), so the quick scan lists the same columns the deep audit's inventory does.
 *
 * Special-category columns (health, biometric …) are left out: PII002 reports them, with a verdict.
 */
import { parseSqlFiles } from './audit/extract/sql.js';
import { parsePrisma } from './audit/extract/prisma.js';
import { classifyField, isSpecial } from './audit/classify/pii.js';

/** Structural markers, not a data category worth listing. */
const SKIP_ELEMENTS = new Set(['user_ref']);

function classifyTables(tables, out) {
  for (const t of tables.values()) {
    const siblings = [...t.columns.keys()];
    const table = t.name || t.key;
    for (const c of t.columns.values()) {
      const sqlType = (c.type || '').split('(')[0] || undefined;
      const cls = classifyField(c.name, { table, siblings, sqlType });
      if (!cls || SKIP_ELEMENTS.has(cls.element) || isSpecial(cls.category)) continue;
      out.push({ element: cls.element, column: `${table}.${c.name}`, file: c.file || t.file, line: c.line || t.line || null, snippet: c.snippet || '' });
    }
  }
}

/**
 * @param {Array<{rel: string, content: string}>} files production files of the scan (tests and kvkk-ignore-file excluded)
 * @returns {Array<{element: string, column: string, file: string, line: number|null, snippet: string}>}
 */
export function schemaPersonalColumns(files) {
  const out = [];
  const sql = files.filter((f) => /\.sql$/i.test(f.rel));
  if (sql.length) {
    try {
      classifyTables(parseSqlFiles(sql).tables, out);
    } catch {
      /* an unparsable migration never breaks the quick scan */
    }
  }
  for (const f of files.filter((x) => /\.prisma$/i.test(x.rel))) {
    try {
      classifyTables(parsePrisma(f), out);
    } catch {
      /* idem */
    }
  }
  return out;
}
