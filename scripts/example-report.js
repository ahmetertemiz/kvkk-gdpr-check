#!/usr/bin/env node
/** Writes examples/reports/audit-app.{md,html}: the audit of examples/audit-app. */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { audit } from '../src/audit/index.js';
import { renderAudit } from '../src/audit/report/index.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NAME = 'audit-app';
const result = await audit(path.join(ROOT, 'examples', NAME), { lang: 'tr' });
const out = path.join(ROOT, 'examples/reports');
fs.mkdirSync(out, { recursive: true });
for (const format of ['md', 'html']) {
  const text = renderAudit(result, { lang: 'tr', format, color: false });
  if (text.includes(ROOT) || text.includes(ROOT.split(path.sep).join('/'))) throw new Error('local path in the report');
  fs.writeFileSync(path.join(out, `${NAME}.${format}`), text);
}
console.log('examples/reports written');
