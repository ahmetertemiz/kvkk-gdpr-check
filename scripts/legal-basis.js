#!/usr/bin/env node
/**
 * Writes docs/hukuki-dayanaklar.md from src/data/legal-basis.js and the rules.
 *   node scripts/legal-basis.js [--check]      --check: exit 1 when the file is out of date
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { RULES } from '../src/rules.js';
import { LIVE_RULES } from '../src/live/rules.js';
import { CHECKED, SOURCES, RULE_CLAIMS, OTHER_CLAIMS, citationStatus } from '../src/data/legal-basis.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'docs/hukuki-dayanaklar.md');

/** Citations of the audit rules: read from the sources, because a rule object is only built when a finding exists. */
function auditRules() {
  const rules = new Map();
  const dir = path.join(ROOT, 'src/audit/legal');
  for (const f of [...fs.readdirSync(path.join(dir, 'checks')).sort().map((x) => path.join(dir, 'checks', x)), path.join(dir, 'secrets.js')]) {
    const t = fs.readFileSync(f, 'utf8');
    const named = new Map([...t.matchAll(/const ([A-Z_]+) = \{\s*\n(?:  [^\n]*\n){0,6}?  refs: \[([^\]]*)\]/g)].map((m) => [m[1], m[2]]));
    const at = [...t.matchAll(/id: ['"`](AUD-[A-Z]+-[A-Z0-9]+)['"`]/g)];
    at.forEach((m, i) => {
      const body = t.slice(m.index, at[i + 1]?.index ?? t.length);
      const own = /refs: \[([\s\S]*?)\],?\s*\n/.exec(body)?.[1];
      const spread = /\.\.\.([A-Z_]{3,})\b|refs: ([A-Z_]+)\.refs/.exec(body.slice(0, 400));
      const list = (spread && named.get(spread[1] || spread[2])) ?? own ?? named.get(spread?.[1] || spread?.[2]) ?? '';
      if (!rules.has(m[1])) rules.set(m[1], new Set());
      for (const r of list.matchAll(/'((?:[^'\\]|\\.)+)'/g)) if (/[A-ZİÇ]/.test(r[1][0]) || /^\d/.test(r[1])) rules.get(m[1]).add(r[1]);
    });
  }
  return rules;
}

const ST = { verified: 'Doğrulandı', unverified: '**Doğrulanmadı**', conflict: '**Kaynakla çelişiyor**' };
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const src = (s) => (s && SOURCES[s] ? `[${cell(SOURCES[s].title)}](${SOURCES[s].url})` : '—');
const row = (who, ref, c) => `| ${who} | ${cell(ref ? `${ref}${c.claim && c.claim !== '—' ? ` — ${c.claim}` : ''}` : c.claim)} | ${src(c.source)} | ${ST[c.status]}${c.note ? `. ${cell(c.note)}` : ''} |`;

export function rulesWithRefs() {
  const all = new Map([...RULES, ...LIVE_RULES].map((r) => [r.id, new Set(r.refs || [])]));
  for (const [id, refs] of auditRules()) all.set(id, refs);
  return all;
}

export function render() {
  const all = rulesWithRefs();
  const rows = [], conflicts = [], open = [];
  for (const [id, refs] of [...all].sort((a, b) => (a[0].startsWith('AUD') ? 1 : 0) - (b[0].startsWith('AUD') ? 1 : 0) || a[0].localeCompare(b[0]))) {
    for (const r of refs) rows.push({ who: id, ref: r, c: citationStatus(r) });
    for (const c of RULE_CLAIMS[id] || []) rows.push({ who: id, ref: null, c });
  }
  const other = OTHER_CLAIMS.map((c) => ({ who: c.where, ref: null, c }));
  const group = (status) => {
    const m = new Map();
    for (const x of [...rows, ...other]) {
      if (x.c.status !== status) continue;
      const k = x.ref || x.c.claim;
      if (!m.has(k)) m.set(k, { ...x, who: new Set() });
      m.get(k).who.add(x.who);
    }
    return [...m.values()].map((x) => row([...x.who].join(', '), x.ref, x.c));
  };
  conflicts.push(...group('conflict'));
  open.push(...group('unverified'));
  const n = (s) => [...rows, ...other].filter((x) => x.c.status === s).length;
  const H = ['| Kural | İddia | Kaynak | Doğrulama durumu |', '|---|---|---|---|'];
  return [
    '# Hukuki dayanaklar',
    '',
    '<!-- scripts/legal-basis.js üretir; elle düzenlemeyin -->',
    '',
    `İnceleme tarihi: ${CHECKED}. Birincil kaynaklar: kvkk.gov.tr, mevzuat.gov.tr, Resmî Gazete, eur-lex.europa.eu, developer.apple.com.`,
    '',
    '**İncelemeyi yapay zekâ yaptı; hiçbir hukukçu doğrulamadı.** "Doğrulandı", atıf yapılan hükmün birincil kaynakta okunduğu ve burada özetleneni söylediği anlamına gelir. Bir bulgunun o hükmü gerçekten ihlal edip etmediği hukuki değerlendirmedir ve doğrulanmamıştır. Kaynak metinlerin ilgili bölümleri okundu, tamamı değil; kaynakların sonradan değişip değişmediğini siz kontrol edin.',
    '',
    `${n('verified')} satır doğrulandı, ${n('unverified')} satır doğrulanmadı, ${n('conflict')} satır kaynakla çelişiyor. Doğrulanmayan ve çelişen dayanaklar raporda "doğrulanmamış dayanak" notuyla çıkar. Çelişen kurallar değiştirilmedi; karar proje sahibinindir.`,
    '',
    '## Kaynakla çelişen iddialar (karar bekliyor)', '', ...H, ...conflicts, '',
    '## Doğrulanamayan iddialar', '', ...H, ...open, '',
    '## Anket ve belge şablonları', '', ...H, ...other.map((x) => row(x.who, x.ref, x.c)), '',
    '## Kurallar', '', ...H, ...rows.map((x) => row(x.who, x.ref, x.c)), '',
  ].join('\n');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const text = render();
  if (process.argv.includes('--check')) {
    const same = fs.existsSync(OUT) && fs.readFileSync(OUT, 'utf8').replace(/\r\n/g, '\n') === text;
    console.log(same ? 'up to date' : 'docs/hukuki-dayanaklar.md is out of date');
    process.exitCode = same ? 0 : 1;
  } else {
    fs.writeFileSync(OUT, text);
    console.log(text.split('\n').slice(8, 11).join('\n'));
  }
}
