#!/usr/bin/env node
/**
 * First-sight counts per stack family for src/audit/legal/support.js. Reads the label files (bench/data.js),
 * writes nothing. Prints the SUPPORT table; --check exits 1 when support.js differs.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { BENCH_DATA } from '../bench/data.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// Family of a benchmark repo, from its name (the stack it was picked for). h-* repos were judged after tuning.
const FAMILY = [
  ['laravel', 'Laravel', /laravel/], ['django', 'Django', /django/], ['flask', 'Flask', /flask/], ['fastapi', 'FastAPI', /fastapi/],
  ['flutter', 'Flutter', /flutter/], ['nuxt', 'Nuxt', /nuxt/], ['nestjs', 'NestJS', /nest/], ['sveltekit', 'SvelteKit', /svelte/],
  ['astro', 'Astro', /astro/], ['convex', 'Convex', /convex/], ['hono', 'Hono', /hono/], ['fastify', 'Fastify / Koa', /fastify|koa/],
  ['express', 'Express', /express/], ['remix', 'Remix / React Router', /remix|rr7/], ['expo-rn', 'Expo / React Native', /expo|rn-|mobile/],
  ['react-spa', 'React SPA (Vite, Lovable, Bolt)', /react-firebase|lovable|bolt|v0|vibe/], ['nextjs', 'Next.js', /next|t3/],
];
export function measureSupport(dir = path.join(BENCH_DATA, 'labels')) {
  const out = {};
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.json')).sort()) {
    const stack = f.slice(0, -5);
    if (!/^(?:n|r\d+)-/.test(stack)) continue;
    const fam = FAMILY.find(([, , re]) => re.test(stack));
    if (!fam) continue;
    const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    const g = (out[fam[0]] ||= { label: fam[1], repos: 0, tp: 0, fp: 0, misses: 0 });
    g.repos++;
    for (const l of j.findings || []) {
      if (l.step || /gate|label-audit/.test(l.round || '')) continue;
      if (l.verdict === 'TP') g.tp++;
      else if (l.verdict === 'FP') g.fp++;
    }
    g.misses += (j.misses || []).length;
  }
  return out;
}
export const tableText = (t) => Object.entries(t).sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([k, v]) => `  '${k}': { label: '${v.label}', repos: ${v.repos}, tp: ${v.tp}, fp: ${v.fp}, misses: ${v.misses} },`).join('\n');
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const t = measureSupport();
  console.log(tableText(t));
  if (process.argv.includes('--check')) {
    const { SUPPORT } = await import('../src/audit/legal/support.js');
    if (JSON.stringify(Object.entries(SUPPORT).sort()) !== JSON.stringify(Object.entries(t).sort())) { console.error('support.js differs from the measurement'); process.exit(1); }
  }
}
