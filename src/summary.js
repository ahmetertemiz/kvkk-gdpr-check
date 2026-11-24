import { SEVERITY_ORDER, SEVERITY_WEIGHT } from './rules.js';

/**
 * Shared result model used by every scanner (code, live URL, mobile…).
 *
 *   Result = {
 *     root?: string,            // scanned directory (code scan)
 *     url?: string,             // scanned URL (live scan)
 *     filesScanned: number,
 *     findings: Finding[],      // sorted most severe first
 *     counts: {critical, high, medium, low, info},
 *     score: number,            // 0..100
 *     signals?: object,         // code-scan facts
 *     live?: object,            // live-scan facts (cookies, requests, banner, headers…)
 *   }
 *   Finding = { rule: Rule, severity: string, locations: Location[] }
 *   Location = { file?, line?, snippet?, label?: string|{tr,en}, count? }
 *   Rule = { id, category, severity, title:{tr,en}, desc:{tr,en}, fix:{tr,en}, refs:string[] }
 */

export function sortFindings(findings) {
  return findings.sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.rule.id.localeCompare(b.rule.id),
  );
}

export function summarize(findings) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  for (const f of findings) counts[f.severity]++;
  // Penalise per rule (not per location) so one noisy rule doesn't zero the score.
  let score = 100;
  for (const f of findings) {
    const w = SEVERITY_WEIGHT[f.severity];
    score -= w + Math.min(f.locations.length - 1, 5) * Math.ceil(w / 5);
  }
  return { counts, score: Math.max(0, score) };
}

/** Merge several results (e.g. code scan + live scan) into one report. */
export function mergeResults(...results) {
  results = results.filter(Boolean);
  const byId = new Map();
  for (const r of results) {
    for (const f of r.findings) {
      const prev = byId.get(f.rule.id);
      if (prev) prev.locations.push(...f.locations);
      else byId.set(f.rule.id, { ...f, locations: [...f.locations] });
    }
  }
  const findings = sortFindings([...byId.values()]);
  const merged = {
    filesScanned: results.reduce((n, r) => n + (r.filesScanned || 0), 0),
    findings,
    ...summarize(findings),
  };
  for (const r of results) {
    if (r.root) merged.root = r.root;
    if (r.url) merged.url = r.url;
    if (r.signals) merged.signals = r.signals;
    if (r.live) merged.live = r.live;
  }
  return merged;
}
