import fs from 'node:fs';
import path from 'node:path';
import { walk } from './walk.js';
import { RULES, SIGNALS } from './rules.js';
import { sortFindings, summarize } from './summary.js';
import { attachSupport } from './support-notice.js';
import { scoreReasons } from './score-gate.js';

const SUPPRESS = /kvkk-ignore(?:[\s:]+([A-Z]{3}\d{3}(?:\s*,\s*[A-Z]{3}\d{3})*))?/;

function maskSecret(s) {
  return s.replace(/([A-Za-z0-9_\-]{6})[A-Za-z0-9_\-.]{8,}([A-Za-z0-9_\-]{4})/g, '$1••••••$2');
}

function isSuppressed(lines, idx, ruleId) {
  for (const l of [lines[idx], lines[idx - 1]]) {
    if (!l) continue;
    const m = l.match(SUPPRESS);
    if (m && (!m[1] || m[1].split(/\s*,\s*/).includes(ruleId))) return true;
  }
  return false;
}

function loadConfig(root) {
  for (const name of ['.kvkkcheckrc.json', 'kvkk-check.config.json']) {
    try {
      return JSON.parse(fs.readFileSync(path.join(root, name), 'utf8'));
    } catch {}
  }
  return {};
}

/**
 * Scan a project directory.
 * @param {string} root
 * @param {{ignore?:string[], disable?:string[]}} opts
 */
export function scan(root, opts = {}) {
  root = path.resolve(root);
  const config = loadConfig(root);
  const ignore = [...(config.ignore || []), ...(opts.ignore || [])];
  const disabled = new Set([...(config.disable || []), ...(opts.disable || [])]);

  const files = walk(root, { ignore });
  const rules = RULES.filter((r) => !disabled.has(r.id));
  const hits = {};
  const add = (rule, f) => (hits[rule.id] ||= []).push(f);

  // --- file rules ---
  const seenLabels = {};
  for (const file of files) {
    if (/kvkk-ignore-file/.test(file.content.slice(0, 500))) continue;
    const lines = file.content.split(/\r?\n/);
    let lineStarts = null; // lazily computed for whole-file patterns
    const lineAt = (index) => {
      if (!lineStarts) {
        lineStarts = [0];
        for (let i = 0; i < file.content.length; i++) if (file.content[i] === '\n') lineStarts.push(i + 1);
      }
      let lo = 0;
      let hi = lineStarts.length - 1;
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (lineStarts[mid] <= index) lo = mid;
        else hi = mid - 1;
      }
      return lo; // 0-based
    };

    for (const rule of rules) {
      if (rule.scope !== 'file' || !rule.kinds.includes(file.kind)) continue;
      if (rule.pathRe && !rule.pathRe.test(file.rel)) continue;
      const patterns = rule.patterns.filter((p) => !p.pathRe || p.pathRe.test(file.rel));
      if (!patterns.length) continue;
      let perFile = 0;

      // Returns true if recorded (or aggregated), false if skipped.
      const record = (p, m, i) => {
        const line = lines[i] ?? '';
        if (p.verify && !p.verify(m, line)) return false;
        if (isSuppressed(lines, i, rule.id)) return false;
        const label = (p.labelFrom ? p.labelFrom(m) : p.label) || m[0];
        const labelKey = typeof label === 'string' ? label : label.en;
        if (rule.aggregate && seenLabels[`${rule.id}:${labelKey}`]) {
          seenLabels[`${rule.id}:${labelKey}`].count++;
          return true;
        }
        let snippet = line.trim().slice(0, 160);
        if (rule.mask) snippet = maskSecret(snippet);
        const finding = { ruleId: rule.id, file: file.rel, line: i + 1, snippet, label, count: 1 };
        if (rule.aggregate) seenLabels[`${rule.id}:${labelKey}`] = finding;
        add(rule, finding);
        perFile++;
        return true;
      };

      // Whole-file (multi-line) patterns.
      for (const p of patterns.filter((x) => x.whole)) {
        const re = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g');
        let m;
        while ((m = re.exec(file.content)) && perFile < 20) {
          record(p, m, lineAt(m.index));
          if (m[0].length === 0) re.lastIndex++;
        }
      }

      // Line patterns.
      const linePatterns = patterns.filter((x) => !x.whole);
      if (!linePatterns.length) continue;
      for (let i = 0; i < lines.length && perFile < 20; i++) {
        const line = lines[i];
        if (line.length > 2000) continue; // minified / generated
        for (const p of linePatterns) {
          const m = line.match(p.re);
          if (m && record(p, m, i)) break;
        }
      }
    }
  }

  // --- signals ---
  // Skip kvkk-ignore-file files so e.g. vendored rule definitions never count as
  // "consent manager present".
  const signalFiles = files.filter((f) => !/kvkk-ignore-file/.test(f.content.slice(0, 500)));
  const signals = {};
  for (const [name, sig] of Object.entries(SIGNALS)) {
    signals[name] = signalFiles.some(
      (f) => (sig.kinds.includes('path') && sig.re.test(f.rel)) || (sig.kinds.includes(f.kind) && sig.re.test(f.content)),
    );
  }

  // --- project rules ---
  for (const rule of rules) {
    if (rule.scope !== 'project') continue;
    const results = rule.check({ files: signalFiles, signals, hits, root, fs, path }) || [];
    for (const r of results) add(rule, { ruleId: rule.id, file: r.file || null, line: r.line || null, snippet: r.snippet || null, label: r.label, severity: r.severity, count: 1 });
  }

  // --- assemble ---
  const ruleById = Object.fromEntries(RULES.map((r) => [r.id, r]));
  const findings = sortFindings(
    Object.entries(hits).map(([id, list]) => {
      const rule = ruleById[id];
      return { rule, severity: list[0].severity || rule.severity, locations: list };
    }),
  );
  const { counts, score } = summarize(findings);

  // Manifests only; score-gate.js attachCoverage adds the analysis layers (CLI, web UI).
  const support = attachSupport(files);
  const reasons = scoreReasons({ support, filesScanned: files.length });
  return { root, filesScanned: files.length, findings, counts, score, signals, support, scoreReliable: !reasons.length, scoreReasons: reasons };
}
