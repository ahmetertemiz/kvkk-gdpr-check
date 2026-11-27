import fs from 'node:fs';
import path from 'node:path';
import { walk } from './walk.js';
import { stripComments } from './strip-comments.js';
import { RULES, SIGNALS } from './rules.js';
import { sortFindings, summarize } from './summary.js';
import { attachSupport } from './support-notice.js';
import { scoreReasons } from './score-gate.js';
import { standInSecret, exposureGuard, realLookingCredential } from './secret-shape.js';
import { capLocation, capEnabled } from './severity-cap.js';
import { realDemotion, realReason } from './real-calibration.js';

const TEST_NOTE = { tr: 'test dosyasında', en: 'in a test file' };
const LOWER = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };
/** One level lower (a secret found in a test file). */
export const lowerSeverity = (s) => LOWER[s] || s;

/** Label with a note in brackets, in both languages. */
function withNote(label, note) {
  if (!note) return label;
  const t = (l, lang) => (typeof l === 'string' ? l : l?.[lang] || l?.en || '');
  return { tr: `${t(label, 'tr')} (${t(note, 'tr')})`, en: `${t(label, 'en')} (${t(note, 'en')})` };
}

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

  const all = walk(root, { ignore, include: opts.include || [] });
  // Test / spec / fixture files are left out like in the deep audit (walk.js isTestPath), unless --include-tests.
  // Secret rules still read them: a real key committed in a test is leaked all the same (reported one level lower).
  const includeTests = !!opts.includeTests;
  const testFiles = includeTests ? [] : all.filter((f) => f.test);
  const files = includeTests ? all : all.filter((f) => !f.test);
  const rules = RULES.filter((r) => !disabled.has(r.id));
  const hits = {};
  const add = (rule, f) => (hits[rule.id] ||= []).push(f);

  // --- file rules ---
  const seenLabels = {};
  for (const file of [...files, ...testFiles]) {
    if (/kvkk-ignore-file/.test(file.content.slice(0, 500))) continue;
    const inTest = !includeTests && !!file.test;
    const lines = file.content.split(/\r?\n/);
    // Rules match the code with its comments blanked (same length, same lines); secret rules read the comments too.
    let bareLines = null;
    const codeLines = (rule) => {
      if (rule.secret) return lines;
      if (!bareLines) bareLines = stripComments(file.content, file.rel).split(/\r?\n/);
      return bareLines;
    };
    let bareContent = null;
    const codeContent = (rule) => (rule.secret ? file.content : (bareContent ??= stripComments(file.content, file.rel)));
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
      if (inTest && !rule.secret) continue;
      if (rule.pathRe && !rule.pathRe.test(file.rel)) continue;
      const patterns = rule.patterns.filter((p) => !p.pathRe || p.pathRe.test(file.rel));
      if (!patterns.length) continue;
      let perFile = 0;
      const matchLines = codeLines(rule);

      // Returns true if recorded (or aggregated), false if skipped.
      const record = (p, m, i) => {
        const line = matchLines[i] ?? '';
        if (p.verify && !p.verify(m, line, file)) return false;
        if (isSuppressed(lines, i, rule.id)) return false;
        // A stand-in value (SENTINEL, an alphabet run, Base64 of readable text, a documented example …) is not a leak,
        // and a public-env secret name used to block a release is not an exposure (src/secret-shape.js).
        if (rule.secret && standInSecret(m, matchLines, i)) return false;
        if (rule.publicEnv && exposureGuard(matchLines, i, m)) return false;
        let label = (p.labelFrom ? p.labelFrom(m) : p.label) || m[0];
        // A pattern may set its own level (e.g. a sensitive word without a person-linked context is information only).
        let severity = typeof p.severity === 'function' ? p.severity(m, line, file) : p.severity || null;
        if (p.note) label = withNote(label, typeof p.note === 'function' ? p.note(m, line, file, severity) : p.note);
        if (inTest) {
          severity = lowerSeverity(severity || rule.severity);
          label = withNote(label, TEST_NOTE);
        }
        const labelKey = `${typeof label === 'string' ? label : label.en}|${severity || ''}`;
        if (rule.aggregate && seenLabels[`${rule.id}:${labelKey}`]) {
          seenLabels[`${rule.id}:${labelKey}`].count++;
          return true;
        }
        let snippet = (lines[i] ?? '').trim().slice(0, 160);
        if (rule.mask) snippet = maskSecret(snippet);
        const finding = { ruleId: rule.id, file: file.rel, line: i + 1, snippet, label, count: 1, ...(severity ? { severity } : {}), ...(rule.secret && realLookingCredential(m, matchLines, i) ? { realKey: true } : {}) };
        if (rule.aggregate) seenLabels[`${rule.id}:${labelKey}`] = finding;
        add(rule, finding);
        perFile++;
        return true;
      };

      // Whole-file (multi-line) patterns.
      const wholeContent = patterns.some((x) => x.whole) ? codeContent(rule) : null;
      for (const p of patterns.filter((x) => x.whole)) {
        const re = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g');
        let m;
        while ((m = re.exec(wholeContent)) && perFile < 20) {
          record(p, m, lineAt(m.index));
          if (m[0].length === 0) re.lastIndex++;
        }
      }

      // Line patterns.
      const linePatterns = patterns.filter((x) => !x.whole);
      if (!linePatterns.length) continue;
      for (let i = 0; i < matchLines.length && perFile < 20; i++) {
        const line = matchLines[i];
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
  // Signals and project rules read the code with its comments blanked, like the file rules.
  const signalFiles = files
    .filter((f) => !/kvkk-ignore-file/.test(f.content.slice(0, 500)))
    .map((f) => {
      const bare = stripComments(f.content, f.rel);
      return bare === f.content ? f : { ...f, content: bare, raw: f.content };
    });
  // A control signal (rules.js) silences an absence finding: it reads every file as written, comments and tests too.
  const controlFiles = [...files, ...testFiles].filter((f) => !/kvkk-ignore-file/.test(f.content.slice(0, 500)));
  const signals = {};
  for (const [name, sig] of Object.entries(SIGNALS)) {
    const pool = sig.control ? controlFiles : signalFiles;
    signals[name] = pool.some(
      (f) => (sig.kinds.includes('path') && sig.re.test(f.rel)) || (sig.kinds.includes(f.kind) && sig.re.test(f.content)),
    );
  }

  // --- project rules ---
  for (const rule of rules) {
    if (rule.scope !== 'project') continue;
    const results = rule.check({ files: signalFiles, signals, hits, root, fs, path }) || [];
    for (const r of results) add(rule, { ruleId: rule.id, file: r.file || null, line: r.line || null, snippet: r.snippet || null, label: r.label, ...(r.severity ? { severity: r.severity } : {}), ...(r.realKey ? { realKey: true } : {}), count: 1 });
  }

  // --- assemble ---
  // One finding per rule and level: locations of one rule may sit at different levels (a lower one for a key in a
  // test file, information only for a sensitive word without a person-linked context).
  const ruleById = Object.fromEntries(RULES.map((r) => [r.id, r]));
  const groups = new Map();
  const reviewGroups = new Map();
  for (const [id, list] of Object.entries(hits)) {
    const rule = ruleById[id];
    // Real-project precision (src/real-calibration.js, demote-only): a rule mostly wrong on the hand-verified real
    // projects goes to "to check" (review), with that rate; a location may also carry its own reviewReason.
    const real = opts.real === false ? null : realDemotion({ source: 'quick', ruleId: id }, opts.realCounts);
    const realWhy = real ? realReason(real, { ruleId: id }) : null;
    for (let loc of list) {
      // Severity cap (src/severity-cap.js): a quick-scan rule no real project measured shows at most "medium", except a
      // real-looking key; the level before the cap stays as severityRaw.
      const raw = loc.severity || rule.severity;
      const cap = !capEnabled(opts.severityCap) ? { severity: raw, raw: null } : capLocation(raw, { source: 'quick', ruleId: id, realKey: !!loc.realKey, counts: opts.realCounts });
      const sev = cap.severity;
      if (cap.raw) loc = { ...loc, severity: sev, severityRaw: cap.raw };
      const key = `${id}|${sev}`;
      const why = loc.reviewReason || realWhy;
      const into = why ? reviewGroups : groups;
      if (!into.has(key)) into.set(key, { rule, severity: sev, locations: [], ...(why ? { review: true } : {}) });
      into.get(key).locations.push(why ? { ...loc, reviewReason: why } : loc);
    }
  }
  const findings = sortFindings([...groups.values()]);
  // Not counted, not scored, not seen by --fail-on unless --fail-on-review.
  const review = sortFindings([...reviewGroups.values()]);
  const { counts, score } = summarize(findings);

  // Manifests only; score-gate.js attachCoverage adds the analysis layers (CLI, web UI).
  const support = attachSupport(files);
  const reasons = scoreReasons({ support, filesScanned: files.length });
  return { root, filesScanned: files.length, testsSkipped: testFiles.length, skippedDirs: all.skippedDirs || [], findings, review, counts, score, signals, support, scoreReliable: !reasons.length, scoreReasons: reasons };
}
