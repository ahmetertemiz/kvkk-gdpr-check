/**
 * Where the benchmark data lives. The labels name real projects and say, file by file, what is wrong with them, so they are
 * not part of the published repository: private/bench (ignored by git and npm) or the directory in KVKK_BENCH_DATA.
 *   repos.json            [{stack, url, commit}]
 *   labels/<stack>.json   verdicts and misses (format: bench/README.md)
 *   engine-subs.json      engine keys of first-sight labels
 *   results/              bench outputs and baselines
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const BENCH_DATA = path.resolve(process.env.KVKK_BENCH_DATA || path.join(ROOT, 'private', 'bench'));
export const hasBenchData = () => fs.existsSync(path.join(BENCH_DATA, 'repos.json')) && fs.existsSync(path.join(BENCH_DATA, 'labels'));
export const NO_DATA = 'benchmark data not found: it is not published (see bench/README.md); set KVKK_BENCH_DATA to your own label set';
