import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { scan } from '../scan.js';
import { mergeResults } from '../summary.js';
import { toHtml } from '../report/html.js';
import { PAGE } from './page.js';

const MAX_BODY = 64 * 1024;
const GITHUB_RE = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/;

const MSG = {
  tr: {
    nothing: 'Bir klasör, site URL\'i veya GitHub repo URL\'i gir.',
    noDir: 'Klasör bulunamadı',
    badRepo: 'Geçersiz GitHub URL\'i. Biçim: https://github.com/kullanici/repo',
    badUrl: 'Geçersiz site URL\'i (http:// veya https:// ile başlamalı).',
    clone: 'Repo klonlanamadı (public mi? git kurulu mu?)',
    live: 'Canlı site taraması yapılamadı',
    docs: 'Doküman üretici çalıştırılamadı',
    noScan: 'Önce bir tarama yap.',
  },
  en: {
    nothing: 'Enter a folder, a site URL or a GitHub repo URL.',
    noDir: 'Folder not found',
    badRepo: 'Invalid GitHub URL. Format: https://github.com/user/repo',
    badUrl: 'Invalid site URL (must start with http:// or https://).',
    clone: 'Could not clone the repo (is it public? is git installed?)',
    live: 'Live site scan failed',
    docs: 'Document generator failed',
    noScan: 'Run a scan first.',
  },
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new HttpError(413, 'Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {});
      } catch {
        reject(new HttpError(400, 'Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function send(res, status, body, type = 'application/json; charset=utf-8', extra = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  res.writeHead(status, {
    'Content-Type': type,
    'Content-Length': buf.length,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
    ...extra,
  });
  res.end(buf);
}

function cloneRepo(url) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-repo-'));
  return new Promise((resolve, reject) => {
    execFile(
      'git',
      ['clone', '--depth', '1', '--single-branch', '--no-tags', '--', url, dir],
      { timeout: 120000, env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: 'echo' }, windowsHide: true },
      (err) => {
        if (err) {
          fs.rmSync(dir, { recursive: true, force: true });
          reject(err);
        } else resolve(dir);
      },
    );
  });
}

function openBrowser(url) {
  try {
    if (process.platform === 'win32') execFile('cmd', ['/c', 'start', '', url], { windowsHide: true }, () => {});
    else if (process.platform === 'darwin') execFile('open', [url], () => {});
    else execFile('xdg-open', [url], () => {});
  } catch {}
}

/**
 * Start the local web UI.
 * @param {{port?:number, lang?:'tr'|'en', open?:boolean, host?:string}} opts
 * @returns {Promise<{server: http.Server, url: string, close: () => Promise<void>}>}
 */
export async function startUi({ port = 4477, lang = 'tr', open = true, quiet = false } = {}) {
  const host = '127.0.0.1';
  const results = new Map(); // scanId -> result (LRU-ish, max 20)
  const files = new Map(); // fileId -> { abs, name }
  const tempDirs = new Set();
  let actualPort = port;

  const allowedHosts = () => new Set([`127.0.0.1:${actualPort}`, `localhost:${actualPort}`]);

  function guard(req) {
    const h = (req.headers.host || '').toLowerCase();
    if (!allowedHosts().has(h)) throw new HttpError(403, 'Forbidden host');
    const origin = req.headers.origin;
    if (origin && !['http://' + `127.0.0.1:${actualPort}`, 'http://' + `localhost:${actualPort}`].includes(origin.toLowerCase())) {
      throw new HttpError(403, 'Forbidden origin');
    }
    if (req.method === 'POST' && !String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
      throw new HttpError(415, 'Content-Type must be application/json');
    }
  }

  async function handleScan(body) {
    const L = body.lang === 'en' ? 'en' : body.lang === 'tr' ? 'tr' : lang;
    const m = MSG[L];
    const p = typeof body.path === 'string' ? body.path.trim() : '';
    const url = typeof body.url === 'string' ? body.url.trim() : '';
    const repo = typeof body.repo === 'string' ? body.repo.trim() : '';
    if (!p && !url && !repo) throw new HttpError(400, m.nothing);
    if (repo && !GITHUB_RE.test(repo)) throw new HttpError(400, m.badRepo);
    let liveUrl = url;
    if (liveUrl && !/^https?:\/\//i.test(liveUrl)) liveUrl = 'https://' + liveUrl;
    if (liveUrl) {
      try {
        const u = new URL(liveUrl);
        if (!/^https?:$/.test(u.protocol)) throw new Error();
      } catch {
        throw new HttpError(400, m.badUrl);
      }
    }
    if (p) {
      const abs = path.resolve(p);
      if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) throw new HttpError(400, `${m.noDir}: ${p}`);
    }

    const parts = [];
    const warnings = [];
    if (p) parts.push(scan(path.resolve(p)));
    if (repo) {
      let dir;
      try {
        dir = await cloneRepo(repo.replace(/\/$/, ''));
      } catch (e) {
        throw new HttpError(400, `${m.clone}: ${String(e.message || e).split('\n')[0]}`);
      }
      try {
        const r = scan(dir);
        r.root = repo;
        parts.push(r);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }
    if (liveUrl) {
      try {
        const { scanUrl } = await import('../live/index.js');
        parts.push(await scanUrl(liveUrl, { lang: L, browser: body.noBrowser ? 'none' : 'auto', maxPages: 5, timeout: 30000 }));
      } catch (e) {
        if (!parts.length) throw new HttpError(500, `${m.live}: ${e.message || e}`);
        warnings.push(`${m.live}: ${e.message || e}`);
      }
    }
    const result = parts.length === 1 ? parts[0] : mergeResults(...parts);
    const scanId = crypto.randomBytes(9).toString('base64url');
    results.set(scanId, result);
    while (results.size > 20) results.delete(results.keys().next().value);
    return {
      scanId,
      score: result.score,
      counts: result.counts,
      warnings,
      html: toHtml(result, { lang: L }),
    };
  }

  async function handleDocs(body) {
    const L = body.lang === 'en' ? 'en' : body.lang === 'tr' ? 'tr' : lang;
    const result = results.get(String(body.scanId || ''));
    if (!result) throw new HttpError(400, MSG[L].noScan);
    const a = body.answers && typeof body.answers === 'object' ? body.answers : {};
    const answers = {};
    for (const k of ['companyName', 'appName', 'email', 'website', 'address']) if (typeof a[k] === 'string' && a[k].trim()) answers[k] = a[k].trim().slice(0, 300);
    let generateDocs;
    try {
      ({ generateDocs } = await import('../docs/index.js'));
    } catch (e) {
      throw new HttpError(500, `${MSG[L].docs}: ${e.message || e}`);
    }
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-docs-'));
    tempDirs.add(outDir);
    let out;
    try {
      out = await generateDocs({ result, answers, outDir, lang: L, interactive: false });
    } catch (e) {
      throw new HttpError(500, `${MSG[L].docs}: ${e.message || e}`);
    }
    const realOut = fs.realpathSync(outDir);
    const list = [];
    for (const f of out?.files || []) {
      let abs;
      try {
        abs = fs.realpathSync(path.resolve(f));
      } catch {
        continue;
      }
      if (!abs.startsWith(realOut + path.sep)) continue; // only files inside the generated dir
      const id = crypto.randomBytes(12).toString('base64url');
      files.set(id, { abs, name: path.relative(realOut, abs).split(path.sep).join('/') });
      list.push({ id, name: files.get(id).name, size: fs.statSync(abs).size });
    }
    return { files: list };
  }

  function handleFile(id, res) {
    const f = files.get(id);
    if (!f || !fs.existsSync(f.abs)) throw new HttpError(404, 'Not found');
    const ext = path.extname(f.abs).toLowerCase();
    const type = { '.md': 'text/markdown; charset=utf-8', '.csv': 'text/csv; charset=utf-8', '.json': 'application/json; charset=utf-8', '.html': 'text/plain; charset=utf-8', '.txt': 'text/plain; charset=utf-8' }[ext] || 'application/octet-stream';
    const safeName = path.basename(f.name).replace(/[^\w.-]/g, '_');
    send(res, 200, fs.readFileSync(f.abs), type, { 'Content-Disposition': `attachment; filename="${safeName}"` });
  }

  const server = http.createServer(async (req, res) => {
    try {
      guard(req);
      const u = new URL(req.url, `http://${req.headers.host}`);
      if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/index.html')) {
        return send(res, 200, PAGE(lang), 'text/html; charset=utf-8', {
          'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-src 'self' blob: data:; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        });
      }
      if (req.method === 'GET' && u.pathname === '/api/health') return send(res, 200, { ok: true });
      if (req.method === 'POST' && u.pathname === '/api/scan') return send(res, 200, await handleScan(await readJson(req)));
      if (req.method === 'POST' && u.pathname === '/api/docs') return send(res, 200, await handleDocs(await readJson(req)));
      if (req.method === 'GET' && u.pathname === '/api/file') return handleFile(u.searchParams.get('id') || '', res);
      throw new HttpError(404, 'Not found');
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      if (status === 500 && !quiet) console.error(e);
      if (!res.headersSent) send(res, status, { error: e.message || String(e) });
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  actualPort = server.address().port;
  const url = `http://127.0.0.1:${actualPort}/`;
  if (!quiet) {
    console.log(lang === 'en' ? `\n  kvkk-gdpr-check UI running at ${url}\n  Press Ctrl+C to stop.\n` : `\n  kvkk-gdpr-check arayüzü çalışıyor: ${url}\n  Durdurmak için Ctrl+C.\n`);
  }
  if (open) openBrowser(url);

  const cleanup = () => {
    for (const d of tempDirs) fs.rmSync(d, { recursive: true, force: true });
    tempDirs.clear();
  };
  process.once('exit', cleanup);

  return {
    server,
    url,
    port: actualPort,
    close: () =>
      new Promise((resolve) => {
        cleanup();
        server.close(() => resolve());
        server.closeAllConnections?.();
      }),
  };
}
