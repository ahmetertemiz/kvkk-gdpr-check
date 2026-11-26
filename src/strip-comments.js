/**
 * Blank out comments before rules match, so a sentence in a comment ("consent is checked here") is not read as code.
 * Comment characters become spaces and newlines stay, so offsets and line numbers do not move. String literals are
 * left alone (a "https://…" URL in a string keeps its "//"). The lexers are deliberately small: an unterminated
 * quote ends at the line break, so a stray apostrophe in markup text cannot swallow the rest of the file.
 */

const C_LIKE = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'java', 'kt', 'kts', 'swift', 'dart', 'go', 'cs', 'prisma', 'rules']);
const JS = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs']);
const HASH = new Set(['py', 'rb', 'ex', 'exs', 'graphql', 'gql']);
const HASH_WS = new Set(['yaml', 'yml', 'toml']); // a # starts a comment only at line start or after white space
const MARKUP = new Set(['html', 'htm', 'vue', 'svelte', 'astro', 'erb', 'twig', 'blade']);

const blank = (s) => s.replace(/[^\r\n]/g, ' ');

function extOf(rel) {
  const base = String(rel).split(/[\\/]/).pop() || '';
  if (/\.rules(\.json)?$/.test(base) || base === 'firestore.rules' || base === 'storage.rules') return 'rules';
  if (/\.blade\.php$/.test(base)) return 'blade';
  return base.includes('.') ? base.split('.').pop().toLowerCase() : '';
}

// Previous significant character / word decides whether "/" starts a regular expression literal (JS only).
// "<" is left out: in JSX "</div>" is a closing tag, not a regex.
const REGEX_AFTER_CHAR = new Set([...'(,=:[!&|?{};+-*%>~^']);
const REGEX_AFTER_WORD = /(?:^|[^\w$])(?:return|typeof|case|do|else|in|of|new|delete|void|throw|yield|await|instanceof)$/;

function regexAllowed(src, i) {
  let j = i - 1;
  while (j >= 0 && /\s/.test(src[j])) j--;
  if (j < 0) return true;
  if (REGEX_AFTER_CHAR.has(src[j])) return true;
  return REGEX_AFTER_WORD.test(src.slice(Math.max(0, j - 12), j + 1));
}

/** C-family source (// and block comments; JS adds template literals and regex literals). */
function stripCLike(src, { js = false, hashToo = false, tripleQuotes = false, rawBackticks = false } = {}) {
  const out = src.split('');
  const n = src.length;
  let i = 0;
  const tpl = []; // brace depth of each open ${ … } inside template literals
  let braces = 0;
  const wipe = (a, b) => { for (let k = a; k < b; k++) if (out[k] !== '\n' && out[k] !== '\r') out[k] = ' '; };
  const skipQuoted = (q) => {
    // i is at the opening quote; returns index after the closing quote (or at the line break if unterminated)
    let k = i + 1;
    while (k < n) {
      const c = src[k];
      if (c === '\\') { k += 2; continue; }
      if (c === q) return k + 1;
      if (c === '\n') return k;
      k++;
    }
    return n;
  };
  const skipTemplate = () => {
    // i is after a backtick or a closing } of ${ }; stops at the closing backtick or at a ${ (pushes)
    let k = i;
    while (k < n) {
      const c = src[k];
      if (c === '\\') { k += 2; continue; }
      if (c === '`') return { end: k + 1, open: false };
      if (c === '$' && src[k + 1] === '{') return { end: k + 2, open: true };
      k++;
    }
    return { end: n, open: false };
  };
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === '/' && d === '/') {
      let k = i;
      while (k < n && src[k] !== '\n') k++;
      wipe(i, k);
      i = k;
      continue;
    }
    if (c === '/' && d === '*') {
      const end = src.indexOf('*/', i + 2);
      const k = end < 0 ? n : end + 2;
      wipe(i, k);
      i = k;
      continue;
    }
    if (hashToo && c === '#') {
      let k = i;
      while (k < n && src[k] !== '\n') k++;
      wipe(i, k);
      i = k;
      continue;
    }
    if (tripleQuotes && (c === '"' || c === "'") && src.startsWith(c.repeat(3), i)) {
      const end = src.indexOf(c.repeat(3), i + 3);
      i = end < 0 ? n : end + 3;
      continue;
    }
    if (c === '"' || c === "'") { i = skipQuoted(c); continue; }
    if (c === '`') {
      if (js) {
        i++;
        const r = skipTemplate();
        i = r.end;
        if (r.open) tpl.push(braces);
        continue;
      }
      if (rawBackticks) { const end = src.indexOf('`', i + 1); i = end < 0 ? n : end + 1; continue; }
    }
    if (js && c === '{') { braces++; i++; continue; }
    if (js && c === '}') {
      if (tpl.length && braces === tpl[tpl.length - 1]) {
        tpl.pop();
        i++;
        const r = skipTemplate();
        i = r.end;
        if (r.open) tpl.push(braces);
        continue;
      }
      braces--;
      i++;
      continue;
    }
    if (js && c === '/' && regexAllowed(src, i)) {
      // regular expression literal: skip to the closing slash outside a character class
      let k = i + 1;
      let cls = false;
      while (k < n && src[k] !== '\n') {
        const ch = src[k];
        if (ch === '\\') { k += 2; continue; }
        if (ch === '[') cls = true;
        else if (ch === ']') cls = false;
        else if (ch === '/' && !cls) break;
        k++;
      }
      i = k < n && src[k] === '/' ? k + 1 : i + 1;
      continue;
    }
    i++;
  }
  return out.join('');
}

/** Python, Ruby, Elixir, GraphQL, YAML, TOML: # comments, quoted strings kept. */
function stripHash(src, { needSpace = false, triple = false } = {}) {
  const out = src.split('');
  const n = src.length;
  let i = 0;
  while (i < n) {
    const c = src[i];
    if (triple && (c === '"' || c === "'") && src.startsWith(c.repeat(3), i)) {
      const end = src.indexOf(c.repeat(3), i + 3);
      i = end < 0 ? n : end + 3;
      continue;
    }
    if (c === '"' || c === "'") {
      let k = i + 1;
      while (k < n && src[k] !== c && src[k] !== '\n') k += src[k] === '\\' && c === '"' ? 2 : 1;
      i = k + 1;
      continue;
    }
    if (c === '#' && (!needSpace || i === 0 || /\s/.test(src[i - 1]))) {
      let k = i;
      while (k < n && src[k] !== '\n') k++;
      for (let j = i; j < k; j++) if (out[j] !== '\r') out[j] = ' ';
      i = k;
      continue;
    }
    i++;
  }
  return out.join('');
}

/** SQL: -- and block comments; '…' strings and "…" identifiers kept. */
function stripSql(src) {
  const out = src.split('');
  const n = src.length;
  let i = 0;
  const wipe = (a, b) => { for (let k = a; k < b; k++) if (out[k] !== '\n' && out[k] !== '\r') out[k] = ' '; };
  while (i < n) {
    const c = src[i];
    if (c === '-' && src[i + 1] === '-') {
      let k = i;
      while (k < n && src[k] !== '\n') k++;
      wipe(i, k);
      i = k;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      const k = end < 0 ? n : end + 2;
      wipe(i, k);
      i = k;
      continue;
    }
    if (c === "'" || c === '"') {
      let k = i + 1;
      while (k < n) {
        if (src[k] === c && src[k + 1] === c) { k += 2; continue; } // doubled quote escape
        if (src[k] === c) break;
        k++;
      }
      i = k + 1;
      continue;
    }
    i++;
  }
  return out.join('');
}

/** HTML-like templates: <!-- --> comments, plus JS comments inside <script> blocks and Astro frontmatter. */
function stripMarkup(src, ext) {
  let s = src.replace(/<!--[\s\S]*?-->/g, blank);
  s = s.replace(/(<script\b[^>]*>)([\s\S]*?)(<\/script>)/gi, (_, a, body, b) => a + stripCLike(body, { js: true }) + b);
  if (ext === 'astro') s = s.replace(/^(---\r?\n)([\s\S]*?)(\r?\n---)/, (_, a, body, b) => a + stripCLike(body, { js: true }) + b);
  return s;
}

/**
 * Same-length copy of `content` with the comments of the file's language blanked. Unknown types (JSON, env, docs)
 * come back unchanged.
 */
export function stripComments(content, rel) {
  if (typeof content !== 'string' || !content) return content;
  const ext = extOf(rel);
  try {
    if (JS.has(ext)) return stripCLike(content, { js: true });
    if (ext === 'go') return stripCLike(content, { rawBackticks: true });
    if (ext === 'kt' || ext === 'kts' || ext === 'swift' || ext === 'dart') return stripCLike(content, { tripleQuotes: true });
    if (C_LIKE.has(ext)) return stripCLike(content);
    if (ext === 'php') return stripCLike(content, { hashToo: true });
    if (ext === 'py') return stripHash(content, { triple: true });
    if (HASH.has(ext)) return stripHash(content);
    if (HASH_WS.has(ext)) return stripHash(content, { needSpace: true });
    if (ext === 'sql') return stripSql(content);
    if (MARKUP.has(ext)) return stripMarkup(content, ext);
  } catch {
    return content;
  }
  return content;
}
