/**
 * What a report calls the project: the folder name, never the path of somebody's machine (reports are shared). Results keep the full
 * path internally (`result.root`), because the document generator and the web UI read the project again.
 */
export function displayRoot(root) {
  if (!root) return null;
  const s = String(root);
  if (/^https?:\/\//i.test(s)) return s; // a repository the user entered in the web UI
  const name = s.replace(/[\\/]+$/, '').split(/[\\/]/).pop();
  return name && !/^[A-Za-z]:$/.test(name) ? name : '.';
}

/** Text (a warning, an error message) with the project's path replaced by its name. */
export function hideRoot(text, root) {
  if (typeof text !== 'string' || !root || /^https?:/i.test(String(root))) return text;
  const name = displayRoot(root);
  let out = text;
  for (const p of new Set([String(root), String(root).split('\\').join('/'), String(root).split('/').join('\\')])) if (p.length > 3) out = out.split(p).join(name);
  return out;
}
