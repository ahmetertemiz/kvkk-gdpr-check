/** The report line for folders left out by default (coding agents, editors, worktree copies). null when none. */
export function skippedDirsText(result, lang = 'tr') {
  const list = Array.isArray(result?.skippedDirs) ? result.skippedDirs : [];
  if (!list.length) return null;
  const item = (d) => {
    const wt = d.reason === 'agent' && d.worktrees ? (lang === 'en' ? ` (${d.worktrees} worktree cop${d.worktrees === 1 ? 'y' : 'ies'})` : ` (${d.worktrees} worktree kopyası)`) : d.reason === 'worktree' ? (lang === 'en' ? ' (worktree copy)' : ' (worktree kopyası)') : '';
    return `${d.rel}${wt}`;
  };
  const names = list.map(item).join(', ');
  return lang === 'en'
    ? `Not scanned (coding-agent / editor folders and worktree copies): ${names}. Scan one with --include <folder>.`
    : `Taranmadı (kodlama ajanı / editör klasörleri ve worktree kopyaları): ${names}. Taramak için --include <klasör>.`;
}
