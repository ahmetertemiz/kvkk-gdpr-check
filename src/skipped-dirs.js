/** Quick-scan report line for test / spec / fixture files left out (secret rules still read them). null when none. */
export function testsSkippedText(result, lang = 'tr') {
  const n = Number(result?.testsSkipped) || 0;
  if (!n) return null;
  return lang === 'en'
    ? `${n} test/spec/fixture file${n === 1 ? '' : 's'} left out (secret-key rules still read them; use --include-tests to scan them).`
    : `${n} test/spec/fixture dosyası tarama dışı bırakıldı (gizli anahtar kuralları yine okur; taramak için --include-tests).`;
}

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
