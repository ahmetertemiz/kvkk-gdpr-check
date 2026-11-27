/**
 * Rules whose meaning changed. Their measurements from before the change describe signals the rule no longer raises, so
 * neither the report's precision line nor the review ordering may add them up into a rule-level rate. Only the listed
 * current sub-signals count; until those are measured the rule reads as "not measured".
 *
 *   AUD-RET-01 (0.2.1): was "no automatic cleanup for this store" (record-*, log-store, bucket); that list is now a fact
 *   (model.noAutoCleanup). The verdict is a promised retention period the code does not apply.
 */
export const CURRENT_SUBS = {
  'AUD-RET-01': ['RET-01:notice-period-unenforced'],
};

const short = (ruleId) => String(ruleId || '').replace(/^AUD-/, '');
const BY_SHORT = new Map(Object.entries(CURRENT_SUBS).map(([id, subs]) => [short(id), new Set(subs)]));

/** True when the rule was redefined (its rule-level counts from before are stale). */
export const isRedefined = (ruleId) => BY_SHORT.has(short(ruleId));

/** Whether a sub-signal key ("RET-01:record-content") may count towards its rule's rate. */
export function countsForRule(subKey) {
  const s = String(subKey || '');
  const cur = BY_SHORT.get(s.split(':')[0]);
  return !cur || cur.has(s);
}
