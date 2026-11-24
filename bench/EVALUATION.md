# How an unseen round is evaluated (from round 10)

Fixed before the round, so that rounds can be compared. Rounds 4 to 9 differ from this and from each other.

1. **Freeze.** Hash `src`, `bin`, `package.json` before and after. Snapshot the label files and `repos.json` (see `data.js`).
2. **Repositories.** One new public repository per slot of `unseen-mix.json`, never one listed in `repos.json`, chosen before the
   tool runs. Clones are read only; their code is never installed or run.
3. **Judging.** Every scored location and every review item gets TP / FP / UNCERTAIN, judged as the label claims.
   *Definitions that have gone wrong before:*
   - RET-01 claims "no retention period and no scheduled deletion". A delete button does not make it false.
   - DEL-01 claims the account deletion does not reach the store. Deleting a single record does not make it false.
   - A review item is judged by the same standard as a finding, not as "worth a look".
4. **Challenge both ways.** Every FP **and every TP** verdict on SEC-*, TRF-*, MIN-*, LB-* and DEL-* rules goes to a skeptic who sees the claim
   and the code but not the first verdict. For RET-01 and TRN / DSR absence claims a random half. Disagreement goes to a third
   judge; the majority is the label. (Until round 9 only FP verdicts were challenged, which pushed precision up.)
5. **Misses.** Absent from findings, review and every register of the report. Each is challenged.
6. **Coverage**, by this rubric and not by an overall impression, per repository:
   - R1: the score is shown as reliable (or coverage ok) **and** at least one of schema, routes, dbWrites, vendors misses or misreads a
     real component without a disclosed gap;
   - R2: any layer is shown as found without a gap although a real part of it was missed;
   - R3: the score was withheld, or the main blind spot was disclosed.
   Report the counts of R1, R2, R3.
7. **Blind audit.** A random sample of at least 40 labels of the round (TP, FP, review, misses) **mixed with as many from the previous round**,
   shuffled, without round or verdict. Report the kept rate of both rounds side by side.
8. **Report.** Raw and audit-corrected precision with intervals, with and without RET-01; misses per repository (total, high); review real /
   noise by calibration status; everything again per support tier. State the concentration: the share of TPs, FPs and review reals that comes
   from the largest repository.

All judges are model agents of one family. No lawyer has reviewed any label.
