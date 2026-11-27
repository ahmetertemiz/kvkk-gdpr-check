# Calibration by measured sub-signal precision (round 7, recalibrated in rounds 8 and 9)

## 0.2: real-project calibration, severity cap, precision in reports

> **0.2.1.** `src/real-precision.js` is regenerated from seven projects: the three of 0.2.0 and the four measured blind
> after it, which are now part of the tuning set. The rules below are unchanged. A sub-signal with ≥ 8 real-project labels
> is judged on its own counts, whatever its 84-project rate; the conflict guard only concerns the rule-total fallback,
> which stays off. A location kept on strong evidence by the benchmark calibration is its own real-project subset
> (`<sub>:strong`, `strongSub` in `src/real-calibration.js`; bench/real.js keys it the same way): decided on its own
> counts when they pass the threshold, otherwise not by the real set. Effect on the 84 benchmark checkouts: 49
> deep-audit locations move to review (SEC-03:no-auth; of the labelled ones 27 TP and 11 FP), none leaves the report,
> 2 locations (SEC-09:password-in-email) keep high instead of medium, 1 (TRN-02:recipient-not-listed) goes from high to
> medium. On the seven projects, scored critical / high / medium deep-audit precision goes from 47 / 94 to 45 / 81.

0.2 adds a second measurement, the real-project set (`bench/real.js`, private labels).
- **Projects:** three hand-verified applications, with the quick scan, the deep audit and the live scan all measured.
- **Data:** the counts are generated into `src/real-precision.js` (`scripts/gen-real-precision.js --in <results.json>`). Only counts are kept: TP / FP / uncertain and FP projects per `source:rule` and `source:rule:sub`.
- **In sample:** the tool is tuned on these projects, so their rates describe the tuning, not unseen code. Reports mark them as "(ayar seti)" / "(tuning set)".

### Real-project calibration: demote only

Code: `src/real-calibration.js`, applied after the benchmark routing in `calibrate.js` and in the quick scan's grouping (`scan.js`). A location moves to review (`result.review[]`, "Doğrulanmalı (puana katılmadı)") when its real-project precision is reliably low:
- at least `REAL_MIN_N = 8` labels;
- FPs from at least `REAL_MIN_FP_PROJECTS = 2` projects;
- the Wilson 90% upper bound is below `REAL_UPPER90_MAX = 0.5`, or the point estimate is below `REAL_POINT_MAX = 0.4` and the lower bound is below `REAL_LOWER90_MAX = 0.3`.

The calibration never promotes a location and never changes a level.
- **Basis:** The sub-signal's own counts decide when it has ≥ 8 labels. Below that, a location without a sub-signal uses its rule's total.
- **Fallback (off):** `REAL_RULE_FALLBACK = false` keeps a location that has a sub-signal on the rule total. Measured on the three projects, turning it on moved 12 locations that the 84-project labels show as right and 3 wrong ones to review, to remove 2 real-set FPs.
- **Conflict guard:** A location demoted on its rule's total whose own sub-signal has at least `CONFIDENCE_MIN_N = 5` benchmark labels is kept, and the conflict is recorded (`realConflict`).

### Severity cap

Code: `src/severity-cap.js`, applied in `runAudit` and in the quick scan's grouping, so counts, score and `--fail-on` see the capped level. A location keeps critical / high only when a measurement supports it:

| Basis (`severityBasis`) | Condition |
|---|---|
| `real` | the rule has ≥ 8 real-project labels and the Wilson 90% lower bound ≥ `CAP_LOWER90_MIN = 0.5` |
| `benchmark` | deep audit only: the real-project rule has fewer than 8 labels and the location's sub-signal is `reliable` on the 84-project set |
| `real-key` | a real-looking credential (`realLookingCredential`, `src/secret-shape.js`). It covers a random provider key, a connection string with a non-default password on a public host, a PEM with a body, and a committed `.env` holding such a value. |

- **Capped levels:** Every other critical / high location becomes medium, with `severityRaw` on the location and on the finding when the finding's own level changed.
- **Live scan:** The live scan is not capped.
- **Rule tests:** `KVKK_NO_SEVERITY_CAP=1` switches the cap off for rule-logic tests.

Effect when introduced, scored critical / high locations:

| Where | Before | After |
|---|---|---|
| Benchmark checkouts (97 folders), quick scan | 124 | 8 (all real-looking keys) |
| Benchmark checkouts (97 folders), deep audit | 450 | 321 |
| Three real projects, quick scan | 3 | 1 |

- **The 321 deep-audit locations:** 307 are kept on a reliable benchmark sub-signal (`benchmark`), 11 on the real set (`real`) and 3 as real-looking keys (`real-key`).
- **Real projects:** The one location left is a committed `.env`, which is correct.

### Precision in reports

`src/precision-note.js` gives every finding one line, the real-project rate and the 84-project rate side by side, never merged.
- **Benchmark side:** It is the sum over the rule's sub-signals in `rule-precision.js`, deep audit only.
- **Small samples:** Below `PRECISION_MIN_N = 5` labels the line gives counts only ("yetersiz veri: 1 konumda 0 doğru"), and JSON `precision.real.precision` / `precision.benchmark.precision` is `null`.
- **Inventory:** Inventory findings (`rule.kind === 'inventory'`: PII001, TRK001, TRF001, WEB018) carry no verdict and get no precision line.

## Benchmark calibration (rounds 7 to 9)

> **Round 9.** Two things differ from the text below, which documents rounds 7 and 8: the data is
> `rule-precision-r9.json` (1464 labels, 60 repos; round 10), and a sub-signal **without any first-sight label goes to review** unless it
> carries strong evidence (status `unmeasured`; a location without `loc.sub` is `unkeyed` and stays scored). Leave-one-round-out
> evidence, all held-out rounds together: 83.1% of scored locations right without the rule, 85.7% with it. Its only prospective rounds do not agree
> (no gain in round 9, 1.6 points in round 10), and what it routes away is real more often than not. See [ACCURACY.md](ACCURACY.md). Counts and key lists quoted below are those of r7.

The audit engine sends a finding location to `result.review[]` ("Doğrulanmalı / needs verification") in three cases (the third is the round 9 rule above):

1. **The absence conclusion is not supported** (since round 4). The location says that something was not found, but
   the layer it searched was not covered, or the confidence is below `ABSENCE_MIN_CONFIDENCE`.
2. **The location's sub-signal has demonstrably low first-sight precision** (round 7, this document). The engine
   already knows the signal type at emit time, and that type was wrong more often than right on repos nobody had
   tuned on.

Review items are listed in their own report section, with the reason on each location. They are not scored: the
score is computed from `result.findings` only (`src/audit/index.js` → `summarize(findings)`).

Code: `src/audit/legal/calibrate.js` (thresholds, routing). Data: `src/audit/legal/rule-precision.js`, generated by
`scripts/gen-rule-precision.js` from `docs/validation/rule-precision-r9.json` (704 first-sight labels, 36 repos, rounds
n and r4 to r7) and its supplement `rule-precision-r7.extra.json` (repos per FP, live counts), which
`scripts/measure-rule-precision.js` measures from the label files (not published) (it reads them only and never writes them).

## Contract C-R7

These are plain fields on a location. A check needs nothing from calibrate.js to set them; `checks/_util.js` offers
`setSub(loc, key, {elements, strong})` and the matching `loc({..., sub, elements, strongEvidence})` parameters.

| field | set by | meaning |
| --- | --- | --- |
| `loc.sub` | check | `'RULE:key'`. RULE is the rule id without `AUD-`, e.g. `DEL-02:fk-no-cascade`, `SEC-SECRET:db-url-password`. Use the keys in `rule-precision.js` `SUBS` (the same as `rules[*].sub` in the measurement JSON). A new key is allowed; it is reported as `unmeasured` until a later round measures it. |
| `loc.elements` | check | `string[]`, the data element names (`el.name`) the location rests on, where applicable |
| `loc.strongEvidence` | check | optional `{code, tr, en}`. Set only when the location has a positive property that the measured FPs of its sub-signal lacked. Each check owner documents its codes in the header of their own file. |
| `loc.calibration` | calibrate | `{sub, status, tp, fp, unc, n, precision, lower90, upper90, repos, modifiers[], strongEvidence?, rawConfidence?}` |
| `loc.reviewReason` | calibrate | `{tr, en}` on a demoted location. The text names the sub-signal (or modifier) and its measured rate, e.g. `ilk görüşte ölçülen isabet %33 (2 TP / 4 FP, 2 proje)`. |
| `runAudit().calibration` | index.js | number of locations per status, for the scored part and for review |

### Statuses

| status | when | effect |
| --- | --- | --- |
| `reliable` | n ≥ 5 and Wilson lower90 ≥ 0.60 | scored; confidence = (tp+1)/(n+2) |
| `measured` | n ≥ 5, not demoted, lower90 < 0.60 | scored; confidence = (tp+1)/(n+2) |
| `insufficient` | n < 5 and not caught by rule (a), or caught by (a)/(b) while all FP labels come from one repo | scored; confidence unchanged; counts recorded |
| `unmeasured` | the key is not in the data | review (round 9), unless strong evidence |
| `unkeyed` | no `loc.sub` | scored; unchanged |
| `demoted` | rule (a), rule (b), or a routing modifier | moved to review with the measured rate in `reviewReason` |
| `kept-strong-evidence` | (a)/(b) would demote, but `loc.strongEvidence` is set | scored; confidence unchanged |

Here n = tp + fp. UNCERTAIN labels are excluded from precision. Intervals are two-sided 90% Wilson intervals
(z = 1.645), computed in code from the counts. Rounded numbers are never copied from the JSON.

### Order

1. The absence/layer logic runs first, exactly as before. It uses the check's own confidence.
2. The calibration annotates every location. If it demotes a location that the absence logic already routed, the
   calibration reason is appended to the layer reason.
3. A finding whose locations are all demoted moves to review as a whole. A mixed finding is split, and each part's
   severity is recomputed as before.
4. `ctx.precisionCalibration === false` or `KVKK_NO_PRECISION_CALIBRATION=1` switches step 2 off. Use it only for
   A/B measurement.

## Thresholds and why

The named exports in calibrate.js are `DEMOTE_UPPER90_MAX = 0.60`, `DEMOTE_UPPER_MIN_N = 2`,
`DEMOTE_POINT_MIN_N = 5`, `DEMOTE_POINT_MAX = 0.70`, `DEMOTE_LOWER90_MAX = 0.60`, `CONFIDENCE_MIN_N = 5` and, new in
round 8, `DEMOTE_MIN_FP_REPOS = 2`.

**Why not "lower90 < 0.60" alone.** A clean 4 TP / 0 FP sub-signal (SEC-13 cookie flags) has a lower bound of 0.596.
Demoting by lower bound alone would move clean, rare signals to review because they are rare, not because there is any
evidence that they are wrong. The rule has to ask "is there evidence of low precision?", not "is there evidence of high
precision?".

**(a) Demote when n ≥ 2 and upper90 < 0.60**, and **(b) when n ≥ 5, precision < 0.70 and lower90 < 0.60**, both only
when the FP labels come from at least two repos. One repo usually has one cause (one schema, one auth helper) repeated
over many locations: nine FP labels from one repo are closer to one observation than to nine.

With the r7 data the rules catch 16 sub-signals:

| rule | sub-signal | TP/FP | FP repos |
| --- | --- | --- | --- |
| a | MIN-01:unused-schema-field | 0/7 | 6 |
| a | TRN-02:category-missing-inferred | 0/7 | 4 |
| a | SEC-03:idor-suspect | 2/8 | 3 |
| a | RET-01:record-name-or-inferred-only | 1/6 | 4 |
| a | SEC-04:inferred-category | 0/5 | 3 |
| a | MIN-01:unused-body-field | 1/4 | 3 |
| a | SEC-04:nonprod-file | 0/4 | 3 |
| a | SEC-01:policy-public-read, SEC-08:reset-oracle, MIN-01:unused-column | 0/2 each | 2 each |
| b | SEC-03:no-auth | 5/6 | 3 |
| b | SEC-08:not-found-message | 5/6 | 5 |
| b | TRN-02:category-missing | 10/7 | 3 |
| b | TRF-01:unknown-location-host | 6/4 | 3 |
| b | RET-01:bucket | 6/3 | 2 |
| b | SEC-08:raw-provider-error | 3/2 | 2 |

Fourteen sub-signals would be demoted by (a)/(b) alone and stay scored because all their FPs come from one repo:
DEL-02:fk-parent-not-deleted 0/9, DEL-02:fk-no-cascade 2/4, DEL-02:vendor-copy 3/2, DEL-02:vendor-sdk-ids 0/3,
SEC-03:unauth-bulk-mutation 0/4, TRN-03 and PRF-01:scraping-tool 0/4 each, SEC-11:non-secret-named-fallback 0/3,
SEC-SECRET:db-url-password 0/3, MIN-02:token-on-create 0/3, SEC-02:policy-any-authenticated 0/2,
SEC-SECRET:gcp-service-account 0/2, SEC-21:weak-password-policy 2/3 and SEC-09:oauth-tokens-unencrypted 4/2. They are
reported `insufficient` with their counts; the check's own confidence is kept. SEC-09:oauth-tokens-unencrypted is the case
the measurement warned about: it would have been demoted only because n reached 5 (its r7 labels are 2/0). The general
rule solves it; no key is special-cased.

### Leave-one-round-out

`node scripts/measure-rule-precision.js --quiet --loro`. For every round group the counts (sub-signals, rule rates and
routing modifiers) are fitted on all the other rounds and the held-out labels are routed by calibrate.js's own
`demotionRule` and `locationModifiers`. Three policies, chosen before the first run:

- (i) **current**: (a) and (b) as in round 7.
- (ii) **fp-repos-2**: (a) and (b) also need FP labels from at least two repos.
- (iii) **shrink-2**: counts shrunk towards the precision of the whole rule with a pseudo-count of 2.

| held out | before | (i) scored TP/FP | TP / FP demoted | (ii) scored TP/FP | TP / FP demoted | (iii) scored TP/FP | TP / FP demoted |
| --- | --- | --- | --- | --- | --- | --- | --- |
| n | 172/51 77.1% | 159/36 81.5% | 13 / 15 | 168/38 81.6% | 4 / 13 | 160/36 81.6% | 12 / 15 |
| r4 | 36/9 80.0% | 34/7 82.9% | 2 / 2 | 35/7 83.3% | 1 / 2 | 34/6 85.0% | 2 / 3 |
| r5 | 62/15 80.5% | 50/12 80.6% | 12 / 3 | 52/12 81.3% | 10 / 3 | 52/12 81.3% | 10 / 3 |
| r6 | 80/57 58.4% | 71/48 59.7% | 9 / 9 | 71/48 59.7% | 9 / 9 | 72/49 59.5% | 8 / 8 |
| **r7** | 153/32 82.7% | **142/22 86.6%** | 11 / 10 | **142/22 86.6%** | 11 / 10 | **145/24 85.8%** | 8 / 8 |
| all | 503/164 75.4% | 456/125 78.5% | 47 / 39 | **468/127 78.7%** | **35 / 37** | 463/127 78.5% | 40 / 37 |

(ii) is adopted: it is not worse than (i) on precision in any fold and demotes 12 fewer TPs (35 vs 47) for 2 more FPs
left scored. What (i) demotes on one repo's evidence was real 12 times out of 14 when another round met the same signal.
(iii) demotes fewer TPs than (i) as well, but is worse than (i) on precision in r6 and r7, so it fails the adoption rule.

**Caveats, read before quoting the table.**

- **Only the r7 row is truly out of sample.** r7 was labelled by an engine nobody had tuned on those repos, and its fold
  is fitted on earlier rounds only. The n, r4, r5 and r6 folds contain later rounds in their training data, and the labels
  of one round shaped the checks that the next round measured. On r7, (i) and (ii) are identical: every r7-relevant
  demotion already had FPs in two repos. The case for (ii) rests on the other folds.
- The gain is small everywhere: calibration lifts a held-out round by 1 to 5 points, not by the 18 points of the
  round-7 in-sample simulation. Most first-sight FPs of a new round come from sub-signals that nobody had measured yet.
- `strongEvidence` is not recorded on labels, so the table ignores it.
- The held-out counts use the label-text mapping of the measurement script, not the engine's `loc.sub`.

**(c) Routing modifiers** apply to a location of any rule:

| modifier | TP/FP/UNC | condition |
| --- | --- | --- |
| `element:name-inferred-only` | 0/19/1 | `loc.elements` is non-empty and every entry is in the name-inferred set (legal_record, body_metrics, income, preferences_profile, employment, order_history, activity_timestamp) |
| `path:nonprod-file` | 1/6/0 | `loc.file` matches `NONPROD_PATH_RE`. The regex is copied into the data file from `checks/security.js` at generation time, so calibrate.js does not import a check file. |

`strongEvidence` does **not** override a modifier. The two modifiers together have 1 TP in 26 labels, and a
property of a location cannot make data that comes from a seed file, or a category guessed from a field name,
any more real.

One deviation from a plain "any rule": `PATH_MODIFIER_EXEMPT_RULES` = {AUD-SEC-SECRET, AUD-SEC-15}. For a committed
credential or a committed database file, the artefact itself is the harm, wherever it sits in the tree. The
modifier was measured only on data-flow conclusions (log, retention and transfer locations). No committed-artefact
label fell in a non-production path, so the measurement says nothing about them. Demoted sub-signals of those rules
still demote through (a) and (b).

The TRN-02 notice-anchor split (policy path 13/9 = 59% vs other path 5/6 = 45%) does **not** separate TP from FP.
It is kept in the data with `routes: false` and never routes.

**(d) n < 5 and not caught by (a), or caught while all FPs come from one repo: `insufficient`.** The location stays scored
with the counts recorded and the check's own confidence.

**(e) An unknown key: `unmeasured`, to review (round 9). No key at all: `unkeyed`, as before.**

**(f) Confidence.** For measured sub-signals with n ≥ 5, `loc.confidence` becomes the Laplace-smoothed precision
(tp+1)/(n+2), and the check's value is kept in `calibration.rawConfidence`. Every `reliable` or `measured` signal has
p ≥ 0.70, so its smoothed confidence is ≥ 0.64 and the report's low-confidence marker (< 0.60) is not set by
calibration alone.

**(g) Strong evidence** overrides (a) and (b): the status is `kept-strong-evidence` and the location stays scored.
The measured rate describes the locations that lacked the property, so the confidence is left as the check set it.

None of these thresholds was tuned to make bench numbers look good. The round-7 values were chosen before any bench run;
the round-8 addition was picked from three policies fixed beforehand, by the leave-one-round-out table.

## Review list (round 8)

The review list of round 7 was 14 real / 15 noise on the unseen repos, in no useful order. Every review location now has:

- `reviewRate`: the smoothed first-sight rate (tp+1)/(n+2) of the routing modifier that moved it, else of its sub-signal,
  else of its whole rule, else the average of this list; `reviewRateBasis` {basis, tp, n} says which. The renderers print
  it as "on first sight about x of y were real".
- `reviewBand`: `likely` (rate ≥ 0.70), `noise` (rate < 1/3) or `uncertain`. The renderers group by band. Nothing is
  hidden: every band is printed.

Entries and locations are sorted by severity tier, then `reviewRate`, then confidence. `live` (labels the current engine
still hits on the bench, exported by the measurement script) breaks ties between equal rates. It is in-sample: it never
affects a status, a rate or a band.

| review locations with a verdict | likely real/noise | uncertain | mostly noise |
| --- | --- | --- | --- |
| r7 list of round 7, rates fitted **before** r7 (out of sample) | 5 / 1 | 5 / 4 | 4 / 10 |
| round-8 list, all 48 stacks (in sample) | 5 / 2 | 30 / 6 | 9 / 20 |

The bands sort the list, they do not decide it: 4 of 14 items in the out-of-sample noise band were real.

Other rules of the list (`organizeReview`): a location that repeats a scored location of the same rule (same file, sub,
elements, entity and label, at most 3 lines apart) is dropped; repeats of one statement in one file (same sub, elements,
entity and label) become one location with `count`, `merged` and `steps`; an item with no file, no layer gap and no data
element moves to `reviewSummary.suppressed[]` with the reason and stays countable. When a notice file exists but could not
be read, the list says "notice found, not parsed" and a `TRN-01:no-notice` conclusion does not stay scored.

## Honest expectation (round 7, r6 data)

The in-sample simulation (`node scripts/measure-rule-precision.js --simulate`) applies the routing above to the
same 517 first-sight labels it was measured on:

| | TP | FP | UNC | precision |
| --- | --- | --- | --- | --- |
| before | 353 | 133 | 31 | 72.6% |
| scored after routing | 308 | 32 | 18 | **90.6%** |
| moved to review | 45 | 101 | 13 | 30.8% |

- **This is in-sample by construction.** The rule was derived from these labels, so the jump from 72.6% to about
  90% is not evidence that it transfers. The real test is the round-7 unseen field run.
- **Cost:** 45 of 353 first-sight TPs (12.7%) move to review. They are still reported, with the reason, but they no
  longer count in the score.
- **Projection on the whole bench (36 repos).** Missing `loc.sub` was filled from the label-text mapping of the
  measurement script. This was done in a scratch harness only; product code never does it. Under that assumption:
  791 TP / 69 FP (92.0%) became 701 TP / 23 FP (96.8%), with tpLost and open misses unchanged. Tuned repos lose
  more TPs per FP removed than first-sight repos, because their FPs were already fixed.

## Regenerating

```sh
node scripts/measure-rule-precision.js --out docs/validation/rule-precision-r9.json --loro       # reads the label files only
node scripts/measure-rule-precision.js --quiet --extra-out docs/validation/rule-precision-r9.extra.json --live <bench report>
node scripts/gen-rule-precision.js --in docs/validation/rule-precision-r9.json                  # writes src/audit/legal/rule-precision.js
node scripts/gen-rule-precision.js --in docs/validation/rule-precision-r9.json --check          # CI: data file in sync
```

Without `--in` the generator reads `rule-precision-r7.json`. Measurement files from round 8 on carry `fpRepos` per
sub-signal themselves; the `.extra.json` supplement supplies it for r7 and carries the live counts. The generator refuses
a supplement that was measured on a different number of labels. The non-production path regex is copied from the
`NONPROD_PATH_RE` constant wherever it lives under `src/audit/legal`, so `--check` only fails when the regex itself
changes; regenerate then.

To add a later round's unseen repos, extend `FIRST_SIGHT_PREFIX` in the measurement script once their first-sight
labels exist. Gate-round labels (made on tuned code), label-audit re-judgements, evidence-step labels and the `h-*` repos
(judged after tuning) stay excluded. When a check rewords a label, extend the label-to-key `MAP` in the measurement
script. The keys themselves must stay stable.
