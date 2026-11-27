# Audit-engine benchmark

> **The label set is not published.** It names real projects and says, file by file, what is wrong with them. `bench/data.js` reads it from
> `private/bench` (ignored by git and npm) or from the directory in `KVKK_BENCH_DATA`. To measure on your own projects create
> `repos.json` (`[{"stack", "url", "commit"}]`) and `labels/<stack>.json` there, in the format below. Paths written as
> `bench/labels`, `bench/repos.json` and `bench/results` in this document mean that directory.

A fixed, labeled set of real repositories (36 as of round 6, listed in `repos.json`) for measuring the deep audit engine (`src/audit`) in
seconds instead of re-running hundreds of judge agents. It answers three questions after every engine
change:

1. **Precision**: of the finding locations that have a verdict, how many are true positives?
2. **Drift**: which new locations appeared (no label yet) and which labeled ones disappeared?
3. **Recall on known misses**: which confirmed false negatives does the engine now catch?

```sh
npm run bench                                 # all repos, table + bench/results/<timestamp>.json + latest.json
node bench/run.js --repo n-express-pg         # one repo (repeatable / comma list)
node bench/run.js --json                      # the full JSON report on stdout
node bench/run.js --min-precision 90          # exit 1 if total precision < 90% (0.9 also accepted)
node bench/run.js --from "/path/{stack}.v4.json"  # score saved JSON reports instead of running the engine
node bench/run.js --compare bench/results/baseline-r6.json   # regressions vs a baseline (new FP, lost TP, re-opened misses, newly demoted)
node bench/run.js --by-sub /tmp/bysub.json    # also write the per-sub-signal tallies to a file
```

Table columns: `sPrec` scored precision, `rev` review locations, `tpDem`/`fpDem` TP/FP labels found only in
review, `recall` (findings or review) and `sRecal` (findings only). See [Metrics](#metrics).

Exit codes: 0 ok, 1 below `--min-precision`, 2 a repo failed (checkout or engine error; see `error` in the row).

## Files

| path | what |
| --- | --- |
| `repos.json` | `[{stack, url, commit}]`: every repo pinned to an exact commit |
| `labels/<stack>.json` | `{findings: [...], misses: [...]}`: verdicts and confirmed misses |
| `lib.js` | pure matcher and scorer (unit-tested in `test/bench.test.js`) |
| `run.js` | checkout, in-process `audit()`, scoring, report |
| `results/` | one JSON per run plus `latest.json` |

## Checkouts

Repo code is never installed or executed; only git plumbing runs. For each repo, `run.js` uses the first of:

1. `--use-dir <stack>=<dir>`
2. `$KVKK_BENCH_SRC/<stack>` (for example the field clones the labels were made from)
3. the cache `$KVKK_BENCH_DIR/<stack>` (default `<os tmpdir>/kvkk-bench`)

Options 1 and 2 are used only when the directory holds exactly the pinned commit's files. Files are
compared by git blob hash, ignoring line-ending conversion, and untracked files that are not ignored make
the directory unusable. The cache is filled with a shallow fetch of the exact commit (`git fetch --depth 1
<url> <sha>` into a bare repo). The tree is then written straight from the object store, with no checkout and
no hooks. Paths this OS cannot hold, such as `x.png:Zone.Identifier` on Windows, are skipped and reported.
`--no-fetch` forbids network access.

## Labels

```jsonc
{
  "findings": [
    { "ruleId": "AUD-SEC-04", "file": "src/utils/jwt.ts", "line": 38, "label": "Ad soyad → log · logger",
      "verdict": "TP", "reason": "…" },
    // a verdict on an evidence step inside a location (the step is what was right or wrong):
    { "ruleId": "AUD-DSR-02", "file": "utils/auth-helpers/server.ts", "line": 313, "label": "…",
      "step": { "file": "utils/auth-helpers/client.ts", "line": 38 }, "verdict": "FP", "reason": "…" }
  ],
  "misses": [
    { "id": "n-remix-prisma#1", "title": "Undisclosed transfer … to Resend (US)", "severity": "high",
      "expect": { "rules": ["AUD-TRF-01"], "keywords": ["resend"] }, "evidence": "…" }
  ]
}
```

`file`, `line` and `label` are copied from the tool's JSON report (`kvkk-check audit -f json`, Turkish
labels). Absence findings have `file: null, line: null`.

Verdicts: `TP` is correct, `FP` is wrong, `UNCERTAIN` means the judges could not settle it. The
initial labels come from round 3 of the field validation (workflow `wf_db468653-48f`). A judge gave each
location a verdict, and a skeptic agent re-checked every FP verdict. An FP whose challenge was not upheld
counts as TP, which is the same rule round 3 used. Each miss is a judge-claimed false negative that a
skeptic confirmed independently.

### Miss expectations

A miss is **fixed** when some location in the run (any severity, scored findings or `result.review[]`
locations, including blind-coverage review items with `file: null`) satisfies `expect`:

| field | meaning |
| --- | --- |
| `rules` | allowed rule ids; empty or absent means any rule (use this when no rule exists yet) |
| `file` | path or list of paths; the location's file **or one of its evidence steps** must match (set `stepFiles: false` to require the location itself) |
| `keywords` | every entry must appear in label + snippet (lowercase, Turkish diacritics folded); `"a\|b"` means a or b |
| `graph` | `{type?, file?, keywords?}` matched against graph nodes instead (e.g. a missing `DataElement` or `Store`) |
| `model` | `{section, keywords}` matched against items of the report model (e.g. `inventory`) |
| `anyOf` / `allOf` | combinations |

Write expectations that **a fixed engine satisfies and the unfixed one does not**. Validate every new or
edited expectation against the output the miss was found in:

```sh
node bench/run.js --from "/path/field/{stack}.v4.json"   # every miss must be open (0/N fixed)
```

Prefer stable anchors (vendor names, function or route names, file paths) over Turkish wording, since
labels get reworded. Keep `rules` broad when the fix could reasonably land under another rule id.

## Scoring

Each tool location is matched one-to-one against the `findings` labels:

1. **Position**: same `ruleId`, same file (suffix match allowed), `|line diff| ≤ 3`. When several labels
   qualify, the closest line wins, then the most similar label text. Labels without a file match
   locations without a file of the same rule when the label token similarity is ≥ 0.3. Digits are ignored,
   so "7 veri unsuru" still matches "8 veri unsuru".
2. **Fallback**: same `ruleId` and label similarity ≥ 0.7, for locations and labels left over. This covers a
   finding that moved but kept its meaning (`matchedBySimilarity` counts these).
3. **Step labels** count only while their parent location still carries that evidence step.

### Scored findings and the review list

The engine has two outputs: scored `findings` and `review[]` ("needs verification", not scored). The
calibration layer moves locations of measurably low-precision sub-signals into review. Each such location
keeps its `file/line/ruleId`, gains a `reviewReason`, and carries `sub` (`'RULE:key'`) and
`calibration {sub, status, precision, n, …}`. Blind-coverage review items have `file: null`.

Matching runs in two passes with the same matcher:

1. **Scored first**: scored locations against all labels, exactly as described above. Scored numbers are
   therefore identical to scoring the findings alone.
2. **Review**: review locations against the labels that pass 1 left over, main and step labels alike.

Each label counts once: in findings, else in review, else lost or gone. When both lists could match a label,
the scored finding gets it and the review location stays unlabeled.

`sub` and `calibration` are read from the location, from the JSON report when it carries them, otherwise from
the raw engine location with the same rule, file, line and label. Engines without calibration score
unchanged.

### Metrics

Per repo (`repos[]`) and in total (`totals`):

| metric | definition |
| --- | --- |
| `tp`, `fp`, `uncertain` | labels matched by a **scored** location, by verdict |
| `precision` (table: `sPrec`) | scored precision `tp / (tp + fp)`. Review and unlabeled locations are excluded |
| `reviewLocations` (`rev`) | number of review locations |
| `tpDemoted` (`tpDem`) | TP labels matched **only** by a review location. Not lost, but no longer scored: a recall cost to the score |
| `fpDemoted` (`fpDem`) | FP labels matched only by a review location. A good outcome: the FP left the score but stays visible |
| `uncDemoted` | UNCERTAIN labels matched only in review |
| `reviewUnlabeled` | review locations without a label (judge them like `unlabeled`) |
| `reviewByStatus` | review locations by `calibration.status` (`uncalibrated` = no calibration metadata, e.g. blind-coverage items) |
| `reviewBySub` | per `loc.sub`: `{n, tp, fp, unc, unlabeled}` of the review locations |
| `tpLabels` | all TP labels of the repo (main and step) |
| `recall` | `(tp + tpDemoted) / tpLabels`: TP labels present in findings **or** review |
| `recallScored` (`sRecal`) | `tp / tpLabels`: TP labels present in the scored findings |
| `precisionWithReview` (totals) | `(tp + tpDemoted) / (tp + fp + tpDemoted + fpDemoted)`: precision if review were scored |
| `unlabeled` | scored locations with no label, each with `{ruleId, file, line, label, severity}`. **The work queue**: judge each one and add a label. Not counted in precision until then |
| `tpLost` | TP labels matched by **neither** list (a recall regression, or a reworded label that moved more than 3 lines) |
| `fpGone` | FP labels matched by neither list (the intended effect of a precision fix) |
| `missesFixed` / `missesOpen` | misses whose expectation is or is not satisfied. **Open means absent from findings AND review** (graph/model expectations count too). Each fixed miss has `via`: `scored`, `review` (only with the review list) or `graph` |
| `missesFixedViaRegister` | fixed misses visible only as a row of a report register (inventory, transfers, deletion matrix), with no finding or review item |
| `missesInternal` | open misses whose fact exists only in the internal graph: the reader sees nothing, so they count as open (round 9) |
| `missesFixedViaReview`, `missesHighOpen` | fixed misses whose `via` is `review`; open misses of severity high |

Recall here is **label recall**: the share of locations that judges once confirmed as TP that the engine
still produces. True false negatives are the misses. Scored precision and both recalls appear side by side,
so pushing everything to review raises `sPrec` but visibly lowers `sRecal`. A precision change only means
something together with `unlabeled`, `tpLost` and `tpDemoted`. An engine that emits nothing has no FPs.

### Per-sub-signal tallies (`bySub`)

`bySub` in the result JSON (and the file written by `--by-sub <file>`) contains:

- `all`: tallies over every repo and label round.
- `firstSight`: labels on `n-*` / `r<k>-*` stacks, finding-level only (no step labels), rounds without `gate`
  (label-audit re-judgements are included). This is the same definition as
  `docs/validation/rule-precision-r6.json`. Unlabeled locations count here only on those stacks.

Each key is the engine's own `loc.sub`. A location without one is keyed `<RULE>:(none)`. Each tally is
`{tp, fp, unc, unlabeled, precision, lower90, repos, scored:{…}, review:{…}, status:{…}}`:

- `tp/fp/unc` pool scored and review: the sub-signal's precision wherever it was routed.
- `lower90` is the Wilson 90% lower bound.
- `status` counts `calibration.status`, falling back to `scored`/`review`.

`notEmitted.{all,firstSight}` counts, per rule, labels that no location matched. Emitted plus not-emitted
reconciles with label-based measurements. The next precision measurement can be read straight from these
engine-emitted keys.

### Comparing with a baseline

`--compare <old report>` adds `comparison` to the result JSON and prints a section after the table:

- Totals before→after, recomputed over the repos both reports contain, so a `--repo` subset compares like with like.
- New FP keys (`fpHits`), newly lost TPs, re-opened misses (fixed before, open now).
- **TP newly demoted** and **FP newly demoted** to review.
- Coverage flips and repos missing from either report.

Keys are exact `[ruleId, file, line, id]`. A metric that an older report (r4–r6 baselines) does not carry
prints `n/a` and never crashes. Against such a baseline every demotion counts as new.

## Adding a repo

1. Clone it, then add `{stack, url, commit}` to `repos.json` using `git rev-parse HEAD`.
2. Run `node bin/cli.js audit <dir> -f json -o <stack>.json --fail-on none` and judge every location.
3. Write `labels/<stack>.json`. Copy `ruleId/file/line/label` from the JSON report, then add `verdict` and a
   short `reason`. Add confirmed misses with expectations, and check that they are open with `--from`.
4. Run `node bench/run.js --repo <stack>`. It should report 0 unlabeled, 0 tpLost and all misses open
   against the version you labeled.

## Updating labels

- For a new `unlabeled` location, judge it and append a `findings` entry.
- For a `tpLost` that is really a reworded or moved finding, update `file/line/label` on the label.
- When a rule is genuinely split or renamed, update `ruleId` (and `rules` in affected expectations).

**Secrets**: some pinned repos contain real committed credentials. Never copy a credential value into a
label, reason, expectation or result. Write `<prefix>_[REDACTED]` instead. `lib.js` redacts
credential-looking values in labels and snippets before writing results, and `test/bench.test.js` fails if
a label file contains one.

## Real-project set (`bench/real.js`)

A second, separate set: the author's live projects, every critical / high / medium location (and some lower ones) judged by
reading the code, for the quick scan, the deep audit and the live scan, not only the audit. Not published: it is read
from `private/bench/real` or `KVKK_REAL_DATA` (`repos.json` with a local `dir` per project, `labels/<stack>.json` in the
format above plus `source` quick|audit|live, `list` scored|review, `tool` (version judged), `basis` location|class).

```sh
npm run bench:real                 # quick scan + deep audit of every project, per-source totals, per-rule table
node bench/real.js --live          # also the live scans (network)
node bench/real.js --no-class      # leave out labels decided for a class of locations instead of one by one
node bench/real.js --out r.json    # the full report (per rule and per sub-signal) as JSON
```

Per source it counts the labels the tool still shows (scored, review), the ones it no longer produces (gone) and the
critical / high / medium locations nobody judged (unlabeled). Live locations (a URL, no line) are matched by text as well.
Once the tool is tuned on these projects their numbers describe the tuning, not unseen code: the success measure is a
project outside both sets.
