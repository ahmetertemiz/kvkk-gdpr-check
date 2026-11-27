# kvkk-gdpr-check

**A command-line tool that scans your software project for KVKK (Turkey) and GDPR privacy risks and shows every finding with file and line.**

> ⚠️ **Many findings may be false alarms; verify every one in the code yourself.** On a real project never seen while the tool was built, 0.1.2 was right on only 8% of the critical, high and medium locations. 0.2 was corrected by looking at three real projects; its result on an unseen project has not been measured yet (see Accuracy below). The most reliable part of a report is the **Inventory**: the personal data the code holds, trackers and the third parties that receive data, and on a live site its cookies.

[Türkçe](README.md) · [Accuracy (Turkish)](docs/ACCURACY.md) · [Example report](examples/reports/audit-app.md)

> ⚖️ Not legal advice. No findings does not mean no problems. Generated documents are drafts; do not publish them before a lawyer has reviewed them.

```bash
npx kvkk-gdpr-check --lang en                                 # quick scan
npx kvkk-gdpr-check audit --lang en -f html -o audit.html     # deep audit
npx kvkk-gdpr-check url https://example.com --lang en         # live site
npx kvkk-gdpr-check docs --lang en                            # document drafts (beta)
```

Requires Node.js 20+. Scanning makes no network request and does not run your code.

- **Deep audit:** follows personal data from form to API, database, log and third party; data inventory, processing activities, transfer register, erasure coverage.
- **Questionnaire (`anket`):** asks what the code cannot tell. Answers never change a finding or the score.
- **Document drafts (beta):** privacy notice, cookie policy, inventory, breach plan, DPIA / LIA / TIA and more. Every draft starts with a warning; open fields are marked `[TO FILL IN: …]` / `[TO VERIFY: …]` and listed at the end. Accuracy on real projects has not been measured.

| Level | Stacks |
|---|---|
| **Supported** | Next.js, React, Expo / React Native, SvelteKit |
| **Limited** | Express, Remix / React Router, Django, Flutter |
| **Experimental** | Laravel, NestJS, Flask, FastAPI, Nuxt, Astro and others |

On a limited, experimental or unrecognised stack the report says so at the top.

**The output is the list of findings with evidence, not the score.** A score is only given on a supported stack when most of the seven analysis layers were seen (28 of the 84 projects of the benchmark); otherwise the report says `N/A (score not reliable)` and why.

**Reading a report.** Every report has two parts:
- **Inventory:** facts, no verdicts.
  - Personal data in the code and the database schema, trackers, recipients.
  - In the deep audit also processing activities, the transfer register and services named in the code with no traced data flow.
- **To check:** findings with a verdict, each with a "Precision:" line from the real-project set and the 84-project set, given separately. Below 5 labels the line gives counts only.

Locations that measured mostly wrong go to "Needs verification (not scored)": not scored and not seen by `--fail-on` unless `--fail-on-review`.

Critical / high is shown only when a measurement supports it; every other location shows at most medium, with the original level in `severityRaw`. Support means one of:
- at least 8 real-project labels with a 90% lower bound of 50% or more;
- in the deep audit, a sub-signal measured reliable on the 84-project set;
- a real-looking key.

**Accuracy.** There are three measurements; they cannot be compared directly.

*Real projects (tuning set).* Every location on three real applications was checked against the code by AI; no lawyer verified any judgement. 0.2's fixes were written by looking at these projects, so the 0.2.0 column describes the tuning, not unseen code.

| | 0.1.3 | 0.2.0 |
|---|---|---|
| Quick scan, scored locations | 24 / 53 (45%) | 24 / 33 (73%) |
| Quick scan, critical + high + medium | 21 / 47 (45%) | 18 / 24 (75%) |
| Deep audit, scored locations | 32 / 71 (45%) | 32 / 55 (58%) |
| Deep audit, critical + high + medium | 7 / 38 (18%) | 7 / 20 (35%) |

- No right location was lost. The 3 that left the quick scan's critical/high/medium row are TRK001, now an inventory fact at level info.
- The independent figures are those before any fix written from a project: 13%, 26% and 8% with 0.1.x. The 8% is the third project, never seen while the tool was built.

*An unseen fourth project.* Not measured yet. Before 0.2.0 is released, the tool will be measured on a real project never seen during development and the result will be written here:
- the precision of the critical, high and medium locations to check;
- the precision of the review list;
- the precision and the completeness of the inventory;
- how many of the real issues found by reading the code appear anywhere in the report.

<!-- to be filled in before 0.2.0 is released; no figures until measured -->

*The 84-project measurement set (deep audit only).* In rounds 8–10 (12 projects each), 80%, 84% and 79% of the scored findings were right (round 9 is about 75% after blind correction). About 8 real issues were missed per project, 2–3 of them high severity, mostly access control. That set:
- covers the deep audit's scored findings only;
- was judged by AI agents of one model family;
- is a set the tool was then tuned on.

**Legal bases:** what was read in a primary source and what could not be verified is listed in [docs/hukuki-dayanaklar.md](docs/hukuki-dayanaklar.md) (Turkish). Findings resting on something unverified say "unverified basis".

MIT License
