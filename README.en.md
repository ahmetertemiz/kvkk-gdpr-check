# kvkk-gdpr-check

**A command-line tool that scans your software project for KVKK (Turkey) and GDPR privacy risks and shows every finding with file and line.**

> ⚠️ **Half of the findings may be false alarms; verify every one in the code yourself.** On four real projects never seen while the tool was built, 59 of 118 critical, high and medium locations were real issues (50%, Wilson 90% interval 43–57%; see Accuracy below).
>
> **It does not replace a security review.** Only 53% of the issues found by reading the code appeared in the report, and only 2 of 10 high-severity ones. The type missed most often is access control.
>
> What the **Inventory** lists is mostly right (84%), but the list is not complete: a quarter to two fifths of the personal-data items and a half to three quarters of the third parties receiving data can be missing.

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
  - What is listed is mostly right (84% on the four unseen projects), but the list is not complete. The quick scan and the deep audit listed 59% and 73% of the personal-data items, and 24% and 56% of the third parties receiving data.
- **To check:** findings with a verdict, each with a "Precision:" line from the real-project set and the 84-project set, given separately. Below 5 labels the line gives counts only.

Locations that measured mostly wrong go to "Needs verification (not scored)": not scored and not seen by `--fail-on` unless `--fail-on-review`. **Do not skip this list:** on the four unseen projects 36% of its items were real issues, and some real issues appear only there.

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

*Four unseen projects* (open-source Next.js / Prisma / tRPC monorepos, one with Drizzle / SQLite).
- **How:** Measured blind with 0.2.0.
  - Every location was read in the code before looking at the tool's label.
  - A separate review that never saw the report read each code base end to end and listed the real issues and the personal data.
- **Two verdicts per location:** "real issue" and "claim factually right".

| Four projects | Quick scan | Deep audit | Both |
|---|---|---|---|
| To check, critical + high + medium: real issue | 18 / 42 (43%) | 41 / 76 (54%) | **59 / 118 (50%; Wilson 90%: 43–57%)** |
| … same, claim factually right | 33 / 45 (73%) | 53 / 78 (68%) | 86 / 123 (70%) |
| Review list: real issue | empty | 57 / 160 (36%) | |
| Inventory precision | 63 / 75 (84%) | 86 / 102 (84%) | |
| Inventory completeness: personal-data items | 35 / 59 (59%) | 43 / 59 (73%) | |
| Inventory completeness: third parties receiving data | 17 / 71 (24%) | 40 / 71 (56%) | |
| Of 139 real issues found by reading the code, shown in the report | | | 73 (53%; 46–59%) |

- **Per project:** 29%, 50%, 55% and 57% of the critical, high and medium locations were real issues. The lowest is on the stack the tool itself rates "experimental", where admin-only procedures were read as unauthenticated.
- **Two criteria side by side:** the claim is factually right in 70% of the critical, high and medium locations, and a real issue in 50%. Most of the gap comes from "no retention period" findings on tables kept for the account's lifetime, and from tables that hold no personal data.
- **Recall:** 73 of 139 issues (53%) appear somewhere in the report. Of the high/medium ones it is 33 of 57, and **of the 10 high-severity issues only 2**.
  - The type missed most often is access control: cross-team access (IDOR), unauthenticated endpoints, role escalation.
  - Next come security configuration, mismatches between the privacy notice and the code, deletion completeness, and undisclosed third-party flows.
- **Fixed after the measurement:** On one of the projects the quick scan's only remaining high location was wrong. A local address (`http://localhost:3000`) was taken for a secret. That project was measured before the fix, and the fix changes that location's level only. The other three were measured with the fixed 0.2.0.

*The 84-project measurement set (deep audit only).* In rounds 8–10 (12 projects each), 80%, 84% and 79% of the scored findings were right (round 9 is about 75% after blind correction). About 8 real issues were missed per project, 2–3 of them high severity, mostly access control. That set:
- covers the deep audit's scored findings only;
- was judged by AI agents of one model family;
- is a set the tool was then tuned on.

**Legal bases:** what was read in a primary source and what could not be verified is listed in [docs/hukuki-dayanaklar.md](docs/hukuki-dayanaklar.md) (Turkish). Findings resting on something unverified say "unverified basis".

MIT License
