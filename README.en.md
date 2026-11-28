# kvkk-gdpr-check

**A command-line tool that scans your software project for KVKK (Turkey) and GDPR privacy risks and shows every finding with file and line.**

> ⚠️ **More than half of the findings may be false alarms; verify every one in the code yourself.** On six real projects never seen while the tool was built (measured with 0.2.0), 71 of 164 critical, high and medium locations were real issues (about 43%, Wilson 90% interval 37–50%). Per project the rate ranged from 13% to 57% (see Accuracy below).
>
> **It does not replace a security review.** Only about half of the issues found by reading the code appeared in the report: 53% on the first four projects, 51% on the next two. Most high-severity issues did not appear as findings. The type missed most often is access control.
>
> What the **Inventory** lists is mostly right (84% on the first four projects, 67% on the next two), but the list is not complete: on the last two projects the deep audit listed only 38% of the personal-data items found by reading the code.

[Türkçe](README.md) · [Accuracy (Turkish)](docs/ACCURACY.md) · [Example report](examples/reports/audit-app.md)

> ⚖️ Not legal advice. No findings does not mean no problems. Generated documents are drafts; do not publish them before a lawyer has reviewed them.

**Status.** Rule-based precision stayed between 13% and 57% per project across the six unseen projects; the changes in 0.2.1 did not raise it. Do not use the tool to reach a verdict on its own. Use it to show a person or an agent reading the code where to look; for agents, the [manual verification skill](skill/kvkk-gdpr-audit/SKILL.md) checks the tool's list in the code one by one.

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
  - What is listed is mostly right (84% on the first four unseen projects, 67% on the next two with 0.2.1), but the list is not complete. On the last two projects the deep audit listed 38% and the quick scan 26% of the personal-data items found by reading the code; the deep audit listed 85% of the third parties receiving data.
- **To check:** findings with a verdict, each with a "Precision:" line from the real-project set and the 84-project set, given separately. Below 5 labels the line gives counts only.

Locations that measured mostly wrong go to "Needs verification (not scored)": not scored and not seen by `--fail-on` unless `--fail-on-review`. **Do not skip this list:** on the last two unseen projects 39% of its items were real issues, more than among the scored critical, high and medium locations (27%). Read both lists with the same care; some real issues appear only there.

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

*Six unseen projects.* Measured blind: first four with 0.2.0, then two more to test 0.2.1, with both 0.2.0 and 0.2.1. The first four projects' labels went into 0.2.1's tuning, so 0.2.1 on unseen code can only be measured on the last two.

| To check, critical + high + medium: real issue | Quick scan | Deep audit | Both |
|---|---|---|---|
| First four projects, 0.2.0 | 18 / 42 (43%) | 41 / 76 (54%) | 59 / 118 (50%; 43–57%) |
| Last two projects, 0.2.0 | 4 / 16 (25%) | 8 / 30 (27%) | 12 / 46 (26%; 17–38%) |
| **Six projects, 0.2.0** | 22 / 58 (38%) | 49 / 106 (46%) | **71 / 164 (43%; Wilson 90%: 37–50%)** |
| Last two projects, 0.2.1 | 4 / 16 (25%) | 8 / 29 (28%) | 12 / 45 (27%; 17–39%) |

- **Per project (0.2.0):** 13%, 29%, 29%, 50%, 55% and 57%. The lowest is a project with only 8 locations.
- **0.2.1's targets and results** (last two projects):
  - *Precision on critical, high and medium locations not below 50%:* **missed**, 27%. 0.2.0 gives 26% on the same projects, so the gap comes from the projects, not the version.
  - *Completeness of third parties receiving data (deep audit) clearly above 56%:* **met**, 22 / 26 (85%); 0.2.0 gives 73% on the same projects.
  - *Share of code-reading issues shown in the report not below 53%:* **narrowly missed**, 35 / 68 (51%); 0.2.0 gives the same 35 / 68.
- **0.2.1's costs** (same two projects, against 0.2.0):
  - The deep audit's inventory precision fell from 72% to 67%; part of the new third-party rows are wrong.
  - Six retention issues moved from findings to the inventory or the review list, one of them high severity: "tables with no automatic cleanup" are now an inventory fact, not a verdict. The number of issues shown somewhere in the report did not change.
- **Review list:** on the last two projects 31 / 79 (39%) of its items were real issues, more than the scored critical, high and medium locations (27%); on all six with 0.2.0, 89 / 240 (37%). Read both lists with the same care.
- **Inventory (last two projects, 0.2.1):** 67% of what is listed is right. The list is not complete: the deep audit listed 38% and the quick scan 26% of the personal-data items.

*First four unseen projects* (open-source Next.js / Prisma / tRPC monorepos, one with Drizzle / SQLite).
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
