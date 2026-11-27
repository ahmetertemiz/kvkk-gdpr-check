# kvkk-gdpr-check

**A command-line tool that scans your software project for KVKK (Turkey) and GDPR privacy risks and shows every finding with file and line.**

> ⚠️ **In the current version most findings may be false alarms.** On three real projects only 8–26% of the critical, high and medium locations were right (see Accuracy below). Verify every finding in the code yourself. The more reliable parts are the third-party and data-flow inventory (which service receives personal data) and the cookie scan of a live site.

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

**Accuracy.** On three real projects, before any fix written from that project, **8%, 13% and 26% of the critical, high and medium locations were right**:
- **Third project:** 3 of 39 right. It was never seen while the tool was built; measured with 0.1.2.
- **First and second projects:** 15 of 113 and 6 of 23 right. In the first, 73 of the wrong ones were copies in a coding agent's worktree; without them it is 38%.

How these were measured: all three scans ran, and every location was checked against the code, again by AI; no lawyer verified any judgement. After 0.1.1 and 0.1.2 the first two projects reach 49% and 86%, but those fixes were written by looking at them, so this is not an independent measure. Most right findings were in the third-party / transfer inventory.

**The higher figure of the measurement set, and why it differs.** On 84 open-source projects (last three rounds, 36 projects), 79-84% of the deep audit's scored findings were right (75-79% after correcting for judging bias); about 8 real issues per project were missed, 2-3 of them high severity, mostly access control. That figure:
- covers the deep audit only (scored findings; not the quick scan, the live scan or the review list);
- was judged by AI agents of one model family;
- comes from projects the tool was then tuned on: rules and precision thresholds were adjusted from their labels after each round.

The quick scan, the live scan, the questionnaire and the drafts are not part of that set.

**Legal bases:** what was read in a primary source and what could not be verified is listed in [docs/hukuki-dayanaklar.md](docs/hukuki-dayanaklar.md) (Turkish). Findings resting on something unverified say "unverified basis".

MIT License
