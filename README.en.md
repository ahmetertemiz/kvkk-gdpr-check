# kvkk-gdpr-check

**A command-line tool that scans your software project for KVKK (Turkey) and GDPR privacy risks and shows every finding with file and line.**

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

**Accuracy of the deep audit** (last three rounds, 36 projects nobody had tuned on): 79-84% of scored findings were right (75-79% after correcting for judging bias); about 8 real issues per project were missed, 2-3 of them high severity, mostly access control. **AI agents of one model family made every judgement; no lawyer verified any of them.** The quick scan, the live scan, the questionnaire and the drafts were not measured.

**Legal bases:** what was read in a primary source and what could not be verified is listed in [docs/hukuki-dayanaklar.md](docs/hukuki-dayanaklar.md) (Turkish). Findings resting on something unverified say "unverified basis".

MIT License
