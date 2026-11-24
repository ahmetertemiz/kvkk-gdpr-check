---
name: kvkk-gdpr-audit
description: Audit the current project for KVKK (Turkey) and GDPR (EU) privacy compliance risks — trackers without consent, exposed secrets, missing Supabase RLS / open Firebase rules, missing privacy notice, sensitive data, data subject rights, international transfers — then propose and apply fixes and draft the privacy notice. Use when the user asks about KVKK, GDPR, privacy, cookie consent, aydınlatma metni, gizlilik politikası, "is my app compliant", or before launching an app that collects user data.
---

# KVKK / GDPR audit

You are helping a developer (often a vibe-coder) find and fix privacy-compliance risks in their app. Be concrete and practical. You are not a lawyer: say so once at the end, not in every paragraph.

## 1. Run the deterministic scanners first

Deep audit (data-flow graph + principle-based legal checks) — this is the primary input:

```bash
npx -y kvkk-gdpr-check audit . -f json -o kvkk-audit.json --fail-on none
```

`kvkk-audit.json` contains `findings` (AUD-* with evidence chains in `locations[].steps`), `model` (`inventory`, `activities` = ROPA, `transfers`, `deletionMatrix`, `dpia`, controller questions), `organization` (answers-based conclusions), the full `graph`, and `scoreReliable` / `coverage`. If `scoreReliable` is false, the stack is not fully supported: say so and fall back to reading the code yourself. Treat each finding as a lead backed by evidence, still verify critical/high ones in code.

Pattern scan (secrets, trackers, mobile/backend config rules) as a complement:

```bash
npx -y kvkk-gdpr-check . --format json --fail-on none --lang tr
```

If `npx` cannot reach the registry and this skill ships next to the CLI, run `node <path-to-repo>/bin/cli.js . --format json --fail-on none`.
Use `--lang en` if the user writes in English.

Parse the JSON: `score`, `counts`, `signals`, and `findings[]` (each with `id`, `severity`, `locations`, `fix`, `refs`).

If the app is deployed (ask for the URL, or find it in README / package.json `homepage` / vercel config), also run the live scan — it opens the site in a real browser, records cookies and tracker requests before consent, clicks "Reject" and checks tracking stops:

```bash
npx -y kvkk-gdpr-check . --url https://THE-SITE --format json --fail-on none
```

(Browser mode needs `playwright-core`; without it the scan falls back to HTTP mode. Add `--pages /signup,/login` for important pages.) The JSON then contains a `live` object with `cookiesBeforeConsent`, `cookiesAfterReject`, `thirdPartyHosts`, `banner`, `headers`, `privacyPageCheck` and `forms` — use those facts directly in your report.

## 2. Verify and go deeper than regex

The scanner is heuristic. For every critical/high finding, open the file and confirm it. Drop false positives and say why. Then look for what regex cannot see:

- **Data flow map.** Trace where each personal data field (from PII001/PII002/PII003 and the DB schema) is collected, stored, logged, and sent (which third parties / LLM prompts). This becomes the data inventory.
- **Consent flow.** Do trackers actually wait for consent? Is "Reject" as easy as "Accept"? Is marketing consent separate from the privacy notice acknowledgement and not a condition of sign-up?
- **Access control.** For Supabase, read every RLS policy; for Firebase, read the rules; for custom APIs, check that endpoints returning user data check that the requester owns it (IDOR).
- **Secrets.** Is any server secret imported into client components (`'use client'`, Vite/Expo client code)?
- **Deletion.** If there is a delete-account flow, does it also delete storage files, rows in other tables, and data at third parties (Stripe customer, mailing list, analytics)?
- **LLM usage.** What user data goes into prompts? Is it necessary? Is there an automated decision with legal/similar effect?
- **Children.** Is the app likely used by minors?

## 3. Report

Write a short report in the user's language:

1. **Score & headline** — the scanner score and the 3 most urgent things.
2. **Findings table** — severity, what, where (`file:line`), fix. Group by: Security → Consent/Tracking → Transparency → Data subject rights → Transfers → Retention.
3. **Data inventory** — table: data field | purpose | legal basis (KVKK md.5/6, GDPR Art.6/9) | storage location | recipients/third parties | retention. Mark guesses as guesses and ask the user to confirm.
4. **Third parties & transfers** — vendor, what data, region, whether a DPA/standard contract is needed (KVKK md.9: standard contract must be notified to the KVKK Authority within 5 business days of signing).

## 4. Offer fixes

Ask before editing. Then fix in this order: critical security (rotate keys — tell the user they must rotate in the provider dashboard, you cannot), RLS/rules, consent gating, pre-ticked boxes, logging PII, Google Fonts self-hosting, account deletion endpoint, data export.

When adding consent, prefer a small open-source solution (e.g. `vanilla-cookieconsent`) with Google Consent Mode v2 defaults set to `denied`, and load non-essential scripts only after consent.

## 5. Draft the documents

If `DOC001`/`DOC002`/`WEB006`/`WEB007`/`WEB008` fired, offer to generate the document set. Ask the user for company name, address, contact email and website first, write them to `kvkk-answers.json`, then:

```bash
npx -y kvkk-gdpr-check docs . --url https://THE-SITE --answers kvkk-answers.json -y --out privacy-docs
```

Answers the code cannot give (VERBİS, role, transfer mechanism per recipient, retention policy, minors, scale) go under `org` in `kvkk-answers.json`: run `npx -y kvkk-gdpr-check anket . -y` for the template, ask the user, fill in, re-run. Never invent an answer; leave `null`. `docs` also writes DPIA / LIA / TIA drafts: keep every `[[...]]` that needs a human decision, and tell the user a lawyer must review them.

This drafts aydınlatma metni, açık rıza metni, çerez politikası (with real cookies when `--url` is given), VERBİS-style data inventory (md + csv), international transfer register, breach response plan, data subject request form, compliance roadmap and an English GDPR privacy policy. Then review and improve the drafts with what you learned in step 2 (the generator only knows what the scanner saw), replace remaining `[[...]]` placeholders you can answer from the codebase, and add the pages to the app with a link next to the sign-up form and in the footer.

## 6. Close

End with: what was fixed, what the user must do manually (rotate keys, sign DPAs, VERBİS check, legal review), and one line: "Bu bir hukuki danışmanlık değildir; yayına almadan önce bir KVKK/GDPR uzmanına kontrol ettirin."
