---
name: kvkk-gdpr-audit
description: Manually verify a project's KVKK (Turkey) / GDPR (EU) privacy risks with kvkk-gdpr-check as the starting list, not the verdict — read every inventory item and every finding in the code, check privacy-notice promises against the code and configuration, mark each item correct / wrong / unclear with evidence, and list what the tool missed. Read-only: the report goes outside the project. Use when the user asks for a KVKK / GDPR / privacy audit, "is my app compliant", aydınlatma metni or çerez kontrolü, or before launching an app that handles personal data.
---

# KVKK / GDPR manual verification

The tool gives you a list; you give the verdict. Its measured precision is in every finding (`precision.text`): many rules are right less than half the time on real projects. **Change nothing in the project.** You only read it and write a report outside it. Write the report in the user's language. You are not a lawyer: say so once, at the end.

## 1. Get the two lists (JSON, outside the project)

Pick an output folder next to the project, never inside it, e.g. `../<project>-kvkk-denetim/` (ask if the user prefers another place).

```bash
npx -y kvkk-gdpr-check audit . -f json -o ../<project>-kvkk-denetim/audit.json --fail-on none
npx -y kvkk-gdpr-check . -f json -o ../<project>-kvkk-denetim/scan.json --fail-on none
```

Add `--url https://THE-SITE` to the second command when the app is deployed (cookies and requests before consent, after "Reject"). Without the registry, use `node <repo>/bin/cli.js` instead of `npx -y kvkk-gdpr-check`.

- **Inventory (facts):**
  - `audit.json` → `model.inventory` (data elements, with sources / stores / recipients), `model.transfers` (transfer register), `model.namedVendors` (named in the code, no flow traced), `model.activities`.
  - `scan.json` → `findings[]` with `kind: "inventory"`.
- **To check (verdicts):**
  - `findings[]` with `kind: "finding"` in both files.
  - `review[]` in both files: not scored, mostly wrong on real projects. Verify them too.
  - Each item carries `precision.text`, and `severityRaw` when its level was capped.
- If `scoreReliable` is false, or `coverage` / `support` says a layer was not analysed, write that at the top. In that layer the lists are incomplete: read the code yourself.

## 2. Read the code first, then the tool's label

For each item, open the file at the location and work out on your own what the code does: where the value comes from, where it goes, what guards it. Only then compare with the tool's title and label. Do not let the label decide; a rule's precision tells you how much to doubt it, not the answer.

- **Verdict, "doğru":** the code really has the problem the finding states, at that location.
  - A detection that is factually right but not a problem is **yanlış**. Examples: the tracker loads only after consent; the log line masks the e-mail.
  - State the reason in the report.
- **Inventory item, "doğru":** the field really holds a person's data, or the vendor really receives personal data.
- **"Belirsiz":** the code alone cannot settle it (configuration outside the repo, a dashboard setting, an unanswered question). Say what would settle it.

## 3. Check the privacy notice's promises against the code

Find the privacy notice, the cookie policy and the in-app texts. Note every concrete promise: a duration ("30 gün", "90 days"), and words such as "yalnızca / only", "asla / never", "gönderilmez / is not sent", "silinir / is deleted", "anonim", "şifreli".

For each promise, find the code or configuration that keeps it, or breaks it:

- **Retention and deletion:** is the job that deletes really scheduled and enabled? Check cron / `pg_cron` / scheduled functions / workflow files and their `enabled` flags; a function nobody calls deletes nothing.
- **"Not sent" / "only":** check every request and SDK on that path, including logs and error monitoring.
- **Vendors:** check the vendors and data elements the notice lists against the inventory. Note both directions: processed but not named, and named but not used.

## 4. Report: one line per item

Every item gets a verdict and **one sentence of evidence** (`file:line` plus what the code does). Group items under the two parts the tool uses, then add the misses.

## 5. What the tool missed (separate heading)

While reading, you will see real issues no list contains:

- a personal-data column or form field missing from the inventory;
- a third party receiving data that is in neither `transfers` nor `namedVendors`;
- a broken promise, a missing access check, a secret in client code.

List each with `file:line`, why it is a problem and, if you can tell, which kind of check should have caught it. These numbers matter as much as the correct ones: report how many misses you found.

## Report skeleton

```markdown
# KVKK / GDPR doğrulama raporu: <proje> (<tarih>, kvkk-gdpr-check <sürüm>)

Kapsam: <analiz edilmeyen katmanlar, skor güvenilir mi>. Proje kodu değiştirilmedi.

## Özet
- Envanter: <n> öğe; doğru <a>, yanlış <b>, belirsiz <c>
- Kontrol edilecekler: <n> konum; doğru <a>, yanlış <b>, belirsiz <c>
- Doğrulanmalı listesi: <n> konum; doğru <a>, yanlış <b>, belirsiz <c>
- Aracın kaçırdığı: <n> sorun
- En acil üç konu: …

## 1. Envanter
| Öğe | Kaynak (kural / model alanı) | Karar | Kanıt |
|---|---|---|---|
| full_name (profiles.full_name) | PII001 | doğru | supabase/migrations/001.sql:8 kullanıcı adı soyadı tutuluyor |

## 2. Kontrol edilecekler
| Kural | Konum | Karar | Kanıt (tek cümle) |
|---|---|---|---|
| AUD-SEC-04 | src/api/mail.ts:43 | yanlış | e-posta loglanmadan önce maskeleniyor (maskEmail, satır 40) |

## 3. Aydınlatma metni vaatleri
| Vaat (metin, yer) | Karar | Kanıt |
|---|---|---|
| "Loglar 30 gün sonra silinir" (gizlilik.tsx:120) | yanlış | silme işi tanımlı ama zamanlanmamış: cron.schedule yok |

## 4. Aracın kaçırdıkları
| Sorun | Yer | Neden sorun | Hangi kontrol yakalamalıydı |
|---|---|---|---|

## 5. Kullanıcının yapması gerekenler
<anahtar döndürme, sözleşmeler, VERBİS, hukuki inceleme …>

Bu bir hukuki danışmanlık değildir; yayına almadan önce bir KVKK/GDPR uzmanına kontrol ettirin.
```

Fixes, document drafts (`kvkk-gdpr-check docs`) and code changes are separate tasks: offer them after the report, and start only when the user asks.
