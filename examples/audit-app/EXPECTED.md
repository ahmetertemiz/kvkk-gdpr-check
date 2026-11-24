# audit-app — expected audit results (ground truth)

A Next.js + Supabase app with deliberate data-protection problems. The audit engine must find these.
(kvkk-ignore-file)

## Data elements & where they enter
| Element | Source | Notes |
|---|---|---|
| full_name, email, phone, birth_date, national_id (tckn), password, marketing_consent | form `signup/page.tsx` (react-hook-form `register`) → `fetch('/api/signup')` | marketing checkbox `defaultChecked` |
| email, free_text (message) | form `support/page.tsx` → server action `submitTicket` (`formData.get`) | |
| health (symptoms), free_text (notes) | request body of `POST /api/health` | special category |
| free_text (chat content) | request body of `POST /api/chat` | user-generated, may contain anything |
| full_name, email, address (shippingAddress) | request body of `POST /api/checkout` | |

## Flows (source → destination)
| Element | Destination | Evidence |
|---|---|---|
| email, full_name, phone, birth_date, tckn, marketing_opt_in | `store:column:profiles.*` (via supabaseAdmin insert, key renaming fullName→full_name, birthDate→birth_date) | api/signup/route.ts |
| email, password | `sink:vendor:supabase` (auth.signUp) | api/signup |
| email, phone | `store:log:console` | api/signup `console.log` |
| email, full_name | `sink:vendor:email-services` (Resend) | api/signup |
| email, phone | `sink:vendor:posthog` via `posthog.identify` (client) | components/Analytics.tsx |
| symptoms(health), notes | `store:column:health_logs.*` AND `sink:vendor:openai` (prompt template literal) | api/health |
| chat content | `sink:vendor:openai` (embeddings + streamText via @ai-sdk/openai) + `store:column:chat_messages.content` + vector embedding | api/chat |
| email, full_name, address | `sink:vendor:stripe` (customers.create) + `orders.shipping_address` | api/checkout |
| email, message | `support_tickets.*` | support/actions.ts |
| all profiles columns incl. tckn, birth_date | `sink:client-response` (select('*') → NextResponse.json) | api/profile |

## Storage facts
- profiles: RLS on, owner policy `auth.uid() = id` ✅; FK → auth.users ON DELETE CASCADE
- health_logs: RLS on but policy `using (true)` for select → **special-category data readable by anyone** ❌; FK → profiles ON DELETE CASCADE
- orders: **RLS off** ❌; FK → profiles with no ON DELETE (= NO ACTION → blocks account deletion or leaves data) ❌
- support_tickets: RLS on, **no policies** (deny all for anon — fine), **no user FK → not reached by account deletion** ❌
- chat_messages: RLS on, owner select policy; FK → auth.users ON DELETE CASCADE ✅; has `embedding vector` (derived personal data)
- storage bucket `avatars`: **public** ❌, not cleaned on deletion

## Expected findings (Phase 1)
1. **Minimisation:** `birth_date` and `tckn` are collected and stored but never read anywhere (only exposed via select('*')). National ID without a visible purpose.
2. **Special category → third country:** health data (symptoms/notes) sent to OpenAI (US) — no consent mechanism, no auth on `/api/health` (userId taken from body → anyone can write anyone's health log).
3. **Special category exposure:** health_logs RLS policy `using (true)`.
4. **Logs:** email + phone logged with console.log.
5. **Analytics:** PostHog initialised without consent gate; identify sends email + phone to US vendor. CookieBanner exists but has no reject and does not gate posthog.
6. **Over-exposure:** `/api/profile` returns `select('*')` → tckn, birth_date sent to client.
7. **Deletion coverage:** `auth.admin.deleteUser` → cascades profiles → health_logs; chat_messages cascades; orders NOT (no ON DELETE); support_tickets NOT (no FK; matched by email only); avatars bucket NOT; Stripe customer NOT; PostHog person NOT; Resend NOT; OpenAI (API retention) NOT.
8. **RLS:** orders holds address + stripe_customer_id with RLS disabled.
9. **Public bucket:** avatars (photos) public.
10. **Marketing consent:** pre-checked checkbox; DB default `marketing_opt_in default true`.
11. **Retention:** no retention job for any table.
12. **Purpose drift:** email collected for account → sent to PostHog (analytics) — different purpose, requires consent.
13. **Free text to LLM:** chat content → OpenAI + embeddings stored (derived data also needs deletion).

## Phase 2 (declared vs actual) — privacy/page.tsx
- Declares: full name, email, phone; recipients Supabase, Stripe; "yurt dışına aktarılmamaktadır".
- Reality: also birth_date, tckn, health data, chat content, address; recipients also PostHog, OpenAI, Resend; **all are US vendors → transfer abroad statement is false**.
