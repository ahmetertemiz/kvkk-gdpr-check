// Round 7 / WS6 (calibration): transparency and declarations.
//   - notice selection: a dedicated privacy-policy path wins over articles / sections that mention privacy
//   - language honesty: a notice the declaration lexicon cannot read yields a declarations gap (C2) and review, never
//     "X is not in the notice"
//   - TRN-02 still fires on a readable notice (EN and TR)
//   - scraping needs a real fetch + parse of a third-party page, not a scraper named in an option string
//   - contract C-R7: sub / elements on TRN-01/02/03, PRF-01, DPIA-01 locations
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit } from '../src/audit/index.js';
import { noticeLanguage, noticeRank, orderNotices } from '../src/audit/extract/declarations.js';
import { detectIndirectSources } from '../src/audit/extract/indirect-sources.js';

function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r7ws6-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return dir;
}
const fid = (f) => f?.rule?.id ?? f?.id;
const locsOf = (list, id) => (list || []).filter((f) => fid(f) === id).flatMap((f) => f.locations || []);
const norm = (p) => String(p || '').split(String.fromCharCode(92)).join('/');

const SCHEMA = `create table public.profiles (
  id uuid primary key references auth.users(id),
  email text not null,
  phone text,
  full_name text,
  national_id text,
  created_at timestamptz default now()
);
alter table public.profiles enable row level security;
`;
const SIGNUP = `'use client';
import { createClient } from '@supabase/supabase-js';
const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);
export default function Signup() {
  async function onSubmit(e) {
    const f = new FormData(e.target);
    await supabase.from('profiles').insert({ email: f.get('email'), phone: f.get('phone'), full_name: f.get('full_name'), national_id: f.get('national_id') });
  }
  return (<form onSubmit={onSubmit}><input name="email" type="email" /><input name="phone" /><input name="full_name" /><input name="national_id" /><button>Sign up</button></form>);
}
`;
const EN_POLICY = `export default function PrivacyPolicy() {
  return (<main><h1>Privacy Policy</h1>
    <p>This privacy policy explains how we collect and process your personal data when you use the service.</p>
    <p>We collect your email address and your full name when you create an account, in order to provide the service.</p>
    <p>The legal basis is the performance of a contract. We retain account data for as long as your account exists.</p>
    <p>You have the right to access, rectify and erase your data. Contact us at privacy@example.org for any request.</p>
    <p>Our data controller is Example Ltd. We do not sell your personal information to third parties.</p>
  </main>);
}
`;
const ARTICLE = `---
title: Why privacy matters for analytics
---
Privacy policy pages are often ignored. In this article we explain how products collect personal data, what a data
controller is, and why your rights to access and erasure matter. We collect nothing here: this is a blog post about
cookies, phone numbers, national identity numbers and email addresses in analytics tools. Contact us for questions.
`;

// ------------------------------------------------------------------ notice selection
test('noticeRank: dedicated policy paths beat articles, sections and components', () => {
  assert.equal(noticeRank('pages/privacy.mdx', 'privacy').rank, 3);
  assert.equal(noticeRank('app/privacy-policy/page.tsx', 'privacy').rank, 3);
  assert.equal(noticeRank('app/(legal)/privacy/page.tsx', 'privacy').rank, 3);
  assert.equal(noticeRank('src/routes/(legal)/privacy/+page.svelte', 'privacy').rank, 3);
  assert.equal(noticeRank('public/gizlilik-politikasi.html', 'privacy').rank, 3);
  assert.equal(noticeRank('src/views/kvkk/aydinlatma-metni.vue', 'privacy').rank, 3);
  assert.equal(noticeRank('content/pages/cookies.mdx', 'cookie').rank, 2);
  assert.equal(noticeRank('content/articles/cookieless-analytics.mdx', 'cookie').rank, 0);
  assert.equal(noticeRank('content/blog/privacy-first-analytics.mdx', 'privacy').rank, 0);
  assert.equal(noticeRank('src/app/(home)/_sections/data-privacy.tsx', 'privacy').rank, 0);
  assert.equal(noticeRank('src/components/PrivacyBanner.tsx', 'privacy').rank, 0);
  assert.equal(noticeRank('src/pages/privacy-settings.tsx', 'privacy').rank, 1);
  const order = orderNotices([
    { id: 'a', file: 'content/blog/privacy-tips.mdx', kind: 'privacy' },
    { id: 'b', file: 'content/pages/privacy.mdx', kind: 'privacy' },
  ]);
  assert.equal(order[0].id, 'b');
  // A readable notice-grade copy beats a higher-ranked notice in an unsupported script.
  const o2 = orderNotices([
    { id: 'th', file: 'src/pages/Privacy.tsx', kind: 'privacy', languageSupported: false },
    { id: 'en', file: 'src/pages/privacy-en-info.tsx', kind: 'privacy', languageSupported: true },
  ]);
  assert.equal(o2[0].id, 'en');
});

test('Next.js app: the privacy-policy route is the notice, not a blog article that mentions privacy', async () => {
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { next: '14.0.0', '@supabase/supabase-js': '2.0.0' } }),
    'supabase/migrations/001_init.sql': SCHEMA,
    'app/signup/page.tsx': SIGNUP,
    'app/privacy-policy/page.tsx': EN_POLICY,
    'content/blog/privacy-matters.mdx': ARTICLE,
  });
  const r = await audit(dir, { lang: 'en' });
  const decls = r.graph.nodesOf('Declaration');
  const chosen = decls.find((d) => d.chosen);
  assert.ok(chosen, 'a notice is chosen');
  assert.equal(norm(chosen.file), 'app/privacy-policy/page.tsx');
  assert.equal(chosen.chosenReason.code, 'policy-path');
  assert.ok(chosen.chosenReason.en && chosen.chosenReason.tr);
  const trn = [...locsOf(r.findings, 'AUD-TRN-02'), ...locsOf(r.review, 'AUD-TRN-02')];
  assert.ok(trn.length, 'TRN-02 on the readable notice');
  for (const l of trn) assert.equal(norm(l.file), 'app/privacy-policy/page.tsx', 'anchored on the chosen notice');
  // phone / national id are not in the policy (the article mentions them, but it is not the notice)
  const missing = trn.filter((l) => l.sub === 'TRN-02:category-missing').flatMap((l) => l.elements);
  assert.ok(missing.includes('phone'), `phone missing: ${missing}`);
  assert.ok(!missing.includes('email'), 'email is declared');
});

test('plain HTML site (different style): gizlilik-politikasi.html is chosen over a Vue section component', async () => {
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { vue: '3.4.0', '@supabase/supabase-js': '2.0.0' } }),
    'supabase/migrations/001_init.sql': SCHEMA,
    'src/components/sections/PrivacyHighlights.vue': `<template><section><h2>Gizlilik politikası</h2><p>Kişisel verileriniz bizim için önemlidir. Verilerinizi toplarken haklarınızı korur, üçüncü taraflarla paylaşmayız. Veri sorumlusu bize ulaşın sayfasındadır. Aydınlatma metni için tıklayın.</p></section></template>`,
    'public/gizlilik-politikasi.html': `<html><body><h1>Gizlilik Politikası ve Aydınlatma Metni</h1>
<p>Veri sorumlusu Örnek Yazılım A.Ş. olarak kişisel verilerinizi KVKK kapsamında işlemekteyiz.</p>
<p>Üyelik sırasında ad soyad, e-posta adresi ve telefon numaranız toplanır ve hizmetin sunulması amacıyla işlenir.</p>
<p>Hukuki sebep sözleşmenin kurulması ve ifasıdır. Verileriniz üyeliğiniz süresince saklanır, sonra imha edilir.</p>
<p>KVKK md.11 kapsamındaki haklarınız için kvkk@example.org adresine başvurabilirsiniz.</p></body></html>`,
  });
  const r = await audit(dir, { lang: 'tr' });
  const chosen = r.graph.nodesOf('Declaration').find((d) => d.chosen);
  assert.equal(norm(chosen?.file), 'public/gizlilik-politikasi.html');
  assert.equal(chosen.language, 'tr');
  assert.equal(chosen.languageSupported, true);
  const trn = [...locsOf(r.findings, 'AUD-TRN-02'), ...locsOf(r.review, 'AUD-TRN-02')];
  const missing = trn.filter((l) => /category-missing/.test(l.sub)).flatMap((l) => l.elements);
  assert.ok(missing.includes('national_id'), `national id is not declared: ${missing}`);
  assert.ok(!missing.includes('phone') && !missing.includes('email'), 'phone / e-mail are declared in Turkish');
});

// ------------------------------------------------------------------ language honesty
test('noticeLanguage: generic script + stop-word detection', () => {
  const en = noticeLanguage('We collect your email address and name. You have the right to access your data. This policy explains how we process the information you provide to us and which third parties may receive it for the purposes described below.');
  assert.equal(en.language, 'en');
  assert.equal(en.languageSupported, true);
  const tr = noticeLanguage('Kişisel verileriniz, hizmetin sunulması amacıyla ve sözleşmenin ifası hukuki sebebine dayanarak işlenmektedir. Bu kapsamda ad soyad, e-posta ve telefon bilgileriniz ile ilgili olarak haklarınızı kullanabilir, veri sorumlusuna başvurabilirsiniz. Verileriniz yurt dışına aktarılmamaktadır ve bir şekilde paylaşılmaz.');
  assert.equal(tr.language, 'tr');
  assert.equal(tr.languageSupported, true);
  const th = noticeLanguage('นโยบายความเป็นส่วนตัว เราเก็บรวบรวมข้อมูลส่วนบุคคลของท่าน เช่น ชื่อ เบอร์โทรศัพท์ และที่อยู่ เพื่อใช้ในการช่วยเหลือผู้ประสบภัย ข้อมูลจะถูกเปิดเผยต่อหน่วยงานที่เกี่ยวข้องเท่านั้น');
  assert.equal(th.script, 'thai');
  assert.equal(th.languageSupported, false);
  const ja = noticeLanguage('当社は、お客様の個人情報を適切に取り扱います。氏名、メールアドレス、電話番号を収集し、サービスの提供のために利用します。');
  assert.equal(ja.languageSupported, false);
  const de = noticeLanguage('Wir verarbeiten Ihre personenbezogenen Daten nur, wenn dies für die Bereitstellung unserer Dienste erforderlich ist. Die Daten werden nicht an Dritte weitergegeben und sind für Sie jederzeit abrufbar. Sie haben das Recht auf Auskunft, Berichtigung und Löschung der Daten bei uns oder bei der Aufsichtsbehörde.');
  assert.equal(de.language, 'de');
  assert.equal(de.languageSupported, false);
  assert.equal(noticeLanguage('Privacy').languageSupported, true, 'too short to judge: nothing asserted');
});

test('a notice in an unsupported script: declarations gap (C2) and review, never "not in the notice"', async () => {
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { react: '18.2.0', '@supabase/supabase-js': '2.0.0' } }),
    'supabase/migrations/001_init.sql': SCHEMA,
    'src/pages/Signup.tsx': SIGNUP,
    'src/pages/Privacy.tsx': `export default function Privacy() {
  return (<div><h1>นโยบายความเป็นส่วนตัว</h1>
    <p>เราเก็บรวบรวมข้อมูลส่วนบุคคลของท่าน เช่น ชื่อ อีเมล เบอร์โทรศัพท์ และเลขประจำตัวประชาชน เพื่อใช้ในการให้บริการ</p>
    <p>ข้อมูลของท่านจะถูกเก็บรักษาอย่างปลอดภัย และจะไม่ถูกเปิดเผยต่อบุคคลภายนอก เว้นแต่ได้รับความยินยอมจากท่าน</p>
    <p>ท่านมีสิทธิ์ขอเข้าถึง แก้ไข หรือลบข้อมูลส่วนบุคคลของท่านได้ตลอดเวลา โดยติดต่อเราทางอีเมล</p>
  </div>);
}
`,
  });
  const r = await audit(dir, { lang: 'en' });
  const d = r.graph.nodesOf('Declaration').find((x) => x.chosen);
  assert.equal(d?.languageSupported, false);
  // No TRN-02 finding asserts absence from the unreadable notice.
  const asserted = locsOf(r.findings, 'AUD-TRN-02').filter((l) => /category-missing|recipient-not-listed/.test(l.sub || ''));
  assert.deepEqual(asserted, [], 'nothing asserted as "not in the notice"');
  const rev = locsOf(r.review, 'AUD-TRN-02');
  assert.ok(rev.length, 'the open question is in review');
  for (const l of rev) {
    assert.ok(l.reviewReason?.en && l.reviewReason?.tr, 'reviewReason on TRN-02 review locations');
    assert.ok(/^TRN-02:/.test(l.sub));
  }
  assert.ok(rev.some((l) => /not covered|language|lexicon|partly/i.test(l.reviewReason.en)));
  // C2: the gap is reported on the declarations layer.
  const layers = r.layers || r.coverage?.layers;
  const gaps = layers?.declarations?.gaps || [];
  assert.ok(gaps.some((g) => g.kind === 'notice-language' || /unsupported language/i.test(String(g.reason))), `declarations gap: ${JSON.stringify(layers?.declarations)}`);
  assert.notEqual(layers?.declarations?.status, 'found');
});

// ------------------------------------------------------------------ scraping
test('scraping: a scraper named in options / unions is not a source; a real fetch + parse is', () => {
  const options = `type SearchProvider = 'exa' | 'firecrawl' | 'tavily';
export const PROVIDERS = [{ value: 'firecrawl', label: 'Firecrawl (scraping)' }, { value: 'exa', label: 'Exa' }];
export function useProvider() { return localStorage.getItem('searchProvider') as SearchProvider; }
const fields = ['name', 'email', 'phone', 'linkedin', 'bio'];
`;
  assert.deepEqual(detectIndirectSources('components/settings.tsx', options).filter((s) => s.via === 'scraping'), []);

  const ownApi = `import * as cheerio from 'cheerio';
export async function preview() {
  const res = await fetch('/api/profile-card');
  const $ = cheerio.load(await res.text());
  return { bio: $('.bio').text(), linkedin: $('a.linkedin').attr('href'), username: $('.handle').text() };
}
`;
  assert.deepEqual(detectIndirectSources('lib/preview.ts', ownApi).filter((s) => s.via === 'scraping'), [], 'own-app relative fetch');

  const real = `import * as cheerio from 'cheerio';
export async function speakers(url: string) {
  const res = await fetch(url, { headers: { 'user-agent': 'bot' } });
  const $ = cheerio.load(await res.text());
  return $('.speaker').map((_, el) => ({ name: $(el).find('.name').text(), bio: $(el).find('.bio').text(), linkedin: $(el).find('a.linkedin').attr('href') })).get();
}
`;
  const hits = detectIndirectSources('lib/speakers.ts', real).filter((s) => s.via === 'scraping');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].externalFetch, true);

  // Different style: Python requests + BeautifulSoup
  const py = `import requests
from bs4 import BeautifulSoup

def attendees(event_url):
    html = requests.get(event_url, timeout=10).text
    soup = BeautifulSoup(html, "html.parser")
    return [{"name": a.select_one(".name").text, "headline": a.select_one(".headline").text, "linkedin": a.select_one("a")["href"]} for a in soup.select(".attendee")]
`;
  const pyHits = detectIndirectSources('scraper/attendees.py', py).filter((s) => s.via === 'scraping');
  assert.equal(pyHits.length, 1);

  // A headless browser that is only imported (never launched) is not a source.
  const importOnly = `import { chromium } from 'playwright';
export type Browser = typeof chromium;
export const profileFields = ['bio', 'linkedin', 'followers', 'username'];
`;
  assert.deepEqual(detectIndirectSources('lib/types.ts', importOnly).filter((s) => s.via === 'scraping'), []);
});

// ------------------------------------------------------------------ contract C-R7 sub keys
const MEASURED = {
  'AUD-TRN-01': /^TRN-01:(no-notice|placeholder-notice|external-notice)$/,
  'AUD-TRN-02': /^TRN-02:(recipient-not-listed|category-missing|category-missing-inferred|transfer-contradiction)$/,
  'AUD-TRN-03': /^TRN-03:(scraping-tool|public-post-api|contact-import|enrichment-api)$/,
  'AUD-PRF-01': /^PRF-01:(scraping-tool|public-post-api|contact-import|enrichment-api)$/,
  'AUD-DPIA-01': /^DPIA-01:(innovative-tech|systematic-monitoring|special-or-large|other-criterion)$/,
};

test('sub keys and elements on every transparency / DPIA location (examples/audit-app reports 18 finding ids)', async () => {
  const r = await audit(path.resolve('examples/audit-app'), { lang: 'tr' });
  const ids = [...new Set(r.findings.map(fid))];
  assert.equal(new Set([...r.findings, ...r.review].map(fid)).size, 18, `finding ids: ${ids.join(' ')}`);
  assert.ok(ids.includes('AUD-TRN-02'), 'TRN-02 survives calibration');
  let n = 0;
  for (const list of [r.findings, r.review]) for (const f of list) {
    const re = MEASURED[fid(f)];
    if (!re) continue;
    for (const l of f.locations) {
      if (!l.sub && fid(f) === 'AUD-TRN-01' && l.reviewReason) continue; // coverage-blind review items come from index.js
      assert.match(String(l.sub), re, `${fid(f)} ${l.label?.en}`);
      assert.ok(Array.isArray(l.elements), `${fid(f)} elements`);
      n++;
    }
  }
  assert.ok(n >= 5);
  const trn = [...locsOf(r.findings, 'AUD-TRN-02'), ...locsOf(r.review, 'AUD-TRN-02')].filter((l) => l.file);
  const contra = trn.find((l) => l.sub === 'TRN-02:transfer-contradiction');
  assert.ok(contra, 'the "no transfer abroad" contradiction is its own sub-signal');
  assert.ok(trn.some((l) => l.sub === 'TRN-02:recipient-not-listed'));
  for (const l of trn) assert.equal(norm(l.file), 'src/app/privacy/page.tsx');
});

test('TRN-02 no-notice / placeholder keys: placeholder policy page beside a decision record stays TRN-01 placeholder', async () => {
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { '@remix-run/react': '2.0.0', '@prisma/client': '5.0.0' } }),
    'prisma/schema.prisma': `model User {\n  id String @id\n  email String @unique\n  name String?\n  phone String?\n}\n`,
    'app/routes/signup.tsx': `import { prisma } from '~/db.server';\nexport async function action({ request }) {\n  const f = await request.formData();\n  await prisma.user.create({ data: { email: String(f.get('email')), name: String(f.get('name')), phone: String(f.get('phone')) } });\n  return null;\n}\nexport default function S() { return <form method="post"><input name="email" /><input name="name" /><input name="phone" /></form>; }\n`,
    'app/routes/privacy.tsx': `export default function Privacy() { return <div>Privacy</div>; }\n`,
    'docs/decisions/003-cookie-consent.md': `# Cookie consent\nWe decided that personal data such as your email is processed by the controller. Privacy policy and cookie policy pages describe your rights to access and erasure. Contact us. Third-party processors receive no data.\n`,
  });
  const r = await audit(dir, { lang: 'en' });
  const t1 = [...locsOf(r.findings, 'AUD-TRN-01'), ...locsOf(r.review, 'AUD-TRN-01')].filter((l) => l.sub);
  assert.ok(t1.some((l) => l.sub === 'TRN-01:placeholder-notice'), JSON.stringify(t1.map((l) => l.sub)));
  assert.deepEqual(locsOf(r.findings, 'AUD-TRN-02').filter((l) => /docs\/decisions/.test(norm(l.file))), []);
});
