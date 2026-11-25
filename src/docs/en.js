// kvkk-ignore-file
import { P, mdTable, toCsv, L, join, header } from './util.js';
import { DATA_SENT, COOKIE_CATEGORIES } from './data.js';
import { recipientsOf, dataSent } from './from-audit.js';

const SEV = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };
const EU = /^(AT|BE|BG|HR|CY|CZ|DK|EE|FI|FR|DE|GR|HU|IE|IT|LV|LT|LU|MT|NL|PL|PT|RO|SK|SI|ES|SE|EU)$/i;

const appName = (a) => P(a.appName, 'App name');
const company = (a) => P(a.companyName, 'Company / person name');
const contactEmail = (a) => P(a.email, 'privacy contact email');
// Criminal convictions fall under GDPR Art.10, not Art.9; appearance and dress are special only under the KVKK.
const gdprSpecial = (c) => c.def.special && c.def.gdprSpecial !== false;
const fname = (c, k) => c.en?.get(k) || ({ 'çerez / çevrimiçi tanımlayıcılar': 'cookies / online identifiers', 'ileti tercihleri': 'messaging preferences' })[k] || k;
const fieldList = (c) => [...c.fields.keys()].map((k) => fname(c, k)).join(', ') || '[[check: which data of this category is processed?]]';

function duration(c) {
  if (c.estimated) return '[[check]]';
  if (c.expiresDays === undefined || c.expiresDays === null || c.expiresDays < 0) return 'Session';
  if (c.expiresDays < 1) return '< 1 day';
  if (c.expiresDays >= 365) return `${Math.round((c.expiresDays / 365) * 10) / 10} years`;
  return `${Math.round(c.expiresDays)} days`;
}

function safeguard(v) {
  if (/US/.test(v.country || '')) return 'EU–US Data Privacy Framework (if certified) or SCCs [[check]]';
  if (EU.test(v.country || '')) return '— (within EU/EEA)';
  return 'SCCs / adequacy decision [[check]]';
}

export function privacyPolicy(f) {
  const a = f.answers;
  const nonEu = !EU.test(a.country || '') ;
  const rows = f.categories.map((c) => [c.def.en + (gdprSpecial(c) ? ' (special category)' : ''), fieldList(c), c.def.purposes.en.join('; '), c.def.basis.en, (a.retention && a.retention[c.id]) || c.def.retention.en]);
  return join(
    header('en', f, 'Privacy Policy'),
    `Last updated: ${f.date}`,
    '## 1. Who we are',
    [
      `${company(a)} ("we", "${appName(a)}") is the controller of your personal data.`,
      '',
      `- Address: ${P(a.address, 'Postal address')}`,
      `- Email: ${contactEmail(a)}`,
      a.website ? `- Website: ${a.website}` : null,
      a.dpoName ? `- Data Protection Officer / privacy contact: ${a.dpoName}` : null,
      a.targetsEU && nonEu ? `- EU representative (GDPR Art.27): ${P(a.euRepresentative, 'EU representative name and address')}` : null,
    ]
      .filter((x) => x !== null)
      .join('\n'),
    '## 2. What we collect, why, and on what legal basis',
    mdTable(['Category', 'Data', 'Purpose', 'Legal basis', 'Retention'], rows),
    f.special.some(gdprSpecial) ? `We process special category data (${f.special.filter(gdprSpecial).map((c) => c.def.en).join(', ')}) only with your explicit consent or another Art.9(2) condition, with additional safeguards. [[check: is this data strictly necessary?]]` : null,
    f.special.some((c) => c.id === 'ceza') ? 'Data on criminal convictions is processed only under official authority or where Union or Member State law authorises it (GDPR Art.10). [[check: which law authorises this processing? Consent alone is not enough]]' : null,
    '## 3. Who we share it with',
    f.vendors.length
      ? mdTable(['Recipient', 'Purpose', 'Location', 'Transfer safeguard'], f.vendors.map((v) => [v.name, v.purpose?.en || '[[check]]', v.country || '[[check]]', f.isAbroad(v.country) ? safeguard(v) : '—']))
      : 'We do not share personal data with third parties except where required by law. [[check]]',
    'All processors act under data processing agreements (Art.28). We do not sell your personal data. [[check: are both statements true, and is the list of recipients complete?]]',
    f.ai.length ? `**AI features.** Content you submit to AI-powered features is sent to ${f.ai.map((v) => v.name).join(', ')} to generate a response. [[check: confirm providers do not train on API data and their retention period]] We do not make decisions based solely on automated processing that produce legal or similarly significant effects. [[check]]` : null,
    '## 4. Cookies',
    f.consentVendors.length
      ? `We use non-essential cookies (${f.consentVendors.map((v) => v.name).join(', ')}) only after you consent. You can change your choice at any time via "Cookie settings". See our cookie policy. [[check: are these really blocked before consent, and does the link exist?]]`
      : 'We only use strictly necessary cookies. [[check]]',
    '## 5. Your rights',
    `You have the right to access (Art.15), rectify (Art.16), erase (Art.17), restrict (Art.18) and port (Art.20) your data, to object (Art.21), and to withdraw consent at any time without affecting prior processing. ${f.hasAccounts ? 'You can delete your account in **Settings → Delete account** [[check: does the app have this?]]. ' : ''}Contact ${contactEmail(a)}; we respond within one month. You may also lodge a complaint with your local supervisory authority${a.country === 'TR' || !a.country ? ' (in Turkey: the Personal Data Protection Authority, kvkk.gov.tr)' : ''}.`,
    '## 6. Children',
    a.children ? `${appName(a)} is not intended for children under ${typeof a.children === 'number' ? a.children : 16}. [[check]]` : `${appName(a)} is not directed at children under [[16]]. [[check]]`,
    '## 7. Security',
    'We protect your data with encryption in transit (TLS), access controls and least-privilege permissions. [[check: add encryption at rest, backups, logging]]',
    '## 8. Changes',
    'We will notify you of material changes in the app or by email. [[check: how do you notify?]]',
  );
}

export function cookiePolicy(f) {
  const a = f.answers;
  const used = Object.keys(COOKIE_CATEGORIES).filter((k) => f.cookies.some((c) => c.category === k));
  if (!used.includes('zorunlu')) used.unshift('zorunlu');
  return join(
    header('en', f, 'Cookie Policy'),
    `Last updated: ${f.date}`,
    `This policy explains how ${appName(a)} (${P(a.website || f.source.url, 'site URL')}) uses cookies and similar technologies.`,
    '## Categories',
    used.map((k) => `- **${COOKIE_CATEGORIES[k].en}:** ${COOKIE_CATEGORIES[k].descEn}`).join('\n'),
    '## Cookie list',
    f.cookiesFromLive
      ? `Detected by an automated scan of ${f.source.url} on ${f.date}.`
      : '> ⚠️ The live site was not scanned, so this list is **estimated** from the services found in the code. Re-run with `kvkk-check docs --url <site> --lang en` for an exact list.',
    f.cookies.length
      ? mdTable(['Cookie', 'Provider', 'Purpose', 'Category', 'Duration', 'Party'], f.cookies.map((c) => [c.name + (c.estimated ? ' (estimated)' : ''), c.provider, c.purpose?.en || '[[check]]', COOKIE_CATEGORIES[c.category]?.en || c.category, duration(c), c.estimated ? '[[check]]' : c.firstParty ? 'First' : 'Third']))
      : 'No cookies other than strictly necessary ones were detected. [[check]]',
    '## Managing your choices',
    '- Use the **"Cookie settings"** link in the footer to change or withdraw consent at any time. [[check: make sure the link exists]]\n- You can also delete or block cookies in your browser settings.',
    `Questions: ${contactEmail(a)}`,
  );
}

export function consentTexts(f) {
  const a = f.answers;
  const blocks = [];
  if (f.marketing) blocks.push('## Marketing messages', `- [ ] I agree to receive news and offers from ${company(a)} by **email / SMS** [[check: channels used]]. I can unsubscribe at any time.`, '> Must be unticked by default and not a condition of sign-up.');
  if (f.consentVendors.length) blocks.push('## Analytics & marketing cookies', `- [ ] I agree to the use of analytics and marketing cookies (${f.consentVendors.map((v) => v.name).join(', ')}).`, '> Collect per category in the cookie banner; do not load scripts that need consent before it is given. Equally prominent accept, reject and preferences buttons are good practice in the KVKK cookie guideline (2025).');
  if (f.special.some(gdprSpecial)) blocks.push('## Special category data', `- [ ] I explicitly consent to the processing of my ${f.special.filter(gdprSpecial).map((c) => c.def.en.toLowerCase()).join(', ')} for [[purpose]].`, '> Keep separate from other consents (GDPR Art.9(2)(a)).');
  if (!blocks.length) blocks.push('No processing requiring consent was detected. [[check]]');
  return join(header('en', f, 'Consent Texts'), 'Present these separately from the privacy policy. Withdrawing consent must be as easy as giving it.', blocks);
}

const INV_HEADERS = ['Category', 'Fields (location)', 'Purpose', 'Legal basis', 'Data subjects', 'Retention', 'Recipients', 'International transfer', 'Security measures'];

function recipientCell(f, catId) {
  const r = recipientsOf(f, catId);
  const out = [...new Set((r ? r.known : f.vendors).map((v) => v.group?.en).filter(Boolean))];
  if (r?.unknown.length) out.push(`[[check: recipients whose data could not be traced: ${r.unknown.map((v) => v.name).join(', ')}]]`);
  return out.join('; ') || 'Not seen in the code [[check: recipients]]';
}
function abroadCell(f, catId) {
  const r = recipientsOf(f, catId, f.abroad);
  if (!r) return f.abroad.length ? `Yes (${f.abroad.map((v) => v.name).join(', ')}) [[check: which category reaches which recipient?]]` : 'None detected [[check]]';
  if (r.known.length) return `Yes (${r.known.map((v) => v.name).join(', ')})`;
  return r.unknown.length ? `[[check: ${r.unknown.map((v) => v.name).join(', ')}]]` : 'Not seen in the code [[check]]';
}

function inventoryRows(f) {
  const a = f.answers;
  return f.categories.map((c) => [
    c.def.en + (gdprSpecial(c) ? ' (special)' : c.def.special ? ' (special under the KVKK)' : ''),
    [...c.fields.entries()].map(([k, v]) => (v.length ? `${fname(c, k)} (${v.slice(0, 2).join(', ')})` : fname(c, k))).join('; ') || '[[check: which data of this category is processed?]]',
    c.def.purposes.en.join('; '),
    c.def.basis.en,
    c.def.subjects.en,
    (a.retention && a.retention[c.id]) || c.def.retention.en,
    recipientCell(f, c.id),
    abroadCell(f, c.id),
    `${c.def.special ? 'Encryption at rest, access logging, least privilege' : 'Access control, TLS, backups'} [[check: are these measures in place? Not derived from the code]]`,
  ]);
}

export function inventoryMd(f) {
  return join(header('en', f, 'Record of Processing Activities'), 'GDPR Art.30. The same table is in `data-inventory.csv`.', mdTable(INV_HEADERS, inventoryRows(f)));
}

export function inventoryCsv(f) {
  return toCsv(INV_HEADERS, inventoryRows(f));
}

export function transfers(f) {
  return join(
    header('en', f, 'International Data Transfers'),
    f.abroad.length
      ? mdTable(['Vendor', 'Company', 'Country', 'Data sent', 'Safeguard', 'DPA'], f.abroad.map((v) => [v.name, v.company || '[[check: company]]', `${v.country} [[check: selected region]]`, dataSent(v, 'en', `${(DATA_SENT[v.category] || { en: '' }).en} [[check: data sent could not be traced; default text]]`), safeguard(v), '[[DPA link]]']))
      : 'No international transfers detected. [[check]]',
    '## Turkey (KVKK md.9)',
    'If you are a Turkish controller: there is no adequacy decision to rely on in most cases [[check]], so use the Board\'s **standard contract** and notify the Authority within **5 business days** of signing.',
    '## Checklist',
    f.abroad.map((v) => `- [ ] ${v.name}: sign DPA, choose EU region if possible, document the safeguard.`).join('\n') || '- [ ] —',
  );
}

export function breach(f) {
  const a = f.answers;
  const steps = [];
  if (f.stack.supabase) steps.push('Supabase: rotate `service_role` and `anon` keys, revoke sessions, review RLS policies and Security Advisor.');
  if (f.stack.firebase) steps.push('Firebase: lock down security rules, rotate service-account keys, review access logs.');
  if (f.stack.stripe) steps.push('Stripe: roll secret keys and webhook secrets.');
  if (f.ai.length) steps.push(`${f.ai.map((v) => v.name).join(', ')}: rotate API keys and check usage.`);
  steps.push('Rotate all secrets; purge leaked keys from git history.');
  return join(
    header('en', f, 'Personal Data Breach Response Plan'),
    `Owner: ${P(a.dpoName, 'Responsible person')} · ${contactEmail(a)}`,
    '## 1. Detect\n- [ ] Record when you became aware (the 72-hour clock starts then).',
    '## 2. Contain\n' + steps.map((s) => `- [ ] ${s}`).join('\n'),
    '## 3. Assess\n- [ ] Data categories and number of people affected, special category data, likely consequences.',
    '## 4. Notify the authority (≤ 72 hours)\nGDPR Art.33: notify the competent supervisory authority without undue delay and within 72 hours unless the breach is unlikely to result in a risk. Turkey: notify the KVKK Board within 72 hours via the breach notification form (KVKK md.12/5, Board decision 2019/10).',
    '## 5. Notify individuals\nGDPR Art.34: without undue delay if high risk. KVKK: within a reasonable time after identifying those affected.',
    '## 6. Document & improve\n- [ ] Record facts, effects and remedial action (Art.33(5)).\n- [ ] Re-run `kvkk-check` and close critical findings.',
  );
}

export function dsrForm(f) {
  const a = f.answers;
  return join(
    header('en', f, 'Data Subject Request Form'),
    `Send to ${contactEmail(a)} or ${P(a.address, 'postal address')}.`,
    mdTable(['Field', 'Value'], [['Full name', ''], ['Email used with the service', ''], ['Country of residence', '']]),
    '## Request\n- [ ] Access (Art.15)\n- [ ] Rectification (Art.16)\n- [ ] Erasure (Art.17)\n- [ ] Restriction (Art.18)\n- [ ] Portability (Art.20)\n- [ ] Objection (Art.21)\n- [ ] Withdraw consent',
    'Details: ______________________',
    'We respond within one month (extendable by two months for complex requests) and may ask you to verify your identity.',
  );
}

export function roadmap(f) {
  const items = f.findings.map((x) => {
    const locs = x.locations.filter((l) => l.file || l.label).slice(0, 3).map((l) => [L(l.label, 'en'), l.file && `\`${l.file}${l.line ? ':' + l.line : ''}\``].filter(Boolean).join(' ')).join(', ');
    return `- [ ] **[${SEV[x.severity]}] ${x.rule.title.en}** \`${x.rule.id}\`${locs ? ` — ${locs}` : ''}\n  - ${x.rule.fix.en}`;
  });
  return join(
    header('en', f, 'Compliance Roadmap'),
    f.scoreReliable ? `Scan score: **${f.score}/100**. Fix CRITICAL and HIGH first.` : `Scan score: **N/A (score not reliable)**${f.scoreReasons.length ? ` — ${f.scoreReasons.map((r) => r.en).join('; ')}` : ''}. Fix CRITICAL and HIGH first.`,
    '## Technical findings',
    items.join('\n') || 'None.',
    '## Organisational tasks',
    '- [ ] Publish privacy-policy.md and link it next to sign-up.\n- [ ] Implement consent texts with unticked boxes.\n- [ ] Publish the cookie policy and a "Cookie settings" link.\n- [ ] Sign DPAs with all processors; document transfer safeguards.\n- [ ] Define retention periods and automate deletion.\n- [ ] Set up a process for data subject requests (one month).\n- [ ] Share the breach response plan with the team.',
  );
}

export const EN_DOCS = [
  ['privacy-policy.md', privacyPolicy],
  ['cookie-policy.md', cookiePolicy],
  ['consent-texts.md', consentTexts],
  ['data-inventory.md', inventoryMd],
  ['data-inventory.csv', inventoryCsv],
  ['international-transfers.md', transfers],
  ['breach-response-plan.md', breach],
  ['dsr-request-form.md', dsrForm],
  ['compliance-roadmap.md', roadmap],
];
