// kvkk-ignore-file
/**
 * Organisational audit: what the code cannot know. The controller answers once (kvkk-answers.json, key `org`), and the answers
 * change conclusions: VERBİS registration, role, transfer mechanisms per recipient, DPIA criteria, policies.
 *
 *   ORG_QUESTIONS               [{key, type, tr, en, when?}]
 *   assessOrg(answers, model, {now}) → { items: [{id, status, severity, title, detail, refs}], dpia, answered, total, vendors }
 *     status  'action'  something is missing or wrong according to the answers
 *             'ok'      the answer says it is in place (declared, not verified)
 *             'open'    not answered, or a person has to decide
 *             'na'      does not apply according to the answers
 *
 * Every conclusion rests on a declaration and says so. Nothing here changes a code finding or the score.
 * Legal thresholds (read on 25.11.2026 on kvkk.gov.tr, the Authority's own announcements; docs/hukuki-dayanaklar.md; not reviewed
 * by a lawyer):
 *   VERBİS exemption  Board decisions 2018/87 (as amended) and 2025/1572: fewer than 50 employees AND balance sheet total below
 *                     TRY 100 million; main activity special-category data: fewer than 10 AND below TRY 10 million.
 *                     Decision 2025/2393: without balance-sheet bookkeeping only the employee criterion counts.
 *   KVKK md.9/5       the standard contract is notified to the Authority within five business days of signature.
 */

export const VERBIS_LIMITS = { general: { employees: 50, balance: 100e6 }, special: { employees: 10, balance: 10e6 } };
export const NOTIFY_BUSINESS_DAYS = 5;
export const THRESHOLDS_CHECKED = '2026-11-25';

const T = (tr, en) => ({ tr, en });

export const ORG_QUESTIONS = [
  { key: 'establishedIn', type: 'text', tr: 'Veri sorumlusu hangi ülkede yerleşik? (ülke kodu, ör. TR)', en: 'Where is the controller established? (country code, e.g. TR)' },
  { key: 'employees', type: 'number', tr: 'Yıllık çalışan sayısı (12 ayın en az 7\'sinde bildirilen)', en: 'Annual number of employees (as reported in at least 7 of 12 months)' },
  { key: 'balanceSheetBooks', type: 'bool', tr: 'Bilanço esasına göre mi defter tutuyorsunuz?', en: 'Do you keep books on a balance-sheet basis?' },
  { key: 'balanceSheetTRY', type: 'number', tr: 'Yıllık mali bilanço toplamı (TL; ciro değil, aktif/pasif toplamı)', en: 'Annual balance sheet total in TRY (not turnover)', when: (a) => a.balanceSheetBooks !== false },
  { key: 'mainActivitySpecial', type: 'bool', tr: 'Ana faaliyet konunuz özel nitelikli veri (sağlık, biyometrik vb.) işlemek mi?', en: 'Is processing special-category data your main activity?' },
  { key: 'verbisRegistered', type: 'bool', tr: 'VERBİS kaydınız var mı?', en: 'Are you registered with VERBİS?' },
  { key: 'role', type: 'choice', choices: ['controller', 'processor', 'both'], tr: 'Rolünüz: controller (veri sorumlusu), processor (müşterileriniz adına veri işleyen), both (ikisi de)', en: 'Your role: controller, processor (on behalf of your customers), both' },
  { key: 'customerDpa', type: 'bool', tr: 'Adına veri işlediğiniz müşterilerle veri işleme sözleşmesi yapıyor musunuz?', en: 'Do you sign a data processing agreement with the customers you process for?', when: (a) => a.role === 'processor' || a.role === 'both' },
  { key: 'largeScale', type: 'bool', tr: 'Büyük ölçekli mi işliyorsunuz? (kişi sayısı, veri hacmi, süre ve coğrafyaya göre sizin değerlendirmeniz; kanunda sayı yok)', en: 'Is the processing large-scale? (your own assessment of number of people, volume, duration, area; the law gives no number)' },
  { key: 'minors', type: 'bool', tr: 'Hizmet 18 yaş altına açık mı?', en: 'Is the service open to people under 18?' },
  { key: 'parentalConsent', type: 'bool', tr: 'Çocuklar için veli onayı alıyor musunuz?', en: 'Do you obtain parental consent for children?', when: (a) => a.minors === true },
  { key: 'retentionPolicy', type: 'bool', tr: 'Yazılı saklama ve imha politikanız var mı (veri kategorisi başına süre)?', en: 'Is there a written retention and disposal policy (period per data category)?' },
  { key: 'accessControl', type: 'bool', tr: 'Üretim verisine kimlerin eriştiği yazılı ve yetkiyle sınırlı mı?', en: 'Is access to production data documented and limited by role?' },
  { key: 'accessLogged', type: 'bool', tr: 'Üretim verisine erişimler kaydediliyor mu?', en: 'Is access to production data logged?' },
  { key: 'breachPlan', type: 'bool', tr: 'Veri ihlali planınız ve 72 saat içinde bildirim prosedürünüz var mı?', en: 'Is there a breach plan with 72-hour notification?' },
  { key: 'dpiaDone', type: 'bool', tr: 'Etki değerlendirmesi (DPIA) yapıldı ve belgelendi mi?', en: 'Has a DPIA been carried out and documented?' },
  { key: 'liaDone', type: 'bool', tr: 'Meşru menfaate dayanan faaliyetler için denge testi (LIA) belgelendi mi?', en: 'Is there a documented LIA for activities based on legitimate interest?' },
  { key: 'targetsEU', type: 'bool', tr: 'AB\'deki kişilere hizmet veriyor ya da onları izliyor musunuz?', en: 'Do you offer services to, or monitor, people in the EU?' },
  { key: 'storeForms', type: 'choice', choices: ['checked', 'unchecked', 'no-app'], tr: 'App Store gizlilik etiketi ve Google Play Veri güvenliği formu rapordaki veri listesiyle karşılaştırıldı mı? (checked / unchecked / no-app: mağazada uygulama yok)', en: 'Were the App Store label and the Play Data safety form compared with the data list of the report? (checked / unchecked / no-app)' },
  { key: 'euRepresentative', type: 'bool', tr: 'AB temsilcisi atandı mı (GDPR Art.27)?', en: 'Has an EU representative been appointed (Art.27)?', when: (a) => a.targetsEU === true },
];

export const MECHANISMS = ['adequacy', 'standard-contract', 'bcr', 'undertaking', 'incidental', 'consent'];

/** Questions per recipient abroad: org.vendors[<vendorId>] */
export const VENDOR_QUESTIONS = [
  { key: 'dpa', type: 'bool', tr: 'Veri işleme sözleşmesi (DPA) imzalı mı?', en: 'Is a DPA in place?' },
  { key: 'mechanism', type: 'choice', choices: MECHANISMS, tr: 'KVKK md.9 aktarım aracı', en: 'Transfer mechanism (KVKK Art.9)' },
  { key: 'signedAt', type: 'date', tr: 'Standart sözleşme imza tarihi (YYYY-AA-GG)', en: 'Standard contract signed on (YYYY-MM-DD)' },
  { key: 'notifiedAt', type: 'date', tr: 'Kurum\'a bildirim tarihi (YYYY-AA-GG)', en: 'Notified to the Authority on (YYYY-MM-DD)' },
  { key: 'region', type: 'text', tr: 'Seçilen veri bölgesi (ör. EU, TR, US)', en: 'Selected data region (e.g. EU, TR, US)' },
];

const known = (v) => v !== undefined && v !== null && v !== '';
const day = (s) => {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  const d = new Date(`${s}T00:00:00Z`);
  return Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== s ? null : d;
};
/** Weekdays after `from` up to and including `to`. Public holidays are not known here. */
export function businessDaysBetween(from, to) {
  let n = 0;
  for (let t = from.getTime() + 864e5; t <= to.getTime(); t += 864e5) { const w = new Date(t).getUTCDay(); if (w !== 0 && w !== 6) n++; }
  return n;
}

/** Keep only the answers of the expected type; a wrong type counts as unanswered and is reported. */
export function cleanOrg(raw) {
  const org = {}, problems = [];
  const src = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const take = (q, v, where) => {
    if (!known(v)) return undefined;
    const ok = q.type === 'bool' ? typeof v === 'boolean' : q.type === 'number' ? typeof v === 'number' && Number.isFinite(v) && v >= 0 : q.type === 'choice' ? q.choices.includes(v) : q.type === 'date' ? !!day(v) : typeof v === 'string';
    if (!ok) { problems.push(where); return undefined; }
    return q.type === 'text' ? v.trim().slice(0, 200) : v;
  };
  for (const q of ORG_QUESTIONS) { const v = take(q, src[q.key], q.key); if (v !== undefined) org[q.key] = v; }
  org.vendors = {};
  for (const [id, a] of Object.entries(src.vendors && typeof src.vendors === 'object' ? src.vendors : {})) {
    const x = {};
    for (const q of VENDOR_QUESTIONS) { const v = take(q, a?.[q.key], `vendors.${id}.${q.key}`); if (v !== undefined) x[q.key] = v; }
    if (Object.keys(x).length) org.vendors[id] = x;
  }
  return { org, problems };
}

/** Distinct recipients abroad (KVKK) of the transfer register. */
export function recipientsAbroad(model) {
  const out = new Map();
  for (const r of model?.transfers || []) {
    if (r.abroadKvkk !== true) continue;
    const id = r.vendorId || r.sinkId;
    if (!id) continue;
    const e = out.get(id) || { id, name: r.vendor, country: r.country, category: r.category, elements: [], special: false, evidence: [], thirdCountryGdpr: r.thirdCountryGdpr === true, regionSelectable: r.regionSelectable === true };
    for (const x of r.elements || []) if (!e.elements.some((y) => y.name === x.name)) e.elements.push(x);
    e.special ||= r.special === true || (r.elements || []).some((x) => x.sensitivity === 'special');
    e.evidence.push(...(r.evidence || []));
    out.set(id, e);
  }
  return [...out.values()];
}

function verbis(a, hasSpecial) {
  const refs = ['KVKK md.16'];
  const title = T('VERBİS kaydı', 'VERBİS registration');
  const it = (status, severity, tr, en) => ({ id: 'ORG-VERBIS', status, severity, title, detail: T(tr, en), refs });
  if (known(a.establishedIn) && !/^TR$/i.test(a.establishedIn)) {
    const reg = a.verbisRegistered;
    return it(reg === true ? 'ok' : reg === false ? 'action' : 'open', reg === true ? 'low' : reg === false ? 'high' : 'medium',
      `Yurt dışında yerleşik veri sorumlularında çalışan sayısı, bilanço ve ana faaliyet ölçütleri dikkate alınmaz (Sorularla VERBİS); Türkiye'de temsilci atanarak kayıt yapılır. ${reg === true ? 'Kayıt yapıldığı beyan edildi.' : reg === false ? 'Kayıt gerekli görünüyor, ama yok.' : 'Kayıt durumu cevaplanmadı.'} Kurulun diğer istisnaları ve KVKK'nın size uygulanıp uygulanmadığı değerlendirilmedi; hukukçuya danışın.`,
      `For controllers established abroad the employee, balance-sheet and main-activity criteria are not considered (the Authority's VERBİS FAQ); registration goes through a representative in Turkey. ${reg === true ? 'Declared as registered.' : reg === false ? 'Registration appears required, but there is none.' : 'Registration status not answered.'} Other exemptions of the Board and whether the KVKK applies to you were not assessed; ask a lawyer.`);
  }
  if (!known(a.employees) || !known(a.mainActivitySpecial)) return it('open', 'medium', 'Çalışan sayısı ve ana faaliyet cevaplanmadan kayıt yükümlülüğü belirlenemez.', 'The duty cannot be determined without the number of employees and the main activity.');
  const lim = a.mainActivitySpecial ? VERBIS_LIMITS.special : VERBIS_LIMITS.general;
  const under = a.employees < lim.employees;
  let exempt = null;
  if (!under) exempt = false;
  else if (a.balanceSheetBooks === false) exempt = true;
  else if (a.balanceSheetBooks === true && known(a.balanceSheetTRY)) exempt = a.balanceSheetTRY < lim.balance;
  if (exempt === null) return it('open', 'medium', 'Defter tutma usulü ve bilanço toplamı cevaplanmadı.', 'Bookkeeping basis and balance sheet total are not answered.');
  const m = (n) => `${n / 1e6}`;
  const rule = T(`Ölçüt: ${a.mainActivitySpecial ? 'ana faaliyet özel nitelikli veri' : 'genel'}; ${lim.employees}'den az çalışan${a.balanceSheetBooks === false ? '' : ` ve ${m(lim.balance)} milyon TL'den az bilanço`} (eşikler ${THRESHOLDS_CHECKED} tarihinde kvkk.gov.tr duyurularından okundu; güncel Kurul kararını doğrulayın).`,
    `Criterion: ${a.mainActivitySpecial ? 'main activity special-category data' : 'general'}; fewer than ${lim.employees} employees${a.balanceSheetBooks === false ? '' : ` and a balance sheet below TRY ${m(lim.balance)} million`} (thresholds read ${THRESHOLDS_CHECKED} on kvkk.gov.tr; verify the current Board decision).`);
  if (exempt) {
    const warn = hasSpecial && !a.mainActivitySpecial ? T(' Kodda özel nitelikli veri bulundu; "ana faaliyet değil" cevabını doğrulayın.', ' Special-category data was found in the code; confirm that it is not your main activity.') : T('', '');
    return it(warn.tr ? 'open' : 'na', 'low', `Beyana göre kayıttan istisna görünüyorsunuz. ${rule.tr} İstisna yalnızca VERBİS kaydını kapsar; aydınlatma, güvenlik ve saklama yükümlülükleri sürer.${warn.tr}`, `According to the answers you appear exempt. ${rule.en} The exemption covers registration only.${warn.en}`);
  }
  if (a.verbisRegistered === true) return it('ok', 'low', `Kayıt gerekli ve yapıldığı beyan edildi. ${rule.tr} Envanterle VERBİS bildiriminin aynı olduğunu kontrol edin.`, `Registration is required and declared as done. ${rule.en} Check that the register matches the inventory.`);
  if (a.verbisRegistered === false) return it('action', 'high', `Kayıt gerekli görünüyor, ama kayıt yok. ${rule.tr}`, `Registration appears required, but there is none. ${rule.en}`);
  return it('open', 'medium', `Kayıt gerekli görünüyor; kayıt durumu cevaplanmadı. ${rule.tr}`, `Registration appears required; its status is not answered. ${rule.en}`);
}

function transferItem(v, a, now) {
  const refs = ['KVKK md.9', ...(v.thirdCountryGdpr ? ['GDPR Art.44-46'] : []), 'GDPR Art.28'];
  const title = T(`Aktarım: ${v.name}`, `Transfer: ${v.name}`);
  const sev = v.special ? 'high' : 'medium';
  const bad = [], open = [], notes = [];
  if (a?.dpa === false) bad.push(T('veri işleme sözleşmesi (DPA) yok', 'no data processing agreement'));
  else if (a?.dpa !== true) open.push(T('DPA durumu cevaplanmadı', 'DPA status not answered'));
  const inTurkey = /^(?:TR|Türkiye|Turkiye|Turkey)$/i.test(a?.region || '');
  if (inTurkey) open.push(T('veri bölgesi Türkiye olarak beyan edildi; alıcının yurt dışından erişimi (destek, alt işleyen) varsa bu da aktarımdır, doğrulayın', 'data region declared as Turkey; access from abroad (support, sub-processors) is still a transfer, verify'));
  else switch (a?.mechanism) {
    case undefined: open.push(T('aktarım aracı cevaplanmadı', 'transfer mechanism not answered')); break;
    case 'standard-contract': {
      const s = day(a.signedAt), n = day(a.notifiedAt);
      if (!s) open.push(T('standart sözleşmenin imza tarihi girilmedi', 'signature date of the standard contract is missing'));
      else if (s > now) bad.push(T('imza tarihi gelecekte', 'the signature date is in the future'));
      else if (n && n < s) bad.push(T('bildirim tarihi imzadan önce', 'the notification date precedes the signature'));
      else if (!n && businessDaysBetween(s, now) > NOTIFY_BUSINESS_DAYS) bad.push(T('standart sözleşme Kurum\'a bildirilmemiş; 5 iş günü geçmiş', 'the standard contract was not notified; five business days have passed'));
      else if (!n) open.push(T(`Kurum'a bildirim bekleniyor (imzadan ${businessDaysBetween(s, now)} iş günü geçti)`, `notification pending (${businessDaysBetween(s, now)} business days since signature)`));
      else if (businessDaysBetween(s, n) > NOTIFY_BUSINESS_DAYS) bad.push(T(`bildirim ${businessDaysBetween(s, n)} iş gününde yapılmış (süre 5)`, `notified after ${businessDaysBetween(s, n)} business days (limit 5)`));
      else notes.push(T('standart sözleşme imzalı ve süresinde bildirilmiş', 'standard contract signed and notified in time'));
      if (s) notes.push(T('resmî tatiller hesaba katılmadı', 'public holidays are not considered'));
      break;
    }
    case 'adequacy': open.push(T('Kurul\'un bu ülke/sektör için yeterlilik kararı olduğunu doğrulayın', 'confirm that the Board issued an adequacy decision for this country / sector')); break;
    case 'incidental': bad.push(T('arızi aktarım istisnası düzenli kullanılan bir hizmete dayanak olmaz', 'the incidental-transfer exception does not support a service in regular use')); break;
    case 'consent': bad.push(T('açık rıza yalnızca arızi aktarımlarda istisnadır; düzenli hizmete dayanak olmaz', 'explicit consent is an exception for incidental transfers only')); break;
    // bcr, undertaking: valid only with a Board decision the tool cannot see
    default: open.push(T(`beyan edilen araç: ${a.mechanism}; Kurul onayı/izni belgesini doğrulayın`, `declared mechanism: ${a.mechanism}; verify the Board's approval`)); break;
  }
  const j = (lang) => [...bad, ...open, ...notes].map((x) => x[lang]).join('; ');
  const data = (lang) => v.elements.map((e) => e.label?.[lang] || e.name).slice(0, 6).join(', ');
  return {
    id: 'ORG-TRANSFER', vendorId: v.id, status: bad.length ? 'action' : open.length ? 'open' : 'ok', severity: sev, title,
    detail: T(`${v.country}; ${data('tr')}. ${j('tr')}.`, `${v.country}; ${data('en')}. ${j('en')}.`), refs,
  };
}

export function assessOrg(rawOrg, model, { now = new Date(), criteria = null } = {}) {
  const { org: a, problems } = cleanOrg(rawOrg);
  const items = [];
  const specialEls = (model?.inventory || []).filter((e) => e.sensitivity === 'special');
  const add = (id, status, severity, title, detail, refs) => items.push({ id, status, severity, title, detail, refs });
  /** yes → ok, no → action, unanswered → open */
  const yesNo = (key, id, severity, title, okD, noD, refs) => add(id, a[key] === true ? 'ok' : a[key] === false ? 'action' : 'open', severity, title, a[key] === true ? okD : a[key] === false ? noD : T('Cevaplanmadı.', 'Not answered.'), refs);

  items.push(verbis(a, specialEls.length > 0));

  if (!known(a.role)) add('ORG-ROLE', 'open', 'medium', T('Rol', 'Role'), T('Veri sorumlusu mu, veri işleyen mi olduğunuz cevaplanmadı. Bu, aydınlatma ve haklar yükümlülüğünün kimde olduğunu belirler.', 'Controller or processor is not answered; it decides who owes notice and data subject rights.'), ['KVKK md.3', 'GDPR Art.4(7)-(8)']);
  else if (a.role === 'controller') add('ORG-ROLE', 'na', 'low', T('Rol: veri sorumlusu', 'Role: controller'), T('Aydınlatma, haklar, güvenlik ve aktarım yükümlülükleri size aittir.', 'Notice, rights, security and transfer duties are yours.'), ['KVKK md.10-12']);
  else {
    add('ORG-ROLE', 'open', 'medium', T(a.role === 'both' ? 'Rol: hem veri sorumlusu hem veri işleyen' : 'Rol: veri işleyen', a.role === 'both' ? 'Role: controller and processor' : 'Role: processor'),
      T('Müşterileriniz adına işlediğiniz veride aydınlatma ve hak başvuruları müşteride, güvenlik birlikte sizdedir (KVKK md.12/2). Rapordaki aydınlatma ve hak bulgularının hangi veri için sizde olduğunu ayırın; aynı veriyi kendi amacınız için kullanıyorsanız o kısım için veri sorumlususunuz.', 'For data processed on behalf of customers, notice and rights requests are theirs, security is shared. Decide for which data the notice and rights findings apply to you; using that data for your own purposes makes you its controller.'), ['KVKK md.12/2', 'GDPR Art.28']);
    yesNo('customerDpa', 'ORG-CUSTOMER-DPA', 'high', T('Müşteri veri işleme sözleşmeleri', 'Customer DPAs'), T('Yapıldığı beyan edildi.', 'Declared as in place.'), T('Adına veri işlediğiniz müşterilerle sözleşme yok.', 'No agreement with the customers you process for.'), ['KVKK md.12/2', 'GDPR Art.28(3)']);
  }

  for (const v of recipientsAbroad(model)) items.push(transferItem(v, a.vendors[v.id], now));

  yesNo('retentionPolicy', 'ORG-RETENTION', 'medium', T('Saklama ve imha politikası', 'Retention and disposal policy'), T('Var olduğu beyan edildi. Kodda süre dolanı silen bir iş bulunmadıysa politika uygulanmıyor olabilir.', 'Declared. If no purge job was found in the code the policy may not be applied.'), T('Yazılı politika yok.', 'No written policy.'), ['KVKK md.7', 'GDPR Art.5(1)(e)']);
  yesNo('accessControl', 'ORG-ACCESS', 'high', T('Üretim verisine erişim yetkisi', 'Access to production data'), T('Yetkiyle sınırlı olduğu beyan edildi.', 'Declared as limited by role.'), T('Erişim yazılı ve sınırlı değil.', 'Access is not documented and limited.'), ['KVKK md.12', 'GDPR Art.32']);
  yesNo('accessLogged', 'ORG-ACCESS-LOG', 'medium', T('Erişim kayıtları', 'Access logs'), T('Tutulduğu beyan edildi.', 'Declared.'), T('Erişim kaydı tutulmuyor.', 'Access is not logged.'), ['KVKK md.12', 'GDPR Art.32']);
  yesNo('breachPlan', 'ORG-BREACH', 'medium', T('Veri ihlali planı', 'Breach plan'), T('Var olduğu beyan edildi.', 'Declared.'), T('İhlal planı ve 72 saatlik bildirim prosedürü yok.', 'No breach plan with 72-hour notification.'), ['KVKK md.12/5', 'GDPR Art.33']);

  if (a.minors === true) yesNo('parentalConsent', 'ORG-MINORS', 'high', T('Çocukların verisi', 'Children\'s data'), T('Veli onayı alındığı beyan edildi.', 'Parental consent declared.'), T('Hizmet çocuklara açık ama veli onayı alınmıyor. GDPR Art.8, rızaya dayanan hizmetlerde 16 yaş altında (üye devlet 13\'e kadar indirebilir) veli onayı arar; KVKK bakımından hukukçuya danışın.', 'Open to children without parental consent. GDPR Art.8 requires it below 16 (Member States may lower it to 13) where the service relies on consent; for the KVKK ask a lawyer.'), ['GDPR Art.8']);
  else add('ORG-MINORS', a.minors === false ? 'na' : 'open', 'medium', T('Çocukların verisi', 'Children\'s data'), a.minors === false ? T('Hizmetin 18 yaş altına kapalı olduğu beyan edildi; kayıt akışında yaş kontrolü olduğunu doğrulayın.', 'Declared closed to minors; confirm that sign-up checks age.') : T('Cevaplanmadı.', 'Not answered.'), ['GDPR Art.8']);

  if (known(a.storeForms) && a.storeForms !== 'no-app') add('ORG-STORE', a.storeForms === 'checked' ? 'ok' : 'action', 'medium', T('Mağaza beyanları', 'Store declarations'), a.storeForms === 'checked' ? T('Karşılaştırıldığı beyan edildi.', 'Declared as compared.') : T('App Store etiketi ve Play Veri güvenliği formu depoda değildir; rapordaki veri ve alıcı listesiyle elle karşılaştırın.', 'The App Store label and the Play Data safety form are not in the repository; compare them by hand with the data and recipients of the report.'), ['KVKK md.10', 'GDPR Art.13']);

  // DPIA: criteria from the code plus what only the controller knows
  const fromCode = criteria || model?.dpia?.criteria || [];
  const fromOrg = [...(a.largeScale === true ? ['largeScale'] : []), ...(a.minors === true ? ['vulnerable'] : [])].filter((x) => !fromCode.includes(x));
  const all = [...fromCode, ...fromOrg];
  const dpia = { criteria: all, fromCode: [...fromCode], fromOrg, required: all.length >= 2, changed: fromOrg.length > 0 && all.length >= 2 && fromCode.length < 2 };
  if (dpia.required) yesNo('dpiaDone', 'ORG-DPIA', a.targetsEU === false ? 'medium' : 'high', T('Etki değerlendirmesi (DPIA)', 'DPIA'), T('Yapıldığı beyan edildi; bu raporun kapsadığı faaliyetleri içerdiğini doğrulayın.', 'Declared as done; confirm it covers the activities in this report.'), T('İki veya daha fazla ölçüt karşılanıyor ama DPIA yapılmamış. (Zorunluluk GDPR kapsamındadır; KVKK\'da aynı adla bir yükümlülük yoktur.)', 'Two or more criteria are met but no DPIA was done. (A GDPR duty; the KVKK has none by that name.)'), ['GDPR Art.35']);
  else add('ORG-DPIA', known(a.largeScale) && known(a.minors) ? 'na' : 'open', 'medium', T('Etki değerlendirmesi (DPIA)', 'DPIA'), known(a.largeScale) && known(a.minors) ? T('Kod ve cevaplara göre ikiden az ölçüt karşılanıyor. Bu, gerekmediğinin kanıtı değildir.', 'Fewer than two criteria by code and answers; that does not prove it is unnecessary.') : T('Ölçek ve yaş grubu cevaplanmadan belirlenemez.', 'Cannot be decided without scale and age group.'), ['GDPR Art.35']);

  const li = (model?.activities || []).filter((x) => (x.legalBasis || []).some((b) => b.key === 'legitimate-interest'));
  if (li.length) yesNo('liaDone', 'ORG-LIA', 'medium', T('Meşru menfaat denge testi (LIA)', 'Legitimate interest assessment'), T('Belgelendiği beyan edildi.', 'Declared as documented.'), T(`${li.length} faaliyet meşru menfaate dayanabilir ama denge testi yok.`, `${li.length} activities may rest on legitimate interest, but there is no LIA.`), ['KVKK md.5/2-f', 'GDPR Art.6(1)(f)']);

  if (a.targetsEU === true && known(a.establishedIn)) {
    const EU = /^(?:AT|BE|BG|HR|CY|CZ|DK|EE|FI|FR|DE|GR|HU|IE|IT|LV|LT|LU|MT|NL|PL|PT|RO|SK|SI|ES|SE|IS|LI|NO|EU)$/i;
    if (!EU.test(a.establishedIn)) yesNo('euRepresentative', 'ORG-EU-REP', 'medium', T('AB temsilcisi', 'EU representative'), T('Atandığı beyan edildi.', 'Declared as appointed.'), T('AB\'deki kişilere hizmet veriliyor ama temsilci yok. Art.27(2) istisnasını değerlendirin.', 'People in the EU are served but there is no representative; consider the Art.27(2) exception.'), ['GDPR Art.27']);
  }

  const applicable = ORG_QUESTIONS.filter((q) => !q.when || q.when(a));
  const order = { action: 0, open: 1, ok: 2, na: 3 };
  const sev = { high: 0, medium: 1, low: 2 };
  items.sort((x, y) => order[x.status] - order[y.status] || sev[x.severity] - sev[y.severity]);
  return {
    provided: Object.keys(a).some((k) => k !== 'vendors') || Object.keys(a.vendors).length > 0,
    items, dpia, problems,
    answered: applicable.filter((q) => known(a[q.key])).length, total: applicable.length,
    unanswered: applicable.filter((q) => !known(a[q.key])).map((q) => ({ key: q.key, tr: q.tr, en: q.en })),
    answers: a,
  };
}

/** One question per line as the reports list them: what is still open, or the fixed list when nothing was answered. */
export function openQuestions(assessment) {
  return (assessment?.unanswered || []).map((q) => ({ tr: q.tr, en: q.en }));
}

export const ORG_STATUS = {
  action: { tr: 'EKSİK', en: 'MISSING' }, open: { tr: 'AÇIK', en: 'OPEN' }, ok: { tr: 'BEYAN EDİLDİ', en: 'DECLARED' }, na: { tr: 'UYGULANMIYOR', en: 'N/A' },
};
export const ORG_TEXT = {
  title: { tr: 'Organizasyon denetimi (beyana dayalı)', en: 'Organisational audit (based on declarations)' },
  hint: { tr: 'Cevaplar kvkk-answers.json dosyasından gelir ve doğrulanmaz; kod bulgularını ve skoru değiştirmez.', en: 'Answers come from kvkk-answers.json and are not verified; they change no code finding and no score.' },
  how: { tr: 'Cevaplamak için: kvkk-check anket', en: 'To answer: kvkk-check anket' },
  dpiaChanged: { tr: 'Cevaplarla birlikte iki DPIA ölçütü karşılanıyor', en: 'Together with the answers, two DPIA criteria are met' },
};

/** Skeleton for kvkk-answers.json: existing answers kept, missing ones null. */
export function orgTemplate(existing, model) {
  const prev = existing && typeof existing === 'object' ? existing : {};
  const org = {};
  for (const q of ORG_QUESTIONS) org[q.key] = known(prev[q.key]) ? prev[q.key] : null;
  org.vendors = { ...(prev.vendors && typeof prev.vendors === 'object' ? prev.vendors : {}) };
  for (const v of recipientsAbroad(model)) {
    const p = org.vendors[v.id] || {};
    org.vendors[v.id] = Object.fromEntries(VENDOR_QUESTIONS.map((q) => [q.key, known(p[q.key]) ? p[q.key] : null]));
  }
  return org;
}
