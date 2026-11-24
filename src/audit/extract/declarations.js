// kvkk-ignore-file  (keyword maps for privacy policy parsing)
/**
 * Declarations extractor: privacy notice / aydınlatma metni / cookie policy texts found in the repo
 * (and from the live scan when available) → Declaration nodes + declaredIn edges.
 *
 *   declaration:policy:<file|live>  {kind:'privacy'|'cookie', file, url?, text, declaredData:[element], declaredVendors:[vendorId],
 *                                    declaresNoTransferAbroad, declaresTransferAbroad, declaredRetention, declaredRights,
 *                                    declaredPurposes, declaredLegalBasis, controller, contactEmail, language,
 *                                    placeholder: bool}   placeholder = lorem ipsum / no substance (a page that only looks like a notice)
 *                                   + language (en/tr/de/… or a script name such as 'thai'), script, languageSupported (the
 *                                     keyword maps can read it: LEXICON_LANGUAGES), languageConfidence
 *                                   + noticeRank 0-3 / noticeRole (policy | cookie-policy | privacy-path | mention), and on the
 *                                     one notice chosen for comparison: chosen:true, chosenReason {code,tr,en}
 *   ctx.shared.notice                {id, file, url, rank, role, reason, language, languageSupported}: the chosen notice
 *   ctx.shared.unparsed (C2)         {layer:'declarations', kind:'notice-language', reason, files} when the chosen notice is in a
 *                                    language/script the lexicon cannot read and no readable notice-grade text exists
 *   declaration:policy:external     {kind:'privacy', external:true, url, urlExpr?, refs:[{file,line,url}], text:''}
 *                                    emitted only when the repo has no textual notice but links to one hosted elsewhere
 *                                    (privacyPolicyUrl config, <a href=…privacy…>, "Privacy" link text, short redirect stubs)
 *                                   + declaredIdps: login providers the notice lists ('google', 'github' …; compare with the
 *                                     configured identity providers, never a recipient mention by itself)
 *                                   + parsed: false when the lexicon cannot read the text (language / script in `language`)
 *   ctx.shared.unparsedNotices       [{file, parsed:false, reason, language}] notice files that exist but carry no readable text
 *                                     in the repo (translated through i18n keys, PDF / Word documents)
 *   edges: declaredIn  DataElement → Declaration, Sink(vendor) → Declaration   (only for nodes that already exist)
 */
import fs from 'node:fs';
import path from 'node:path';
import { parseFile, walk } from './_jsx.js';
import { annotateVendorUsage } from './endpoints-ext.js';

export const name = 'declarations';
export const order = 65; // after flow (40) and live (60)

const PATH_PRIVACY = /(privacy|gizlilik|kvkk|aydinlatma|aydınlatma|veri[-_]?koruma|data[-_]?protection)/i;
const PATH_COOKIE = /(cookie|cerez|çerez)/i;

export const DATA_KEYWORDS = [
  ['full_name', /\bad[ıi]?\s*,?\s*soyad|ad-soyad|\bisim\b|\bfull name\b|\byour name\b|\bname\b/i],
  ['email', /e-?posta|e-?mail/i],
  ['phone', /telefon|\bphone\b|\bgsm\b|cep numara/i],
  // "kvkk@x.com adresine başvurun" / "email address" are not postal addresses.
  ['address', /(ikamet|teslimat|fatura|açık|posta|ev|iş|kargo)\s+adres|\badres bilgi|\badresiniz\b(?!e)|(?<!e-?posta\s)(?<!e-?mail\s)\badres(?!ine|e\s|i\s|inden)\b|postal address|shipping address|billing address|home address|(?<!e-?mail\s)(?<!ip\s)\baddress(es)?\b/i],
  ['birth_date', /doğum tarih|dogum tarih|date of birth|birth ?date|doğum günü/i],
  ['national_id', /t\.?c\.? kimlik|kimlik numara|national id|identity number|tckn/i],
  ['health', /sağlık|saglik|\bhealth\b|tıbbi|medical/i],
  ['precise_location', /\bkonum|\blocation\b|\bgps\b|coğrafi/i],
  ['ip_address', /\bip adres|\bip address|\bIP\b/],
  ['device_id', /cihaz (kimli|bilgi)|device (id|identifier|information)|reklam kimli|advertising id/i],
  ['payment_info', /ödeme bilgi|odeme bilgi|payment (information|details)|fatura bilgi|billing/i],
  ['card_number', /kart bilgi|kart numara|card (number|details)|kredi kartı/i],
  ['order_history', /sipariş|siparis|\border(s)?\b|satın alma|purchase history/i],
  ['password', /şifre|parola|\bpassword/i],
  ['photo', /fotoğraf|fotograf|\bphoto|avatar|profil resmi|görsel|profile (picture|image)/i],
  ['voice_video', /ses kayd|video kayd|voice recording|audio recording/i],
  // Policies describe user content in their own words: "search queries", "the questions you submit", "prompts",
  // "files you upload", "conversations", "feedback".
  ['free_text', /mesaj|\bmessage|yorum|\bcomment|sohbet|\bchat\b|içerik|user content|search quer|\bquer(y|ies)\b|questions (and searches )?you|\bprompts?\b|\binputs?\b|content (that )?you|you (submit|enter|type|write|provide|share|post)\b|conversation|feedback|arama sorgu|girdi(ler)?iniz|sorgular/i],
  // Subscription / payment history and invoices are the customer-transaction record.
  ['order_history', /payment history|transaction history|billing history|subscription (data|status|history|information|details)|invoices?\b|ödeme geçmiş|işlem geçmiş|abonelik bilgi|fatura geçmiş/i],
  ['username', /\buser ?names?\b|kullanıcı ad|\b(social|social media|twitter|x|instagram|github|tiktok) handles?\b|screen name|display name/i],
  ['approx_location', /\blocation\b|\bkonum|\bcity\b|şehir|time ?zone|saat dilimi|country of residence|ikamet (ettiğiniz )?(il|ülke)/i],
  ['uploaded_file', /files? (that )?you (upload|attach|share|provide)|uploaded (files?|documents?)|attachments?\b|yüklediğiniz (dosya|belge)/i],
  ['uploaded_image', /images? (that )?you (upload|share|provide)|uploaded (images?|photos?)|photos? (that )?you upload|yüklediğiniz (görsel|fotoğraf|resim)/i],
  ['marketing_consent', /pazarlama|kampanya|\bmarketing\b|ticari elektronik ileti|newsletter|bülten/i],
  ['biometric', /biyometrik|biometric|yüz tanıma|face recognition|parmak izi|fingerprint/i],
  ['employment', /meslek|iş bilgi|occupation|employment|özgeçmiş|\bcv\b/i],
  ['user_agent', /tarayıcı (bilgi|türü)|browser (type|information)|user agent/i],
];

const NO_TRANSFER = [
  /yurt\s*dış[ıi]na\s+(hiçbir\s+şekilde\s+|kesinlikle\s+)?aktar[ıi]?l?ma(mak|z|yacak|maktad[ıi]r|m[ıi]yor|mamaktad[ıi]r)/i,
  /yurt\s*dış[ıi]na\s+aktarm[ıi]yoruz/i,
  /yurt\s*dış[ıi]nda\s+(saklanmamaktad[ıi]r|işlenmemektedir|tutulmamaktad[ıi]r)/i,
  /(do not|don't|never|will not|won't)\s+transfer[^.]{0,80}(outside|abroad|other countr|third countr)/i,
  /(is|are|will)\s+not\s+(be\s+)?transferred\s+(outside|abroad|to (any )?(other|third) countr)/i,
];
const YES_TRANSFER = [/yurt\s*dış[ıi]na\s+aktar[ıi]l(abilir|maktad[ıi]r|ır)/i, /yurt\s*dış[ıi]ndaki/i, /transfer(red)?\s+(to|outside)[^.]{0,60}(countr|united states|abd|usa|eu|abroad)/i, /international transfer/i, /standart sözleşme|standard contractual clauses|\bSCC/i];
const RETENTION = /saklama süre|süre(si)? boyunca saklan|saklanacakt|imha|retention|retain(ed|s)?\b[^.]{0,30}\bfor\b|stored for|kept for|delete[sd]? after/i;
const RIGHTS = /md\.?\s*11|11\.\s*madde|madde\s*11|haklar[ıi]n[ıi]z|ilgili kişi hak|your rights|right to (access|erasure|rectif|object|portab)|başvur/i;
const LEGAL_BASIS = /hukuki sebep|hukuki dayanak|legal basis|lawful basis|md\.?\s*5|madde\s*5|açık rıza|meşru menfaat|sözleşmenin (kurulması|ifası)|legitimate interest|performance of (a )?contract|consent/i;
const PURPOSE = /amac[ıi]yla|amaçlar[ıi]|amaçla|purpose|in order to|için işl/i;

function textFromJsx(file) {
  const ast = parseFile(file);
  if (!ast) return file.content;
  const parts = [];
  walk(ast, (n, parents) => {
    const inJsx = parents.some((p) => p.type === 'JSXElement' || p.type === 'JSXFragment');
    if (n.type === 'JSXText') parts.push(n.value);
    else if (inJsx && n.type === 'StringLiteral' && parents[parents.length - 1]?.type !== 'JSXAttribute') parts.push(n.value);
    else if (inJsx && n.type === 'TemplateElement') parts.push(n.value.cooked);
    else if (!inJsx && n.type === 'StringLiteral' && n.value.length > 60) parts.push(n.value); // long text constants (policy arrays)
  });
  return parts.join(' ').replace(/\s+/g, ' ').trim();
}

function textFromMarkup(content) {
  return content
    .replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/[#*_>`|]/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

const EVERYDAY_WORD = /^(line|render|railway|branch|adjust|segment|insider|polar|parallel|axiom|luma|clarity|exa|amplitude|neon|fly|crisp|replicate|together|sentry|claude|plausible|unsplash|stripe)$/i;

function vendorPatterns(vendors) {
  const out = [];
  for (const v of vendors) {
    const names = new Set();
    for (const part of v.name.split(/\s*\/\s*|\s*\(\s*|\)\s*/)) {
      const p = part.trim();
      if (p.length >= 4 && !/^(servis|service|seçilen|e-posta|email|google|meta|microsoft|facebook|cloud|web|sdk|make|pixel|push|messaging api)$/i.test(p) && !/[{}]/.test(p)) names.add(p);
    }
    if (v.company && v.company !== '—') {
      const c = v.company.split(/[\s/,]/)[0];
      if (c.length >= 5 && !/^(google|meta|microsoft|amazon)$/i.test(c)) names.add(c);
    }
    // Names a notice uses for exactly this recipient (vendors.js aliases; never a bare parent-company name).
    for (const a of v.aliases || []) if (a.length >= 3 && a !== v.productOf) names.add(a);
    if (!names.size) continue;
    const alt = (list) => list.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    // Names that are also everyday words ("render", "line", "branch") count only with the brand's capital letter.
    const plain = [...names].filter((n) => !EVERYDAY_WORD.test(n));
    const words = [...names].filter((n) => EVERYDAY_WORD.test(n)).map((n) => (n === n.toUpperCase() ? n : n[0].toUpperCase() + n.slice(1)));
    const res = [plain.length ? new RegExp(`\\b(${alt(plain)})\\b`, 'i') : null, words.length ? new RegExp(`\\b(${alt(words)})\\b`) : null].filter(Boolean);
    out.push({ id: v.id, category: v.category, re: { test: (t) => res.some((re) => re.test(t)) } });
  }
  return out;
}

// A sentence that says the data is NOT collected / stored ("we never store payment card details", "kart bilgileriniz
// saklanmamaktadır") does not declare it. Sharing / selling denials ("we do not sell your email") still mention data
// that is processed, so only collection-type verbs negate.
const NEG_COLLECT = [
  /\b(do(es)?\s+not|don['’]t|doesn['’]t|never|will\s+not|won['’]t|no\s+longer|cannot|can['’]t)\b[^.;:]{0,80}?\b(collect|store|process|keep|retain|receive|save|record|track|obtain|gather|have\s+access|access)/i,
  /\b(is|are|will\s+be|be)\s+(not|never)\s+(collected|stored|processed|retained|saved|kept|recorded)/i,
  /(topla|işle|isle|sakla|kaydet|kaydedil|toplan|işlen|saklan|eriş)[a-zçğıöşü]*?(m[ıi]yor|m[ae]z\b|m[ae]m[ae]k|m[ae]y[ıi]z|m[ae]d[ıi])/i,
];
const EXCLUDED_BEFORE = /\b(but\s+not|not\s+including|excluding|except(\s+for)?|other\s+than)\b[^,.;]{0,40}$/i;
function sentencesOf(text) {
  return String(text).split(/(?<=[.!?;])\s+|\n+|\s[•·]\s/).map((s) => s.trim()).filter(Boolean);
}

// Login providers named in a notice ("sign in with Google, Facebook or GitHub") and social links ("follow us on X") say
// nothing about a product of the same brand receiving data: a Discord webhook or Slack channel is not disclosed by them.
const LOGIN_SENTENCE = /\b(?:log[\s-]?in|log[\s-]?on|sign(?:ing)?[\s-]?(?:in|up)|regist(?:er|ration)|authenticat\w*|oauth|single sign-on|sso|social (?:media )?(?:login|log-in|account|network|sign-?in|platform|media)s?|third[- ]party (?:login|account|authentication))\b|giriş yap|oturum aç|kayıt ol|sosyal (?:medya )?(?:hesab|giriş)|hesab[ıi]n[ıi]zla/i;
const SOCIAL_LINK_SENTENCE = /\b(?:follow|find|join|connect with|contact|reach|like|message) us (?:on|at|via|through|in)\b|\bour (?:twitter|x|github|discord|linkedin|facebook|instagram|youtube|slack|telegram)\b|\bshare (?:this|on|via)\b|bizi takip|takip edin|\bopen[- ]source\b.*\bgithub\b|\bgithub (?:repo|repository|issues?)\b/i;
const IDP_NAMES = [
  ['google', /\bgoogle\b/i], ['facebook', /\bfacebook\b|\bmeta (?:login|account)\b/i], ['twitter', /\btwitter\b|\bx \(formerly twitter\)|\bsign in with x\b/i], ['linkedin', /\blinked-?in\b/i], ['github', /\bgithub\b/i],
  ['gitlab', /\bgitlab\b/i], ['discord', /\bdiscord\b/i], ['apple', /\bapple\b/i], ['microsoft', /\bmicrosoft\b|\bazure ad\b|\bentra\b/i], ['slack', /\bslack\b/i], ['spotify', /\bspotify\b/i], ['twitch', /\btwitch\b/i],
  ['instagram', /\binstagram\b/i], ['kakao', /\bkakao(?:talk)?\b/i], ['line', /\bLINE\b(?= (?:account|login|app)|[,)]| or| and)/], ['naver', /\bnaver\b/i], ['yahoo', /\byahoo\b/i], ['notion', /\bnotion\b/i], ['zoom', /\bzoom\b/i], ['bitbucket', /\bbitbucket\b/i], ['reddit', /\breddit\b/i], ['tiktok', /\btik ?tok\b/i],
];
// Catalogue vendors whose notice name is only the login brand's name (a product of that brand, not its sign-in).
const BRAND_ONLY_VENDOR = /^(discord|slack|linkedin-insight|x-pixel|meta-pixel|facebook-sdk|tiktok-pixel|line|kakao|youtube)$/;

/** Login providers a notice lists: names in sentences about signing in with a third-party account. */
export function declaredIdpsOf(text) {
  const sents = sentencesOf(text);
  const out = new Set();
  sents.forEach((s, i) => {
    if (SOCIAL_LINK_SENTENCE.test(s)) return;
    const login = LOGIN_SENTENCE.test(s);
    // "… through a social account. Supported providers: Google, GitHub." / a list right after the sentence.
    const listAfter = !login && i > 0 && LOGIN_SENTENCE.test(sents[i - 1]) && IDP_NAMES.filter(([, re]) => re.test(s)).length >= 2 && s.length < 200;
    if (!login && !listAfter) return;
    // One name in a login sentence counts only when the sentence is about an account at that provider.
    const hits = IDP_NAMES.filter(([, re]) => re.test(s)).map(([n]) => n);
    if (hits.length === 1 && !/\b(?:with|via|through|using|from|your|by)\b[^.]{0,40}|ile giriş|hesab/i.test(s)) return;
    for (const h of hits) out.add(h);
  });
  return [...out];
}

/** Is this vendor named as a recipient (not only in a login-provider list, a social link or a footer)? */
function namedAsRecipient(v, text, sents) {
  if (!v.re.test(text)) return false;
  if (!BRAND_ONLY_VENDOR.test(v.id) && v.category !== 'auth') return true;
  return sents.some((s) => v.re.test(s) && !SOCIAL_LINK_SENTENCE.test(s) && (v.category === 'auth' || !LOGIN_SENTENCE.test(s)));
}

/** Data elements a policy text declares (synonym-aware; mentions inside "we do not collect …" sentences do not count). */
export function declaredDataOf(text) {
  const sents = sentencesOf(text);
  const out = new Set();
  for (const [el, re] of DATA_KEYWORDS) {
    if (out.has(el) || !re.test(text)) continue;
    if (sents.some((s) => {
      if (NEG_COLLECT.some((n) => n.test(s))) return false;
      // "payment history (but not payment card details)", "all data except your email": an excluded mention.
      const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
      for (const m of s.matchAll(g)) if (!EXCLUDED_BEFORE.test(s.slice(Math.max(0, m.index - 50), m.index))) return true;
      return false;
    })) out.add(el);
  }
  return [...out];
}

export function analysePolicyText(text, vendors) {
  const declaredData = declaredDataOf(text);
  const sents = sentencesOf(text);
  const declaredVendors = vendorPatterns(vendors).filter((v) => namedAsRecipient(v, text, sents)).map((v) => v.id);
  const declaredIdps = declaredIdpsOf(text);
  const LEGAL_FORM = String.raw`(?:A\.\s?Ş\.|A\.S\.|Ltd\.?\s*Şti\.?|Limited Şirketi|Anonim Şirketi|LLC|Inc\.|GmbH|Ltd\.|S\.A\.|B\.V\.)`;
  const ctlTr = String.raw`veri sorumlusu(?:\s+sıfatıyla)?\s*[:：]?\s*`;
  const controller = (
    text.match(new RegExp(ctlTr + String.raw`([A-ZÇĞİÖŞÜ0-9][^\n]{1,90}?` + LEGAL_FORM + ')', 'i')) ||
    text.match(new RegExp(ctlTr + String.raw`([A-ZÇĞİÖŞÜ0-9][^.\n,(]{2,90})`, 'i')) ||
    text.match(new RegExp(String.raw`\bcontroller\s+(?:is|:)\s*([^\n]{2,90}?` + LEGAL_FORM + ')', 'i')) ||
    text.match(/\bcontroller\s+(?:is|:)\s*([^.\n]{3,90})/i)
  )?.[1]?.trim() || null;
  const contactEmail = text.match(/[\w.+-]+@[\w-]+\.[\w.-]+/)?.[0] || null;
  return {
    declaredData,
    declaredVendors,
    declaredIdps,
    declaresNoTransferAbroad: NO_TRANSFER.some((re) => re.test(text)),
    declaresTransferAbroad: YES_TRANSFER.some((re) => re.test(text)) && !NO_TRANSFER.some((re) => re.test(text)),
    declaredRetention: RETENTION.test(text),
    declaredRights: RIGHTS.test(text),
    declaredLegalBasis: LEGAL_BASIS.test(text),
    declaredPurposes: PURPOSE.test(text),
    controller,
    contactEmail,
    ...noticeLanguage(text),
  };
}

// ---------------------------------------------------------------------------
// Language honesty: the keyword maps above (DATA_KEYWORDS, NO_TRANSFER, …) are written for the LEXICON_LANGUAGES
// only. A notice in another language or script is not "silent" about a data category: we simply cannot read it.
// Detection is generic: the dominant Unicode script of the letters, then (for Latin script) a stop-word vote among
// common European languages. Short texts (< MIN_WORDS words) are not judged.
export const LEXICON_LANGUAGES = ['en', 'tr'];
const SCRIPT_RES = [
  ['latin', /\p{Script=Latin}/u], ['cyrillic', /\p{Script=Cyrillic}/u], ['greek', /\p{Script=Greek}/u],
  ['arabic', /\p{Script=Arabic}/u], ['hebrew', /\p{Script=Hebrew}/u], ['thai', /\p{Script=Thai}/u],
  ['devanagari', /\p{Script=Devanagari}/u], ['bengali', /\p{Script=Bengali}/u], ['tamil', /\p{Script=Tamil}/u],
  ['han', /\p{Script=Han}/u], ['kana', /[\p{Script=Hiragana}\p{Script=Katakana}]/u], ['hangul', /\p{Script=Hangul}/u],
  ['georgian', /\p{Script=Georgian}/u], ['armenian', /\p{Script=Armenian}/u], ['ethiopic', /\p{Script=Ethiopic}/u],
  ['khmer', /\p{Script=Khmer}/u], ['lao', /\p{Script=Lao}/u], ['myanmar', /\p{Script=Myanmar}/u],
];
// Distinctive function words per language (words shared by several languages are left out).
const STOP_WORDS = {
  en: 'the and of to we you your our is are for with this that by be may will which from have not any such information',
  tr: 've bir bu ile için olarak veya olan ise gibi tarafından kapsamında hakkında kişisel verileriniz verilerin şekilde ilgili değil',
  de: 'und der die das wir ihre sie nicht mit von zu für auf ist werden personenbezogenen daten unsere oder bei',
  fr: 'les des et est nous vos vous pour une dans données personnelles que qui sur avec sont ou par',
  es: 'los las y el del que para sus datos personales nosotros con una por es su o al',
  it: 'il gli della che per dati personali sono una con nostro di nel delle alla',
  pt: 'os das dos que para seus dados pessoais com uma não nós ao pela pelo ou',
  nl: 'het en van wij uw voor gegevens persoonsgegevens niet met een zijn worden ook',
};
const STOP_SETS = Object.fromEntries(Object.entries(STOP_WORDS).map(([k, v]) => [k, new Set(v.split(' '))]));
const MIN_WORDS = 30;

/**
 * Language / script of a notice text.
 * @returns {{language:string, script:string, languageSupported:boolean, languageConfidence:number}}
 *   language: ISO-ish code ('en', 'tr', 'de' …) for Latin script, the script name otherwise ('thai', 'han' …),
 *   'und' when the text is too short to judge (treated as supported: nothing is asserted from length alone).
 */
export function noticeLanguage(text) {
  const s = String(text || '').slice(0, 20000);
  const counts = {};
  let letters = 0;
  for (const ch of s) {
    if (!/\p{L}/u.test(ch)) continue;
    letters++;
    const hit = SCRIPT_RES.find(([, re]) => re.test(ch));
    const k = hit ? hit[0] : 'other';
    counts[k] = (counts[k] || 0) + 1;
  }
  if (!letters) return { language: 'und', script: 'none', languageSupported: true, languageConfidence: 0 };
  const [script, n] = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
  const latinShare = (counts.latin || 0) / letters;
  const words = s.toLocaleLowerCase('tr').match(/[\p{Script=Latin}]+/gu) || [];
  const votes = Object.fromEntries(Object.keys(STOP_SETS).map((k) => [k, 0]));
  for (const w of words) for (const k of Object.keys(STOP_SETS)) if (STOP_SETS[k].has(w)) votes[k]++;
  // Turkish-only letters are a strong signal on their own.
  votes.tr += (s.match(/[ğışİĞŞ]/g) || []).length / 4;
  const ranked = Object.entries(votes).sort((a, b) => b[1] - a[1]);
  const lexHits = LEXICON_LANGUAGES.reduce((acc, k) => acc + votes[k], 0);
  if (script !== 'latin') {
    // A non-Latin notice with a substantial lexicon-language part (bilingual page) can still be read for that part.
    const bilingual = latinShare >= 0.3 && words.length >= MIN_WORDS && lexHits >= 8;
    return { language: bilingual ? ranked[0][0] : script, script, languageSupported: bilingual, languageConfidence: +(n / letters).toFixed(2) };
  }
  if (words.length < MIN_WORDS || ranked[0][1] < 3) return { language: ranked[0][1] ? ranked[0][0] : 'und', script, languageSupported: true, languageConfidence: 0 };
  const [best, bestVotes] = ranked[0];
  const supported = LEXICON_LANGUAGES.includes(best) || lexHits >= 0.6 * bestVotes;
  return { language: best, script, languageSupported: supported, languageConfidence: +(bestVotes / Math.max(1, words.length)).toFixed(2) };
}

// ---------------------------------------------------------------------------
// Notice selection: which text is "the privacy notice". A dedicated policy route / file (privacy.mdx,
// app/privacy-policy/page.tsx, gizlilik-politikasi.html, kvkk/aydinlatma-metni.vue) wins over articles, docs,
// marketing sections and components that merely mention privacy or cookies.
const ROUTE_FILE_NAME = /^(page|index|\+page|route|default|_index|content|main)$/i;
const POLICY_CORE = new Set(['privacy', 'gizlilik', 'kvkk', 'aydinlatma', 'aydınlatma', 'datenschutz', 'datenschutzerklarung', 'datenschutzerklaerung', 'datenschutzerklärung', 'gdpr', 'protection', 'koruma', 'confidentialite', 'confidentialité', 'privacidad', 'privacidade']);
const COOKIE_CORE = new Set(['cookie', 'cookies', 'cerez', 'çerez']);
const POLICY_FILLER = new Set(['policy', 'policies', 'notice', 'statement', 'politikasi', 'politikası', 'metni', 'bildirimi', 'sozlesmesi', 'sözleşmesi', 'page', 'legal', 'our', 'data', 'veri', 'and', 've', 'terms', 'center', 'centre', 'info', 'politique', 'de', 'politica', 'política', 'en', 'tr', 'us', 'eu', 'uk', 'v1', 'v2']);
// Article / documentation collections, page sections and UI components: they talk about privacy, they are not the notice.
const MENTION_PATH = /(^|\/)(_?sections?|components?|blocks|widgets|partials|ui|features|content\/(?!pages?\/|legal\/)[^/]+|blog|posts|articles|news|guides|tutorials|docs?|documentation|decisions?|adrs?|rfcs?|changelog|press|case-studies|examples?|stories)\//i;

function policyName(rel) {
  const parts = String(rel || '').split('/').filter(Boolean);
  let base = (parts.pop() || '').replace(/\.[^.]+$/, '');
  // Route files (page.tsx, index.vue, +page.svelte) take their name from the nearest non-group directory.
  // Next.js route groups "(legal)" and dynamic segments "[locale]" / "{lang}" are skipped too.
  while ((ROUTE_FILE_NAME.test(base) || /^\(.*\)$|^\[.*\]$|^\{.*\}$/.test(base)) && parts.length) base = parts.pop();
  return base.replace(/\[[^\]]*\]|\{[^}]*\}/g, '').toLowerCase();
}

/**
 * Rank of a declaration as THE notice: 3 a dedicated privacy-policy path, 2 a dedicated cookie-policy path,
 * 1 another privacy-named path, 0 an article / docs / section / component that only mentions privacy.
 * @returns {{rank:number, role:'policy'|'cookie-policy'|'privacy-path'|'mention', code:string}}
 */
export function noticeRank(rel, kind) {
  if (!rel) return { rank: 3, role: 'policy', code: 'live-privacy-page' };
  if (MENTION_PATH.test(rel)) return { rank: 0, role: 'mention', code: 'mention-path' };
  const toks = policyName(rel).split(/[-_.\s]+/).filter(Boolean);
  const meaningful = toks.filter((t) => !POLICY_FILLER.has(t));
  const onlyPolicy = meaningful.length > 0 && meaningful.every((t) => POLICY_CORE.has(t) || COOKIE_CORE.has(t));
  if (onlyPolicy && meaningful.some((t) => POLICY_CORE.has(t)) && !(meaningful.length === 1 && ['protection', 'koruma'].includes(meaningful[0]) && !toks.some((t) => t === 'data' || t === 'veri'))) return { rank: 3, role: 'policy', code: 'policy-path' };
  if (onlyPolicy && meaningful.every((t) => COOKIE_CORE.has(t))) return { rank: 2, role: 'cookie-policy', code: 'cookie-policy-path' };
  return { rank: kind === 'privacy' ? 1 : 0, role: kind === 'privacy' ? 'privacy-path' : 'mention', code: kind === 'privacy' ? 'privacy-word-path' : 'cookie-word-path' };
}

const RANK_REASON = {
  'policy-path': ['ayrı bir gizlilik politikası / aydınlatma metni sayfası', 'a dedicated privacy-policy / notice page'],
  'live-privacy-page': ['canlı sitedeki gizlilik sayfası', 'the privacy page of the live site'],
  'cookie-policy-path': ['ayrı bir çerez politikası sayfası (gizlilik politikası bulunamadı)', 'a dedicated cookie-policy page (no privacy policy found)'],
  'privacy-word-path': ['yolunda "gizlilik" geçen bir dosya (ayrı bir politika sayfası bulunamadı)', 'a file whose path mentions privacy (no dedicated policy page found)'],
  'cookie-word-path': ['yolunda "çerez" geçen bir dosya', 'a file whose path mentions cookies'],
  'mention-path': ['gizlilikten söz eden bir makale / bölüm (ayrı bir politika sayfası bulunamadı)', 'an article / section that mentions privacy (no dedicated policy page found)'],
};

/**
 * Order notice candidates (non-placeholder, with text) best first: a readable notice-grade text, rank, a readable
 * language, then discovery order (equal-rank notices are compared together anyway; only the anchor differs).
 * Shared with legal/checks/transparency.js.
 */
export function orderNotices(nodes) {
  const ok = (x) => x.n.languageSupported !== false;
  // A readable notice-grade text (rank >= 1) beats an unreadable one of a higher rank (e.g. an English copy next to
  // a notice in an unsupported script).
  const grade = (x) => (x.r >= 1 && ok(x) ? 1 : 0);
  return nodes.map((n, i) => ({ n, i, r: typeof n.noticeRank === 'number' ? n.noticeRank : noticeRank(n.file, n.kind).rank }))
    .sort((a, b) => grade(b) - grade(a) || b.r - a.r || ok(b) - ok(a) || a.i - b.i)
    .map((x) => x.n);
}

/** Mark ranks / the chosen notice on Declaration nodes; report an unreadable notice as a declarations-layer gap (C2). */
function selectNotice(ctx) {
  const ids = [...new Set(ctx.shared.declarations || [])];
  const nodes = ids.map((id) => ctx.graph.node?.(id)).filter(Boolean);
  for (const n of nodes) {
    if (n.external) continue;
    const r = noticeRank(n.file, n.kind);
    n.noticeRank = r.rank;
    n.noticeRole = r.role;
    n.noticeRankCode = r.code;
  }
  const cands = nodes.filter((n) => !n.external && !n.placeholder && String(n.text || '').trim());
  if (!cands.length) return;
  const chosen = orderNotices(cands)[0];
  const [rtr, ren] = RANK_REASON[chosen.noticeRankCode] || RANK_REASON['privacy-word-path'];
  chosen.chosen = true;
  chosen.chosenReason = { code: chosen.noticeRankCode, tr: `Aydınlatma metni olarak seçildi: ${rtr}`, en: `Chosen as the privacy notice: ${ren}` };
  ctx.shared.notice = { id: chosen.id, file: chosen.file || null, url: chosen.url || null, rank: chosen.noticeRank, role: chosen.noticeRole, reason: chosen.chosenReason, language: chosen.language, languageSupported: chosen.languageSupported !== false };
  if (chosen.languageSupported === false) {
    const lang = chosen.language || chosen.script || 'unknown';
    if (!Array.isArray(ctx.shared.unparsed)) ctx.shared.unparsed = [];
    ctx.shared.unparsed.push({
      layer: 'declarations', kind: 'notice-language', extractor: name,
      label: { tr: `Aydınlatma metni desteklenmeyen bir dilde/yazıda (${lang})`, en: `Privacy notice in an unsupported language/script (${lang})` },
      files: chosen.file ? [chosen.file] : [], count: 1,
      reason: `notice in an unsupported language/script (${lang}); the declaration lexicon covers ${LEXICON_LANGUAGES.join(', ')}`,
    });
  }
}

// ---------------------------------------------------------------------------
// Placeholder notices (DCL-1): lorem ipsum filler, or a page with privacy headings but no content.
const LOREM = /\blorem ipsum\b|\bdolor sit amet\b|\bconsectetur adipiscing\b|\bsed do eiusmod\b|\btempor incididunt\b/i;
const LATIN_FILLER = new Set(('lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua '
  + 'enim ad minim veniam quis nostrud exercitation ullamco laboris nisi aliquip ex ea commodo consequat duis aute irure reprehenderit voluptate velit esse '
  + 'cillum eu fugiat nulla pariatur excepteur sint occaecat cupidatat non proident sunt culpa qui officia deserunt mollit anim id est laborum '
  + 'blandit libero volutpat cras ornare arcu cursus dictum nunc vel risus commodo viverra maecenas accumsan faucibus nisl tincidunt eget nullam nisi varius quam '
  + 'quisque diam donec ultrices pharetra turpis gravida semper auctor neque vitae tempus elementum facilisis leo fringilla ullamcorper imperdiet malesuada '
  + 'pellentesque felis odio tortor porta nibh fames ac egestas convallis posuere morbi scelerisque fermentum dui justo hendrerit rutrum hac habitasse platea '
  + 'dictumst sagittis purus suscipit habitant tristique suspendisse mauris nec lectus vulputate integer erat lacus massa sapien eros mi urna orci feugiat '
  + 'aliquam etiam aenean vivamus praesent phasellus curabitur proin fusce vestibulum nam at quisque lobortis pretium congue amet vivamus sodales mattis').split(/\s+/));

/** True when policy text is filler (lorem ipsum) or carries no substance at all. */
export function isPlaceholderNotice(text, facts) {
  if (LOREM.test(text)) {
    const words = text.toLowerCase().match(/[a-z]+/g) || [];
    const latin = words.filter((w) => LATIN_FILLER.has(w)).length;
    if (words.length && latin / words.length >= 0.25) return true;
  }
  const f = facts || {};
  // Substance is measured with the lexicon: a text in a language it cannot read is unjudged, not empty.
  if (f.languageSupported === false && String(text).trim().length >= 200) return false;
  const substance = (f.declaredData?.length || 0) + (f.declaredVendors?.length || 0)
    + [f.declaredRights, f.declaredPurposes, f.declaredLegalBasis, f.declaredRetention, f.controller, f.contactEmail].filter(Boolean).length;
  // A stub ("<div>Privacy</div>", "Privacy policy coming soon") is not a notice even if it names one word.
  if (String(text).trim().length < 200 && substance < 3) return true;
  return substance === 0;
}

// ---------------------------------------------------------------------------
// Is this text a notice at all? Files are picked by path (privacy / cookie / kvkk …), which also catches architecture
// decision records about cookies, privacy-settings screens, cookie banners and toggles. Their UI copy ("Show my
// email", "Location sharing") must not count as declarations.
const NOTICE_MARKERS = [
  /personal (data|information)|kişisel veri|personenbezogen|your (data|information)|verileriniz/i,
  /\b(we|biz)\b[^.]{0,40}\b(collect|process|use|store|share|disclose|retain)\b|topla(r|n|d|m)|işle(r|n|d|m|y)|saklan|aktarıl/i,
  /privacy (policy|notice|statement)|cookie (policy|notice)|aydınlatma metni|gizlilik (politikası|bildirimi|sözleşmesi)|çerez politikası|data protection|veri koruma/i,
  /third[- ]part|üçüncü (kişi|taraf)|service providers?|processors?\b|alıcı grupları/i,
  /controller|veri sorumlusu|contact us|bize ulaş|data protection officer|\bdpo\b/i,
  RIGHTS, RETENTION, LEGAL_BASIS,
];
export function noticeScore(text) {
  return NOTICE_MARKERS.filter((re) => re.test(text)).length;
}
/** Paths that are documentation / decision records / UI pieces rather than a published notice. */
const NON_NOTICE_PATH = /(^|\/)(docs?|decisions?|adrs?|rfcs?|changelog|blog|posts|articles|news|examples?|stories|storybook)\/|(^|\/)(readme|changelog|contributing)[^/]*$|(^|\/)(components?|ui|widgets?|hooks?|icons?)\/|(settings?|preferences?|toggle|switch|button|badge|banner|modal|dialog|popup|drawer|link|footer|header|nav|menu|checkbox|form|card|tab)s?([-_.][^/]*)?\.(tsx|jsx|vue|svelte|astro|ts|js)$|\/(settings?|preferences?|account)\//i;

// ---------------------------------------------------------------------------
// External notices (DCL-2): the notice is hosted elsewhere and the repo only links to it.
const PRIVACY_WORD = /(privacy|gizlilik|aydinlatma|aydınlatma|kvkk|datenschutz)/i;
const PRIVACY_URL_PROP = /\b(privacyPolicyUrl|privacyPolicyURL|privacyUrl|privacyURL|privacyPolicyLink|privacyLink|privacy_policy_url|privacy_url)\b\s*[:=]\s*([^,\n};]+)/g;
const LINK_TAG = /<(a|Link|NextLink|RouterLink|router-link|NavLink)\b([^>]*)>([\s\S]{0,300}?)<\/\1>/g;
// Links to someone else's privacy policy (reCAPTCHA / OAuth notices) are not the app's own notice.
const THIRD_PARTY_POLICY_HOST = /(^|\.)(google\.com|policies\.google\.com|apple\.com|facebook\.com|meta\.com|microsoft\.com|github\.com|stripe\.com|twitter\.com|x\.com|cloudflare\.com|hcaptcha\.com|vercel\.com|supabase\.com|firebase\.google\.com|openai\.com|anthropic\.com)$/i;

function hrefOf(attrs) {
  const m = attrs.match(/\b(?:href|to|:href)\s*=\s*(?:"([^"]*)"|'([^']*)'|\{\s*([^}]*?)\s*\})/);
  if (!m) return null;
  if (m[1] != null || m[2] != null) return { literal: m[1] ?? m[2] };
  const expr = m[3];
  const lit = expr.match(/^(["'`])([^"'`$]*)\1$/);
  return lit ? { literal: lit[2] } : { expr };
}

function isOwnExternalUrl(url, ctx) {
  let host;
  try {
    host = new URL(url.startsWith('//') ? 'https:' + url : url).hostname;
  } catch {
    return false;
  }
  if (THIRD_PARTY_POLICY_HOST.test(host)) return false;
  if (ctx.vendors?.vendorForUrl?.(url.startsWith('//') ? 'https:' + url : url)) return false;
  return true;
}

/**
 * A reference counts when it is an absolute URL to a non-vendor host, or an expression (config/constant) whose
 * text names privacy. Relative literal paths ("/privacy") only count when they look like an in-repo page we could
 * not read; a dead in-app link is not a notice.
 */
function externalRef(ctx, file, lineNo, h, linkText) {
  if (!h) return null;
  if (h.literal != null) {
    const u = h.literal.trim();
    if (!/^(https?:)?\/\//i.test(u) || /\{\{|\{%|<%/.test(u)) return null;
    if (!PRIVACY_WORD.test(u) && !PRIVACY_WORD.test(linkText || '')) return null;
    return isOwnExternalUrl(u, ctx) ? { file, line: lineNo, url: u } : null;
  }
  const expr = h.expr.trim();
  const abs = expr.match(/["'`](https?:\/\/[^"'`\s]+)["'`]/)?.[1];
  if (abs) return (PRIVACY_WORD.test(abs) || PRIVACY_WORD.test(linkText || '')) && isOwnExternalUrl(abs, ctx) ? { file, line: lineNo, url: abs } : null;
  if (PRIVACY_WORD.test(expr) || PRIVACY_WORD.test(linkText || '')) return { file, line: lineNo, url: null, urlExpr: expr.slice(0, 120) };
  return null;
}

function collectExternalRefs(ctx) {
  const refs = [];
  for (const f of ctx.files) {
    if (f.test || f.kind !== 'code') continue;
    if (!/\.(tsx|jsx|js|ts|mjs|vue|svelte|astro|html?|erb|twig|blade|php)$/.test(f.rel)) continue;
    if (!PRIVACY_WORD.test(f.content)) continue;
    const lineAt = (off) => f.content.slice(0, off).split('\n').length;
    let m;
    PRIVACY_URL_PROP.lastIndex = 0;
    while ((m = PRIVACY_URL_PROP.exec(f.content))) {
      const v = m[2].trim();
      const lit = v.match(/^(["'`])([^"'`]*)\1$/);
      const lineNo = lineAt(m.index);
      if (lit) {
        if (/^(https?:)?\/\//i.test(lit[2]) && isOwnExternalUrl(lit[2], ctx)) refs.push({ file: f.rel, line: lineNo, url: lit[2] });
      } else if (v && !/^(null|undefined|''|""|false)$/.test(v)) refs.push({ file: f.rel, line: lineNo, url: null, urlExpr: v.slice(0, 120) });
    }
    LINK_TAG.lastIndex = 0;
    while ((m = LINK_TAG.exec(f.content))) {
      const text = m[3].replace(/<[^>]+>|\{[^}]*\}/g, ' ').replace(/\s+/g, ' ').trim();
      const r = externalRef(ctx, f.rel, lineAt(m.index), hrefOf(m[2]), text);
      if (r) refs.push(r);
    }
  }
  return refs;
}

function addExternalDeclaration(ctx, refs, stubs) {
  const all = [...stubs, ...refs];
  if (!all.length) return;
  const best = all.find((r) => r.url) || all[0];
  const id = 'declaration:policy:external';
  ctx.graph.addNode({
    id, type: 'Declaration', kind: 'privacy', external: true, placeholder: false,
    url: best.url || null, urlExpr: best.url ? undefined : best.urlExpr, file: best.file, line: best.line, text: '',
    refs: all.slice(0, 10).map(({ file, line: l, url, urlExpr }) => ({ file, line: l, url: url || null, urlExpr })),
    declaredData: [], declaredVendors: [], declaresNoTransferAbroad: false, declaresTransferAbroad: false,
    declaredRetention: false, declaredRights: false, declaredLegalBasis: false, declaredPurposes: false, controller: null, contactEmail: null,
    evidence: all.slice(0, 5).map((r) => ctx.ev(r.file, r.line, r.url || r.urlExpr || null, 'declared', 0.6, 'privacy notice hosted outside the repo')),
  });
  (ctx.shared.declarations ||= []).push(id);
}

/**
 * A page route file (not a component, layout or config) whose JSX is only intrinsic elements and text: it neither
 * renders a custom component (<PolicyContent />, <MDXContent />) nor imports local content / markdown.
 */
function isStubPage(f, text) {
  if (!/\.(tsx|jsx|vue|svelte|astro|html?|md|mdx)$/.test(f.rel)) return false;
  if (!/(^|\/)(app|pages|routes|src\/routes|src\/pages|src\/app)\//.test(f.rel) && !/\.(html?|md|mdx)$/.test(f.rel)) return false;
  if (/(^|\/)(layout|_layout|template|loading|error|head|config)\.[a-z]+$/.test(f.rel)) return false;
  const c = f.content;
  if (/<[A-Z][\w.]*[\s/>]/.test(c.replace(/<(Fragment|React\.Fragment|Head|Title|Meta)\b/g, ''))) return false;
  if (/\bimport\b[^\n]*['"](\.{1,2}\/|@\/|~\/|#|\$lib)[^'"]*['"]|\.(md|mdx|json|txt|html)['"]|\b(getStaticProps|loader|load|fetch|useQuery|marked|remark|mdx|dangerouslySetInnerHTML|v-html|\{@html)\b/.test(c)) return false;
  return (text || '').trim().length < 80;
}

function addDeclaration(ctx, id, props) {
  const { graph, ev } = ctx;
  const facts = analysePolicyText(props.text, ctx.vendors.VENDORS);
  facts.placeholder = isPlaceholderNotice(props.text, facts);
  facts.parsed = facts.languageSupported !== false;
  graph.addNode({ id, type: 'Declaration', ...props, text: props.text.slice(0, 20000), ...facts, evidence: [ev(props.file || props.url, props.line || 1, props.text.slice(0, 160), props.url && !props.file ? 'runtime' : 'declared', 0.9)] });
  if (facts.placeholder) {
    (ctx.shared.declarations ||= []).push(id);
    return; // filler declares nothing
  }
  for (const el of facts.declaredData) {
    const did = `data:${el}`;
    if (graph.has(did)) graph.addEdge({ from: did, to: id, type: 'declaredIn', evidence: [ev(props.file || props.url, props.line || 1, null, 'declared', 0.7)] });
  }
  for (const v of facts.declaredVendors) {
    const sid = `sink:vendor:${v}`;
    if (graph.has(sid)) graph.addEdge({ from: sid, to: id, type: 'declaredIn', evidence: [ev(props.file || props.url, props.line || 1, null, 'declared', 0.8)] });
  }
  (ctx.shared.declarations ||= []).push(id);
}

/** Text comes from a translation dictionary: t('privacy.title'), useTranslations('Privacy'), <Trans …>, $t('…'), {{ 'x' | translate }}. */
const I18N_PAGE = /\b(?:useTranslations?|getTranslations?|useI18n|useTranslation|FormattedMessage)\b|<Trans\b|\$t\(|(?:^|[^\w$.])t\(\s*["'`]|\|\s*translate\b/;

/** Notice documents that are not text files (public/privacy-policy.pdf): they exist, their contents were not read. */
function documentNotices(ctx) {
  const out = [];
  if (!ctx.root) return out;
  for (const d of ['public', 'static', 'assets', 'docs', 'legal', 'public/legal', 'public/docs', 'static/legal']) {
    let ents = [];
    try {
      ents = fs.readdirSync(path.join(ctx.root, d));
    } catch {
      continue;
    }
    for (const n of ents.slice(0, 400)) if (/\.(pdf|docx?|odt)$/i.test(n) && PATH_PRIVACY.test(n)) out.push({ file: `${d}/${n}`, parsed: false, reason: 'document', language: null });
  }
  return out;
}

export function extract(ctx) {
  const stubs = [];
  const unparsed = [];
  let textual = 0;
  for (const f of ctx.files) {
    if (/(^|\/)(api|server|lib|utils?|hooks?|test|tests|__tests__|node_modules)\//.test(f.rel) || /\.(test|spec)\./.test(f.rel)) continue;
    const kind = PATH_COOKIE.test(f.rel) ? 'cookie' : PATH_PRIVACY.test(f.rel) ? 'privacy' : null;
    if (!kind) continue;
    if (!/\.(tsx|jsx|js|ts|html?|md|mdx|txt|vue|svelte|astro)$/.test(f.rel)) continue;
    const text = /\.(tsx|jsx|js|ts)$/.test(f.rel) ? textFromJsx(f) : textFromMarkup(f.content);
    // Documentation, decision records and UI pieces whose path mentions privacy / cookies are not notices unless
    // their text reads like one.
    if (NON_NOTICE_PATH.test(f.rel) && !LOREM.test(text) && noticeScore(text) < 3) continue;
    if (text.length < 80) {
      // A link or redirect stub, not the policy itself: remember where it points (external notice).
      if (kind !== 'privacy') continue;
      if (I18N_PAGE.test(f.content) && noticeRank(f.rel, kind).rank >= 3) unparsed.push({ file: f.rel, parsed: false, reason: 'i18n', language: null });
      const url = f.content.match(/["'`(](https?:\/\/[^"'`\s)]+)/)?.[1];
      const redirectExpr = f.content.match(/\b(?:redirect|permanentRedirect|location\.(?:href|replace|assign))\s*(?:\(|=)\s*([\w.[\]'"]+)/)?.[1];
      if (url && isOwnExternalUrl(url, ctx)) stubs.push({ file: f.rel, line: 1, url });
      else if (!url && redirectExpr && !/^["']\//.test(redirectExpr)) stubs.push({ file: f.rel, line: 1, url: null, urlExpr: redirectExpr });
      // A privacy route that renders only a word or two ("<div>Privacy</div>") and delegates nowhere is a placeholder
      // notice (DCL-1), not an absent file: the app links to a page that says nothing.
      else if (!url && !redirectExpr && isStubPage(f, text)) {
        addDeclaration(ctx, `declaration:policy:${f.rel}`, { kind, file: f.rel, line: 1, text: text || '(empty)' });
        textual++;
      }
      continue;
    }
    addDeclaration(ctx, `declaration:policy:${f.rel}`, { kind, file: f.rel, line: 1, text });
    if (kind === 'privacy') textual++;
  }
  // Live scan: privacy page text, if the live scanner captured it.
  const live = ctx.live;
  const liveText = live?.privacyPageCheck?.text || live?.privacyText || live?.privacyPageText;
  if (liveText && liveText.length >= 80) {
    addDeclaration(ctx, 'declaration:policy:live', { kind: 'privacy', url: live.privacyPageCheck?.url || live.url, text: liveText });
  } else if (live?.privacyPageCheck?.url) {
    // No text, but we know which elements the live checker found present/missing.
    ctx.graph.addNode({
      id: 'declaration:policy:live', type: 'Declaration', kind: 'privacy', url: live.privacyPageCheck.url, text: '',
      livePresent: live.privacyPageCheck.present || [], liveMissing: live.privacyPageCheck.missing || [],
      declaredData: [], declaredVendors: [], evidence: [ctx.ev(live.privacyPageCheck.url, 1, null, 'runtime', 0.7)],
    });
    (ctx.shared.declarations ||= []).push('declaration:policy:live');
  }
  // No textual privacy notice in the repo (a placeholder still counts as textual: it is what the link points to).
  if (!textual && !ctx.graph.has('declaration:policy:live')) addExternalDeclaration(ctx, collectExternalRefs(ctx), stubs);
  selectNotice(ctx);
  for (const id of ctx.shared.declarations || []) {
    const n = ctx.graph.node?.(id);
    if (n && !n.external && n.parsed === false && n.file) unparsed.push({ file: n.file, parsed: false, reason: 'language', language: n.language || n.script || null });
  }
  unparsed.push(...documentNotices(ctx));
  if (unparsed.length) ctx.shared.unparsedNotices = unparsed;
  if (ctx.shared.notice) {
    const n = ctx.graph.node?.(ctx.shared.notice.id);
    ctx.shared.notice.parsed = n ? n.parsed !== false : true;
    ctx.shared.notice.declaredIdps = n?.declaredIdps || [];
  }
  // Vendor sinks added by the extractors that run between endpoints-ext and this one.
  try {
    annotateVendorUsage(ctx);
  } catch {}
}
