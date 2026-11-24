// kvkk-ignore-file  (rule definitions)
/**
 * Extra web / data-flow rules: PII sent to analytics, fingerprinting, device APIs,
 * personal data flowing into LLM prompts, marketing communications.
 */

const LLM_CALL = /(chat\.completions\.create|responses\.create|messages\.create|\bgenerateText\(|\bstreamText\(|\bgenerateObject\(|\bstreamObject\(|generateContent\(|\.chat\.send|ChatOpenAI\(|ChatAnthropic\(|client\.chat\(|ollama\.chat)/;
const PII_IN_CODE = /\b(email|e_?posta|phone|telefon|tckn|tc_?kimlik|address|adres|birth_?date|dogum|health\w*|saglik\w*|diagnos\w*|full_?name|fullName|first_?name|last_?name|ad_?soyad|iban|medical\w*|profile\.\w+|user\.(name|email|phone))\b/i;

export const WEB_EXTRA_RULES = [
  {
    id: 'WEX001',
    category: 'transfer',
    severity: 'medium',
    scope: 'file',
    kinds: ['code'],
    patterns: [
      {
        label: { tr: 'Analitiğe kişisel veri', en: 'Personal data sent to analytics' },
        re: /(posthog\.(identify|people\.set|setPersonProperties)|mixpanel\.(identify|people\.set|register)|analytics\.(identify|track)|amplitude\.(setUserId|identify)|Sentry\.setUser|setUser\(|gtag\(\s*['"]set['"]\s*,\s*['"]user_data|LogRocket\.identify|FS\.identify|clarity\(\s*['"]identify|hj\(\s*['"]identify|Intercom\(\s*['"]boot|fbq\(\s*['"]init['"]\s*,\s*['"]\d+['"]\s*,)[^\n]*\b(email|phone|telefon|name|fullName|full_name|tckn|address|adres|birth)/i,
      },
    ],
    title: { tr: 'Kişisel veri analitik/izleme aracına gönderiliyor', en: 'Personal data sent to an analytics/tracking tool' },
    desc: {
      tr: 'identify/setUser çağrılarına e-posta, telefon veya ad eklemek, kişisel veriyi doğrudan (genellikle ABD\'deki) analitik sağlayıcısına aktarır ve kullanıcıyı platformlar arası eşleştirmeye açar.',
      en: 'Putting email, phone or name into identify/setUser calls transfers personal data directly to the (usually US) analytics vendor and enables cross-platform matching.',
    },
    fix: {
      tr: 'Sadece rastgele/dahili kullanıcı ID\'si gönder; e-posta vb. gerekiyorsa hash\'le ve bunu aydınlatma metninde/çerez politikasında belirt. Rıza yoksa identify çağırma.',
      en: 'Send only an internal/random user ID; if email etc. is required, hash it and disclose it. Do not call identify without consent.',
    },
    refs: ['KVKK md.4, md.5, md.9', 'GDPR Art.5(1)(c), Art.6, Art.44'],
  },
  {
    id: 'WEX002',
    category: 'tracking',
    severity: 'high',
    scope: 'file',
    kinds: ['code', 'manifest'],
    aggregate: true,
    patterns: [
      { label: 'FingerprintJS', re: /(@fingerprintjs\/|fingerprintjs2?|fpjs\.io|fpcdn\.io)/i },
      { label: 'ClientJS', re: /(['"]clientjs['"]|new ClientJS\()/ },
      { label: 'Canvas fingerprint', re: /fingerprint[^\n]{0,80}toDataURL|toDataURL[^\n]{0,80}fingerprint/i },
    ],
    title: { tr: 'Cihaz parmak izi (fingerprinting)', en: 'Device fingerprinting' },
    desc: {
      tr: 'Parmak izi çıkarma, çerez olmadan kullanıcıyı tanır; ePrivacy ve KVKK Çerez Rehberi açısından çerezle aynı şekilde rıza gerektirir ve kullanıcı tarafından silinemediği için daha müdahalecidir.',
      en: 'Fingerprinting identifies users without cookies; it requires consent just like cookies (ePrivacy, EDPB Guidelines 2/2023) and is more intrusive because users cannot clear it.',
    },
    fix: {
      tr: 'Sadece dolandırıcılık önleme gibi gerçekten gerekli bir amaç için kullan, bunu meşru menfaat değerlendirmesiyle belgele ve aydınlatma metninde açıkla; analitik/reklam için kullanacaksan rızaya bağla.',
      en: 'Use it only where strictly necessary (e.g. fraud prevention), document a legitimate-interest assessment and disclose it; gate analytics/ad use behind consent.',
    },
    refs: ['KVKK Çerez Rehberi', 'ePrivacy Art.5(3)', 'EDPB Guidelines 2/2023', 'GDPR Art.6'],
  },
  {
    id: 'WEX003',
    category: 'personal-data',
    severity: 'info',
    scope: 'file',
    kinds: ['code', 'manifest'],
    aggregate: true,
    patterns: [
      { label: { tr: 'Konum', en: 'Geolocation' }, re: /(navigator\.geolocation|expo-location|react-native-geolocation|@react-native-community\/geolocation|\bgeolocator\b|CLLocationManager|FusedLocationProviderClient)/ },
      { label: { tr: 'Kamera / mikrofon', en: 'Camera / microphone' }, re: /(getUserMedia|expo-camera|react-native-vision-camera|expo-av|AVCaptureSession|\bcamera:\s*\^|image_picker)/ },
      { label: { tr: 'Rehber (kişiler)', en: 'Contacts' }, re: /(expo-contacts|react-native-contacts|contacts_service|flutter_contacts|CNContactStore|navigator\.contacts)/ },
      { label: { tr: 'IP adresi kaydı', en: 'IP address logging' }, re: /\b(req\.ip\b|request\.remote_addr|x-forwarded-for|REMOTE_ADDR|request\.client\.host|getClientIp)/i },
      { label: { tr: 'Ses kaydı / konuşma tanıma', en: 'Voice recording / speech recognition' }, re: /(MediaRecorder|SpeechRecognition|webkitSpeechRecognition|expo-speech-recognition|whisper)/ },
    ],
    title: { tr: 'Cihaz/ağ verisi toplanıyor (envanter)', en: 'Device/network data collected (inventory)' },
    desc: {
      tr: 'Konum, kamera/mikrofon görüntüsü, rehber ve IP adresi kişisel veridir; rehber ise üçüncü kişilerin verisidir. Her biri amaç, hukuki sebep ve saklama süresiyle aydınlatma metninde yer almalı.',
      en: 'Location, camera/microphone input, contacts and IP addresses are personal data; contacts are third parties\' data. Each needs a purpose, legal basis and retention in your notice.',
    },
    fix: {
      tr: 'Veriyi sadece ihtiyaç anında, en düşük hassasiyette topla (ör. yaklaşık konum), mümkünse cihazda işle; IP\'leri kısa süre sakla veya maskele.',
      en: 'Collect only when needed and at the lowest precision (e.g. approximate location), process on-device where possible; keep IPs briefly or truncate them.',
    },
    refs: ['KVKK md.4, md.10', 'GDPR Art.5(1)(c), Art.13'],
  },
  {
    id: 'WEX004',
    category: 'transfer',
    severity: 'medium',
    scope: 'project',
    check: ({ files }) => {
      const out = [];
      for (const f of files) {
        if (f.kind !== 'code' || !LLM_CALL.test(f.content) || !PII_IN_CODE.test(f.content)) continue;
        const lines = f.content.split(/\r?\n/);
        const i = lines.findIndex((l) => LLM_CALL.test(l));
        const pii = f.content.match(PII_IN_CODE)[0];
        out.push({ label: { tr: `LLM çağrısı + "${pii}"`, en: `LLM call + "${pii}"` }, file: f.rel, line: i + 1, snippet: lines[i].trim().slice(0, 160) });
      }
      return out;
    },
    title: { tr: 'Kişisel veri LLM prompt\'una gidiyor olabilir', en: 'Personal data may flow into an LLM prompt' },
    desc: {
      tr: 'Aynı dosyada hem bir LLM çağrısı hem de kişisel veri alanları var. Kullanıcı profili, e-posta veya sağlık bilgisi prompt\'a ekleniyorsa bu, LLM sağlayıcısına yurt dışı aktarımdır ve çoğu zaman amaç için gerekli değildir.',
      en: 'The same file contains an LLM call and personal data fields. If profile, email or health data is put into the prompt, that is an international transfer to the LLM provider and often not necessary for the purpose.',
    },
    fix: {
      tr: 'Prompt\'a yalnızca görevin gerektirdiği veriyi koy; isim/e-posta/TCKN gibi tanımlayıcıları çıkar veya takma adla değiştir (pseudonymisation). Sağlayıcıda veri saklamayı ve eğitimde kullanımı kapat, DPA imzala.',
      en: 'Put only what the task needs into the prompt; strip or pseudonymise identifiers like names/emails/IDs. Disable provider retention/training and sign a DPA.',
    },
    refs: ['KVKK md.4, md.9', 'GDPR Art.5(1)(c), Art.25, Art.44'],
  },
  {
    id: 'WEX005',
    category: 'consent',
    severity: 'low',
    scope: 'project',
    check: ({ files }) => {
      const marketing = files.find(
        (f) => f.kind === 'code' && /(newsletter|bülten|bulten|kampanya|marketing[-_ ]?(email|mail|sms)|broadcasts?\.(create|send)|audiences?\/|lists\/[\w{]+\/members|contacts\.create|netgsm|iletimerkezi|mutlucell|verimor|toplu[-_ ]?sms|bulk[-_ ]?sms)/i.test(f.content),
      );
      if (!marketing) return [];
      const optOut = files.some((f) => /(unsubscribe|abonelikten\s*ç[ıi]k|aboneli[gğ]i\s*iptal|List-Unsubscribe|opt[-_ ]?out|ileti\s*almak\s*istemiyorum|\bRET\b|iys|İYS)/i.test(f.content));
      return optOut ? [] : [{ label: { tr: 'pazarlama iletişimi', en: 'marketing communication' }, file: marketing.rel }];
    },
    title: { tr: 'Pazarlama iletisi var ama ret (opt-out) / İYS izi yok', en: 'Marketing messages without opt-out / IYS' },
    desc: {
      tr: 'Ticari elektronik iletiler (e-posta/SMS/arama) için önceden onay ve her iletide kolay ret imkânı zorunludur. Türkiye\'de onaylar İleti Yönetim Sistemi\'ne (İYS) kaydedilmeli; aksi halde ileti başına idari para cezası riski vardır.',
      en: 'Commercial electronic messages need prior opt-in and an easy opt-out in every message. In Turkey, consents must be registered in the IYS (İleti Yönetim Sistemi).',
    },
    fix: {
      tr: 'Her iletiye "abonelikten çık" bağlantısı / SMS\'e RET talimatı ekle, onay ve retleri İYS\'ye senkronize et, onay metnini aydınlatma metninden ayrı tut.',
      en: 'Add an unsubscribe link / SMS opt-out to every message, sync consents with IYS (TR), keep the opt-in text separate from the privacy notice.',
    },
    refs: ['6563 s. Kanun md.6, md.8', 'Ticari İletişim ve Ticari Elektronik İletiler Hk. Yönetmelik', 'GDPR Art.21(2)', 'ePrivacy Art.13'],
  },
];
