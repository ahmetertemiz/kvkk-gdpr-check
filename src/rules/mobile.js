// kvkk-ignore-file  (rule definitions)
/**
 * Mobile rules: Android (AndroidManifest, network security config, Gradle),
 * iOS (Info.plist, privacy manifest, entitlements), Expo (app.json / app.config),
 * Flutter and React Native SDKs.
 */

const HIGH_RISK_PERMS = [
  'ACCESS_BACKGROUND_LOCATION', 'READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'READ_CALL_LOG', 'WRITE_CALL_LOG',
  'PROCESS_OUTGOING_CALLS', 'READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS', 'QUERY_ALL_PACKAGES',
  'MANAGE_EXTERNAL_STORAGE', 'READ_PHONE_NUMBERS', 'BODY_SENSORS', 'BODY_SENSORS_BACKGROUND', 'SYSTEM_ALERT_WINDOW',
  'BIND_ACCESSIBILITY_SERVICE', 'PACKAGE_USAGE_STATS', 'READ_PRIVILEGED_PHONE_STATE',
];
const OTHER_PERMS = [
  'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'CAMERA', 'RECORD_AUDIO', 'READ_PHONE_STATE',
  'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'READ_MEDIA_AUDIO',
  'READ_CALENDAR', 'WRITE_CALENDAR', 'ACTIVITY_RECOGNITION', 'BLUETOOTH_SCAN', 'NEARBY_WIFI_DEVICES',
  'USE_BIOMETRIC', 'USE_FINGERPRINT', 'AD_ID', 'POST_NOTIFICATIONS',
];
const permRe = (list) => new RegExp(`(?:android\\.permission\\.|com\\.google\\.android\\.gms\\.permission\\.|["'])(${list.join('|')})\\b`);

const IOS_KEYS =
  'NS(?:Location(?:Always|WhenInUse|AlwaysAndWhenInUse)?|Contacts|Camera|Microphone|PhotoLibrary(?:Add)?|Calendars(?:FullAccess|WriteOnly)?|Reminders(?:FullAccess)?|Health(?:Share|Update|ClinicalHealthRecordsShare)|Motion|Bluetooth(?:Always|Peripheral)|FaceID|SpeechRecognition|UserTracking|LocalNetwork|NearbyInteraction|SensorKit)UsageDescription';

const TRACKING_SDKS =
  /(react-native-appsflyer|appsflyer_sdk|AppsFlyerLib|com\.appsflyer|react-native-adjust|adjust_sdk|com\.adjust\.sdk|AdjustConfig|react-native-branch|flutter_branch_sdk|io\.branch|react-native-fbsdk|FBSDKCoreKit|FBSDKLoginKit|com\.facebook\.android|facebook_app_events|flutter_facebook_auth|google_mobile_ads|react-native-google-mobile-ads|Google-Mobile-Ads-SDK|play-services-ads|firebase_analytics|@react-native-firebase\/analytics|FirebaseAnalytics|firebase-analytics|expo-firebase-analytics|@amplitude\/analytics-react-native|mixpanel-react-native|mixpanel_flutter|segment_analytics|@segment\/analytics-react-native|onesignal|react-native-onesignal)/i;

const TRACKING_SDK_NAMES = [
  ['AppsFlyer', /appsflyer/i], ['Adjust', /adjust/i], ['Branch', /branch/i], ['Meta (Facebook) SDK', /fbsdk|facebook/i],
  ['Google AdMob', /mobile[-_]?ads|play-services-ads/i], ['Firebase Analytics', /firebase[-_/]?analytics|FirebaseAnalytics/i],
  ['Amplitude', /amplitude/i], ['Mixpanel', /mixpanel/i], ['Segment', /segment/i], ['OneSignal', /onesignal/i],
];

function isIosProject(files) {
  return files.some((f) => /(^|\/)ios\//.test(f.rel) || /\.swift$/.test(f.rel) || /Info\.plist$/.test(f.rel) || /(^|\/)Podfile$/.test(f.rel));
}
function isAndroidProject(files) {
  return files.some((f) => /AndroidManifest\.xml$/.test(f.rel) || /(^|\/)android\//.test(f.rel) || /\.kt$/.test(f.rel));
}
function isExpo(files) {
  return files.some((f) => f.kind === 'manifest' && /"expo"\s*:/.test(f.content));
}
function isMobileProject(files) {
  return (
    isIosProject(files) || isAndroidProject(files) || isExpo(files) ||
    files.some((f) => /pubspec\.yaml$/.test(f.rel) || (f.kind === 'manifest' && /"react-native"\s*:/.test(f.content)))
  );
}
function findSdks(files) {
  const found = new Map();
  for (const f of files) {
    if (!['manifest', 'code', 'config'].includes(f.kind) && !/build\.gradle/.test(f.rel)) continue;
    const lines = f.content.split(/\r?\n/);
    lines.forEach((ln, i) => {
      if (!TRACKING_SDKS.test(ln)) return;
      const name = TRACKING_SDK_NAMES.find(([, re]) => re.test(ln))?.[0] || 'Tracking SDK';
      if (!found.has(name)) found.set(name, { label: name, file: f.rel, line: i + 1, snippet: ln.trim().slice(0, 160) });
    });
  }
  return [...found.values()];
}

export const MOBILE_RULES = [
  {
    id: 'MOB001',
    category: 'mobile',
    severity: 'medium',
    scope: 'file',
    kinds: ['mobile', 'config', 'code'],
    aggregate: true,
    patterns: [{ re: permRe(HIGH_RISK_PERMS), labelFrom: (m) => m[1] }],
    title: { tr: 'Yüksek riskli Android izni', en: 'High-risk Android permission' },
    desc: {
      tr: 'Arka plan konumu, SMS, arama kaydı, rehber, tüm uygulamaların listesi gibi izinler çok geniş kişisel veriye (ve üçüncü kişilerin verisine) erişim sağlar. Google Play bu izinler için ayrıca beyan ve gerekçe ister; ölçülülük ilkesi açısından da en riskli alandır.',
      en: 'Background location, SMS, call log, contacts, installed-apps permissions expose very broad personal data (including third parties\'). Google Play requires a declaration and justification; they are the riskiest area for proportionality.',
    },
    fix: {
      tr: 'İzin gerçekten çekirdek işlev için mi gerekli? Değilse kaldır (dikkat: bazı SDK\'lar manifest merge ile izin ekler — tools:node="remove" kullan). Gerekiyorsa izni ihtiyaç anında iste, aydınlatma metninde ve Play Data safety formunda belirt.',
      en: 'Is it really needed for core functionality? If not, remove it (SDKs may inject permissions via manifest merge — use tools:node="remove"). If needed, request it in context and disclose it in your privacy notice and Play Data safety form.',
    },
    refs: ['KVKK md.4/2-ç', 'GDPR Art.5(1)(c), Art.25', 'Google Play User Data policy'],
  },
  {
    id: 'MOB002',
    category: 'mobile',
    severity: 'info',
    scope: 'file',
    kinds: ['mobile', 'config', 'code'],
    aggregate: true,
    patterns: [
      { re: permRe(OTHER_PERMS), labelFrom: (m) => m[1] },
      { re: new RegExp(`\\b(${IOS_KEYS})\\b`), labelFrom: (m) => m[1] },
    ],
    title: { tr: 'Mobil cihaz izinleri (envanter)', en: 'Mobile device permissions (inventory)' },
    desc: {
      tr: 'Konum, kamera, mikrofon, fotoğraflar, takvim, reklam kimliği gibi izinler kişisel veri toplar. Her biri aydınlatma metninde, App Store gizlilik etiketlerinde ve Play Data safety formunda tutarlı biçimde yer almalı.',
      en: 'Location, camera, microphone, photos, calendar, advertising ID permissions collect personal data. Each must be disclosed consistently in the privacy notice, App Store privacy labels and Play Data safety form.',
    },
    fix: {
      tr: 'iOS kullanım açıklamalarını (…UsageDescription) somut ve dürüst yaz ("Konumunuz yalnızca yakındaki mağazaları göstermek için kullanılır"). Kullanılmayan izinleri kaldır.',
      en: 'Write concrete, honest iOS usage descriptions ("Your location is only used to show nearby stores"). Remove unused permissions.',
    },
    refs: ['KVKK md.10', 'GDPR Art.13', 'App Store Review Guideline 5.1.1'],
  },
  {
    id: 'MOB003',
    category: 'mobile',
    severity: 'high',
    scope: 'file',
    kinds: ['mobile', 'config', 'code', 'manifest'],
    aggregate: true,
    patterns: [
      { label: 'HealthKit', re: /(com\.apple\.developer\.healthkit|NSHealth(Share|Update)UsageDescription|HKHealthStore|react-native-health\b|@kingstinct\/react-native-healthkit)/ },
      { label: 'Health Connect / Google Fit', re: /(android\.permission\.health\.|androidx\.health\.connect|health_connect|react-native-health-connect|com\.google\.android\.gms\.fitness|\bhealth:\s*\^)/ },
    ],
    title: { tr: 'Sağlık verisi erişimi (HealthKit / Health Connect)', en: 'Health data access (HealthKit / Health Connect)' },
    desc: {
      tr: 'Sağlık verileri özel nitelikli kişisel veridir. Apple ve Google sağlık verisinin reklam/pazarlama için kullanılmasını ve üçüncü taraflarla paylaşılmasını yasaklar; ayrıca açık bir gizlilik politikası şarttır.',
      en: 'Health data is special category data. Apple and Google forbid using it for advertising/marketing or sharing it with third parties, and require a clear privacy policy.',
    },
    fix: {
      tr: 'Sadece gerekli veri türlerini oku, açık rıza al, sağlık verisini analitik/LLM/reklam SDK\'larına gönderme, şifreli sakla ve DPIA yap.',
      en: 'Read only the data types you need, get explicit consent, never send health data to analytics/LLM/ad SDKs, encrypt it and run a DPIA.',
    },
    refs: ['KVKK md.6', 'GDPR Art.9, Art.35', 'App Store Guideline 5.1.3', 'Google Play Health apps policy'],
  },
  {
    id: 'MOB004',
    category: 'mobile',
    severity: 'medium',
    scope: 'file',
    kinds: ['mobile', 'config'],
    patterns: [
      { label: 'android:usesCleartextTraffic="true"', re: /usesCleartextTraffic\s*=\s*["']true["']/ },
      { label: 'cleartextTrafficPermitted="true"', re: /cleartextTrafficPermitted\s*=\s*["']true["']/ },
      { label: 'android:debuggable="true"', re: /android:debuggable\s*=\s*["']true["']/ },
      { label: 'NSAllowsArbitraryLoads = true', re: /NSAllowsArbitraryLoads<\/key>\s*<true\s*\/>/, whole: true },
      { label: 'NSAllowsArbitraryLoads = true', re: /"NSAllowsArbitraryLoads"\s*:\s*true/ },
    ],
    title: { tr: 'Mobil uygulamada şifresiz trafik veya debug açık', en: 'Mobile app allows cleartext traffic or is debuggable' },
    desc: {
      tr: 'Şifresiz HTTP trafiğine izin vermek, kullanıcı verisinin ağda okunmasına yol açar. debuggable sürüm, cihazdaki uygulama verisine erişimi kolaylaştırır.',
      en: 'Allowing cleartext HTTP lets user data be read on the network. A debuggable build makes on-device app data easy to extract.',
    },
    fix: {
      tr: 'Tüm trafiği HTTPS yap; istisna gerekiyorsa sadece belirli alan adına izin ver (domain-config / NSExceptionDomains). Release build\'de debuggable kapalı olsun.',
      en: 'Use HTTPS everywhere; if an exception is needed, scope it to a domain (domain-config / NSExceptionDomains). Never ship debuggable release builds.',
    },
    refs: ['KVKK md.12', 'GDPR Art.32', 'OWASP MASVS-NETWORK'],
  },
  {
    id: 'MOB005',
    category: 'mobile',
    severity: 'low',
    scope: 'file',
    kinds: ['mobile'],
    patterns: [{ label: 'android:allowBackup="true"', re: /android:allowBackup\s*=\s*["']true["']/ }],
    title: { tr: 'Android otomatik yedekleme açık', en: 'Android auto-backup enabled' },
    desc: {
      tr: 'allowBackup=true iken uygulama verisi (oturum token\'ları, önbellek, yerel veritabanı) Google Drive yedeğine veya adb ile dışarı alınabilir.',
      en: 'With allowBackup=true, app data (session tokens, caches, local DB) can end up in Google Drive backups or be extracted via adb.',
    },
    fix: {
      tr: 'android:allowBackup="false" yap veya dataExtractionRules / fullBackupContent ile hassas dosyaları hariç tut.',
      en: 'Set android:allowBackup="false" or exclude sensitive files with dataExtractionRules / fullBackupContent.',
    },
    refs: ['KVKK md.12', 'GDPR Art.32', 'OWASP MASVS-STORAGE'],
  },
  {
    id: 'MOB006',
    category: 'mobile',
    severity: 'medium',
    scope: 'file',
    kinds: ['code'],
    patterns: [
      { label: 'SharedPreferences', re: /(prefs|preferences|sharedPreferences|SharedPreferences)\??\.set(String|Bool)?\(\s*['"][^'"]*(token|jwt|password|sifre|session|secret|refresh)/i },
      { label: 'SharedPreferences (Android)', re: /putString\(\s*["'][^"']*(token|jwt|password|session|secret)/i },
      { label: 'UserDefaults', re: /UserDefaults\.standard\.set\([^)]*(token|jwt|password|session|secret)/i },
      { label: 'MMKV / Hive (şifresiz)', re: /(MMKV|storage|box)\.(set|put)(String)?\(\s*['"][^'"]*(token|jwt|password|session|secret)/i },
    ],
    title: { tr: 'Mobilde token/şifre güvensiz depolamada', en: 'Token/password in insecure mobile storage' },
    desc: {
      tr: 'SharedPreferences / UserDefaults / AsyncStorage şifrelenmez; root/jailbreak, yedekler veya kötü amaçlı uygulamalar ile okunabilir.',
      en: 'SharedPreferences / UserDefaults / AsyncStorage are unencrypted and readable via root/jailbreak, backups or malware.',
    },
    fix: {
      tr: 'Keychain (iOS) / Keystore + EncryptedSharedPreferences (Android) kullan: expo-secure-store, react-native-keychain, flutter_secure_storage.',
      en: 'Use Keychain (iOS) / Keystore + EncryptedSharedPreferences (Android): expo-secure-store, react-native-keychain, flutter_secure_storage.',
    },
    refs: ['KVKK md.12', 'GDPR Art.32', 'OWASP MASVS-STORAGE'],
  },

  // ---------------- project-level ----------------
  {
    id: 'MOB007',
    category: 'mobile',
    severity: 'high',
    scope: 'project',
    check: ({ files }) => {
      if (!isIosProject(files) && !isExpo(files)) return [];
      const sdks = findSdks(files);
      if (!sdks.some((s) => ['AppsFlyer', 'Adjust', 'Branch', 'Meta (Facebook) SDK', 'Google AdMob'].includes(s.label))) return [];
      const hasAtt = files.some((f) =>
        /(NSUserTrackingUsageDescription|AppTrackingTransparency|ATTrackingManager|expo-tracking-transparency|react-native-tracking-transparency|app_tracking_transparency)/.test(f.content),
      );
      return hasAtt ? [] : sdks.filter((s) => s.label !== 'Firebase Analytics' && s.label !== 'OneSignal');
    },
    title: { tr: 'iOS reklam/atıf SDK\'sı var ama App Tracking Transparency yok', en: 'iOS ad/attribution SDK without App Tracking Transparency' },
    desc: {
      tr: 'Kullanıcıyı başka şirketlerin uygulama/sitelerinde izleyen veya IDFA kullanan SDK\'lar için Apple ATT izni zorunludur; aksi halde uygulama reddedilir. Ayrıca bu izleme KVKK/GDPR kapsamında açık rıza gerektirir.',
      en: 'Apple requires the ATT prompt for SDKs that track users across other companies\' apps/sites or use the IDFA; otherwise the app is rejected. This tracking also requires consent under GDPR/KVKK.',
    },
    fix: {
      tr: 'NSUserTrackingUsageDescription ekle ve SDK\'yı başlatmadan önce ATT izni iste (expo-tracking-transparency / AppTrackingTransparency). Reddedilirse IDFA\'sız modda çalıştır. AB kullanıcıları için Google UMP veya bir CMP de ekle.',
      en: 'Add NSUserTrackingUsageDescription and request ATT permission before initialising the SDK (expo-tracking-transparency / AppTrackingTransparency). Run without IDFA if denied. Add Google UMP or a CMP for EU users too.',
    },
    refs: ['App Store Guideline 5.1.2', 'KVKK md.5', 'GDPR Art.6–7', 'ePrivacy Art.5(3)'],
  },
  {
    id: 'MOB008',
    category: 'mobile',
    severity: 'medium',
    scope: 'project',
    check: ({ files }) => {
      if (!isIosProject(files) && !isExpo(files)) return [];
      const has = files.some((f) => /\.xcprivacy$/.test(f.rel) || /"privacyManifests"\s*:|privacyManifests\s*:/.test(f.content));
      return has ? [] : [{ label: 'PrivacyInfo.xcprivacy' }];
    },
    title: { tr: 'iOS Privacy Manifest (PrivacyInfo.xcprivacy) bulunamadı', en: 'iOS Privacy Manifest (PrivacyInfo.xcprivacy) not found' },
    desc: {
      tr: 'Apple 1 Mayıs 2024\'ten beri "required reason API" (UserDefaults, dosya zaman damgası, disk alanı vb.) kullanan uygulamalardan privacy manifest istiyor; toplanan veri türleri ve izleme alan adları da burada beyan edilir. Neredeyse tüm uygulamalar bu API\'leri dolaylı olarak kullanır.',
      en: 'Since 1 May 2024 Apple requires a privacy manifest for apps using "required reason APIs" (UserDefaults, file timestamps, disk space…), declaring collected data types and tracking domains. Nearly every app uses these APIs indirectly.',
    },
    fix: {
      tr: 'Xcode\'da File > New > App Privacy ile PrivacyInfo.xcprivacy ekle (Expo: app.json → ios.privacyManifests). NSPrivacyAccessedAPITypes, NSPrivacyCollectedDataTypes ve NSPrivacyTracking alanlarını doldur.',
      en: 'Add PrivacyInfo.xcprivacy via Xcode File > New > App Privacy (Expo: app.json → ios.privacyManifests). Fill NSPrivacyAccessedAPITypes, NSPrivacyCollectedDataTypes and NSPrivacyTracking.',
    },
    refs: ['Apple: Privacy manifest files', 'App Store Review Guideline 5.1.1'],
  },
  {
    id: 'MOB009',
    category: 'mobile',
    severity: 'info',
    scope: 'project',
    check: ({ files }) => {
      if (!isMobileProject(files)) return [];
      const sdks = findSdks(files);
      return sdks.length ? sdks : [{ label: { tr: 'mobil uygulama', en: 'mobile app' } }];
    },
    title: {
      tr: 'Mağaza gizlilik beyanları: App Store Privacy Labels / Play Data safety',
      en: 'Store privacy declarations: App Store Privacy Labels / Play Data safety',
    },
    desc: {
      tr: 'Mağaza beyanları, uygulamanın ve içindeki tüm SDK\'ların topladığı verilerle birebir tutarlı olmalı. Tutarsızlık uygulamanın kaldırılmasına ve aldatıcı ticari uygulama iddialarına yol açabilir. Listelenen SDK\'lar beyana dahil edilmeli.',
      en: 'Store declarations must match exactly what the app and every bundled SDK collects. Mismatches can get the app removed and lead to deceptive-practice claims. The listed SDKs must be included.',
    },
    fix: {
      tr: 'Her SDK\'nın kendi "data safety / privacy label" rehberine bakarak formları doldur; `kvkk-check docs` çıktısındaki veri envanterini kullan. Uygulama içinde ve mağazada gizlilik politikası URL\'i ver.',
      en: 'Fill the forms using each SDK\'s own data-safety / privacy-label guidance and the data inventory from `kvkk-check docs`. Provide a privacy policy URL in-app and on the store listing.',
    },
    refs: ['App Store Review Guideline 5.1.1', 'Google Play Data safety', 'KVKK md.10', 'GDPR Art.13'],
  },
];
