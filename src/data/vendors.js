// kvkk-ignore-file  (vendor database; contains tracker names on purpose)
/**
 * Known third parties: trackers, processors, AI providers, CDNs.
 * Shared by the live URL scanner (domains, cookies), the document generator
 * (purpose, recipient group, country) and reports.
 *
 * category:
 *   analytics | marketing | session-replay | consent | processor | infra | ai |
 *   payments | email | sms | support | fonts | embed | auth | errors | push | maps
 * consentRequired: true if the vendor sets non-essential cookies / identifiers
 *   and therefore must not load before consent (ePrivacy Art.5(3), KVKK Çerez Rehberi).
 * labels: names used by code-scan rules (TRK001/TRF001/TRF002…) so findings can be mapped back.
 * cookies: regex sources matched against cookie names (live scan + cookie policy).
 */

import { EXTRA_VENDORS } from '../live/extra-vendors.js';

const G = {
  analytics: { tr: 'Analitik hizmet sağlayıcıları', en: 'Analytics providers' },
  marketing: { tr: 'Reklam ve pazarlama iş ortakları', en: 'Advertising and marketing partners' },
  hosting: { tr: 'Barındırma ve altyapı hizmet sağlayıcıları', en: 'Hosting and infrastructure providers' },
  ai: { tr: 'Yapay zekâ hizmet sağlayıcıları', en: 'AI service providers' },
  payments: { tr: 'Ödeme hizmet sağlayıcıları', en: 'Payment service providers' },
  comms: { tr: 'İletişim (e-posta/SMS/bildirim) hizmet sağlayıcıları', en: 'Communication (email/SMS/push) providers' },
  support: { tr: 'Müşteri destek hizmet sağlayıcıları', en: 'Customer support providers' },
  errors: { tr: 'Hata izleme hizmet sağlayıcıları', en: 'Error monitoring providers' },
  content: { tr: 'İçerik ve gömülü medya sağlayıcıları', en: 'Content and embedded media providers' },
  auth: { tr: 'Kimlik doğrulama hizmet sağlayıcıları', en: 'Authentication providers' },
};

export const RECIPIENT_GROUPS = G;

const BASE_VENDORS = [
  // ---------------- Analytics ----------------
  {
    id: 'google-analytics', name: 'Google Analytics / Tag Manager', company: 'Google LLC', country: 'US',
    category: 'analytics', consentRequired: true, group: G.analytics,
    labels: ['Google Analytics / GTM'],
    domains: ['google-analytics.com', 'googletagmanager.com', 'analytics.google.com', 'region1.google-analytics.com'],
    cookies: ['^_ga$', '^_ga_', '^_gid$', '^_gat', '^__utm', '^_dc_gtm_'],
    purpose: { tr: 'Ziyaretçi davranışının analiz edilmesi ve istatistik üretilmesi', en: 'Analysing visitor behaviour and producing statistics' },
    privacyUrl: 'https://policies.google.com/privacy',
  },
  {
    id: 'google-ads', name: 'Google Ads / DoubleClick', company: 'Google LLC', country: 'US',
    category: 'marketing', consentRequired: true, group: G.marketing,
    labels: ['Google Ads'],
    domains: ['googleadservices.com', 'googlesyndication.com', 'doubleclick.net', 'adservice.google.com', 'pagead2.googlesyndication.com'],
    cookies: ['^_gcl_', '^IDE$', '^DSID$', '^test_cookie$', '^__gads$', '^__gpi$', '^NID$', '^ANID$'],
    purpose: { tr: 'Reklam gösterimi, dönüşüm ölçümü ve yeniden hedefleme', en: 'Ad delivery, conversion measurement and retargeting' },
    privacyUrl: 'https://policies.google.com/technologies/ads',
  },
  {
    id: 'meta-pixel', name: 'Meta (Facebook) Pixel', company: 'Meta Platforms Ireland Ltd. / Meta Platforms Inc.', country: 'US',
    category: 'marketing', consentRequired: true, group: G.marketing,
    labels: ['Meta (Facebook) Pixel'],
    domains: ['connect.facebook.net', 'facebook.com/tr', 'facebook.net'],
    cookies: ['^_fbp$', '^_fbc$', '^fr$'],
    purpose: { tr: 'Reklam dönüşüm ölçümü ve hedefleme', en: 'Ad conversion measurement and targeting' },
    privacyUrl: 'https://www.facebook.com/privacy/policy',
  },
  {
    id: 'hotjar', name: 'Hotjar', company: 'Hotjar Ltd.', country: 'MT',
    category: 'session-replay', consentRequired: true, group: G.analytics,
    labels: ['Hotjar'],
    domains: ['hotjar.com', 'hotjar.io'],
    cookies: ['^_hj'],
    purpose: { tr: 'Isı haritası ve oturum kaydı ile kullanım analizi', en: 'Heatmaps and session recordings' },
    privacyUrl: 'https://www.hotjar.com/legal/policies/privacy/',
  },
  {
    id: 'clarity', name: 'Microsoft Clarity', company: 'Microsoft Corporation', country: 'US',
    category: 'session-replay', consentRequired: true, group: G.analytics,
    labels: ['Microsoft Clarity'],
    domains: ['clarity.ms'],
    cookies: ['^_clck$', '^_clsk$', '^CLID$', '^MUID$', '^ANONCHK$', '^SM$'],
    purpose: { tr: 'Isı haritası ve oturum kaydı ile kullanım analizi', en: 'Heatmaps and session recordings' },
    privacyUrl: 'https://privacy.microsoft.com/privacystatement',
  },
  {
    id: 'mixpanel', name: 'Mixpanel', company: 'Mixpanel Inc.', country: 'US',
    category: 'analytics', consentRequired: true, group: G.analytics,
    labels: ['Mixpanel'],
    domains: ['mixpanel.com', 'mxpnl.com'],
    cookies: ['^mp_'],
    purpose: { tr: 'Ürün kullanım analizi', en: 'Product analytics' },
    privacyUrl: 'https://mixpanel.com/legal/privacy-policy/',
  },
  {
    id: 'segment', name: 'Segment', company: 'Twilio Inc.', country: 'US',
    category: 'analytics', consentRequired: true, group: G.analytics,
    labels: ['Segment'],
    domains: ['segment.com', 'segment.io', 'cdn.segment.com', 'api.segment.io'],
    cookies: ['^ajs_'],
    purpose: { tr: 'Analitik verilerin toplanması ve diğer araçlara iletilmesi', en: 'Collecting analytics data and forwarding it to other tools' },
    privacyUrl: 'https://www.twilio.com/legal/privacy',
  },
  {
    id: 'posthog', name: 'PostHog', company: 'PostHog Inc.', country: 'US/EU',
    category: 'analytics', consentRequired: true, group: G.analytics,
    labels: ['PostHog'],
    domains: ['posthog.com', 'i.posthog.com', 'us.i.posthog.com', 'eu.i.posthog.com'],
    cookies: ['^ph_', '_posthog$'],
    purpose: { tr: 'Ürün kullanım analizi ve oturum kaydı', en: 'Product analytics and session recording' },
    privacyUrl: 'https://posthog.com/privacy',
  },
  {
    id: 'amplitude', name: 'Amplitude', company: 'Amplitude Inc.', country: 'US',
    category: 'analytics', consentRequired: true, group: G.analytics,
    labels: ['Amplitude'],
    domains: ['amplitude.com', 'api2.amplitude.com', 'cdn.amplitude.com'],
    cookies: ['^AMP_', '^amp_'],
    purpose: { tr: 'Ürün kullanım analizi', en: 'Product analytics' },
    privacyUrl: 'https://amplitude.com/privacy',
  },
  {
    id: 'tiktok-pixel', name: 'TikTok Pixel', company: 'TikTok Technology Ltd. / ByteDance', country: 'US/SG',
    category: 'marketing', consentRequired: true, group: G.marketing,
    labels: ['TikTok Pixel'],
    domains: ['analytics.tiktok.com', 'tiktok.com/i18n/pixel'],
    cookies: ['^_ttp$', '^_tt_enable_cookie$', '^ttwid$'],
    purpose: { tr: 'Reklam dönüşüm ölçümü ve hedefleme', en: 'Ad conversion measurement and targeting' },
    privacyUrl: 'https://www.tiktok.com/legal/privacy-policy',
  },
  {
    id: 'linkedin-insight', name: 'LinkedIn Insight Tag', company: 'LinkedIn Ireland / LinkedIn Corp.', country: 'US',
    category: 'marketing', consentRequired: true, group: G.marketing,
    labels: ['LinkedIn Insight'],
    domains: ['snap.licdn.com', 'px.ads.linkedin.com'],
    cookies: ['^li_', '^bcookie$', '^lidc$', '^UserMatchHistory$', '^AnalyticsSyncHistory$', '^bscookie$'],
    purpose: { tr: 'Reklam dönüşüm ölçümü ve hedefleme', en: 'Ad conversion measurement and targeting' },
    privacyUrl: 'https://www.linkedin.com/legal/privacy-policy',
  },
  {
    id: 'yandex-metrica', name: 'Yandex Metrica', company: 'Yandex LLC', country: 'RU',
    category: 'session-replay', consentRequired: true, group: G.analytics,
    labels: ['Yandex Metrica'],
    domains: ['mc.yandex.ru', 'mc.yandex.com', 'yandex.ru/metrika'],
    cookies: ['^_ym', '^yandexuid$', '^yuidss$', '^ymex$'],
    purpose: { tr: 'Ziyaretçi analizi ve oturum kaydı', en: 'Visitor analytics and session recording' },
    privacyUrl: 'https://yandex.com/legal/confidential/',
  },
  {
    id: 'x-pixel', name: 'X (Twitter) Pixel', company: 'X Corp.', country: 'US',
    category: 'marketing', consentRequired: true, group: G.marketing,
    labels: ['X (Twitter) Pixel'],
    domains: ['static.ads-twitter.com', 'analytics.twitter.com', 't.co'],
    cookies: ['^muc_ads$', '^personalization_id$', '^guest_id'],
    purpose: { tr: 'Reklam dönüşüm ölçümü', en: 'Ad conversion measurement' },
    privacyUrl: 'https://x.com/en/privacy',
  },
  {
    id: 'criteo', name: 'Criteo', company: 'Criteo SA', country: 'FR',
    category: 'marketing', consentRequired: true, group: G.marketing,
    labels: ['Criteo'],
    domains: ['criteo.com', 'criteo.net'],
    cookies: ['^cto_'],
    purpose: { tr: 'Yeniden hedefleme reklamları', en: 'Retargeting ads' },
    privacyUrl: 'https://www.criteo.com/privacy/',
  },
  {
    id: 'fingerprintjs', name: 'FingerprintJS', company: 'FingerprintJS Inc.', country: 'US',
    category: 'analytics', consentRequired: true, group: G.analytics,
    labels: ['FingerprintJS'],
    domains: ['fpjs.io', 'fpcdn.io', 'api.fpjs.io'],
    cookies: ['^_vid_t$', '^_iidt$'],
    purpose: { tr: 'Cihaz parmak izi ile tanımlama', en: 'Device fingerprinting' },
    privacyUrl: 'https://fingerprint.com/privacy-policy/',
  },
  {
    id: 'vercel-analytics', name: 'Vercel Web Analytics / Speed Insights', company: 'Vercel Inc.', country: 'US',
    category: 'analytics', consentRequired: false, group: G.analytics,
    labels: ['Vercel Analytics / Speed Insights'],
    domains: ['vitals.vercel-insights.com', 'va.vercel-scripts.com'],
    cookies: [],
    purpose: { tr: 'Çerezsiz, toplu site trafiği ve performans ölçümü', en: 'Cookieless aggregate traffic and performance metrics' },
    privacyUrl: 'https://vercel.com/legal/privacy-policy',
  },
  {
    id: 'plausible', name: 'Plausible / Umami / Simple Analytics', company: '—', country: 'EU',
    category: 'analytics', consentRequired: false, group: G.analytics,
    labels: ['Plausible / Umami'],
    domains: ['plausible.io', 'umami.is', 'cloud.umami.is', 'simpleanalytics.com', 'scripts.simpleanalyticscdn.com'],
    cookies: [],
    purpose: { tr: 'Çerezsiz, anonim site istatistikleri', en: 'Cookieless anonymous site statistics' },
    privacyUrl: 'https://plausible.io/privacy',
  },

  // ---------------- Mobile SDKs ----------------
  {
    id: 'firebase-analytics', name: 'Google Analytics for Firebase', company: 'Google LLC', country: 'US',
    category: 'analytics', consentRequired: true, group: G.analytics,
    labels: ['Firebase Analytics'], domains: ['app-measurement.com', 'firebaselogging-pa.googleapis.com'], cookies: [],
    purpose: { tr: 'Mobil uygulama kullanım analizi', en: 'Mobile app analytics' },
    privacyUrl: 'https://firebase.google.com/support/privacy',
  },
  {
    id: 'appsflyer', name: 'AppsFlyer', company: 'AppsFlyer Ltd.', country: 'IL/US',
    category: 'marketing', consentRequired: true, group: G.marketing,
    labels: ['AppsFlyer'], domains: ['appsflyer.com', 'appsflyersdk.com'], cookies: ['^afUserId$', '^AF_SYNC$'],
    purpose: { tr: 'Mobil reklam atıf (attribution) ölçümü', en: 'Mobile ad attribution' },
    privacyUrl: 'https://www.appsflyer.com/legal/privacy-policy/',
  },
  {
    id: 'adjust', name: 'Adjust', company: 'Adjust GmbH', country: 'DE',
    category: 'marketing', consentRequired: true, group: G.marketing,
    labels: ['Adjust'], domains: ['adjust.com', 'adj.st'], cookies: [],
    purpose: { tr: 'Mobil reklam atıf (attribution) ölçümü', en: 'Mobile ad attribution' },
    privacyUrl: 'https://www.adjust.com/terms/privacy-policy/',
  },
  {
    id: 'branch', name: 'Branch', company: 'Branch Metrics Inc.', country: 'US',
    category: 'marketing', consentRequired: true, group: G.marketing,
    labels: ['Branch'], domains: ['branch.io', 'app.link'], cookies: [],
    purpose: { tr: 'Derin bağlantı ve reklam atıf ölçümü', en: 'Deep linking and attribution' },
    privacyUrl: 'https://legal.branch.io/',
  },
  {
    id: 'admob', name: 'Google AdMob', company: 'Google LLC', country: 'US',
    category: 'marketing', consentRequired: true, group: G.marketing,
    labels: ['Google AdMob'], domains: ['googleads.g.doubleclick.net', 'admob.com'], cookies: [],
    purpose: { tr: 'Uygulama içi reklam gösterimi', en: 'In-app advertising' },
    privacyUrl: 'https://policies.google.com/technologies/ads',
  },
  {
    id: 'facebook-sdk', name: 'Meta (Facebook) SDK', company: 'Meta Platforms Inc.', country: 'US',
    category: 'marketing', consentRequired: true, group: G.marketing,
    labels: ['Facebook SDK'], domains: ['graph.facebook.com'], cookies: [],
    purpose: { tr: 'Facebook ile giriş, uygulama olayları ve reklam ölçümü', en: 'Facebook login, app events and ad measurement' },
    privacyUrl: 'https://www.facebook.com/privacy/policy',
  },

  // ---------------- Infrastructure / processors ----------------
  {
    id: 'supabase', name: 'Supabase', company: 'Supabase Inc.', country: 'US (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Supabase'], domains: ['supabase.co', 'supabase.in'], cookies: ['^sb-'],
    purpose: { tr: 'Veritabanı, kimlik doğrulama ve dosya depolama', en: 'Database, authentication and file storage' },
    privacyUrl: 'https://supabase.com/privacy',
  },
  {
    id: 'firebase', name: 'Firebase / Google Cloud', company: 'Google LLC', country: 'US (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Firebase / Google Cloud'], domains: ['firebaseio.com', 'firestore.googleapis.com', 'firebasestorage.googleapis.com', 'identitytoolkit.googleapis.com'], cookies: [],
    purpose: { tr: 'Veritabanı, kimlik doğrulama ve dosya depolama', en: 'Database, authentication and file storage' },
    privacyUrl: 'https://firebase.google.com/support/privacy',
  },
  {
    id: 'aws', name: 'Amazon Web Services', company: 'Amazon Web Services Inc.', country: 'US (bölge seçilebilir)',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['AWS'], domains: ['amazonaws.com', 'cloudfront.net'], cookies: ['^AWSALB'],
    purpose: { tr: 'Sunucu, depolama ve altyapı hizmetleri', en: 'Servers, storage and infrastructure' },
    privacyUrl: 'https://aws.amazon.com/privacy/',
  },
  {
    id: 'vercel', name: 'Vercel', company: 'Vercel Inc.', country: 'US',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['Vercel'], domains: ['vercel.app', 'vercel.com', 'blob.vercel-storage.com', 'vercel-storage.com'], cookies: [],
    purpose: { tr: 'Web uygulamasının barındırılması', en: 'Web application hosting' },
    privacyUrl: 'https://vercel.com/legal/privacy-policy',
  },
  {
    id: 'netlify', name: 'Netlify', company: 'Netlify Inc.', country: 'US',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['Netlify'], domains: ['netlify.app', 'netlify.com'], cookies: [],
    purpose: { tr: 'Web uygulamasının barındırılması', en: 'Web application hosting' },
    privacyUrl: 'https://www.netlify.com/privacy/',
  },
  {
    id: 'cloudflare', name: 'Cloudflare', company: 'Cloudflare Inc.', country: 'US',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['Cloudflare'], domains: ['cloudflare.com', 'cdnjs.cloudflare.com', 'challenges.cloudflare.com', 'cloudflareinsights.com', 'r2.cloudflarestorage.com', 'workers.dev'], cookies: ['^__cf_bm$', '^cf_clearance$', '^__cflb$', '^_cfuvid$'],
    purpose: { tr: 'CDN, güvenlik ve bot koruması', en: 'CDN, security and bot protection' },
    privacyUrl: 'https://www.cloudflare.com/privacypolicy/',
  },
  {
    id: 'cloudinary', name: 'Cloudinary', company: 'Cloudinary Ltd.', country: 'US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Cloudinary / Uploadthing'], domains: ['cloudinary.com', 'res.cloudinary.com'], cookies: [],
    purpose: { tr: 'Görsel ve dosya depolama/işleme', en: 'Image and file storage/processing' },
    privacyUrl: 'https://cloudinary.com/privacy',
  },
  {
    id: 'clerk', name: 'Clerk / Auth0', company: 'Clerk Inc. / Okta Inc.', country: 'US',
    category: 'auth', consentRequired: false, group: G.auth,
    labels: ['Clerk / Auth0'], domains: ['clerk.com', 'clerk.accounts.dev', 'auth0.com'], cookies: ['^__session$', '^__client', '^auth0'],
    purpose: { tr: 'Kullanıcı kimlik doğrulama', en: 'User authentication' },
    privacyUrl: 'https://clerk.com/legal/privacy',
  },

  // ---------------- AI ----------------
  {
    id: 'openai', name: 'OpenAI', company: 'OpenAI, L.L.C. / OpenAI Ireland Ltd.', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['OpenAI'], domains: ['api.openai.com'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli özelliklerin sunulması', en: 'Providing AI-powered features' },
    privacyUrl: 'https://openai.com/policies/privacy-policy/',
  },
  {
    id: 'anthropic', name: 'Anthropic (Claude)', company: 'Anthropic PBC', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Anthropic'], domains: ['api.anthropic.com'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli özelliklerin sunulması', en: 'Providing AI-powered features' },
    privacyUrl: 'https://www.anthropic.com/legal/privacy',
  },
  {
    id: 'gemini', name: 'Google Gemini', company: 'Google LLC', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Google Gemini'], domains: ['generativelanguage.googleapis.com', 'aiplatform.googleapis.com'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli özelliklerin sunulması', en: 'Providing AI-powered features' },
    privacyUrl: 'https://policies.google.com/privacy',
  },
  {
    id: 'vercel-ai', name: 'Vercel AI SDK (seçilen model sağlayıcısı)', company: '—', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Vercel AI SDK'], domains: ['ai-gateway.vercel.sh'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli özelliklerin sunulması', en: 'Providing AI-powered features' },
    privacyUrl: '',
  },
  {
    id: 'other-ai', name: 'Mistral / Groq / Replicate / Together', company: '—', country: 'US/EU',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Mistral / Groq / Replicate / Together'], domains: ['api.mistral.ai', 'api.groq.com', 'api.replicate.com', 'api.together.xyz'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli özelliklerin sunulması', en: 'Providing AI-powered features' },
    privacyUrl: '',
  },

  // ---------------- Payments ----------------
  {
    id: 'stripe', name: 'Stripe', company: 'Stripe Inc. / Stripe Payments Europe Ltd.', country: 'US/IE',
    category: 'payments', consentRequired: false, group: G.payments,
    labels: ['Stripe'], domains: ['stripe.com', 'js.stripe.com', 'm.stripe.network', 'api.stripe.com'], cookies: ['^__stripe_mid$', '^__stripe_sid$', '^m$'],
    purpose: { tr: 'Ödemelerin alınması ve dolandırıcılık önleme', en: 'Processing payments and fraud prevention' },
    privacyUrl: 'https://stripe.com/privacy',
  },
  {
    id: 'iyzico', name: 'iyzico / PayTR', company: 'iyzi Ödeme ve Elektronik Para Hizmetleri A.Ş. / PayTR', country: 'TR',
    category: 'payments', consentRequired: false, group: G.payments,
    labels: ['Iyzico / PayTR'], domains: ['iyzipay.com', 'iyzico.com', 'paytr.com'], cookies: [],
    purpose: { tr: 'Ödemelerin alınması', en: 'Processing payments' },
    privacyUrl: 'https://www.iyzico.com/gizlilik-politikasi',
  },
  {
    id: 'paddle', name: 'Paddle', company: 'Paddle.com Market Ltd.', country: 'UK',
    category: 'payments', consentRequired: false, group: G.payments,
    labels: ['Paddle / Lemon Squeezy', 'Paddle'], domains: ['paddle.com', 'paddle.io', 'cdn.paddle.com'], cookies: [],
    purpose: { tr: 'Ödemelerin alınması (satıcı kayıtlı aracı)', en: 'Processing payments (merchant of record)' },
    privacyUrl: 'https://www.paddle.com/legal/privacy',
  },

  // ---------------- Communications ----------------
  {
    id: 'email-services', name: 'E-posta servisi (Resend/SendGrid/Mailchimp/Postmark/Mailgun/Brevo)', company: '—', country: 'US/EU',
    category: 'email', consentRequired: false, group: G.comms,
    labels: ['E-posta servisi (Resend/SendGrid/Mailchimp/Postmark/Mailgun/Brevo)', 'Email service (Resend/SendGrid/Mailchimp/Postmark/Mailgun/Brevo)'],
    domains: ['resend.com', 'sendgrid.net', 'list-manage.com', 'mailchimp.com', 'postmarkapp.com', 'mailgun.net', 'brevo.com', 'sendinblue.com'], cookies: [],
    purpose: { tr: 'İşlemsel ve (onay varsa) pazarlama e-postalarının gönderimi', en: 'Sending transactional and (with consent) marketing emails' },
    privacyUrl: '',
  },
  {
    id: 'twilio', name: 'Twilio', company: 'Twilio Inc.', country: 'US',
    category: 'sms', consentRequired: false, group: G.comms,
    labels: ['Twilio'], domains: ['twilio.com'], cookies: [],
    purpose: { tr: 'SMS doğrulama ve bildirim gönderimi', en: 'SMS verification and notifications' },
    privacyUrl: 'https://www.twilio.com/legal/privacy',
  },
  {
    id: 'push', name: 'OneSignal / Expo Push / FCM', company: 'OneSignal Inc. / Expo / Google LLC', country: 'US',
    category: 'push', consentRequired: false, group: G.comms,
    labels: ['OneSignal / Expo Push / FCM'], domains: ['onesignal.com', 'exp.host', 'fcm.googleapis.com'], cookies: [],
    purpose: { tr: 'Anlık bildirim gönderimi', en: 'Push notifications' },
    privacyUrl: '',
  },
  {
    id: 'support-chat', name: 'Intercom / Crisp / Tawk / Zendesk', company: '—', country: 'US/EU',
    category: 'support', consentRequired: true, group: G.support,
    labels: ['Intercom / Crisp / Tawk / Zendesk'],
    domains: ['intercom.io', 'intercomcdn.com', 'crisp.chat', 'tawk.to', 'zdassets.com', 'zendesk.com'],
    cookies: ['^intercom-', '^crisp-client', '^TawkConnectionTime$', '^__zlcmid$', '^twk_'],
    purpose: { tr: 'Canlı destek ve müşteri iletişimi', en: 'Live chat and customer support' },
    privacyUrl: '',
  },
  {
    id: 'sentry', name: 'Sentry', company: 'Functional Software Inc.', country: 'US/EU',
    category: 'errors', consentRequired: false, group: G.errors,
    labels: ['Sentry'], domains: ['sentry.io', 'ingest.sentry.io', 'browser.sentry-cdn.com'], cookies: [],
    purpose: { tr: 'Uygulama hatalarının izlenmesi', en: 'Application error monitoring' },
    privacyUrl: 'https://sentry.io/privacy/',
  },
  {
    id: 'logrocket', name: 'LogRocket / FullStory', company: 'LogRocket Inc. / FullStory Inc.', country: 'US',
    category: 'session-replay', consentRequired: true, group: G.analytics,
    labels: ['LogRocket / FullStory'], domains: ['logrocket.io', 'lr-ingest.io', 'lr-in-prod.com', 'fullstory.com'], cookies: ['^_lr_', '^fs_uid$'],
    purpose: { tr: 'Oturum kaydı ve hata analizi', en: 'Session replay and debugging' },
    privacyUrl: '',
  },

  // ---------------- Fonts / embeds / maps ----------------
  {
    id: 'google-fonts', name: 'Google Fonts', company: 'Google LLC', country: 'US',
    category: 'fonts', consentRequired: true, group: G.content,
    labels: ['Google Fonts CDN'], domains: ['fonts.googleapis.com', 'fonts.gstatic.com'], cookies: [],
    purpose: { tr: 'Yazı tiplerinin yüklenmesi (IP adresi Google\'a iletilir)', en: 'Loading web fonts (IP address is sent to Google)' },
    privacyUrl: 'https://developers.google.com/fonts/faq/privacy',
  },
  {
    id: 'youtube', name: 'YouTube', company: 'Google LLC', country: 'US',
    category: 'embed', consentRequired: true, group: G.content,
    labels: ['YouTube embed'], domains: ['youtube.com', 'ytimg.com', 'googlevideo.com'], cookies: ['^YSC$', '^VISITOR_INFO1_LIVE$', '^VISITOR_PRIVACY_METADATA$', '^PREF$', '^__Secure-YEC$'],
    purpose: { tr: 'Gömülü video oynatma', en: 'Embedded video playback' },
    privacyUrl: 'https://policies.google.com/privacy',
  },
  {
    id: 'vimeo', name: 'Vimeo', company: 'Vimeo.com Inc.', country: 'US',
    category: 'embed', consentRequired: true, group: G.content,
    labels: ['Vimeo embed'], domains: ['vimeo.com', 'vimeocdn.com'], cookies: ['^vuid$', '^__cf_bm$'],
    purpose: { tr: 'Gömülü video oynatma', en: 'Embedded video playback' },
    privacyUrl: 'https://vimeo.com/privacy',
  },
  {
    id: 'google-maps', name: 'Google Maps', company: 'Google LLC', country: 'US',
    category: 'maps', consentRequired: true, group: G.content,
    labels: ['Google Maps embed'], domains: ['maps.googleapis.com', 'maps.gstatic.com', 'google.com/maps'], cookies: [],
    purpose: { tr: 'Harita gösterimi', en: 'Displaying maps' },
    privacyUrl: 'https://policies.google.com/privacy',
  },
  {
    id: 'recaptcha', name: 'Google reCAPTCHA', company: 'Google LLC', country: 'US',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['Google reCAPTCHA'], domains: ['recaptcha.net', 'google.com/recaptcha', 'gstatic.com/recaptcha'], cookies: ['^_GRECAPTCHA$'],
    purpose: { tr: 'Bot ve spam koruması', en: 'Bot and spam protection' },
    privacyUrl: 'https://policies.google.com/privacy',
  },

  // ---------------- Consent managers (informational) ----------------
  {
    id: 'consent-managers', name: 'Consent yönetim platformu', company: '—', country: '—',
    category: 'consent', consentRequired: false, group: G.hosting,
    labels: [],
    domains: ['cookiebot.com', 'consent.cookiebot.com', 'onetrust.com', 'cookielaw.org', 'usercentrics.eu', 'iubenda.com', 'termly.io', 'osano.com', 'cdn.jsdelivr.net/gh/orestbida/cookieconsent'],
    cookies: ['^CookieConsent$', '^OptanonConsent$', '^OptanonAlertBoxClosed$', '^cc_cookie$', '^klaro$', '^uc_', '^euconsent'],
    purpose: { tr: 'Çerez tercihlerinin saklanması', en: 'Storing cookie preferences' },
    privacyUrl: '',
  },

  // ---------------- AI (China-based model APIs) ----------------
  // Listed after the general entries so path-specific domains above keep precedence in vendorForUrl.
  {
    id: 'volcengine-ark', name: 'Volcengine Ark / Doubao', company: 'Volcano Engine (ByteDance)', country: 'CN',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Volcengine Ark / Doubao'], domains: ['volces.com', 'volcengineapi.com'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli özelliklerin sunulması', en: 'Providing AI-powered features' },
    privacyUrl: 'https://www.volcengine.com/docs/6256/64902',
  },
  {
    id: 'deepseek', name: 'DeepSeek', company: 'DeepSeek (Hangzhou DeepSeek AI Co., Ltd.)', country: 'CN',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['DeepSeek'], domains: ['api.deepseek.com'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli özelliklerin sunulması', en: 'Providing AI-powered features' },
    privacyUrl: 'https://platform.deepseek.com/downloads/DeepSeek%20Privacy%20Policy.html',
  },
  {
    id: 'moonshot', name: 'Moonshot AI / Kimi', company: 'Moonshot AI (Beijing Moonshot Technology Co., Ltd.)', country: 'CN',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Moonshot AI / Kimi'], domains: ['api.moonshot.cn', 'api.moonshot.ai'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli özelliklerin sunulması', en: 'Providing AI-powered features' },
    privacyUrl: '',
  },
  {
    id: 'zhipu', name: 'Zhipu AI / BigModel (GLM)', company: 'Zhipu AI (Beijing Zhipu Huazhang Technology Co., Ltd.)', country: 'CN',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Zhipu AI / BigModel'], domains: ['open.bigmodel.cn'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli özelliklerin sunulması', en: 'Providing AI-powered features' },
    privacyUrl: '',
  },
  {
    id: 'dashscope', name: 'Alibaba Cloud Model Studio (DashScope / Qwen)', company: 'Alibaba Cloud (Alibaba Group)', country: 'CN',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Alibaba DashScope / Qwen'], domains: ['dashscope.aliyuncs.com', 'dashscope-intl.aliyuncs.com'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli özelliklerin sunulması', en: 'Providing AI-powered features' },
    privacyUrl: 'https://www.alibabacloud.com/help/en/legal/latest/alibaba-cloud-international-website-privacy-policy',
  },
  {
    id: 'baidu-qianfan', name: 'Baidu Qianfan / Wenxin', company: 'Baidu, Inc.', country: 'CN',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Baidu Qianfan'], domains: ['qianfan.baidubce.com', 'aip.baidubce.com'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli özelliklerin sunulması', en: 'Providing AI-powered features' },
    privacyUrl: '',
  },
  {
    id: 'lovable-ai', name: 'Lovable AI Gateway', company: 'Lovable Labs Incorporated AB', country: 'SE/US',
    category: 'ai', consentRequired: false, group: G.ai,
    // The gateway (Sweden) forwards prompts to the selected model provider (OpenAI, Google…, US).
    onwardCountries: ['US'],
    labels: ['Lovable AI Gateway'], domains: ['ai.gateway.lovable.dev'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli özelliklerin sunulması', en: 'Providing AI-powered features' },
    privacyUrl: 'https://lovable.dev/privacy',
  },

  // ---------------- Other processors / content ----------------
  {
    id: 'ms-translator', name: 'Microsoft Translator / Azure AI Services', company: 'Microsoft Corporation', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Microsoft Translator / Azure AI Services'],
    domains: ['api.cognitive.microsofttranslator.com', 'microsofttranslator.com', 'cognitiveservices.azure.com', 'api.cognitive.microsoft.com'], cookies: [],
    purpose: { tr: 'Metin çevirisi ve yapay zekâ hizmetleri', en: 'Text translation and AI services' },
    privacyUrl: 'https://privacy.microsoft.com/privacystatement',
  },
  {
    id: 'gravatar', name: 'Gravatar', company: 'Automattic Inc.', country: 'US',
    category: 'embed', consentRequired: false, group: G.content,
    labels: ['Gravatar'], domains: ['gravatar.com', 'secure.gravatar.com', 'en.gravatar.com'], cookies: [],
    purpose: { tr: 'Profil resimlerinin gösterimi (e-posta adresinin özeti ve IP adresi iletilir)', en: 'Displaying avatars (an e-mail hash and the IP address are sent)' },
    privacyUrl: 'https://automattic.com/privacy/',
  },
  {
    id: 'jsdelivr', name: 'jsDelivr CDN', company: 'jsDelivr (Prospect One)', country: 'PL/US',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['jsDelivr CDN'], domains: ['cdn.jsdelivr.net', 'fastly.jsdelivr.net', 'gcore.jsdelivr.net', 'testingcf.jsdelivr.net'], cookies: [],
    purpose: { tr: 'Kütüphane ve dosyaların CDN üzerinden yüklenmesi (IP adresi CDN\'e iletilir)', en: 'Loading libraries and files from a CDN (IP address is sent to the CDN)' },
    privacyUrl: 'https://www.jsdelivr.com/terms/privacy-policy-jsdelivr-net',
  },
  {
    id: 'elastic', name: 'Elastic Cloud / Elasticsearch Service', company: 'Elasticsearch B.V. / Elastic N.V.', country: 'US (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Elastic Cloud'], domains: ['elastic-cloud.com', 'elastic.cloud', 'found.io', 'cloud.es.io'], cookies: [],
    aliases: ['elastic cloud'], hosting: 'search', engine: 'elasticsearch',
    purpose: { tr: 'Arama ve günlük (log) verilerinin barındırılması', en: 'Hosting search and log data' },
    privacyUrl: 'https://www.elastic.co/legal/privacy-statement',
  },

  // ---------------- Managed databases / caches (hosting: where the app's stores live) ----------------
  // `hosting` ('database' | 'cache' | 'search') marks a vendor whose servers hold the app's own stores; `engine`
  // narrows which stores ('mysql' | 'postgres' | 'mongodb' | 'redis' | …). `aliases`: names that identify the vendor
  // in config comments (".env.example: # Database (MySQL - PlanetScale)").
  {
    id: 'planetscale', name: 'PlanetScale', company: 'PlanetScale Inc.', country: 'US (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['PlanetScale'], domains: ['psdb.cloud', 'planetscale.com'], cookies: [],
    aliases: ['planetscale'], hosting: 'database', engine: 'mysql',
    purpose: { tr: 'Veritabanının barındırılması', en: 'Database hosting' },
    privacyUrl: 'https://planetscale.com/legal/privacy',
  },
  {
    id: 'neon', name: 'Neon (Serverless Postgres)', company: 'Neon Inc.', country: 'US (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Neon'], domains: ['neon.tech', 'neon.build'], cookies: [],
    aliases: ['neon postgres', 'neon database', 'neon db', 'neon.tech', 'vercel postgres'], hosting: 'database', engine: 'postgres',
    purpose: { tr: 'Veritabanının barındırılması', en: 'Database hosting' },
    privacyUrl: 'https://neon.tech/privacy-policy',
  },
  {
    id: 'mongodb-atlas', name: 'MongoDB Atlas', company: 'MongoDB Inc.', country: 'US (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['MongoDB Atlas'], domains: ['mongodb.net'], cookies: [],
    aliases: ['mongodb atlas', 'mongo atlas'], hosting: 'database', engine: 'mongodb',
    purpose: { tr: 'Veritabanının barındırılması', en: 'Database hosting' },
    privacyUrl: 'https://www.mongodb.com/legal/privacy/privacy-policy',
  },
  {
    id: 'upstash', name: 'Upstash (Redis / Vercel KV)', company: 'Upstash Inc.', country: 'US (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Upstash'], domains: ['upstash.io'], cookies: [],
    aliases: ['upstash', 'vercel kv', 'vercel redis'], hosting: 'cache', engine: 'redis',
    purpose: { tr: 'Önbellek / anahtar-değer verilerinin barındırılması', en: 'Hosting cache / key-value data' },
    privacyUrl: 'https://upstash.com/trust/privacy.pdf',
  },
  {
    id: 'redis-cloud', name: 'Redis Cloud', company: 'Redis Ltd.', country: 'US (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Redis Cloud'], domains: ['redislabs.com', 'redis-cloud.com', 'redns.redis-cloud.com'], cookies: [],
    aliases: ['redis cloud', 'redis enterprise cloud', 'redislabs'], hosting: 'cache', engine: 'redis',
    purpose: { tr: 'Önbellek / anahtar-değer verilerinin barındırılması', en: 'Hosting cache / key-value data' },
    privacyUrl: 'https://redis.io/legal/privacy-policy/',
  },
  {
    id: 'aiven', name: 'Aiven', company: 'Aiven Oy', country: 'FI (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Aiven'], domains: ['aivencloud.com'], cookies: [],
    aliases: ['aiven'], hosting: 'database',
    purpose: { tr: 'Veritabanının barındırılması', en: 'Database hosting' },
    privacyUrl: 'https://aiven.io/privacy',
  },
  {
    id: 'turso', name: 'Turso (libSQL)', company: 'ChiselStrike Inc.', country: 'US (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Turso'], domains: ['turso.io'], cookies: [],
    aliases: ['turso'], hosting: 'database', engine: 'sqlite',
    purpose: { tr: 'Veritabanının barındırılması', en: 'Database hosting' },
    privacyUrl: 'https://turso.tech/privacy-policy',
  },
  {
    id: 'cockroachdb', name: 'CockroachDB Cloud', company: 'Cockroach Labs Inc.', country: 'US (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['CockroachDB Cloud'], domains: ['cockroachlabs.cloud'], cookies: [],
    aliases: ['cockroachdb', 'cockroach cloud'], hosting: 'database', engine: 'postgres',
    purpose: { tr: 'Veritabanının barındırılması', en: 'Database hosting' },
    privacyUrl: 'https://www.cockroachlabs.com/privacy/',
  },
  {
    id: 'algolia', name: 'Algolia', company: 'Algolia SAS', country: 'FR/US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Algolia'], domains: ['algolia.net', 'algolianet.com', 'algolia.io', 'algolia.com'], cookies: [],
    aliases: ['algolia'], hosting: 'search',
    purpose: { tr: 'Arama dizininin barındırılması ve arama sorgularının işlenmesi', en: 'Hosting the search index and processing search queries' },
    privacyUrl: 'https://www.algolia.com/policies/privacy/',
  },

  // ---------------- Generic SMTP ----------------
  // Mail sent through an SMTP server named only in configuration (SMTP_HOST / MAIL_SERVER / EMAIL_HOST): the operator
  // is unknown from the code. relayOnly: a transactional relay, not a store an erasure request could target.
  {
    id: 'smtp', name: 'SMTP sunucusu (ortam değişkeniyle yapılandırılmış)', company: '—', country: '—',
    category: 'email', consentRequired: false, group: G.comms, relayOnly: true,
    labels: ['SMTP (env-configured)'], domains: [], cookies: [],
    purpose: { tr: 'İşlemsel e-postaların gönderimi', en: 'Sending transactional emails' },
    privacyUrl: '',
  },

  // ---------------- Webhooks / automation ----------------
  {
    id: 'slack', name: 'Slack', company: 'Slack Technologies LLC (Salesforce)', country: 'US',
    category: 'support', consentRequired: false, group: G.comms,
    labels: ['Slack'], domains: ['hooks.slack.com', 'slack.com'], cookies: [],
    // envKeys: env variables whose value is this vendor's endpoint (a webhook URL configured only in the environment).
    envKeys: ['^SLACK_(?:[A-Z0-9]+_)*WEBHOOK(?:_URL)?$', '^SLACK_(?:[A-Z0-9]+_)*HOOK_URL$'],
    purpose: { tr: 'Ekip içi bildirim ve mesaj gönderimi', en: 'Sending notifications and messages to a team workspace' },
    privacyUrl: 'https://slack.com/trust/privacy/privacy-policy',
  },
  {
    id: 'discord', name: 'Discord (webhook)', company: 'Discord Inc.', country: 'US',
    category: 'support', consentRequired: false, group: G.comms,
    labels: ['Discord'], domains: ['discord.com/api/webhooks', 'discordapp.com/api/webhooks'], cookies: [],
    envKeys: ['^DISCORD_(?:[A-Z0-9]+_)*WEBHOOK(?:_URL)?$'],
    purpose: { tr: 'Ekip içi bildirim ve mesaj gönderimi', en: 'Sending notifications and messages to a team channel' },
    privacyUrl: 'https://discord.com/privacy',
  },
  {
    id: 'buildship', name: 'BuildShip', company: 'Rowy Inc.', country: 'US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['BuildShip'], domains: ['buildship.run', 'buildship.app'], cookies: [],
    purpose: { tr: 'İş akışı otomasyonu (webhook ile iletilen verinin işlenmesi)', en: 'Workflow automation (processing data sent by webhook)' },
    privacyUrl: 'https://buildship.com/privacy',
  },
  {
    id: 'zapier', name: 'Zapier / Make', company: 'Zapier Inc. / Celonis (Make)', country: 'US/CZ',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Zapier / Make'], domains: ['hooks.zapier.com', 'make.com', 'integromat.com'], cookies: [],
    purpose: { tr: 'İş akışı otomasyonu (webhook ile iletilen verinin işlenmesi)', en: 'Workflow automation (processing data sent by webhook)' },
    privacyUrl: 'https://zapier.com/privacy',
  },

  // ---------------- Contact / profile enrichment (indirect collection about third persons) ----------------
  // enrichment: the vendor returns personal data about people who are not users of the app (KVKK md.10 / GDPR Art.14).
  {
    id: 'hunter', name: 'Hunter.io', company: 'Hunter Web Services', country: 'FR/US',
    category: 'processor', consentRequired: false, group: G.marketing, enrichment: true,
    labels: ['Hunter.io'], domains: ['hunter.io'], cookies: [],
    purpose: { tr: 'E-posta adresi bulma ve doğrulama (kişi verisinin zenginleştirilmesi)', en: 'Email finding and verification (contact enrichment)' },
    privacyUrl: 'https://hunter.io/privacy-policy',
  },
  {
    id: 'apollo', name: 'Apollo.io', company: 'Apollo.io Inc. (ZenLeads)', country: 'US',
    category: 'processor', consentRequired: false, group: G.marketing, enrichment: true,
    labels: ['Apollo.io'], domains: ['api.apollo.io', 'app.apollo.io'], cookies: [],
    purpose: { tr: 'Satış/potansiyel müşteri verisi ve kişi zenginleştirme', en: 'Sales prospect data and contact enrichment' },
    privacyUrl: 'https://www.apollo.io/privacy-policy',
  },
  {
    id: 'clearbit', name: 'Clearbit (HubSpot Breeze Intelligence)', company: 'HubSpot Inc.', country: 'US',
    category: 'processor', consentRequired: false, group: G.marketing, enrichment: true,
    labels: ['Clearbit'], domains: ['clearbit.com'], cookies: [],
    purpose: { tr: 'Kişi ve şirket verisinin zenginleştirilmesi', en: 'Person and company data enrichment' },
    privacyUrl: 'https://legal.hubspot.com/privacy-policy',
  },
  {
    id: 'luma', name: 'Luma (lu.ma)', company: 'Luma AI Inc.', country: 'US',
    category: 'embed', consentRequired: false, group: G.content,
    labels: ['Luma'], domains: ['lu.ma', 'api.lu.ma'], cookies: [],
    purpose: { tr: 'Etkinlik ve katılımcı verileri', en: 'Event and attendee data' },
    privacyUrl: 'https://lu.ma/privacy-policy',
  },

  // ---------------- Public CDNs / font hosts loaded by pages ----------------
  {
    id: 'unpkg', name: 'unpkg CDN', company: 'unpkg (Cloudflare Inc. altyapısı)', country: 'US',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['unpkg CDN'], domains: ['unpkg.com'], cookies: [],
    purpose: { tr: 'Kütüphane ve dosyaların CDN üzerinden yüklenmesi (IP adresi CDN\'e iletilir)', en: 'Loading libraries and files from a CDN (IP address is sent to the CDN)' },
    privacyUrl: 'https://www.cloudflare.com/privacypolicy/',
  },
  {
    id: 'jquery-cdn', name: 'jQuery / Bootstrap CDN', company: 'OpenJS Foundation / StackPath', country: 'US',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['jQuery / Bootstrap CDN'], domains: ['code.jquery.com', 'stackpath.bootstrapcdn.com', 'maxcdn.bootstrapcdn.com', 'netdna.bootstrapcdn.com'], cookies: [],
    purpose: { tr: 'Kütüphane ve dosyaların CDN üzerinden yüklenmesi (IP adresi CDN\'e iletilir)', en: 'Loading libraries and files from a CDN (IP address is sent to the CDN)' },
    privacyUrl: 'https://openjsf.org/wp-content/uploads/sites/84/2021/04/OpenJS-Foundation-Privacy-Policy-2019-11-15.pdf',
  },
  {
    id: 'adobe-fonts', name: 'Adobe Fonts (Typekit)', company: 'Adobe Inc.', country: 'US',
    category: 'fonts', consentRequired: true, group: G.content,
    labels: ['Adobe Fonts'], domains: ['use.typekit.net', 'p.typekit.net'], cookies: [],
    purpose: { tr: 'Yazı tiplerinin yüklenmesi (IP adresi Adobe\'ye iletilir)', en: 'Loading web fonts (IP address is sent to Adobe)' },
    privacyUrl: 'https://www.adobe.com/privacy/policies/adobe-fonts.html',
  },
  {
    id: 'font-awesome', name: 'Font Awesome CDN', company: 'Fonticons Inc.', country: 'US',
    category: 'fonts', consentRequired: true, group: G.content,
    labels: ['Font Awesome CDN'], domains: ['kit.fontawesome.com', 'use.fontawesome.com', 'ka-f.fontawesome.com', 'ka-p.fontawesome.com'], cookies: [],
    purpose: { tr: 'İkon yazı tiplerinin yüklenmesi (IP adresi iletilir)', en: 'Loading icon fonts (IP address is sent)' },
    privacyUrl: 'https://fontawesome.com/privacy',
  },
  {
    id: 'bunny-fonts', name: 'Bunny Fonts', company: 'BunnyWay d.o.o.', country: 'SI',
    category: 'fonts', consentRequired: false, group: G.content,
    labels: ['Bunny Fonts'], domains: ['fonts.bunny.net'], cookies: [],
    purpose: { tr: 'Yazı tiplerinin yüklenmesi (kayıt tutmayan AB CDN\'i)', en: 'Loading web fonts (EU CDN without logging)' },
    privacyUrl: 'https://bunny.net/privacy',
  },

  // ---------------- Identity providers / auth brokers ----------------
  // impliedData: personal data every use of the vendor carries even when no variable is passed (network metadata,
  // device signals, the identity the provider returns). Consumers may add these as low-confidence flows.
  {
    id: 'google-signin', name: 'Google Sign-In (Google Identity Services)', company: 'Google LLC', country: 'US',
    category: 'auth', consentRequired: false, group: G.auth,
    labels: ['Google Sign-In'], domains: ['accounts.google.com/gsi', 'accounts.google.com/o/oauth2', 'oauth2.googleapis.com', 'openidconnect.googleapis.com', 'www.googleapis.com/oauth2'], cookies: [],
    impliedData: ['email', 'full_name', 'avatar_url', 'ip_address'],
    purpose: { tr: 'Google hesabıyla giriş (kimlik doğrulama)', en: 'Sign-in with a Google account (authentication)' },
    privacyUrl: 'https://policies.google.com/privacy',
  },
  {
    id: 'apple-signin', name: 'Sign in with Apple', company: 'Apple Inc.', country: 'US',
    category: 'auth', consentRequired: false, group: G.auth,
    labels: ['Sign in with Apple'], domains: ['appleid.apple.com'], cookies: [],
    impliedData: ['email', 'full_name', 'ip_address'],
    purpose: { tr: 'Apple kimliğiyle giriş (kimlik doğrulama)', en: 'Sign-in with an Apple ID (authentication)' },
    privacyUrl: 'https://www.apple.com/legal/privacy/',
  },
  {
    id: 'workos', name: 'WorkOS', company: 'WorkOS Inc.', country: 'US',
    category: 'auth', consentRequired: false, group: G.auth,
    labels: ['WorkOS'], domains: ['api.workos.com', 'workos.com', 'authkit.app'], cookies: ['^wos-session$'],
    impliedData: ['email', 'full_name', 'ip_address', 'user_agent'],
    purpose: { tr: 'Kurumsal tek oturum açma (SSO), dizin senkronizasyonu, kullanıcı yönetimi ve denetim kayıtları', en: 'Enterprise single sign-on, directory sync, user management and audit logs' },
    privacyUrl: 'https://workos.com/legal/privacy',
  },
  {
    id: 'stytch', name: 'Stytch', company: 'Stytch Inc. (Twilio)', country: 'US',
    category: 'auth', consentRequired: false, group: G.auth,
    labels: ['Stytch'], domains: ['api.stytch.com', 'test.stytch.com', 'stytch.com'], cookies: ['^stytch_session'],
    impliedData: ['email', 'ip_address', 'user_agent'],
    purpose: { tr: 'Kullanıcı kimlik doğrulama (şifresiz giriş, OAuth, OTP) ve bot tespiti', en: 'User authentication (passwordless, OAuth, OTP) and bot detection' },
    privacyUrl: 'https://stytch.com/legal/privacy-policy',
  },
  {
    id: 'lovable-auth', name: 'Lovable Cloud Auth (OAuth aracısı)', company: 'Lovable Labs Incorporated AB', country: 'SE/US',
    category: 'auth', consentRequired: false, group: G.auth,
    // The broker relays the sign-in to the chosen identity provider (Google, Apple…, US) and hands the tokens back.
    onwardCountries: ['US'],
    labels: ['Lovable Cloud Auth'], domains: ['oauth.lovable.app', 'auth.lovable.dev'], cookies: [],
    impliedData: ['email', 'full_name', 'avatar_url'],
    purpose: { tr: 'Sosyal hesapla giriş için kimlik doğrulama aracılığı', en: 'Brokering social sign-in (OAuth) for the app' },
    privacyUrl: 'https://lovable.dev/privacy',
  },

  // ---------------- Bot detection / CAPTCHA ----------------
  {
    id: 'vercel-botid', name: 'Vercel BotID', company: 'Vercel Inc.', country: 'US',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['Vercel BotID'], domains: [], cookies: [],
    impliedData: ['ip_address', 'user_agent', 'device_id'],
    purpose: { tr: 'Tarayıcı ve cihaz sinyalleriyle bot tespiti', en: 'Bot detection from browser and device signals' },
    privacyUrl: 'https://vercel.com/legal/privacy-policy',
  },
  {
    id: 'hcaptcha', name: 'hCaptcha', company: 'Intuition Machines Inc.', country: 'US',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['hCaptcha'], domains: ['hcaptcha.com', 'api.hcaptcha.com', 'js.hcaptcha.com'], cookies: ['^hc_accessibility$', '^hmt_id$'],
    impliedData: ['ip_address', 'user_agent', 'device_id'],
    purpose: { tr: 'Bot ve spam koruması', en: 'Bot and spam protection' },
    privacyUrl: 'https://www.hcaptcha.com/privacy',
  },

  // ---------------- Webhook delivery / audit logs ----------------
  {
    id: 'svix', name: 'Svix (webhook iletimi)', company: 'Svix Inc.', country: 'US (EU bölgesi seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Svix'], domains: ['api.svix.com', 'api.eu.svix.com', 'api.us.svix.com', 'svix.com'], cookies: [],
    purpose: { tr: 'Webhook olaylarının müşteri uç noktalarına iletilmesi (olay içeriği Svix\'te saklanır ve üçüncü kişilere iletilir)', en: 'Delivering webhook events to customer endpoints (event payloads are stored by Svix and forwarded to third parties)' },
    privacyUrl: 'https://www.svix.com/privacy/',
  },
  {
    id: 'hookdeck', name: 'Hookdeck', company: 'Hookdeck Technologies Inc.', country: 'CA/US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Hookdeck'], domains: ['hookdeck.com', 'api.hookdeck.com', 'events.hookdeck.com', 'hkdk.events'], cookies: [],
    purpose: { tr: 'Webhook olaylarının alınması, kuyruklanması ve iletilmesi', en: 'Receiving, queueing and delivering webhook events' },
    privacyUrl: 'https://hookdeck.com/privacy-policy',
  },
  {
    id: 'retraced', name: 'Retraced (denetim kaydı servisi)', company: 'BoxyHQ / self-hosted', country: 'US (self-hosted olabilir)',
    category: 'processor', consentRequired: false, group: G.hosting, selfHostable: true,
    labels: ['Retraced'], domains: [], cookies: [],
    purpose: { tr: 'Kullanıcı işlemlerinin denetim kaydının (audit log) tutulması', en: 'Keeping an audit log of user actions' },
    privacyUrl: 'https://boxyhq.com/privacy',
  },

  // ---------------- Telemetry / observability ----------------
  {
    id: 'otel-exporter', name: 'OpenTelemetry dışa aktarıcısı (yapılandırılan izleme arka ucu)', company: '—', country: '—',
    category: 'errors', consentRequired: false, group: G.errors,
    // The backend (Vercel, Datadog, Honeycomb, Grafana, a self-hosted collector…) is chosen by deployment configuration.
    labels: ['OpenTelemetry exporter'], domains: [], cookies: [],
    impliedData: ['ip_address', 'user_agent'],
    purpose: { tr: 'Uygulama izleme (trace/span) verilerinin dışa aktarılması', en: 'Exporting application traces / spans' },
    privacyUrl: '',
  },
  {
    id: 'langfuse', name: 'Langfuse', company: 'Langfuse GmbH', country: 'DE/US (bölge seçilebilir)',
    category: 'ai', consentRequired: false, group: G.ai, selfHostable: true,
    labels: ['Langfuse'], domains: ['cloud.langfuse.com', 'us.cloud.langfuse.com'], cookies: [],
    purpose: { tr: 'Yapay zekâ çağrılarının (istem ve yanıtlar) izlenmesi ve değerlendirilmesi', en: 'Tracing and evaluating AI calls (prompts and completions)' },
    privacyUrl: 'https://langfuse.com/privacy',
  },
  {
    id: 'langsmith', name: 'LangSmith / Helicone', company: 'LangChain Inc. / Helicone Inc.', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['LangSmith / Helicone'], domains: ['api.smith.langchain.com', 'smith.langchain.com', 'oai.helicone.ai', 'anthropic.helicone.ai', 'gateway.helicone.ai', 'api.helicone.ai'], cookies: [],
    purpose: { tr: 'Yapay zekâ çağrılarının (istem ve yanıtlar) izlenmesi', en: 'Tracing AI calls (prompts and completions)' },
    privacyUrl: 'https://www.langchain.com/privacy-policy',
  },
  {
    id: 'datadog', name: 'Datadog', company: 'Datadog Inc.', country: 'US (EU bölgesi seçilebilir)',
    category: 'errors', consentRequired: false, group: G.errors,
    labels: ['Datadog'], domains: ['datadoghq.com', 'datadoghq.eu', 'browser-intake-datadoghq.com', 'browser-intake-datadoghq.eu'], cookies: ['^_dd_s$'],
    impliedData: ['ip_address', 'user_agent'],
    purpose: { tr: 'Uygulama performansı, log ve hata izleme', en: 'Application performance, log and error monitoring' },
    privacyUrl: 'https://www.datadoghq.com/legal/privacy/',
  },
  {
    id: 'newrelic', name: 'New Relic', company: 'New Relic Inc.', country: 'US (EU bölgesi seçilebilir)',
    category: 'errors', consentRequired: false, group: G.errors,
    labels: ['New Relic'], domains: ['nr-data.net', 'newrelic.com', 'js-agent.newrelic.com', 'bam.nr-data.net', 'bam.eu01.nr-data.net'], cookies: ['^JSESSIONID$'],
    impliedData: ['ip_address', 'user_agent'],
    purpose: { tr: 'Uygulama performansı ve hata izleme', en: 'Application performance and error monitoring' },
    privacyUrl: 'https://newrelic.com/termsandconditions/privacy',
  },

  // ---------------- Log shipping (log lines, request metadata and error contexts are stored at the vendor) ----------------
  // category 'processor': a server-side log shipper receives what the app sends; it collects nothing by itself.
  {
    id: 'axiom', name: 'Axiom', company: 'Axiom Inc.', country: 'US (EU bölgesi seçilebilir)',
    category: 'processor', consentRequired: false, group: G.errors,
    labels: ['Axiom'], domains: ['api.axiom.co', 'api.eu.axiom.co', 'cloud.axiom.co', 'axiom.co'], cookies: [],
    purpose: { tr: 'Uygulama loglarının ve olaylarının saklanması ve sorgulanması', en: 'Storing and querying application logs and events' },
    privacyUrl: 'https://axiom.co/privacy',
  },
  {
    id: 'betterstack', name: 'Better Stack (Logtail)', company: 'Better Stack Inc.', country: 'US/EU',
    category: 'processor', consentRequired: false, group: G.errors,
    labels: ['Better Stack (Logtail)'], domains: ['in.logs.betterstack.com', 'betterstack.com', 'in.logtail.com', 'logtail.com'], cookies: [],
    purpose: { tr: 'Uygulama loglarının saklanması ve izlenmesi', en: 'Storing and monitoring application logs' },
    privacyUrl: 'https://betterstack.com/privacy',
  },
  {
    id: 'logzio', name: 'Logz.io', company: 'Logshero Ltd. (Logz.io)', country: 'US/EU (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.errors,
    labels: ['Logz.io'], domains: ['listener.logz.io', 'listener-eu.logz.io', 'logz.io'], cookies: [],
    purpose: { tr: 'Uygulama loglarının saklanması ve analizi', en: 'Storing and analysing application logs' },
    privacyUrl: 'https://logz.io/about-us/privacy-policy/',
  },
  {
    id: 'papertrail-loggly', name: 'Papertrail / Loggly (SolarWinds)', company: 'SolarWinds Worldwide LLC', country: 'US',
    category: 'processor', consentRequired: false, group: G.errors,
    labels: ['Papertrail / Loggly'], domains: ['papertrailapp.com', 'logs.collector.solarwinds.com', 'loggly.com', 'logs-01.loggly.com'], cookies: [],
    purpose: { tr: 'Uygulama loglarının saklanması ve izlenmesi', en: 'Storing and monitoring application logs' },
    privacyUrl: 'https://www.solarwinds.com/legal/privacy',
  },
  {
    id: 'splunk', name: 'Splunk (HTTP Event Collector)', company: 'Splunk LLC (Cisco)', country: 'US (bölge seçilebilir; kendi sunucunuzda olabilir)',
    category: 'processor', consentRequired: false, group: G.errors,
    labels: ['Splunk'], domains: ['splunkcloud.com'], cookies: [],
    purpose: { tr: 'Log ve olay verisinin toplanması ve analizi', en: 'Collecting and analysing log and event data' },
    privacyUrl: 'https://www.splunk.com/en_us/legal/privacy/privacy-policy.html',
  },
  {
    id: 'google-cloud-logging', name: 'Google Cloud Logging', company: 'Google LLC', country: 'US (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.errors,
    labels: ['Google Cloud Logging'], domains: ['logging.googleapis.com'], cookies: [],
    purpose: { tr: 'Uygulama loglarının saklanması', en: 'Storing application logs' },
    privacyUrl: 'https://cloud.google.com/terms/cloud-privacy-notice',
  },

  // ---------------- Message queues / schedulers (message bodies are stored and delivered by the vendor) ----------------
  {
    id: 'upstash-qstash', name: 'Upstash QStash', company: 'Upstash Inc.', country: 'US (EU bölgesi seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Upstash QStash'], domains: ['qstash.upstash.io', 'qstash-eu-central-1.upstash.io', 'qstash-us-east-1.upstash.io'], cookies: [],
    purpose: { tr: 'Zamanlanmış görevlerin ve mesajların kuyruklanıp iletilmesi (mesaj içeriği sağlayıcıda saklanır)', en: 'Queueing and delivering scheduled jobs and messages (message bodies are stored by the vendor)' },
    privacyUrl: 'https://upstash.com/trust/privacy.pdf',
  },

  // ---------------- Stock media / image APIs (called from the visitor's browser or the server) ----------------
  {
    id: 'unsplash', name: 'Unsplash', company: 'Unsplash Inc.', country: 'US',
    category: 'embed', consentRequired: false, group: G.content,
    labels: ['Unsplash'], domains: ['api.unsplash.com', 'images.unsplash.com', 'plus.unsplash.com', 'unsplash.com'], cookies: [],
    purpose: { tr: 'Stok görsellerin aranması ve gösterilmesi', en: 'Searching and displaying stock images' },
    privacyUrl: 'https://unsplash.com/privacy',
  },
  {
    id: 'pexels', name: 'Pexels', company: 'Pexels GmbH (Canva)', country: 'DE',
    category: 'embed', consentRequired: false, group: G.content,
    labels: ['Pexels'], domains: ['api.pexels.com', 'images.pexels.com', 'videos.pexels.com'], cookies: [],
    purpose: { tr: 'Stok görsel ve videoların aranması ve gösterilmesi', en: 'Searching and displaying stock photos and videos' },
    privacyUrl: 'https://www.pexels.com/privacy-policy/',
  },
  {
    id: 'giphy', name: 'GIPHY', company: 'GIPHY Inc. (Shutterstock)', country: 'US',
    category: 'embed', consentRequired: false, group: G.content,
    labels: ['GIPHY'], domains: ['api.giphy.com', 'media.giphy.com', 'giphy.com'], cookies: [],
    purpose: { tr: 'GIF arama ve gösterimi', en: 'Searching and displaying GIFs' },
    privacyUrl: 'https://support.giphy.com/hc/en-us/articles/360032872931-GIPHY-Privacy-Policy',
  },

  // ---------------- Web reading / search APIs for LLM pipelines ----------------
  {
    id: 'jina', name: 'Jina AI (Reader / Search)', company: 'Jina AI GmbH (Elastic)', country: 'DE/US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Jina AI'], domains: ['r.jina.ai', 's.jina.ai', 'api.jina.ai', 'deepsearch.jina.ai'], cookies: [],
    purpose: { tr: 'Web sayfalarının okunması, arama ve gömme (embedding) hizmeti', en: 'Reading web pages, search and embeddings' },
    privacyUrl: 'https://jina.ai/legal/',
  },

  // ---------------- SaaS APIs, storage, payments, maps ----------------
  {
    id: 'elevenlabs', name: 'ElevenLabs', company: 'ElevenLabs Inc.', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['ElevenLabs'], domains: ['api.elevenlabs.io', 'elevenlabs.io'], cookies: [],
    purpose: { tr: 'Ses tanıma (konuşmadan metne) ve ses sentezi', en: 'Speech recognition (speech-to-text) and speech synthesis' },
    privacyUrl: 'https://elevenlabs.io/privacy-policy',
  },
  {
    id: 'appwrite', name: 'Appwrite Cloud', company: 'Appwrite Code Ltd.', country: 'US/EU (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Appwrite'], domains: ['cloud.appwrite.io', 'appwrite.io', 'appwrite.global'], cookies: ['^a_session_'],
    purpose: { tr: 'Veritabanı, kimlik doğrulama ve dosya depolama (barındırılan arka uç)', en: 'Database, authentication and file storage (hosted backend)' },
    privacyUrl: 'https://appwrite.io/privacy',
  },
  {
    id: 'lemonsqueezy', name: 'Lemon Squeezy', company: 'Lemon Squeezy LLC (Stripe)', country: 'US',
    category: 'payments', consentRequired: false, group: G.payments,
    labels: ['Lemon Squeezy'], domains: ['lemonsqueezy.com', 'api.lemonsqueezy.com'], cookies: [],
    envKeys: ['^LEMON_?SQUEEZY_[A-Z0-9_]*(URL|LINK)$'],
    purpose: { tr: 'Ödemelerin alınması ve abonelik yönetimi (satıcı kayıtlı aracı)', en: 'Processing payments and subscriptions (merchant of record)' },
    privacyUrl: 'https://www.lemonsqueezy.com/privacy',
  },
  {
    id: 'razorpay', name: 'Razorpay', company: 'Razorpay Software Pvt. Ltd.', country: 'IN',
    category: 'payments', consentRequired: false, group: G.payments,
    labels: ['Razorpay'], domains: ['razorpay.com', 'api.razorpay.com', 'checkout.razorpay.com'], cookies: [],
    purpose: { tr: 'Ödemelerin alınması', en: 'Processing payments' },
    privacyUrl: 'https://razorpay.com/privacy/',
  },
  {
    id: 'polar', name: 'Polar', company: 'Polar Software Inc.', country: 'US',
    category: 'payments', consentRequired: false, group: G.payments,
    labels: ['Polar'], domains: ['api.polar.sh', 'sandbox-api.polar.sh', 'polar.sh'], cookies: [],
    purpose: { tr: 'Ödemelerin alınması ve abonelik yönetimi (satıcı kayıtlı aracı)', en: 'Processing payments and subscriptions (merchant of record)' },
    privacyUrl: 'https://polar.sh/legal/privacy',
  },
  {
    id: 'dodo-payments', name: 'Dodo Payments', company: 'Dodo Payments Inc.', country: 'US/IN',
    category: 'payments', consentRequired: false, group: G.payments,
    labels: ['Dodo Payments'], domains: ['live.dodopayments.com', 'test.dodopayments.com', 'dodopayments.com'], cookies: [],
    purpose: { tr: 'Ödemelerin alınması ve abonelik yönetimi (satıcı kayıtlı aracı)', en: 'Processing payments and subscriptions (merchant of record)' },
    privacyUrl: 'https://dodopayments.com/privacy-policy',
  },
  {
    id: 'supermemory', name: 'Supermemory', company: 'Supermemory Inc.', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Supermemory'], domains: ['api.supermemory.ai', 'supermemory.ai'], cookies: [],
    purpose: { tr: 'Yapay zekâ için kullanıcı belleğinin (anılar, notlar) saklanması ve aranması', en: 'Storing and searching user memories for AI features' },
    privacyUrl: 'https://supermemory.ai/privacy',
  },
  {
    id: 'exa', name: 'Exa (web arama API)', company: 'Exa Labs Inc.', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Exa'], domains: ['api.exa.ai'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli web araması (sorgular sağlayıcıya gider)', en: 'AI web search (queries are sent to the provider)' },
    privacyUrl: 'https://exa.ai/privacy-policy',
  },
  {
    id: 'firecrawl', name: 'Firecrawl', company: 'Mendable Inc. (Firecrawl)', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Firecrawl'], domains: ['api.firecrawl.dev'], cookies: [],
    purpose: { tr: 'Web sayfalarının taranması ve arama (sorgular sağlayıcıya gider)', en: 'Web scraping and search (queries are sent to the provider)' },
    privacyUrl: 'https://www.firecrawl.dev/privacy-policy',
  },
  {
    id: 'tavily', name: 'Tavily', company: 'Tavily Inc.', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Tavily'], domains: ['api.tavily.com'], cookies: [],
    purpose: { tr: 'Yapay zekâ için web araması (sorgular sağlayıcıya gider)', en: 'Web search for AI (queries are sent to the provider)' },
    privacyUrl: 'https://tavily.com/privacy',
  },
  {
    id: 'parallel', name: 'Parallel Web Systems', company: 'Parallel Web Systems Inc.', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Parallel'], domains: ['api.parallel.ai'], cookies: [],
    purpose: { tr: 'Yapay zekâ için web araması ve araştırma (sorgular sağlayıcıya gider)', en: 'Web search and research for AI (queries are sent to the provider)' },
    privacyUrl: 'https://parallel.ai/privacy-policy',
  },
  {
    id: 'valyu', name: 'Valyu', company: 'Valyu Ltd.', country: 'UK',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Valyu'], domains: ['api.valyu.network', 'api.valyu.ai'], cookies: [],
    purpose: { tr: 'Yapay zekâ için arama (sorgular sağlayıcıya gider)', en: 'Search for AI (queries are sent to the provider)' },
    privacyUrl: 'https://www.valyu.ai/privacy-policy',
  },
  {
    id: 'daytona', name: 'Daytona (kod çalıştırma ortamı)', company: 'Daytona Platforms Inc.', country: 'US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Daytona'], domains: ['app.daytona.io', 'daytona.io'], cookies: [],
    purpose: { tr: 'Kullanıcı kodunun ve verisinin bulut ortamında çalıştırılması', en: 'Running user code and data in cloud sandboxes' },
    privacyUrl: 'https://www.daytona.io/privacy-policy',
  },
  {
    id: 'tigris', name: 'Tigris (nesne depolama)', company: 'Tigris Data Inc.', country: 'US (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Tigris'], domains: ['storage.tigris.dev', 't3.storage.dev', 'tigris.dev'], cookies: [],
    purpose: { tr: 'Dosya ve görsel depolama (S3 uyumlu nesne depolama)', en: 'File and image storage (S3-compatible object storage)' },
    privacyUrl: 'https://www.tigrisdata.com/docs/legal/privacy-policy/',
  },
  // S3-compatible object storage whose endpoint is configured only in the environment: the operator (AWS, R2, Tigris,
  // MinIO …) is not named by the code.
  {
    id: 'object-storage', name: 'S3 uyumlu nesne depolama (ortam değişkeniyle yapılandırılmış)', company: '—', country: '—',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['S3-compatible object storage (env-configured)'], domains: [], cookies: [],
    purpose: { tr: 'Dosya ve görsel depolama', en: 'File and image storage' },
    privacyUrl: '',
  },
  {
    id: 'dropbox', name: 'Dropbox', company: 'Dropbox Inc.', country: 'US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Dropbox'], domains: ['api.dropboxapi.com', 'content.dropboxapi.com', 'dropbox.com'], cookies: [],
    purpose: { tr: 'Dosyaların bulut depolamada saklanması', en: 'Storing files in cloud storage' },
    privacyUrl: 'https://www.dropbox.com/privacy',
  },
  {
    id: 'google-drive', name: 'Google Drive', company: 'Google LLC', country: 'US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Google Drive'], domains: ['www.googleapis.com/drive', 'www.googleapis.com/upload/drive', 'drive.google.com'], cookies: [],
    purpose: { tr: 'Dosyaların bulut depolamada saklanması', en: 'Storing files in cloud storage' },
    privacyUrl: 'https://policies.google.com/privacy',
  },
  {
    id: 'carto', name: 'CARTO basemaps', company: 'CartoDB Inc. (CARTO)', country: 'US/ES',
    category: 'maps', consentRequired: true, group: G.content,
    labels: ['CARTO basemaps'], domains: ['basemaps.cartocdn.com', 'cartocdn.com', 'carto.com'], cookies: [],
    purpose: { tr: 'Harita altlık görsellerinin (tile) gösterimi', en: 'Displaying map base tiles' },
    privacyUrl: 'https://carto.com/privacy',
  },
  {
    id: 'mapbox', name: 'Mapbox', company: 'Mapbox Inc.', country: 'US',
    category: 'maps', consentRequired: true, group: G.content,
    labels: ['Mapbox'], domains: ['api.mapbox.com', 'events.mapbox.com', 'tiles.mapbox.com'], cookies: [],
    purpose: { tr: 'Harita gösterimi', en: 'Displaying maps' },
    privacyUrl: 'https://www.mapbox.com/legal/privacy',
  },

  // ---------------- Identity providers for social sign-in (OAuth / OIDC) ----------------
  // The browser is redirected to the provider, which receives the sign-in event (IP address, device) and hands the
  // profile (name, e-mail, avatar) back to the app. IDP_VENDOR_BY_PROVIDER maps provider names to these ids.
  {
    id: 'github', name: 'GitHub (OAuth girişi)', company: 'GitHub Inc. (Microsoft)', country: 'US',
    category: 'auth', consentRequired: false, group: G.auth,
    labels: ['GitHub'], domains: ['github.com/login/oauth', 'api.github.com/user', 'avatars.githubusercontent.com'], cookies: [],
    impliedData: ['email', 'full_name', 'avatar_url', 'ip_address'],
    purpose: { tr: 'GitHub hesabıyla giriş (kimlik doğrulama)', en: 'Sign-in with a GitHub account (authentication)' },
    privacyUrl: 'https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement',
  },
  {
    id: 'facebook-login', name: 'Facebook (OAuth girişi)', company: 'Meta Platforms Ireland Ltd. / Meta Platforms Inc.', country: 'US',
    category: 'auth', consentRequired: false, group: G.auth,
    labels: ['Facebook Login'], domains: ['www.facebook.com/dialog/oauth', 'graph.facebook.com/oauth'], cookies: [],
    impliedData: ['email', 'full_name', 'avatar_url', 'ip_address'],
    purpose: { tr: 'Facebook hesabıyla giriş (kimlik doğrulama)', en: 'Sign-in with a Facebook account (authentication)' },
    privacyUrl: 'https://www.facebook.com/privacy/policy',
  },
  {
    id: 'gitlab', name: 'GitLab (OAuth girişi)', company: 'GitLab Inc.', country: 'US',
    category: 'auth', consentRequired: false, group: G.auth,
    labels: ['GitLab'], domains: ['gitlab.com/oauth', 'gitlab.com/api/v4/user'], cookies: [],
    impliedData: ['email', 'full_name', 'avatar_url', 'ip_address'],
    purpose: { tr: 'GitLab hesabıyla giriş (kimlik doğrulama)', en: 'Sign-in with a GitLab account (authentication)' },
    privacyUrl: 'https://about.gitlab.com/privacy/',
  },
  {
    id: 'discord-login', name: 'Discord (OAuth girişi)', company: 'Discord Inc.', country: 'US',
    category: 'auth', consentRequired: false, group: G.auth,
    labels: ['Discord login'], domains: ['discord.com/api/oauth2', 'discord.com/oauth2', 'discord.com/api/users/@me', 'cdn.discordapp.com/avatars'], cookies: [],
    impliedData: ['email', 'username', 'avatar_url', 'ip_address'],
    purpose: { tr: 'Discord hesabıyla giriş (kimlik doğrulama)', en: 'Sign-in with a Discord account (authentication)' },
    privacyUrl: 'https://discord.com/privacy',
  },
  {
    id: 'x-login', name: 'X / Twitter (OAuth girişi)', company: 'X Corp.', country: 'US',
    category: 'auth', consentRequired: false, group: G.auth,
    labels: ['X login'], domains: ['api.twitter.com/oauth', 'api.twitter.com/2/users/me', 'twitter.com/i/oauth2', 'api.x.com/2/users/me', 'x.com/i/oauth2'], cookies: [],
    impliedData: ['username', 'full_name', 'avatar_url', 'ip_address'],
    purpose: { tr: 'X (Twitter) hesabıyla giriş (kimlik doğrulama)', en: 'Sign-in with an X (Twitter) account (authentication)' },
    privacyUrl: 'https://x.com/privacy',
  },
  {
    id: 'linkedin-login', name: 'LinkedIn (OAuth girişi)', company: 'LinkedIn Ireland / LinkedIn Corp.', country: 'US',
    category: 'auth', consentRequired: false, group: G.auth,
    labels: ['LinkedIn login'], domains: ['linkedin.com/oauth', 'api.linkedin.com/v2/userinfo', 'api.linkedin.com/v2/me'], cookies: [],
    impliedData: ['email', 'full_name', 'avatar_url', 'ip_address'],
    purpose: { tr: 'LinkedIn hesabıyla giriş (kimlik doğrulama)', en: 'Sign-in with a LinkedIn account (authentication)' },
    privacyUrl: 'https://www.linkedin.com/legal/privacy-policy',
  },
  {
    id: 'microsoft-login', name: 'Microsoft hesabı / Entra ID (OAuth girişi)', company: 'Microsoft Corporation', country: 'US',
    category: 'auth', consentRequired: false, group: G.auth,
    labels: ['Microsoft login'], domains: ['login.microsoftonline.com', 'login.live.com', 'graph.microsoft.com/v1.0/me', 'graph.microsoft.com/oidc'], cookies: [],
    impliedData: ['email', 'full_name', 'ip_address'],
    purpose: { tr: 'Microsoft hesabıyla giriş (kimlik doğrulama)', en: 'Sign-in with a Microsoft account (authentication)' },
    privacyUrl: 'https://privacy.microsoft.com/privacystatement',
  },

  // ---------------- Messaging platforms (bots, login, push; r8) ----------------
  {
    id: 'line', name: 'LINE (Messaging API / LIFF)', company: 'LY Corporation', country: 'JP',
    category: 'messaging', consentRequired: false, group: G.comms,
    labels: ['LINE'], domains: ['api.line.me', 'api-data.line.me', 'access.line.me', 'liff.line.me', 'static.line-scdn.net', 'notify-api.line.me'], cookies: [],
    envKeys: ['^LINE_(?:CHANNEL|MESSAGING|BOT|LOGIN|NOTIFY)_[A-Z0-9_]+$'],
    purpose: { tr: 'LINE üzerinden mesajlaşma, bot ve giriş', en: 'Messaging, bots and sign-in through LINE' },
    privacyUrl: 'https://www.lycorp.co.jp/en/company/privacypolicy/',
  },
  {
    id: 'whatsapp', name: 'WhatsApp Business (Meta)', company: 'Meta Platforms Inc. / WhatsApp LLC', country: 'US',
    category: 'messaging', consentRequired: false, group: G.comms,
    labels: ['WhatsApp'], domains: ['waba-v2.360dialog.io', 'api.whatsapp.com'], cookies: [],
    envKeys: ['^(?:WHATSAPP|WABA)_[A-Z0-9_]*(?:TOKEN|PHONE_NUMBER_ID|PHONE_ID|BUSINESS_ACCOUNT_ID)$'],
    purpose: { tr: 'WhatsApp üzerinden mesajlaşma', en: 'Messaging through WhatsApp' },
    privacyUrl: 'https://www.whatsapp.com/legal/privacy-policy',
  },
  {
    id: 'telegram', name: 'Telegram Bot API', company: 'Telegram FZ-LLC', country: 'AE/UK',
    category: 'messaging', consentRequired: false, group: G.comms,
    labels: ['Telegram'], domains: ['api.telegram.org', 'telegram.org/js'], cookies: [],
    envKeys: ['^TELEGRAM_(?:BOT_)?TOKEN$'],
    purpose: { tr: 'Telegram üzerinden mesajlaşma ve bildirim', en: 'Messaging and notifications through Telegram' },
    privacyUrl: 'https://telegram.org/privacy',
  },
  {
    id: 'viber', name: 'Viber (Rakuten)', company: 'Viber Media S.à r.l. (Rakuten)', country: 'LU/JP',
    category: 'messaging', consentRequired: false, group: G.comms,
    labels: ['Viber'], domains: ['chatapi.viber.com'], cookies: [],
    purpose: { tr: 'Viber üzerinden mesajlaşma', en: 'Messaging through Viber' },
    privacyUrl: 'https://www.viber.com/en/terms/viber-privacy-policy/',
  },
  {
    id: 'kakao', name: 'KakaoTalk / Kakao API', company: 'Kakao Corp.', country: 'KR',
    category: 'messaging', consentRequired: false, group: G.comms,
    labels: ['Kakao'], domains: ['kapi.kakao.com', 'kauth.kakao.com', 'developers.kakao.com', 't1.kakaocdn.net', 'bizmessage.kakao.com'], cookies: [],
    purpose: { tr: 'KakaoTalk mesajlaşma, giriş ve harita', en: 'KakaoTalk messaging, sign-in and maps' },
    privacyUrl: 'https://www.kakao.com/policy/privacy',
  },

  // ---------------- Map tile providers: every tile request carries the visitor's IP and the viewed area (r8) ----------------
  {
    id: 'osm-tiles', name: 'OpenStreetMap (harita altlığı)', company: 'OpenStreetMap Foundation', country: 'UK/NL',
    category: 'embed', consentRequired: true, group: G.content,
    labels: ['OpenStreetMap tiles'], domains: ['tile.openstreetmap.org', 'openstreetmap.org/export/embed'], cookies: [],
    mapTiles: true,
    purpose: { tr: 'Harita altlık görsellerinin (tile) gösterimi', en: 'Displaying map base tiles' },
    privacyUrl: 'https://osmfoundation.org/wiki/Privacy_Policy',
  },
  {
    id: 'opentopomap', name: 'OpenTopoMap', company: 'OpenTopoMap', country: 'DE',
    category: 'embed', consentRequired: true, group: G.content,
    labels: ['OpenTopoMap'], domains: ['tile.opentopomap.org', 'opentopomap.org'], cookies: [],
    mapTiles: true,
    purpose: { tr: 'Harita altlık görsellerinin (tile) gösterimi', en: 'Displaying map base tiles' },
    privacyUrl: 'https://opentopomap.org/about',
  },
  {
    id: 'arcgis', name: 'Esri ArcGIS Online', company: 'Esri Inc.', country: 'US',
    category: 'embed', consentRequired: true, group: G.content,
    labels: ['ArcGIS'], domains: ['server.arcgisonline.com', 'services.arcgisonline.com', 'arcgisonline.com', 'js.arcgis.com', 'basemaps.arcgis.com', 'arcgis.com'], cookies: [],
    mapTiles: true,
    purpose: { tr: 'Harita altlık görsellerinin (tile) gösterimi', en: 'Displaying map base tiles' },
    privacyUrl: 'https://www.esri.com/en-us/privacy/overview',
  },
  {
    id: 'maptiler', name: 'MapTiler', company: 'MapTiler AG', country: 'CH',
    category: 'embed', consentRequired: true, group: G.content,
    labels: ['MapTiler'], domains: ['api.maptiler.com', 'maptiler.com'], cookies: [],
    mapTiles: true,
    purpose: { tr: 'Harita altlık görsellerinin (tile) gösterimi', en: 'Displaying map base tiles' },
    privacyUrl: 'https://www.maptiler.com/privacy-policy/',
  },
  {
    id: 'stadia-maps', name: 'Stadia Maps / Stamen', company: 'Stadia Maps Inc.', country: 'US/EE',
    category: 'embed', consentRequired: true, group: G.content,
    labels: ['Stadia Maps'], domains: ['tiles.stadiamaps.com', 'stadiamaps.com', 'stamen-tiles.a.ssl.fastly.net', 'tile.stamen.com'], cookies: [],
    mapTiles: true,
    purpose: { tr: 'Harita altlık görsellerinin (tile) gösterimi', en: 'Displaying map base tiles' },
    privacyUrl: 'https://stadiamaps.com/privacy-policy/',
  },
  {
    id: 'thunderforest', name: 'Thunderforest', company: 'Gravitystorm Ltd.', country: 'UK',
    category: 'embed', consentRequired: true, group: G.content,
    labels: ['Thunderforest'], domains: ['tile.thunderforest.com'], cookies: [],
    mapTiles: true,
    purpose: { tr: 'Harita altlık görsellerinin (tile) gösterimi', en: 'Displaying map base tiles' },
    privacyUrl: 'https://www.thunderforest.com/privacy/',
  },

  // ---------------- Model hubs, hosting platforms, data platforms (r8) ----------------
  {
    id: 'huggingface', name: 'Hugging Face', company: 'Hugging Face Inc.', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Hugging Face'], domains: ['api-inference.huggingface.co', 'router.huggingface.co', 'huggingface.co', 'hf.space', 'endpoints.huggingface.cloud'], cookies: [],
    purpose: { tr: 'Yapay zekâ modellerinin çalıştırılması (çıkarım API)', en: 'Running AI models (inference API)' },
    privacyUrl: 'https://huggingface.co/privacy',
  },
  {
    id: 'azure-openai', name: 'Azure OpenAI', company: 'Microsoft Corporation', country: 'US (bölge seçilebilir)',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['Azure OpenAI'], domains: ['openai.azure.com'], cookies: [],
    purpose: { tr: 'Yapay zekâ destekli özelliklerin sunulması', en: 'Providing AI-powered features' },
    privacyUrl: 'https://privacy.microsoft.com/privacystatement',
  },
  {
    id: 'openrouter', name: 'OpenRouter', company: 'OpenRouter Inc.', country: 'US',
    category: 'ai', consentRequired: false, group: G.ai,
    labels: ['OpenRouter'], domains: ['openrouter.ai'], cookies: [],
    purpose: { tr: 'Yapay zekâ çağrılarının model sağlayıcılarına yönlendirilmesi', en: 'Routing AI calls to model providers' },
    privacyUrl: 'https://openrouter.ai/privacy',
  },
  {
    id: 'fly', name: 'Fly.io', company: 'Fly.io Inc.', country: 'US (bölge seçilebilir)',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['Fly.io'], domains: ['fly.io', 'fly.dev', 'flycast'], cookies: [],
    appHosting: true,
    purpose: { tr: 'Uygulamanın ve verilerinin barındırılması', en: 'Hosting the application and its data' },
    privacyUrl: 'https://fly.io/legal/privacy-policy/',
  },
  {
    id: 'render', name: 'Render', company: 'Render Services Inc.', country: 'US (bölge seçilebilir)',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['Render'], domains: ['onrender.com', 'render.com'], cookies: [],
    appHosting: true,
    purpose: { tr: 'Uygulamanın ve verilerinin barındırılması', en: 'Hosting the application and its data' },
    privacyUrl: 'https://render.com/privacy',
  },
  {
    id: 'railway', name: 'Railway', company: 'Railway Corp.', country: 'US (bölge seçilebilir)',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['Railway'], domains: ['railway.app', 'up.railway.app', 'rlwy.net'], cookies: [],
    appHosting: true,
    purpose: { tr: 'Uygulamanın ve verilerinin barındırılması', en: 'Hosting the application and its data' },
    privacyUrl: 'https://railway.com/legal/privacy',
  },
  {
    id: 'heroku', name: 'Heroku (Salesforce)', company: 'Salesforce Inc.', country: 'US (AB bölgesi seçilebilir)',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['Heroku'], domains: ['herokuapp.com', 'heroku.com', 'herokudns.com'], cookies: [],
    appHosting: true,
    purpose: { tr: 'Uygulamanın ve verilerinin barındırılması', en: 'Hosting the application and its data' },
    privacyUrl: 'https://www.salesforce.com/company/privacy/',
  },
  {
    id: 'google-cloud', name: 'Google Cloud (App Engine / Cloud Run)', company: 'Google LLC', country: 'US (bölge seçilebilir)',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['Google Cloud'], domains: ['run.app', 'appspot.com', 'cloudfunctions.net', 'storage.googleapis.com'], cookies: [],
    appHosting: true,
    purpose: { tr: 'Uygulamanın ve verilerinin barındırılması', en: 'Hosting the application and its data' },
    privacyUrl: 'https://cloud.google.com/terms/cloud-privacy-notice',
  },
  {
    id: 'azure', name: 'Microsoft Azure', company: 'Microsoft Corporation', country: 'US (bölge seçilebilir)',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['Microsoft Azure'], domains: ['azurewebsites.net', 'azurestaticapps.net', 'blob.core.windows.net', 'database.windows.net'], cookies: [],
    appHosting: true,
    purpose: { tr: 'Uygulamanın ve verilerinin barındırılması', en: 'Hosting the application and its data' },
    privacyUrl: 'https://privacy.microsoft.com/privacystatement',
  },
  {
    id: 'digitalocean', name: 'DigitalOcean', company: 'DigitalOcean LLC', country: 'US (bölge seçilebilir)',
    category: 'infra', consentRequired: false, group: G.hosting,
    labels: ['DigitalOcean'], domains: ['ondigitalocean.app', 'digitaloceanspaces.com', 'db.ondigitalocean.com'], cookies: [],
    appHosting: true,
    purpose: { tr: 'Uygulamanın ve verilerinin barındırılması', en: 'Hosting the application and its data' },
    privacyUrl: 'https://www.digitalocean.com/legal/privacy-policy',
  },
  {
    id: 'tidb-cloud', name: 'TiDB Cloud (PingCAP)', company: 'PingCAP Inc.', country: 'US (bölge seçilebilir)',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['TiDB Cloud'], domains: ['tidbcloud.com'], cookies: [],
    hosting: 'database', engine: 'mysql',
    purpose: { tr: 'Veritabanının barındırılması', en: 'Database hosting' },
    privacyUrl: 'https://www.pingcap.com/privacy-policy/',
  },
  {
    id: 'uploadthing', name: 'UploadThing', company: 'Ping Labs Inc.', country: 'US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['UploadThing'], domains: ['uploadthing.com', 'utfs.io', 'ufs.sh', 'ingest.uploadthing.com'], cookies: [],
    purpose: { tr: 'Yüklenen dosyaların saklanması', en: 'Storing uploaded files' },
    privacyUrl: 'https://uploadthing.com/privacy',
  },
  {
    id: 'imagekit', name: 'ImageKit', company: 'ImageKit Inc.', country: 'US/IN',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['ImageKit'], domains: ['ik.imagekit.io', 'upload.imagekit.io', 'api.imagekit.io'], cookies: [],
    purpose: { tr: 'Görsel ve dosya depolama/işleme', en: 'Image and file storage/processing' },
    privacyUrl: 'https://imagekit.io/privacy-policy/',
  },
  {
    id: 'uploadcare', name: 'Uploadcare', company: 'Uploadcare Inc.', country: 'US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Uploadcare'], domains: ['uploadcare.com', 'ucarecdn.com', 'upload.uploadcare.com'], cookies: [],
    purpose: { tr: 'Yüklenen dosyaların saklanması', en: 'Storing uploaded files' },
    privacyUrl: 'https://uploadcare.com/about/privacy-policy/',
  },
  {
    id: 'pusher', name: 'Pusher (MessageBird)', company: 'Pusher Ltd.', country: 'UK/US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Pusher'], domains: ['pusher.com', 'pusherapp.com'], cookies: [],
    purpose: { tr: 'Gerçek zamanlı mesaj iletimi', en: 'Realtime message delivery' },
    privacyUrl: 'https://pusher.com/legal/privacy-policy/',
  },
  {
    id: 'ably', name: 'Ably', company: 'Ably Real-time Ltd.', country: 'UK/US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Ably'], domains: ['ably.io', 'ably.net', 'ably.com'], cookies: [],
    purpose: { tr: 'Gerçek zamanlı mesaj iletimi', en: 'Realtime message delivery' },
    privacyUrl: 'https://ably.com/privacy',
  },
  {
    id: 'liveblocks', name: 'Liveblocks', company: 'Liveblocks Inc.', country: 'US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Liveblocks'], domains: ['liveblocks.io', 'api.liveblocks.io'], cookies: [],
    purpose: { tr: 'Ortak çalışma ve gerçek zamanlı içerik', en: 'Collaboration and realtime content' },
    privacyUrl: 'https://liveblocks.io/privacy',
  },
  {
    id: 'inngest', name: 'Inngest', company: 'Inngest Inc.', country: 'US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Inngest'], domains: ['inn.gs', 'inngest.com', 'api.inngest.com'], cookies: [],
    purpose: { tr: 'Arka plan işlerinin çalıştırılması (olay içeriği)', en: 'Background jobs (event payloads)' },
    privacyUrl: 'https://www.inngest.com/privacy',
  },
  {
    id: 'trigger-dev', name: 'Trigger.dev', company: 'Trigger.dev Ltd.', country: 'UK/US',
    category: 'processor', consentRequired: false, group: G.hosting,
    labels: ['Trigger.dev'], domains: ['trigger.dev', 'api.trigger.dev'], cookies: [],
    purpose: { tr: 'Arka plan işlerinin çalıştırılması (görev içeriği)', en: 'Background jobs (task payloads)' },
    privacyUrl: 'https://trigger.dev/legal/privacy',
  },
];

// ---------------------------------------------------------------------------
// Names for notice-vs-code matching (consumed by extract/declarations.js and legal/checks/transparency.js).
//   aliases    names a privacy notice uses for exactly this recipient (whole phrase, case-insensitive). "Google Login"
//              is an alias of google-signin, not of the Gemini API: a parent company's name is never an alias.
//   productOf  parent company whose bare name ("Google", "Meta") covers the company but not a particular product
//   tokens     for e-mail and hosting vendors: distinctive single words a notice uses
//   members    for grouped entries (one id, several companies): [{id, name, aliases, country?}] — a notice that names one
//              member says nothing about the others
// ---------------------------------------------------------------------------
const VENDOR_NAMES = {
  'google-analytics': { aliases: ['google analytics', 'google tag manager'], productOf: 'google' },
  'google-ads': { aliases: ['google ads', 'google adsense', 'doubleclick'], productOf: 'google' },
  'google-fonts': { aliases: ['google fonts'], productOf: 'google' },
  'google-maps': { aliases: ['google maps'], productOf: 'google' },
  'google-drive': { aliases: ['google drive'], productOf: 'google' },
  'google-cloud-logging': { aliases: ['google cloud logging'], productOf: 'google' },
  'google-cloud': { aliases: ['google cloud', 'google cloud platform', 'cloud run', 'app engine'], productOf: 'google', tokens: ['gcp'] },
  'google-signin': { aliases: ['google sign-in', 'google sign in', 'sign in with google', 'google login', 'login with google', 'log in with google', 'google oauth', 'google account', 'google hesabı', 'google ile giriş'], productOf: 'google' },
  gemini: { aliases: ['google gemini', 'gemini api', 'google ai', 'google generative ai', 'vertex ai', 'gemini'], productOf: 'google' },
  firebase: { aliases: ['firebase', 'cloud firestore', 'google firebase'], productOf: 'google', tokens: ['firebase'] },
  'firebase-analytics': { aliases: ['firebase analytics', 'google analytics for firebase'], productOf: 'google' },
  recaptcha: { aliases: ['recaptcha', 'google recaptcha'], productOf: 'google' },
  youtube: { aliases: ['youtube'], productOf: 'google' },
  admob: { aliases: ['admob', 'google admob'], productOf: 'google' },
  'meta-pixel': { aliases: ['meta pixel', 'facebook pixel'], productOf: 'meta' },
  'facebook-sdk': { aliases: ['facebook sdk', 'meta sdk'], productOf: 'meta' },
  'facebook-login': { aliases: ['facebook login', 'login with facebook', 'sign in with facebook', 'facebook account', 'facebook ile giriş'], productOf: 'meta' },
  whatsapp: { aliases: ['whatsapp', 'whatsapp business'], productOf: 'meta' },
  'microsoft-login': { aliases: ['microsoft account', 'microsoft entra', 'azure ad', 'sign in with microsoft', 'microsoft login'], productOf: 'microsoft' },
  'ms-translator': { aliases: ['microsoft translator', 'azure ai'], productOf: 'microsoft' },
  azure: { aliases: ['microsoft azure', 'azure'], productOf: 'microsoft', tokens: ['azure'] },
  clarity: { aliases: ['microsoft clarity'], productOf: 'microsoft' },
  github: { aliases: ['github login', 'login with github', 'sign in with github', 'github oauth', 'github account', 'github ile giriş'], productOf: 'github' },
  gitlab: { aliases: ['gitlab login', 'sign in with gitlab', 'gitlab account'], productOf: 'gitlab' },
  'x-login': { aliases: ['twitter login', 'login with twitter', 'sign in with twitter', 'sign in with x', 'x login'], productOf: 'x' },
  'discord-login': { aliases: ['discord login', 'login with discord', 'sign in with discord', 'discord account'], productOf: 'discord' },
  discord: { aliases: ['discord'], productOf: 'discord' },
  'linkedin-login': { aliases: ['linkedin login', 'sign in with linkedin', 'linkedin account'], productOf: 'linkedin' },
  'linkedin-insight': { aliases: ['linkedin insight'], productOf: 'linkedin' },
  'apple-signin': { aliases: ['sign in with apple', 'apple login', 'apple id', 'apple ile giriş'], productOf: 'apple' },
  aws: { aliases: ['amazon web services', 'aws', 'amazon s3', 'aws s3', 'cloudfront', 'amazon ses'], productOf: 'amazon', tokens: ['aws', 's3'] },
  vercel: { aliases: ['vercel'], tokens: ['vercel'] },
  netlify: { aliases: ['netlify'], tokens: ['netlify'] },
  cloudflare: { aliases: ['cloudflare', 'cloudflare turnstile', 'cloudflare workers', 'cloudflare r2'], tokens: ['cloudflare'] },
  fly: { aliases: ['fly.io', 'flyio'], tokens: ['fly.io'] },
  render: { aliases: ['render.com', 'render services'], tokens: ['render.com'] },
  railway: { aliases: ['railway.app', 'railway corp'], tokens: ['railway.app'] },
  heroku: { aliases: ['heroku'], productOf: 'salesforce', tokens: ['heroku'] },
  digitalocean: { aliases: ['digitalocean', 'digital ocean'], tokens: ['digitalocean'] },
  supabase: { aliases: ['supabase'], tokens: ['supabase'] },
  openai: { aliases: ['openai', 'chatgpt', 'gpt-4'] },
  anthropic: { aliases: ['anthropic', 'claude'] },
  huggingface: { aliases: ['hugging face', 'huggingface'] },
  openrouter: { aliases: ['openrouter'] },
  stripe: { aliases: ['stripe'] },
  sentry: { aliases: ['sentry', 'functional software'] },
  posthog: { aliases: ['posthog'] },
  svix: { aliases: ['svix'] },
  uploadthing: { aliases: ['uploadthing'] },
  unsplash: { aliases: ['unsplash'] },
  line: { aliases: ['line messaging', 'line liff', 'line app', 'line official account', 'line login', 'ly corporation'] },
  telegram: { aliases: ['telegram'] },
  viber: { aliases: ['viber'] },
  kakao: { aliases: ['kakaotalk', 'kakao'] },
  'osm-tiles': { aliases: ['openstreetmap', 'open street map'] },
  arcgis: { aliases: ['arcgis', 'esri'] },
  opentopomap: { aliases: ['opentopomap'] },
  smtp: { aliases: ['smtp'], tokens: ['smtp'] },
  'email-services': {
    tokens: ['resend', 'sendgrid', 'mailchimp', 'mandrill', 'postmark', 'mailgun', 'brevo', 'sendinblue'],
    members: [
      { id: 'resend', name: 'Resend', aliases: ['resend'], country: 'US' }, { id: 'sendgrid', name: 'SendGrid', aliases: ['sendgrid', 'twilio sendgrid'], country: 'US' },
      { id: 'mailchimp', name: 'Mailchimp', aliases: ['mailchimp', 'mandrill'], country: 'US' }, { id: 'postmark', name: 'Postmark', aliases: ['postmark'], country: 'US' },
      { id: 'mailgun', name: 'Mailgun', aliases: ['mailgun'], country: 'US' }, { id: 'brevo', name: 'Brevo', aliases: ['brevo', 'sendinblue'], country: 'FR' },
    ],
  },
  clerk: { members: [{ id: 'clerk', name: 'Clerk', aliases: ['clerk'], country: 'US' }, { id: 'auth0', name: 'Auth0', aliases: ['auth0', 'okta'], country: 'US' }] },
  cloudinary: { aliases: ['cloudinary'], members: [{ id: 'cloudinary', name: 'Cloudinary', aliases: ['cloudinary'], country: 'US' }] },
  plausible: {
    members: [
      { id: 'plausible', name: 'Plausible', aliases: ['plausible'], country: 'EU' }, { id: 'umami', name: 'Umami', aliases: ['umami'], country: 'US/EU' },
      { id: 'simple-analytics', name: 'Simple Analytics', aliases: ['simple analytics'], country: 'NL' },
    ],
  },
  push: {
    members: [
      { id: 'onesignal', name: 'OneSignal', aliases: ['onesignal'], country: 'US' }, { id: 'expo-push', name: 'Expo Push', aliases: ['expo push', 'expo notifications'], country: 'US' },
      { id: 'fcm', name: 'Firebase Cloud Messaging', aliases: ['firebase cloud messaging', 'fcm'], country: 'US' },
    ],
  },
  'support-chat': {
    members: [
      { id: 'intercom', name: 'Intercom', aliases: ['intercom'], country: 'US' }, { id: 'crisp', name: 'Crisp', aliases: ['crisp'], country: 'FR' },
      { id: 'tawk', name: 'Tawk.to', aliases: ['tawk.to', 'tawk'], country: 'US' }, { id: 'zendesk', name: 'Zendesk', aliases: ['zendesk'], country: 'US' },
    ],
  },
  logrocket: { members: [{ id: 'logrocket', name: 'LogRocket', aliases: ['logrocket'], country: 'US' }, { id: 'fullstory', name: 'FullStory', aliases: ['fullstory'], country: 'US' }] },
  'other-ai': {
    members: [
      { id: 'mistral', name: 'Mistral', aliases: ['mistral', 'mistral ai'], country: 'FR' }, { id: 'groq', name: 'Groq', aliases: ['groq'], country: 'US' },
      { id: 'replicate', name: 'Replicate', aliases: ['replicate'], country: 'US' }, { id: 'together', name: 'Together AI', aliases: ['together ai'], country: 'US' },
    ],
  },
  langsmith: { members: [{ id: 'langsmith', name: 'LangSmith', aliases: ['langsmith', 'langchain'], country: 'US' }, { id: 'helicone', name: 'Helicone', aliases: ['helicone'], country: 'US' }] },
  upstash: { tokens: ['upstash'] },
  neon: { tokens: ['neon.tech'] },
  iyzico: { members: [{ id: 'iyzico', name: 'iyzico', aliases: ['iyzico'], country: 'TR' }, { id: 'paytr', name: 'PayTR', aliases: ['paytr'], country: 'TR' }] },
};

// Vendors discovered on real sites (kept in the live scanner module).
export const VENDORS = [...BASE_VENDORS, ...EXTRA_VENDORS].map((v) => {
  const x = VENDOR_NAMES[v.id];
  if (!x) return v.aliases ? v : { ...v, aliases: [] };
  return { ...v, ...x, aliases: [...new Set([...(v.aliases || []), ...(x.aliases || [])])] };
});

/**
 * Third-party SDKs in non-npm dependency manifests (requirements.txt / pyproject / Pipfile, Gemfile, composer.json, go.mod).
 * npm packages are mapped by extract/_sinks.js VENDOR_BY_PKG. Each entry: [name regex, vendorId, flags?].
 * selfHostable: the package is also a client for self-hosted software (Elasticsearch), so it is evidence of a third
 * party only when the configured host is a managed service. Names are matched lower-cased; PyPI names are
 * normalised per PEP 503 (runs of - _ . become -).
 */
export const DEPENDENCY_VENDORS = {
  pypi: [
    [/^openai$/, 'openai'],
    [/^anthropic$/, 'anthropic'],
    [/^(google-generativeai|google-genai|google-cloud-aiplatform)$/, 'gemini'],
    [/^(mistralai|groq|replicate|together|cohere)$/, 'other-ai'],
    [/^dashscope$/, 'dashscope'],
    [/^(zhipuai|zai-sdk)$/, 'zhipu'],
    [/^(volcengine-python-sdk|volcengine)$/, 'volcengine-ark'],
    [/^qianfan$/, 'baidu-qianfan'],
    [/^azure-ai-translation-text$/, 'ms-translator'],
    [/^(libgravatar|django-gravatar2|flask-gravatar)$/, 'gravatar'],
    [/^flask-moment$/, 'jsdelivr'], // include_moment() loads moment.js from cdn.jsdelivr.net by default
    [/^(sentry-sdk|raven)$/, 'sentry'],
    [/^(huggingface-hub|transformers-api)$/, 'huggingface'],
    [/^(langchain-openai|llama-index-llms-openai)$/, 'openai'],
    [/^(langchain-anthropic|llama-index-llms-anthropic)$/, 'anthropic'],
    [/^(langchain-google-genai|langchain-google-vertexai)$/, 'gemini'],
    [/^django-ses$/, 'aws'],
    [/^line-bot-sdk$/, 'line'],
    [/^(python-telegram-bot|aiogram|pytelegrambotapi)$/, 'telegram'],
    [/^(google-cloud-storage)$/, 'google-cloud'],
    [/^(azure-storage-blob)$/, 'azure'],
    [/^(upstash-redis|upstash-ratelimit)$/, 'upstash'],
    [/^posthog$/, 'posthog'],
    [/^mixpanel$/, 'mixpanel'],
    [/^(segment-analytics-python|analytics-python)$/, 'segment'],
    [/^amplitude-analytics$/, 'amplitude'],
    [/^(stripe|dj-stripe)$/, 'stripe'],
    [/^razorpay$/, 'razorpay'],
    [/^elevenlabs$/, 'elevenlabs'],
    [/^appwrite$/, 'appwrite'],
    [/^dropbox$/, 'dropbox'],
    [/^iyzipay$/, 'iyzico'],
    [/^twilio$/, 'twilio'],
    [/^(sendgrid|postmarker|resend|mailchimp-marketing|mailchimp3|mailgun|sib-api-v3-sdk|brevo-python)$/, 'email-services'],
    [/^(boto3|botocore|aioboto3)$/, 'aws'],
    [/^(firebase-admin|pyrebase4?|google-cloud-firestore)$/, 'firebase'],
    [/^(supabase|supabase-py)$/, 'supabase'],
    [/^cloudinary$/, 'cloudinary'],
    [/^onesignal-sdk$/, 'push'],
    [/^svix$/, 'svix'],
    [/^workos$/, 'workos'],
    [/^stytch$/, 'stytch'],
    [/^(langfuse)$/, 'langfuse'],
    [/^(langsmith)$/, 'langsmith'],
    [/^(ddtrace|datadog|datadog-api-client)$/, 'datadog'],
    [/^newrelic$/, 'newrelic'],
    [/^opentelemetry-exporter-otlp(-proto-http|-proto-grpc)?$/, 'otel-exporter'],
    [/^(flask-hcaptcha|hcaptcha)$/, 'hcaptcha'],
    [/^(django-recaptcha|flask-recaptcha|flask-wtf-recaptcha|recaptcha-enterprise|google-cloud-recaptcha-enterprise)$/, 'recaptcha'],
    [/^(elasticsearch|elasticsearch-dsl|elastic-transport)$/, 'elastic', { selfHostable: true }],
  ],
  rubygems: [
    [/^(ruby-openai|openai)$/, 'openai'],
    [/^anthropic$/, 'anthropic'],
    [/^(sentry-ruby|sentry-rails|sentry-raven)$/, 'sentry'],
    [/^posthog-ruby$/, 'posthog'],
    [/^mixpanel-ruby$/, 'mixpanel'],
    [/^analytics-ruby$/, 'segment'],
    [/^stripe$/, 'stripe'],
    [/^iyzipay$/, 'iyzico'],
    [/^twilio-ruby$/, 'twilio'],
    [/^(sendgrid-ruby|postmark|postmark-rails|resend|mailgun-ruby|gibbon)$/, 'email-services'],
    [/^aws-sdk(-|$)/, 'aws'],
    [/^cloudinary$/, 'cloudinary'],
    [/^(gravatar_image_tag|gravatarify)$/, 'gravatar'],
    [/^(elasticsearch|searchkick|elasticsearch-model)$/, 'elastic', { selfHostable: true }],
  ],
  composer: [
    [/^openai-php\//, 'openai'],
    [/^(sentry\/sentry|sentry\/sentry-laravel|sentry\/sentry-symfony)$/, 'sentry'],
    [/^posthog\/posthog-php$/, 'posthog'],
    [/^mixpanel\/mixpanel-php$/, 'mixpanel'],
    [/^segmentio\/analytics-php$/, 'segment'],
    [/^stripe\/stripe-php$/, 'stripe'],
    [/^iyzico\/iyzipay-php$/, 'iyzico'],
    [/^twilio\/sdk$/, 'twilio'],
    [/^(sendgrid\/sendgrid|wildbit\/postmark-php|resend\/resend-php|mailgun\/mailgun-php|drewm\/mailchimp-api)$/, 'email-services'],
    [/^aws\/aws-sdk-php/, 'aws'],
    [/^kreait\/(firebase-php|laravel-firebase)$/, 'firebase'],
    [/^cloudinary\//, 'cloudinary'],
    [/^laravel\/cashier(-stripe)?$/, 'stripe'],
    [/^laravel\/cashier-paddle$/, 'paddle'],
    [/^lemonsqueezy\/laravel$/, 'lemonsqueezy'],
    [/^razorpay\/razorpay$/, 'razorpay'],
    [/^league\/flysystem-aws-s3-v3$/, 'aws'],
    [/^spatie\/(dropbox-api|flysystem-dropbox)$/, 'dropbox'],
    [/^masbug\/flysystem-google-drive-ext$/, 'google-drive'],
    [/^appwrite\/appwrite$/, 'appwrite'],
    [/^(elasticsearch\/elasticsearch|elastic\/)/, 'elastic', { selfHostable: true }],
  ],
  go: [
    [/^github\.com\/(sashabaranov\/go-openai|openai\/openai-go)/, 'openai'],
    [/^github\.com\/anthropics\/anthropic-sdk-go/, 'anthropic'],
    [/^github\.com\/getsentry\/sentry-go/, 'sentry'],
    [/^github\.com\/posthog\/posthog-go/, 'posthog'],
    [/^github\.com\/stripe\/stripe-go/, 'stripe'],
    [/^github\.com\/twilio\/twilio-go/, 'twilio'],
    [/^github\.com\/(sendgrid\/sendgrid-go|resend\/resend-go|mailgun\/mailgun-go)/, 'email-services'],
    [/^github\.com\/aws\/aws-sdk-go/, 'aws'],
    [/^firebase\.google\.com\/go/, 'firebase'],
    [/^github\.com\/supabase-community\/supabase-go/, 'supabase'],
    [/^github\.com\/elastic\/go-elasticsearch/, 'elastic', { selfHostable: true }],
  ],
};

/**
 * Vendor behind a dependency-manifest package name.
 * ecosystem: 'pypi' | 'rubygems' | 'composer' | 'go' (omitted = try all).
 * Returns { vendor, selfHostable, ecosystem } or null.
 */
export function vendorForDependency(name, ecosystem) {
  if (!name) return null;
  const ecos = ecosystem ? [ecosystem] : Object.keys(DEPENDENCY_VENDORS);
  for (const eco of ecos) {
    const n = eco === 'pypi' ? String(name).toLowerCase().replace(/[-_.]+/g, '-') : String(name).toLowerCase();
    for (const [re, id, flags] of DEPENDENCY_VENDORS[eco] || []) {
      if (!re.test(n)) continue;
      const vendor = vendorById(id);
      if (vendor) return { vendor, selfHostable: !!flags?.selfHostable, ecosystem: eco };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

const cookieIndex = VENDORS.flatMap((v) => v.cookies.map((c) => ({ re: new RegExp(c), vendor: v })));

/** Find the vendor that owns a cookie name. */
export function vendorForCookie(name) {
  return cookieIndex.find((c) => c.re.test(name))?.vendor || null;
}

/** Find the vendor for a request URL / hostname. */
export function vendorForUrl(url) {
  let host = url;
  let full = url;
  try {
    const u = new URL(url);
    host = u.hostname;
    full = u.hostname + u.pathname;
  } catch {}
  for (const v of VENDORS) {
    for (const d of v.domains) {
      if (d.includes('/')) {
        if (full.includes(d)) return v;
      } else if (host === d || host.endsWith('.' + d)) return v;
    }
  }
  return null;
}

/** Find a vendor by the label a code-scan rule emitted. */
export function vendorForLabel(label) {
  const l = typeof label === 'string' ? label : label?.en;
  return VENDORS.find((v) => v.labels.includes(l) || (typeof label === 'object' && v.labels.includes(label.tr))) || null;
}

export function vendorById(id) {
  return VENDORS.find((v) => v.id === id) || unknownSdkVendor(id);
}

/**
 * Synthetic catalogue entry for a remote-service SDK that is not in the catalogue (`unknown:<package>`, emitted by the
 * unknown-SDK heuristic in extract/_sinks.js). The operator and its country are unknown: transfer checks treat the
 * recipient as "location unknown – verify", and coverage reports the vendors layer as partial (unknownVendor).
 * Not part of VENDORS, so URL / cookie / label lookups never return it.
 */
export function unknownSdkVendor(id) {
  const m = typeof id === 'string' ? id.match(/^unknown:(.+)$/) : null;
  if (!m) return null;
  return {
    id, name: `${m[1]} (bilinmeyen SDK / unknown SDK)`, company: '—', country: undefined,
    category: 'unknown', consentRequired: false, group: G.hosting, unknownVendor: true, package: m[1],
    labels: [], domains: [], cookies: [],
    purpose: { tr: 'Paket bir uzak hizmete veri gönderiyor; hizmet sağlayıcısı katalogda yok – doğrulayın', en: 'The package sends data to a remote service that is not in the catalogue – verify' },
    privacyUrl: '',
  };
}

/**
 * Identity-provider vendor behind an OAuth / OIDC provider name (next-auth / better-auth / Supabase / Firebase / passport /
 * remix-auth provider ids): 'github' → 'github', 'azure-ad' → 'microsoft-login', 'apple.com' → 'apple-signin'. Null for
 * brokers, SAML / generic OIDC placeholders and unknown names.
 */
export const IDP_VENDOR_BY_PROVIDER = {
  github: 'github', gitlab: 'gitlab', discord: 'discord-login', twitter: 'x-login', x: 'x-login', linkedin: 'linkedin-login',
  microsoft: 'microsoft-login', 'azure-ad': 'microsoft-login', azure: 'microsoft-login', azuread: 'microsoft-login', 'microsoft-entra-id': 'microsoft-login',
  entra: 'microsoft-login', live: 'microsoft-login', apple: 'apple-signin', google: 'google-signin', facebook: 'facebook-login', meta: 'facebook-login',
  line: 'line', kakao: 'kakao', kakaotalk: 'kakao',
};
export function idpVendorForProvider(provider) {
  const p = String(provider || '').toLowerCase().replace(/\.com$/, '').replace(/[_\s]+/g, '-');
  const id = Object.prototype.hasOwnProperty.call(IDP_VENDOR_BY_PROVIDER, p) ? IDP_VENDOR_BY_PROVIDER[p] : null;
  return id ? vendorById(id) : null;
}

/** Vendor whose endpoint an env variable holds by its name (vendors.js envKeys: SLACK_WEBHOOK_URL → Slack), or null. */
let envKeyIndex = null;
export function vendorForEnvKey(key) {
  if (!key) return null;
  envKeyIndex ||= VENDORS.flatMap((v) => (v.envKeys || []).map((k) => ({ re: new RegExp(k), vendor: v })));
  return envKeyIndex.find((x) => x.re.test(String(key)))?.vendor || null;
}

/**
 * Vendor named in free text (a config comment such as "# Database (MySQL - PlanetScale)"): matches the catalog
 * `aliases` only (distinctive multi-letter names), whole-word, case-insensitive. Returns the first hit or null.
 */
export function vendorForName(text) {
  const t = String(text || '').toLowerCase();
  if (!t) return null;
  // Hosting vendors first: the caller reads config comments ("# Database (Neon)").
  for (const v of [...VENDORS.filter((x) => x.hosting), ...VENDORS.filter((x) => !x.hosting)]) {
    for (const a of v.aliases || []) {
      const re = new RegExp(`(^|[^a-z0-9])${a.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}($|[^a-z0-9])`);
      if (re.test(t)) return v;
    }
  }
  return null;
}

// Cloud region codes (AWS / GCP / Azure / Alibaba / Volcengine style) → country or area.
const REGION_PREFIX = [
  [/^cn-(hongkong|hk)/, 'HK'],
  [/^cn-/, 'CN'],
  [/^(eu|europe)-?/, 'EU'],
  [/^(us|na)-/, 'US'],
  [/^ap-northeast-1|^asia-northeast1|^ap-tokyo/, 'JP'],
  [/^ap-northeast-2|^asia-northeast3|^ap-seoul/, 'KR'],
  [/^ap-south-|^asia-south/, 'IN'],
  [/^ap-southeast-1|^asia-southeast1|^ap-singapore/, 'SG'],
  [/^ap-southeast-2|^australia-/, 'AU'],
  [/^sa-east-|^southamerica-/, 'BR'],
  [/^ca-central-|^northamerica-northeast/, 'CA'],
  [/^me-central-|^me-south-/, 'AE'],
  [/^il-central-/, 'IL'],
  [/^tr-/, 'TR'],
];
// A region code is a host label (or dash-joined part of one): 'ark.cn-beijing.volces.com', 'aws-0-eu-central-1.pooler.supabase.com',
// 'ep-x.us-east-2.aws.neon.tech'. Bare 'eu' / 'us' labels (eu.i.posthog.com, api.eu.mixpanel.com) too.
const REGION_TOKEN = /(?:^|[.-])((?:cn|eu|us|na|ap|sa|ca|me|il|tr|europe|asia|australia|southamerica|northamerica)-[a-z]+(?:-?\d)?)(?=$|[.-])/;
// Country-code TLDs whose sites are normally hosted under that jurisdiction (generic-use ccTLDs such as .io, .ai,
// .co, .me, .tv, .ly, .sh are deliberately absent).
const CC_TLD = { cn: 'CN', ru: 'RU', tr: 'TR', by: 'BY', ir: 'IR', kp: 'KP', jp: 'JP', kr: 'KR', de: 'DE', fr: 'FR', nl: 'NL', pl: 'PL', it: 'IT', es: 'ES', se: 'SE', at: 'AT', ch: 'CH', uk: 'UK', in: 'IN', br: 'BR' };

/**
 * Hosting country / region hinted by a hostname. Returns { country, region?, source:'region-code'|'eu-label'|'cctld' } or null.
 *   'ark.cn-beijing.volces.com' → { country:'CN', region:'cn-beijing' }    'eu.i.posthog.com' → { country:'EU' }
 *   'aws-0-eu-central-1.pooler.supabase.com' → { country:'EU', region:'eu-central-1' }    'api.moonshot.cn' → { country:'CN' }
 */
export function regionForHost(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h || /[{}$%<>\s]/.test(h)) return null;
  const m = h.match(REGION_TOKEN);
  if (m) {
    const region = m[1];
    for (const [re, country] of REGION_PREFIX) if (re.test(region)) return { country, region, source: 'region-code' };
  }
  const labels = h.split('.');
  if (labels.length > 2 && labels.slice(0, -2).some((l) => /^eu\d?$/.test(l))) return { country: 'EU', source: 'eu-label' };
  const tld = labels[labels.length - 1];
  if (labels.length >= 2 && CC_TLD[tld]) return { country: CC_TLD[tld], source: 'cctld' };
  return null;
}
