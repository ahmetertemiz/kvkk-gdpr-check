// kvkk-ignore-file
/**
 * Extra vendors seen on real sites that src/data/vendors.js doesn't cover yet.
 * Same shape as VENDORS. Candidates to merge into src/data/vendors.js.
 */
const marketing = { tr: 'Reklam ve pazarlama iş ortakları', en: 'Advertising and marketing partners' };
const analytics = { tr: 'Analitik hizmet sağlayıcıları', en: 'Analytics providers' };

export const EXTRA_VENDORS = [
  { id: 'pinterest', name: 'Pinterest Tag', company: 'Pinterest Inc.', country: 'US', category: 'marketing', consentRequired: true, group: marketing, labels: ['Pinterest Tag'], domains: ['ct.pinterest.com', 's.pinimg.com', 'pintrk'], cookies: ['^_pin_unauth$', '^_pinterest_ct', '^_derived_epik$', '^_epik$'], purpose: { tr: 'Reklam dönüşüm ölçümü', en: 'Ad conversion measurement' }, privacyUrl: 'https://policy.pinterest.com/privacy-policy' },
  { id: 'bing-ads', name: 'Microsoft Advertising (Bing UET)', company: 'Microsoft Corporation', country: 'US', category: 'marketing', consentRequired: true, group: marketing, labels: ['Microsoft Advertising'], domains: ['bat.bing.com', 'bat.bing.net'], cookies: ['^_uetsid$', '^_uetvid$', '^MUID$', '^_uetmsclkid$'], purpose: { tr: 'Reklam dönüşüm ölçümü', en: 'Ad conversion measurement' }, privacyUrl: 'https://privacy.microsoft.com/privacystatement' },
  { id: 'snap-pixel', name: 'Snap Pixel', company: 'Snap Inc.', country: 'US', category: 'marketing', consentRequired: true, group: marketing, labels: ['Snap Pixel'], domains: ['sc-static.net', 'tr.snapchat.com'], cookies: ['^_scid', '^_sctr$'], purpose: { tr: 'Reklam dönüşüm ölçümü', en: 'Ad conversion measurement' }, privacyUrl: 'https://values.snap.com/privacy/privacy-policy' },
  { id: 'reddit-pixel', name: 'Reddit Pixel', company: 'Reddit Inc.', country: 'US', category: 'marketing', consentRequired: true, group: marketing, labels: ['Reddit Pixel'], domains: ['redditstatic.com', 'alb.reddit.com'], cookies: ['^_rdt_uuid$'], purpose: { tr: 'Reklam dönüşüm ölçümü', en: 'Ad conversion measurement' }, privacyUrl: 'https://www.reddit.com/policies/privacy-policy' },
  { id: 'insider', name: 'Insider', company: 'Useinsider Ltd.', country: 'TR/SG', category: 'marketing', consentRequired: true, group: marketing, labels: ['Insider'], domains: ['useinsider.com', 'api.useinsider.com'], cookies: ['^ins-', '^spUID$', '^insdrSV$'], purpose: { tr: 'Kişiselleştirme ve pazarlama otomasyonu', en: 'Personalisation and marketing automation' }, privacyUrl: 'https://useinsider.com/privacy-policy/' },
  { id: 'segmentify', name: 'Segmentify', company: 'Segmentify', country: 'TR', category: 'marketing', consentRequired: true, group: marketing, labels: ['Segmentify'], domains: ['segmentify.com'], cookies: ['^SegmentifyUserId', '^_sgf'], purpose: { tr: 'Ürün önerisi ve kişiselleştirme', en: 'Product recommendations and personalisation' }, privacyUrl: '' },
  { id: 'mapp', name: 'Mapp / Webtrekk', company: 'Mapp Digital', country: 'DE/US', category: 'analytics', consentRequired: true, group: analytics, labels: ['Mapp / Webtrekk'], domains: ['wt-safetag.com', 'wt-eu02.net', 'webtrekk.net', 'mapp.com'], cookies: ['^wt3_', '^wteid_', '^wtstp_'], purpose: { tr: 'Web analitiği', en: 'Web analytics' }, privacyUrl: 'https://mapp.com/privacy/' },
  { id: 'hubspot', name: 'HubSpot', company: 'HubSpot Inc.', country: 'US', category: 'marketing', consentRequired: true, group: marketing, labels: ['HubSpot'], domains: ['js.hs-scripts.com', 'js.hs-analytics.net', 'track.hubspot.com', 'js.hsforms.net', 'js.hs-banner.com'], cookies: ['^__hstc$', '^hubspotutk$', '^__hssc$', '^__hssrc$'], purpose: { tr: 'Pazarlama otomasyonu ve analiz', en: 'Marketing automation and analytics' }, privacyUrl: 'https://legal.hubspot.com/privacy-policy' },
  { id: 'klaviyo', name: 'Klaviyo', company: 'Klaviyo Inc.', country: 'US', category: 'marketing', consentRequired: true, group: marketing, labels: ['Klaviyo'], domains: ['klaviyo.com', 'static.klaviyo.com'], cookies: ['^__kla_id$'], purpose: { tr: 'E-posta pazarlama ve davranış takibi', en: 'Email marketing and behaviour tracking' }, privacyUrl: 'https://www.klaviyo.com/legal/privacy' },
  { id: 'matomo', name: 'Matomo', company: '—', country: 'self-hosted/EU', category: 'analytics', consentRequired: true, group: analytics, labels: ['Matomo'], domains: ['matomo.cloud', 'innocraft.cloud'], cookies: ['^_pk_id', '^_pk_ses', '^_pk_ref', '^MATOMO_SESSID$'], purpose: { tr: 'Web analitiği', en: 'Web analytics' }, privacyUrl: '' },
  { id: 'vwo', name: 'VWO / Optimizely / AB Tasty', company: '—', country: 'US/IN/FR', category: 'analytics', consentRequired: true, group: analytics, labels: ['A/B testing'], domains: ['visualwebsiteoptimizer.com', 'dev.visualwebsiteoptimizer.com', 'optimizely.com', 'cdn.optimizely.com', 'abtasty.com'], cookies: ['^_vwo_', '^_vis_opt_', '^optimizelyEndUserId$', '^ABTasty'], purpose: { tr: 'A/B testleri', en: 'A/B testing' }, privacyUrl: '' },
  { id: 'taboola', name: 'Taboola / Outbrain', company: 'Taboola Inc. / Outbrain Inc.', country: 'US/IL', category: 'marketing', consentRequired: true, group: marketing, labels: ['Taboola / Outbrain'], domains: ['taboola.com', 'outbrain.com', 'outbrainimg.com'], cookies: ['^t_gid$', '^taboola_', '^obuid$'], purpose: { tr: 'Önerilen içerik reklamları', en: 'Native content ads' }, privacyUrl: '' },
  { id: 'adform', name: 'Adform / RTB House / Admatic', company: '—', country: 'EU/TR', category: 'marketing', consentRequired: true, group: marketing, labels: ['Ad networks'], domains: ['adform.net', 'adformdsp.net', 'creativecdn.com', 'rtbhouse.com', 'admatic.com.tr', 'adnxs.com', 'rubiconproject.com', 'pubmatic.com', 'casalemedia.com', 'openx.net', 'amazon-adsystem.com', 'criteo.net'], cookies: ['^TPID$', '^__qca$', '^ad-id$', '^ad-privacy$', '^anj$', '^uuid2$'], purpose: { tr: 'Programatik reklam', en: 'Programmatic advertising' }, privacyUrl: '' },
  { id: 'session-replay-extra', name: 'Smartlook / Mouseflow / Lucky Orange / Inspectlet / Crazy Egg', company: '—', country: 'US/EU', category: 'session-replay', consentRequired: true, group: analytics, labels: ['Session replay'], domains: ['smartlook.com', 'smartlook.cloud', 'mouseflow.com', 'luckyorange.com', 'luckyorange.net', 'inspectlet.com', 'crazyegg.com'], cookies: ['^SL_', '^mf_', '^_lo_', '^__insp_', '^_ce\\.'], purpose: { tr: 'Oturum kaydı ve ısı haritası', en: 'Session recording and heatmaps' }, privacyUrl: '' },
  { id: 'didomi', name: 'Didomi / Quantcast Choice', company: '—', country: 'FR/US', category: 'consent', consentRequired: false, group: analytics, labels: [], domains: ['sdk.privacy-center.org', 'didomi.io', 'quantcast.mgr.consensu.org', 'cmp.quantcast.com'], cookies: ['^didomi_token$', '^euconsent-v2$', '^addtl_consent$'], purpose: { tr: 'Çerez tercihlerinin saklanması', en: 'Storing cookie preferences' }, privacyUrl: '' },
];

const cookieIdx = EXTRA_VENDORS.flatMap((v) => v.cookies.map((c) => ({ re: new RegExp(c), v })));

export function extraVendorForCookie(name) {
  return cookieIdx.find((c) => c.re.test(name))?.v || null;
}

export function extraVendorForUrl(url) {
  let host = '';
  let full = url;
  try {
    const u = new URL(url);
    host = u.hostname;
    full = u.hostname + u.pathname;
  } catch {}
  for (const v of EXTRA_VENDORS) {
    for (const d of v.domains) {
      if (!d.includes('.')) {
        if (full.includes(d)) return v;
      } else if (d.includes('/')) {
        if (full.includes(d)) return v;
      } else if (host === d || host.endsWith('.' + d)) return v;
    }
  }
  return null;
}
