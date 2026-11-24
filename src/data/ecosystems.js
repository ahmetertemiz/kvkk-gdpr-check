/**
 * Third-party SDKs in mobile / JVM / Rust dependency manifests, and the vendors behind workflow-automation nodes.
 *
 * vendors.js DEPENDENCY_VENDORS covers pypi / rubygems / composer / go; npm is mapped by extract/_sinks.js. This table adds
 *   pub        pubspec.yaml dependencies (Dart / Flutter)
 *   cocoapods  Podfile `pod 'Name'` (subspecs 'Firebase/Auth' keep their full name)
 *   maven      build.gradle(.kts) coordinates 'group:artifact' (and Gradle plugin ids, eco 'gradle-plugin')
 *   cargo      Cargo.toml [dependencies]
 *   nuget      *.csproj <PackageReference Include="…">
 *
 * Each entry: [name regex, vendorId | [vendorId, fallbackId …]]. The first id the vendor catalogue knows wins
 * (vendorById); an SDK whose vendor is not in the catalogue maps to nothing rather than to an invented entry.
 * Names are matched lower-cased.
 */

export const ECOSYSTEM_VENDORS = {
  pub: [
    [/^firebase_analytics$/, ['firebase-analytics', 'firebase']],
    [/^firebase_messaging$/, ['push', 'firebase']],
    [/^firebase_crashlytics$/, ['crashlytics', 'firebase']],
    [/^(firebase_vertexai|firebase_ai)$/, ['gemini', 'firebase']],
    [/^(firebase_[a-z_]+|cloud_firestore|cloud_functions|flutterfire_ui|firebase_ui_[a-z_]+)$/, 'firebase'],
    [/^(supabase_flutter|supabase|gotrue|postgrest|realtime_client|storage_client)$/, 'supabase'],
    [/^(sentry_flutter|sentry|sentry_dio|sentry_logging)$/, 'sentry'],
    [/^google_mobile_ads$/, 'admob'],
    [/^onesignal_flutter$/, ['onesignal', 'push']],
    [/^purchases_flutter$/, ['revenuecat']],
    [/^google_sign_in$/, 'google-signin'],
    [/^sign_in_with_apple$/, 'apple-signin'],
    [/^(flutter_facebook_auth|facebook_app_events|flutter_facebook_sdk)$/, 'facebook-sdk'],
    [/^mixpanel_flutter$/, 'mixpanel'],
    [/^amplitude_flutter$/, 'amplitude'],
    [/^posthog_flutter$/, 'posthog'],
    [/^appsflyer_sdk$/, 'appsflyer'],
    [/^adjust_sdk$/, 'adjust'],
    [/^flutter_branch_sdk$/, 'branch'],
    [/^(segment_analytics|analytics_segment)$/, 'segment'],
    [/^google_maps_flutter$/, 'google-maps'],
    [/^(mapbox_maps_flutter|mapbox_gl)$/, 'mapbox'],
    [/^(flutter_stripe|stripe_sdk|stripe_payment)$/, 'stripe'],
    [/^(dart_openai|openai_dart|langchain_openai)$/, 'openai'],
    [/^(anthropic_sdk_dart|langchain_anthropic)$/, 'anthropic'],
    [/^(google_generative_ai|langchain_google)$/, 'gemini'],
    [/^appwrite$/, 'appwrite'],
    [/^(cloudinary_flutter|cloudinary_public|cloudinary_sdk)$/, 'cloudinary'],
    [/^(algolia|algolia_helper_flutter|algoliasearch)$/, 'algolia'],
    [/^datadog_flutter_plugin$/, 'datadog'],
    [/^intercom_flutter$/, 'support-chat'],
    [/^twilio_flutter$/, 'twilio'],
    [/^elevenlabs_flutter$/, 'elevenlabs'],
  ],
  cocoapods: [
    [/^(firebase\/analytics|firebaseanalytics)$/, ['firebase-analytics', 'firebase']],
    [/^(firebase\/messaging|firebasemessaging)$/, ['push', 'firebase']],
    [/^(firebase\/crashlytics|firebasecrashlytics)$/, ['crashlytics', 'firebase']],
    [/^(firebase(\/[\w-]+)?|firebase[a-z]+)$/, 'firebase'],
    [/^google-mobile-ads-sdk$/, 'admob'],
    [/^sentry(\/[\w-]+)?$/, 'sentry'],
    [/^onesignal(xcframework)?$/, ['onesignal', 'push']],
    [/^(revenuecat|purchases)$/, ['revenuecat']],
    [/^supabase$/, 'supabase'],
    [/^(mixpanel|mixpanel-swift)$/, 'mixpanel'],
    [/^(amplitude|amplitude-ios|amplitudeswift)$/, 'amplitude'],
    [/^appsflyerframework$/, 'appsflyer'],
    [/^adjust$/, 'adjust'],
    [/^branch$/, 'branch'],
    [/^(fbsdkcorekit|fbsdkloginkit|facebookcore|facebooklogin|fbaudiencenetwork)$/, 'facebook-sdk'],
    [/^googlesignin$/, 'google-signin'],
    [/^(googlemaps|google-maps-ios-utils)$/, 'google-maps'],
    [/^(stripe|stripepaymentsheet|stripepayments)$/, 'stripe'],
    [/^posthog$/, 'posthog'],
    [/^(analytics|segment-analytics)$/, 'segment'],
    [/^intercom$/, 'support-chat'],
    [/^algoliasearchclient$/, 'algolia'],
    [/^datadogsdk(objc)?$/, 'datadog'],
    [/^(mapbox-ios-sdk|mapboxmaps)$/, 'mapbox'],
  ],
  maven: [
    [/^com\.google\.firebase:firebase-analytics(-ktx)?$/, ['firebase-analytics', 'firebase']],
    [/^com\.google\.firebase:firebase-messaging(-ktx)?$/, ['push', 'firebase']],
    [/^com\.google\.firebase:firebase-crashlytics(-ktx|-ndk)?$/, ['crashlytics', 'firebase']],
    [/^com\.google\.firebase:/, 'firebase'],
    [/^com\.google\.android\.gms:play-services-ads(-lite)?$/, 'admob'],
    [/^com\.google\.android\.gms:play-services-maps$/, 'google-maps'],
    [/^com\.google\.android\.gms:play-services-auth$/, 'google-signin'],
    [/^io\.sentry:sentry(-android)?/, 'sentry'],
    [/^com\.onesignal:onesignal$/, ['onesignal', 'push']],
    [/^com\.revenuecat\.purchases:/, ['revenuecat']],
    [/^io\.github\.jan-tennert\.supabase:/, 'supabase'],
    [/^com\.mixpanel\.android:/, 'mixpanel'],
    [/^com\.amplitude:/, 'amplitude'],
    [/^com\.appsflyer:/, 'appsflyer'],
    [/^com\.adjust\.sdk:/, 'adjust'],
    [/^io\.branch\.sdk\.android:/, 'branch'],
    [/^com\.facebook\.android:(facebook|audience-network)/, 'facebook-sdk'],
    [/^com\.stripe:stripe-android/, 'stripe'],
    [/^com\.posthog:/, 'posthog'],
    [/^com\.segment\.analytics\.(android|kotlin):/, 'segment'],
    [/^io\.intercom\.android:/, 'support-chat'],
    [/^com\.datadoghq:/, 'datadog'],
    [/^com\.mapbox\.maps:/, 'mapbox'],
    [/^com\.twilio:/, 'twilio'],
    [/^com\.algolia:/, 'algolia'],
    [/^com\.aallam\.openai:/, 'openai'],
    [/^com\.google\.ai\.client\.generativeai:/, 'gemini'],
  ],
  // Gradle plugins whose only purpose is a vendor integration.
  'gradle-plugin': [
    [/^com\.google\.gms\.google-services$/, 'firebase'],
    [/^com\.google\.firebase\.crashlytics$/, ['crashlytics', 'firebase']],
    [/^io\.sentry\.android\.gradle$/, 'sentry'],
  ],
  cargo: [
    [/^async-openai$/, 'openai'],
    [/^(sentry|sentry-[\w-]+)$/, 'sentry'],
    [/^(async-stripe|stripe-rust)$/, 'stripe'],
    [/^aws-sdk-[\w-]+$/, 'aws'],
    [/^(firebase-rs|firestore)$/, 'firebase'],
    [/^posthog-rs$/, 'posthog'],
  ],
  nuget: [
    [/^(openai|azure\.ai\.openai|betalgo\.openai)$/, 'openai'],
    [/^anthropic\.sdk$/, 'anthropic'],
    [/^sentry(\.[\w.]+)?$/, 'sentry'],
    [/^stripe\.net$/, 'stripe'],
    [/^awssdk\.[\w.]+$/, 'aws'],
    [/^(firebaseadmin|google\.cloud\.firestore)$/, 'firebase'],
    [/^twilio$/, 'twilio'],
    [/^sendgrid$/, 'email-services'],
    [/^(supabase|supabase-csharp)$/, 'supabase'],
  ],
};

/**
 * Vendor behind a package of one of the ecosystems above.
 * @param {string} name   package name / pod / 'group:artifact' / plugin id
 * @param {string} eco    'pub' | 'cocoapods' | 'maven' | 'gradle-plugin' | 'cargo' | 'nuget'
 * @param {(id:string)=>object|null} vendorById  catalogue lookup (ctx.vendors.vendorById)
 * @returns {{vendor:object, ecosystem:string}|null}
 */
export function vendorForEcosystemPackage(name, eco, vendorById) {
  if (!name || typeof vendorById !== 'function') return null;
  const n = String(name).toLowerCase();
  for (const [re, ids] of ECOSYSTEM_VENDORS[eco] || []) {
    if (!re.test(n)) continue;
    for (const id of Array.isArray(ids) ? ids : [ids]) {
      let v = null;
      try {
        v = vendorById(id);
      } catch {
        v = null;
      }
      if (v) return { vendor: v, ecosystem: eco };
    }
    return null; // the first matching rule decides; an unknown vendor maps to nothing
  }
  return null;
}

/**
 * Workflow-automation node types (n8n LangChain / base nodes, Make modules, Pipedream apps) → vendor ids.
 * Matched against the node type with any package prefix removed ('@n8n/n8n-nodes-langchain.lmChatAnthropic' → 'lmChatAnthropic'),
 * lower-cased. Credential type names (n8n `credentials` keys) are matched by WORKFLOW_CREDENTIAL_VENDORS.
 */
export const WORKFLOW_NODE_VENDORS = [
  [/^(lmchatanthropic|anthropic|lmanthropic)$/, 'anthropic'],
  [/^(lmchatgooglegemini|lmchatgooglevertex|embeddingsgooglegemini|embeddingsgooglevertex|googlegemini|lmgooglepalm|lmchatgooglepalm|embeddingsgooglepalm)$/, 'gemini'],
  [/^(lmchatopenai|lmopenai|embeddingsopenai|openai|openaiassistant|lmchatazureopenai|embeddingsazureopenai)$/, 'openai'],
  [/^(lmchatmistralcloud|embeddingsmistralcloud|mistralai|lmchatgroq|lmcohere|embeddingscohere|lmchatopenrouter|lmchatxaigrok|lmchatdeepseek|lmchattogetherai|lmchatperplexity|perplexity)$/, 'other-ai'],
  [/^(supabase|vectorstoresupabase)$/, 'supabase'],
  [/^(googlefirebasecloudfirestore|googlefirebaserealtimedatabase)$/, 'firebase'],
  [/^(slack|slacktrigger)$/, 'slack'],
  [/^(discord)$/, 'discord'],
  [/^(twilio|twiliotrigger)$/, 'twilio'],
  [/^(stripe|stripetrigger)$/, 'stripe'],
  [/^(sendgrid|mailgun|mailchimp|mailchimptrigger|brevo|sendinblue|postmarktrigger|mailjet|resend)$/, 'email-services'],
  [/^(hubspot|hubspottrigger)$/, 'hubspot'],
  [/^(elevenlabs)$/, 'elevenlabs'],
  [/^(onesignal)$/, ['onesignal', 'push']],
  [/^(awss3|awsses|awslambda|awstextract|awstranscribe|awsrekognition|awscomprehend|awssns|awssqs)$/, 'aws'],
  [/^(googledrive|googledrivetrigger)$/, 'google-drive'],
  [/^(dropbox)$/, 'dropbox'],
  [/^(posthog)$/, 'posthog'],
  [/^(segment)$/, 'segment'],
  [/^(mixpanel)$/, 'mixpanel'],
  [/^(intercom)$/, 'support-chat'],
  [/^(apollo|apolloio)$/, 'apollo'],
  [/^(hunter)$/, 'hunter'],
  [/^(clearbit)$/, 'clearbit'],
  [/^(firecrawl)$/, 'firecrawl'],
  [/^(tavily|tooltavily)$/, 'tavily'],
];

export const WORKFLOW_CREDENTIAL_VENDORS = [
  [/^anthropicapi$/, 'anthropic'],
  [/^(googlepalmapi|googlegeminiapi|googlevertexapi)$/, 'gemini'],
  [/^(openaiapi|azureopenaiapi)$/, 'openai'],
  [/^(mistralcloudapi|groqapi|cohereapi|openrouterapi|xaiapi|deepseekapi|perplexityapi)$/, 'other-ai'],
  [/^supabaseapi$/, 'supabase'],
  [/^(slackapi|slackoauth2api)$/, 'slack'],
  [/^twilioapi$/, 'twilio'],
  [/^stripeapi$/, 'stripe'],
  [/^(sendgridapi|mailgunapi|mailchimpapi|sendinblueapi|brevoapi|postmarkapi|mailjetemailapi|resendapi)$/, 'email-services'],
  [/^(hubspotapi|hubspotoauth2api|hubspotapptoken)$/, 'hubspot'],
  [/^elevenlabsapi$/, 'elevenlabs'],
  [/^(aws|awsassumerole)$/, 'aws'],
];

/** Vendor for a workflow node type or credential type (null when unknown or not in the catalogue). */
export function vendorForWorkflowNode(type, vendorById, table = WORKFLOW_NODE_VENDORS) {
  if (!type || typeof vendorById !== 'function') return null;
  const short = String(type).split('.').pop().toLowerCase();
  for (const [re, ids] of table) {
    if (!re.test(short)) continue;
    for (const id of Array.isArray(ids) ? ids : [ids]) {
      let v = null;
      try {
        v = vendorById(id);
      } catch {
        v = null;
      }
      if (v) return v;
    }
    return null;
  }
  return null;
}
