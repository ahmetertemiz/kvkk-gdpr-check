// kvkk-ignore-file  (personal-data dictionary)
/**
 * Personal data classifier: field / variable / column name → data element.
 *
 *   classifyField('phone_number') → { element:'phone', category:'contact', sensitivity:'normal', identifier:'direct', confidence:0.95, label }
 *   classifyField('created_at')   → null
 *
 * Categories follow the VERBİS data categories (KVKK) and map to GDPR Art.4/9.
 * sensitivity: 'normal' | 'high' (financial, national ID, precise location, credentials, children) | 'special' (KVKK md.6 / GDPR Art.9)
 * identifier:  'direct' (identifies alone) | 'indirect' (quasi-identifier) | 'none'
 */

export const CATEGORIES = {
  identity: { tr: 'Kimlik', en: 'Identity' },
  contact: { tr: 'İletişim', en: 'Contact' },
  location: { tr: 'Lokasyon', en: 'Location' },
  finance: { tr: 'Finans', en: 'Financial' },
  'customer-transaction': { tr: 'Müşteri İşlem', en: 'Customer transaction' },
  'transaction-security': { tr: 'İşlem Güvenliği', en: 'Transaction security' },
  professional: { tr: 'Mesleki Deneyim', en: 'Professional' },
  marketing: { tr: 'Pazarlama', en: 'Marketing' },
  audiovisual: { tr: 'Görsel ve İşitsel Kayıtlar', en: 'Audio-visual records' },
  legal: { tr: 'Hukuki İşlem', en: 'Legal' },
  'user-content': { tr: 'Kullanıcı İçeriği (serbest metin)', en: 'User content (free text)' },
  device: { tr: 'Cihaz / Çevrimiçi Tanımlayıcı', en: 'Device / online identifier' },
  health: { tr: 'Sağlık Bilgileri', en: 'Health data' },
  biometric: { tr: 'Biyometrik Veri', en: 'Biometric data' },
  genetic: { tr: 'Genetik Veri', en: 'Genetic data' },
  religion: { tr: 'Din, Mezhep, Felsefi İnanç', en: 'Religious / philosophical beliefs' },
  ethnicity: { tr: 'Irk ve Etnik Köken', en: 'Racial or ethnic origin' },
  political: { tr: 'Siyasi Düşünce', en: 'Political opinions' },
  union: { tr: 'Sendika / Dernek / Vakıf Üyeliği', en: 'Trade union membership' },
  'sex-life': { tr: 'Cinsel Hayat / Yönelim', en: 'Sex life / orientation' },
  criminal: { tr: 'Ceza Mahkûmiyeti ve Güvenlik Tedbirleri', en: 'Criminal convictions' },
  appearance: { tr: 'Kılık ve Kıyafet', en: 'Appearance / dress' },
};

export const SPECIAL_CATEGORIES = new Set(['health', 'biometric', 'genetic', 'religion', 'ethnicity', 'political', 'union', 'sex-life', 'criminal', 'appearance']);

/**
 * Dictionary. `m` = token sequences (joined by '_') that must match the normalised name;
 * a leading '*' allows any prefix tokens, trailing '*' any suffix tokens. First match wins, so
 * more specific entries come first. `x` = token sequences that veto the entry.
 */
const D = [
  // ---------- special categories (KVKK md.6 / GDPR Art.9) ----------
  { e: 'health', c: 'health', s: 'special', i: 'none', l: ['Sağlık bilgisi', 'Health information'],
    m: ['*health*', '*saglik*', '*diagnos*', '*teshis*', '*disease*', '*hastalik*', '*illness*', '*symptom*', '*semptom*', '*medical*', '*tibbi*', '*medication*', '*ilac*', '*prescription*', '*recete*', '*allerg*', '*alerji*', '*blood_type*', '*kan_grubu*', '*blood_pressure*', '*tansiyon*', '*heart_rate*', '*nabiz*', '*glucose*', '*seker*', '*bmi*', '*pregnan*', '*hamile*', '*gebelik*', '*disabilit*', '*engel*', '*mental*', '*therapy*', '*terapi*', '*psych*', '*depress*', '*anxiety*', '*vaccin*', '*asi*', '*covid*', '*patient*', '*hasta*', '*treatment*', '*tedavi*', '*menstrua*', '*period_tracking*', '*fertility*'],
    // Service / infrastructure health checks and game hit points are not a person's health.
    x: ['*heartbeat*', '*health_check*', '*healthcheck*', '*healthz*', '*health_endpoint*', '*health_url*', '*health_path*', '*health_route*', '*health_probe*', '*service_health*', '*system_health*', '*server_health*', '*db_health*', '*database_health*', '*api_health*', '*app_health*', '*node_health*', '*cluster_health*', '*pod_health*', '*queue_health*', '*worker_health*', '*liveness*', '*readiness*', '*max_health*', '*health_bar*', '*health_points*', '*health_regen*', '*player_health*', '*enemy_health*', '*boss_health*', '*boy_name*', '*weight_unit*',
      // "engel" (disability) is also the stem of "engelle-" (to block); a mental model is a UX notion; an A/B test has a
      // treatment arm.
      '*engelle', '*engellen*', '*engelled*', '*engelley*', '*engelleme*', '*mental_model*', '*treatment_group*', '*treatment_arm*', '*treatment_variant*'] },
  // Body metrics: health data in fitness/health apps, but often product dimensions elsewhere → low confidence.
  { e: 'body_metrics', c: 'health', s: 'special', i: 'none', k: 0.5, l: ['Vücut ölçüleri / aktivite (olası sağlık verisi)', 'Body metrics / activity (possible health data)'],
    m: ['*body_weight*', '*weight*', '*kilo*', '*height*', '*boy*', '*sleep*', '*uyku*', '*steps*', '*adim*', '*calorie*', '*kalori*', 'mood', '*mood_score*', '*ruh_hali*', '*stress_level*', '*stres*'],
    amb: ['*'],
    x: ['*font_weight*', '*weight_unit*', '*line_height*', '*max_height*', '*min_height*', '*row_height*', '*package_weight*', '*product_weight*', '*shipping_weight*', '*stress_test*', '*stress_mode*', '*stress_run*', '*mood_board*', '*moodboard*', '*boy_name*', '*image_height*', '*video_height*', '*pixel_height*', '*thumbnail_height*', '*image_width*', '*video_width*'] },
  { e: 'biometric', c: 'biometric', s: 'special', i: 'direct', l: ['Biyometrik veri', 'Biometric data'],
    m: ['*biometric*', '*biyometrik*', '*fingerprint*', '*parmak_izi*', '*face_id*', '*face_embedding*', '*face_descriptor*', '*face_encoding*', '*face_template*', '*facial*', '*yuz_tanima*', '*iris*', '*retina*', '*voice_print*', '*voiceprint*', '*ses_izi*', '*palm*'],
    x: ['*device_fingerprint*', '*browser_fingerprint*', '*fingerprint_hash_of_file*'] },
  { e: 'genetic', c: 'genetic', s: 'special', i: 'direct', l: ['Genetik veri', 'Genetic data'], m: ['*genetic*', '*genetik*', '*dna*', '*genome*', '*genom*'] },
  { e: 'religion', c: 'religion', s: 'special', i: 'none', l: ['Din / inanç', 'Religion / belief'], m: ['*religio*', '*din*', '*mezhep*', '*belief*', '*inanc*', '*faith*'], x: ['*din_*_saat*'] },
  { e: 'ethnicity', c: 'ethnicity', s: 'special', i: 'none', l: ['Etnik köken', 'Ethnic origin'], m: ['*ethnic*', '*etnik*', '*race*', '*irk*', '*irki*'], x: ['*race_condition*', '*racer*'] },
  { e: 'political_opinion', c: 'political', s: 'special', i: 'none', l: ['Siyasi görüş', 'Political opinion'], m: ['*political*', '*siyasi*', '*party_membership*', '*parti_uyelik*'] },
  { e: 'union_membership', c: 'union', s: 'special', i: 'none', l: ['Sendika üyeliği', 'Union membership'], m: ['*union_member*', '*sendika*', '*dernek_uye*', '*vakif_uye*'] },
  { e: 'sexual_orientation', c: 'sex-life', s: 'special', i: 'none', l: ['Cinsel yönelim / hayat', 'Sexual orientation / life'], m: ['*sexual*', '*cinsel*', '*orientation*', '*yonelim*', '*sex_life*'] },
  { e: 'criminal_record', c: 'criminal', s: 'special', i: 'none', l: ['Sabıka / ceza kaydı', 'Criminal record'], m: ['*criminal*', '*sabika*', '*conviction*', '*mahkumiyet*', '*adli_sicil*', '*police_record*'] },

  // ---------- transaction security / credentials (high) ----------
  { e: 'password', c: 'transaction-security', s: 'high', i: 'none', l: ['Şifre', 'Password'], m: ['*password*', '*passwd*', 'pwd', '*sifre*', '*parola*', '*passcode*', 'pin', 'pin_code'], x: ['*password_reset_sent_at*', '*password_changed_at*'] },
  { e: 'auth_token', c: 'transaction-security', s: 'high', i: 'none', l: ['Oturum / erişim token\'ı', 'Session / access token'], m: ['*access_token*', '*refresh_token*', '*id_token*', '*session_token*', '*auth_token*', 'jwt', '*api_key*', '*secret*', 'otp', '*otp_code*', '*verification_code*', '*dogrulama_kodu*', '*mfa_secret*', '*totp*', '*recovery_code*', '*session_cookie*', '*auth_cookie*', '*session_secret*'], x: ['*csrf*'] },
  { e: 'ip_address', c: 'transaction-security', s: 'normal', i: 'indirect', l: ['IP adresi', 'IP address'], m: ['ip', '*ip_address*', '*ip_addr*', '*client_ip*', '*remote_addr*', '*ip_adresi*', '*x_forwarded_for*', 'ipv4', 'ipv6', '*last_ip*', '*signup_ip*', '*login_ip*'] },
  { e: 'device_id', c: 'device', s: 'normal', i: 'indirect', l: ['Cihaz kimliği', 'Device identifier'], m: ['*device_id*', '*device_token*', '*push_token*', '*fcm_token*', '*expo_push_token*', '*apns_token*', '*apns_device_token*', '*notification_token*', '*expo_token*', '*gcm_token*', '*push_subscription*', '*messaging_token*', '*push_device_token*', '*idfa*', '*gaid*', '*advertising_id*', '*ad_id*', '*android_id*', '*imei*', '*udid*', '*installation_id*', '*cihaz_id*', '*device_fingerprint*', '*browser_fingerprint*', '*visitor_id*', '*anonymous_id*', '*fingerprint*'] },
  // Behavioural activity tracking: when the person was last seen / active / logged in (VERBİS: İşlem Güvenliği —
  // giriş-çıkış bilgileri). Timestamps by nature, so the `_at` / timestamp-type metadata rules do not apply.
  { e: 'activity_timestamp', c: 'transaction-security', s: 'normal', i: 'none', k: 0.7, l: ['Son görülme / etkinlik zamanı (davranış takibi)', 'Last seen / activity timestamp (behavioural tracking)'],
    m: ['last_seen*', 'last_active*', 'last_activity*', 'last_login*', 'last_logged_in*', 'last_online*', 'last_visit*', 'son_gorulme*', 'son_giris*', 'son_aktif*', 'son_cevrimici*'],
    x: ['*id', '*ids', '*uuid', '*ip*', '*message*', '*version*', '*sync*', '*count*', '*page*', '*url*', '*path*', '*location*', '*device*'] },
  { e: 'user_agent', c: 'device', s: 'normal', i: 'indirect', l: ['Tarayıcı / cihaz bilgisi', 'User agent / device info'], m: ['*user_agent*', 'ua', '*device_model*', '*os_version*', '*browser*'] },

  // ---------- identity ----------
  { e: 'national_id', c: 'identity', s: 'high', i: 'direct', l: ['TC Kimlik No / ulusal kimlik', 'National ID number'], m: ['tckn', '*tc_kimlik*', '*tckimlik*', '*tc_no*', 'tcno', '*kimlik_no*', '*identity_number*', '*national_id*', '*nationalid*', '*ssn*', '*social_security*', '*vkn*', '*vergi_no*', '*tax_id*', '*tax_number*'] },
  { e: 'passport_number', c: 'identity', s: 'high', i: 'direct', l: ['Pasaport / ehliyet no', 'Passport / licence number'], m: ['*passport*', '*pasaport*', '*driver_license*', '*driving_licence*', '*ehliyet*', '*license_number*'] },
  { e: 'id_document', c: 'identity', s: 'high', i: 'direct', l: ['Kimlik belgesi görüntüsü', 'ID document image'], m: ['*id_card*', '*kimlik_karti*', '*id_photo*', '*id_document*', '*kimlik_foto*', '*selfie_with_id*', '*kyc*'] },
  { e: 'full_name', c: 'identity', s: 'normal', i: 'direct', l: ['Ad soyad', 'Full name'], m: ['*full_name*', '*fullname*', '*ad_soyad*', '*adsoyad*', '*display_name*', '*real_name*', 'name!', 'isim', 'ad', '*first_name*', '*firstname*', '*last_name*', '*lastname*', '*surname*', '*soyad*', '*given_name*', '*family_name*', '*middle_name*', '*customer_name*', '*user_name_real*', '*contact_name*', '*cardholder_name*', '*billing_name*', '*shipping_name*', '*recipient_name*'],
    x: ['*file_name*', '*filename*', '*table_name*', '*bucket_name*', '*product_name*', '*company_name*', '*domain_name*', '*event_name*', '*host_name*', '*hostname*', '*class_name*', '*classname*', '*key_name*', '*column_name*', '*model_name*', '*plan_name*', '*app_name*', '*brand_name*', '*city_name*', '*country_name*', '*category_name*', '*tag_name*', '*role_name*', '*project_name*', '*team_name*', '*channel_name*', '*field_name*', '*display_name_of_*',
      '*namespace*', '*name_space*', '*nameserver*', '*name_server*', '*connection_name*', '*directory_name*', '*tenant_name*', '*workspace_name*', '*org_name*', '*organization_name*', '*integration_name*', '*webhook_name*', '*endpoint_name*', '*provider_name*', '*service_name*', '*queue_name*', '*job_name*', '*task_name*', '*step_name*', '*stage_name*', '*env_name*', '*environment_name*', '*branch_name*', '*repo_name*', '*repository_name*', '*package_name*', '*module_name*', '*function_name*', '*method_name*', '*route_name*', '*page_name*', '*component_name*', '*template_name*', '*list_name*', '*group_name*', '*folder_name*', '*board_name*', '*space_name*', '*site_name*', '*store_name*', '*shop_name*', '*venue_name*', '*room_name*', '*device_name*', '*font_name*', '*color_name*', '*theme_name*', '*metric_name*', '*index_name*', '*db_name*', '*database_name*', '*schema_name*', '*cookie_name*', '*header_name*', '*param_name*', '*attribute_name*', '*property_name*', '*variable_name*', '*token_name*', '*secret_name*', '*api_key_name*', '*course_name*', '*game_name*', '*pet_name*', '*item_name*'] },
  { e: 'username', c: 'identity', s: 'normal', i: 'direct', l: ['Kullanıcı adı', 'Username'], m: ['*username*', '*user_name*', '*kullanici_adi*', '*handle*', '*nickname*', '*screen_name*'] },
  // Age-gate answers ("I am over 18", ageVerified): the minimised alternative to a birth date / age. Before `age`.
  { e: 'age_gate', c: 'identity', s: 'normal', i: 'none', k: 0.6, l: ['Yaş doğrulaması (18+ onayı)', 'Age confirmation (18+ check)'],
    m: ['is_adult', '*over_18*', '*over18*', '*over_13*', '*over13*', '*over_16*', '*over16*', '*over_21*', '*over21*', '*age_verified*', '*age_confirmed*', '*age_confirmation*', '*age_verification*', '*age_check*', '*age_gate*', '*age_consent*', '*age_attest*', 'is_of_age', '*of_legal_age*', '*legal_age_confirm*', '*plus_18*', '*18_plus*', '*yas_onay*', '*yas_dogrulama*', '*resit*'] },
  { e: 'birth_date', c: 'identity', s: 'normal', i: 'indirect', l: ['Doğum tarihi', 'Date of birth'], m: ['*birth*', '*dob*', '*dogum*', '*birthday*'], x: ['*page*', '*storage*', '*usage*', '*message*', '*image*', '*average*', '*package*', '*language*', '*percentage*', '*mileage*'] },
  // Age in years / age range: its own element (less identifying than a date of birth, often shown on profiles).
  // Not maxAge / min_age / cache_age / token_age / message_age (settings, filters, durations).
  { e: 'age', c: 'identity', s: 'normal', i: 'indirect', l: ['Yaş', 'Age'],
    m: ['age!', 'yas', 'yasi!', '*age_range*', '*age_group*', '*age_bracket*', '*age_band*', 'user_age', 'person_age', 'customer_age', 'patient_age', 'member_age', 'student_age', 'child_age', 'current_age', 'actual_age', 'years_old', 'yas_araligi', 'yas_grubu'],
    x: ['*max_age*', '*min_age*', '*maxage*', '*minage*', '*cache_age*', '*token_age*', '*message_age*', '*file_age*', '*page*', '*storage*', '*usage*', '*image*', '*average*', '*package*', '*language*', '*percentage*', '*mileage*'] },
  { e: 'gender', c: 'identity', s: 'normal', i: 'indirect', l: ['Cinsiyet', 'Gender'], m: ['*gender*', '*cinsiyet*', 'sex'] },
  { e: 'nationality', c: 'identity', s: 'normal', i: 'indirect', l: ['Uyruk', 'Nationality'], m: ['*nationality*', '*uyruk*', '*citizenship*', '*vatandaslik*'] },
  { e: 'marital_status', c: 'identity', s: 'normal', i: 'indirect', l: ['Medeni durum', 'Marital status'], m: ['*marital*', '*medeni_hal*', '*medeni_durum*'] },

  // ---------- contact ----------
  { e: 'email', c: 'contact', s: 'normal', i: 'direct', l: ['E-posta', 'Email'], m: ['*email*', '*e_mail*', '*eposta*', '*e_posta*', '*mail*'], x: ['*mail_server*', '*mailer*', '*mail_template*', '*email_template*', '*email_verified*', '*email_confirmed_at*', '*email_change_sent_at*', '*email_sent*', '*mail_subject*', '*email_subject*', '*email_body*', '*mail_body*', '*email_type*', '*mail_type*', '*mail_provider*'] },
  { e: 'phone', c: 'contact', s: 'normal', i: 'direct', l: ['Telefon', 'Phone number'], m: ['*phone*', '*telefon*', '*tel_no*', 'tel', '*gsm*', '*mobile*', '*cep*', '*msisdn*', '*whatsapp*', '*contact_info*', '*contact_details*', '*contact_number*', '*contact_no*', '*iletisim_bilgi*'], x: ['*mobile_app*', '*phone_confirmed_at*', '*phone_change_sent_at*', '*is_mobile*', '*mobile_menu*', '*mobile_view*'] },
  { e: 'address', c: 'contact', s: 'normal', i: 'direct', l: ['Adres', 'Postal address'], m: ['*address*', '*adres*', '*street*', '*sokak*', '*cadde*', '*mahalle*', '*neighborhood*', '*postal_code*', '*postcode*', '*zip*', '*posta_kodu*', '*apartment*', '*daire*', '*shipping_address*', '*billing_address*', '*teslimat_adresi*', '*fatura_adresi*'], x: ['*ip_address*', '*email_address*', '*mac_address*', '*wallet_address*', '*contract_address*', '*address_bar*', '*memory_address*'] },
  { e: 'social_profile', c: 'contact', s: 'normal', i: 'direct', l: ['Sosyal medya hesabı', 'Social media profile'], m: ['*instagram*', '*twitter*', '*linkedin*', '*facebook_id*', '*tiktok*', '*github_username*', '*social_url*', '*bluesky*', '*mastodon*',
    // Account ids on an external messaging / social / identity platform (line_user_id, telegram_chat_id) identify the person there.
    '*line!_user_id', '*line!_uid', '*telegram_user_id', '*telegram_uid', '*discord_user_id', '*discord_uid', '*slack_user_id', '*slack_uid', '*kakao_user_id', '*kakao_uid', '*wechat_user_id', '*wechat_uid', '*viber_user_id', '*viber_uid', '*signal_user_id', '*signal_uid', '*google_user_id', '*google_uid', '*apple_user_id', '*apple_uid', '*github_user_id', '*github_uid', '*gitlab_user_id', '*gitlab_uid', '*twitter_user_id', '*twitter_uid', '*facebook_user_id', '*facebook_uid', '*fb_user_id', '*fb_uid', '*microsoft_user_id', '*microsoft_uid', '*twitch_user_id', '*twitch_uid', '*spotify_user_id', '*spotify_uid', '*steam_user_id', '*steam_uid', '*reddit_user_id', '*reddit_uid', '*instagram_user_id', '*instagram_uid', '*tiktok_user_id', '*tiktok_uid', '*linkedin_user_id', '*linkedin_uid', '*zalo_user_id', '*zalo_uid', '*naver_user_id', '*naver_uid', '*telegram_chat_id', '*wechat_open_id', '*wechat_openid'] },

  // ---------- location ----------
  { e: 'precise_location', c: 'location', s: 'high', i: 'indirect', l: ['Hassas konum', 'Precise location'], m: ['*latitude*', 'lat', '*longitude*', 'lng', 'lon', 'long', '*coords*', '*coordinates*', '*geo_point*', '*geolocation*', '*gps*', '*konum*', '*location_history*', '*current_location*', '*geom*', '*geography*'] },
  { e: 'approx_location', c: 'location', s: 'normal', i: 'indirect', l: ['Yaklaşık konum (şehir/ülke)', 'Approximate location (city/country)'], m: ['city', 'sehir', 'il', 'ilce', 'district', 'region', 'country', 'ulke', '*user_city*', '*user_country*', '*timezone*', '*location*'],
    // A bare "location" is as often a redirect URL / HTTP header / file or storage location; "region" an AWS region;
    // "timezone" a cron setting. City / country stay (checkout forms, geo-IP) but need context when one is given.
    amb: ['*location*', 'region', 'district', '*timezone*'], ambSoft: ['city', 'sehir', 'country', 'ulke', 'il', 'ilce'] },

  // ---------- finance ----------
  { e: 'card_number', c: 'finance', s: 'high', i: 'direct', l: ['Kart numarası', 'Card number'], m: ['*card_number*', '*cardnumber*', '*credit_card*', '*kart_no*', '*kart_numarasi*', '*pan*', '*cvv*', '*cvc*', '*card_expiry*', '*expiry_date*'] },
  { e: 'iban', c: 'finance', s: 'high', i: 'direct', l: ['IBAN / banka hesabı', 'IBAN / bank account'], m: ['*iban*', '*bank_account*', '*account_number*', '*hesap_no*', '*routing_number*', '*swift*'] },
  { e: 'income', c: 'finance', s: 'high', i: 'none', l: ['Gelir / maaş / kredi notu', 'Income / salary / credit score'], m: ['*salary*', '*maas*', '*income*', '*gelir*', '*credit_score*', '*kredi_notu*', '*debt*', '*borc*', '*net_worth*'],
    x: ['*income_statement*', '*gelir_tablosu*', '*operating_income*', '*income_tax_rate*'] },
  { e: 'payment_info', c: 'finance', s: 'normal', i: 'indirect', l: ['Ödeme kaydı', 'Payment record'], m: ['*stripe_customer_id*', '*customer_id*', '*payment_method*', '*last4*', '*card_last*', '*card_brand*', '*invoice*', '*fatura*', '*transaction_id*', '*odeme*', '*subscription_id*'] },
  { e: 'wallet_address', c: 'finance', s: 'normal', i: 'direct', l: ['Kripto cüzdan adresi', 'Crypto wallet address'], m: ['*wallet_address*', '*wallet*', '*eth_address*'] },

  // ---------- customer transaction / professional / marketing ----------
  { e: 'order_history', c: 'customer-transaction', s: 'normal', i: 'none', l: ['Sipariş / işlem geçmişi', 'Order / transaction history'], m: ['*order*', '*siparis*', '*purchase*', '*cart*', '*sepet*', '*booking*', '*rezervasyon*', '*appointment*', '*randevu*'], x: ['*order_by*', '*sort_order*', '*display_order*', '*orderby*'] },
  { e: 'employment', c: 'professional', s: 'normal', i: 'indirect', l: ['Meslek / iş bilgisi', 'Employment info'],
    // company / position / headline are an employer, a layout value or an article title unless a person context
    // (lead / candidate / profile object, name + bio siblings, career words) corroborates them.
    amb: ['job!', 'company', 'company_name', 'current_company', 'headline', 'position', 'job_position', 'current_position', 'work_experience'],
    m: ['job!', 'company', 'company_name', 'current_company', 'headline', 'position', 'job_position', 'current_position', 'work_experience', '*job_title*', '*occupation*', '*meslek*', '*employer*', '*isveren*', '*company_role*', '*resume*', '*cv*', '*ozgecmis*', '*education*', '*egitim*', '*school*', '*okul*', '*university*', '*diploma*'] },
  { e: 'marketing_consent', c: 'marketing', s: 'normal', i: 'none', l: ['Pazarlama tercihleri / izinleri', 'Marketing preferences / consent'], m: ['*marketing*', '*newsletter*', '*bulten*', '*kampanya*', '*opt_in*', '*optin*', '*subscribe*', '*abone*', '*iys*', '*ileti_izni*', '*promo*'] },
  { e: 'preferences_profile', c: 'marketing', s: 'normal', i: 'none', l: ['İlgi alanları / profil', 'Interests / profiling'], m: ['*interests*', '*ilgi_alan*', '*hobbies*', '*hobi*', '*segment*', '*persona!*', '*lifestyle*'],
    // A "segment" is a customer / audience segment only in a marketing or person context; in code it is far more often
    // a text, path, URL, route, audio or timeline segment (content.segments, path segments, transcript segments).
    amb: ['*segment*'] },

  // ---------- audio-visual ----------
  { e: 'photo', c: 'audiovisual', s: 'normal', i: 'direct', l: ['Fotoğraf / avatar', 'Photo / avatar'], m: ['*avatar*', '*profile_photo*', '*profile_picture*', '*profile_image*', '*photo*', '*fotograf*', '*foto*', '*selfie*', '*picture_url*'] },
  { e: 'voice_video', c: 'audiovisual', s: 'normal', i: 'direct', l: ['Ses / video kaydı', 'Voice / video recording'], m: ['*voice*', '*audio_recording*', '*ses_kaydi*', '*video_recording*', '*recording*', '*kayit_video*', '*call_recording*', 'audio', 'audio_file', 'audio_blob', 'audio_data', 'audio_buffer', 'speech_audio', 'voice_note'],
    // A bare `audio` upload (formData.get('audio') sent to transcription) is the speaker's voice; an <audio> element,
    // player, context or device setting is not. Soft: kept without context, dropped when a context does not corroborate it.
    ambSoft: ['audio', 'audio_data', 'audio_buffer'],
    x: ['*audio_context*', '*audio_element*', '*audio_ref*', '*audio_player*', '*audio_enabled*', '*audio_device*', '*audio_track*', '*audio_level*', '*audio_volume*', '*voice_id*', '*voice_model*', '*voice_name*', '*voice_over*',
      // A catalogue of text-to-speech voices to pick from (voices, selectedVoice, voiceOptions) is a setting, not a recording.
      'voices', 'voice_list', 'voice_options', 'voice_settings', 'voice_picker', 'selected_voice', 'tts_voice*', 'available_voices', 'default_voice'] },

  // ---------- legal ----------
  { e: 'legal_record', c: 'legal', s: 'normal', i: 'none', l: ['Hukuki işlem / sözleşme kaydı', 'Legal / contract record'], m: ['*contract*', '*sozlesme*', '*signature*', '*imza*', '*court*', '*dava*', '*icra*', '*lawsuit*'],
    // "contract" / "signature" are mostly technical in code (smart contracts, API contracts, WebAuthn / JWT signatures).
    amb: ['*contract*', '*signature*'],
    // Cryptographic / webhook-verification signatures are integrity metadata, not a person's signature.
    x: ['*webhook*', '*hmac*', '*stripe_signature*', '*hub_signature*', '*svix_signature*', '*request_signature*', '*signature_header*', '*signature_secret*', '*signature_key*', '*signing*', '*sig_header*', '*digest*', '*jws*'] },

  // ---------- user-generated free text (may contain anything) ----------
  { e: 'free_text', c: 'user-content', s: 'normal', i: 'none', l: ['Serbest metin / kullanıcı içeriği', 'Free text / user content'], m: ['*notes*', 'note!', '*not*', '*message*', '*mesaj*', '*comment*', '*yorum*', '*bio*', '*about_me*', '*hakkimda*', '*journal*', '*gunluk*', '*diary*', '*chat*', '*sohbet*', '*conversation*', '*prompt*', '*transcript*', '*description*', '*aciklama*', '*feedback*', '*review*', '*content*'],
    x: ['*error_message*', '*commit_message*', '*print_message*', '*log_message*', '*debug_message*', '*status_message*', '*success_message*', '*toast_message*', '*message_key*', '*message_template*', '*not_null*', '*not_found*', '*notify*', '*notification*', '*content_type*', '*not_before*', '*utm_content*'] },
];

// ---------------------------------------------------------------------------

const TR_MAP = { ı: 'i', İ: 'i', ş: 's', Ş: 's', ğ: 'g', Ğ: 'g', ü: 'u', Ü: 'u', ö: 'o', Ö: 'o', ç: 'c', Ç: 'c' };

/** "phoneNumber" / "phone-number" / "Telefon No" → ["phone","number"] */
export function tokenize(name) {
  return String(name)
    .replace(/[ıİşŞğĞüÜöÖçÇ]/g, (c) => TR_MAP[c])
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

// Tokens matched with a prefix ("diagnos" matches "diagnosis"); exact-only for very short tokens.
// A token ending in '!' is a whole-token match (optionally plural): 'persona!' matches persona(s), not personality.
function compileStrict(pattern) {
  const startAny = pattern.startsWith('*');
  const endAny = pattern.endsWith('*');
  const core = pattern.replace(/^\*|\*$/g, '');
  const parts = core.split('*').map((p) => p.split('_').filter(Boolean));
  const tok = (t) => (t.endsWith('!') ? `${t.slice(0, -1)}s?` : t.length <= 3 ? t : `${t}[a-z0-9]*`);
  const rx = new RegExp(
    (startAny ? '^_(?:[a-z0-9]+_)*?' : '^_') +
      parts.map((p) => p.map(tok).join('_') + '_').join('(?:[a-z0-9]+_)*?') +
      (endAny ? '' : '$'),
  );
  return (tokens) => rx.test('_' + tokens.join('_') + '_');
}

const compileAmb = (p) => (p === '*' ? () => true : compileStrict(p));
const COMPILED = D.map((d) => ({
  ...d,
  mf: d.m.map(compileStrict),
  xf: (d.x || []).map(compileStrict),
  ambf: (d.amb || []).map(compileAmb),
  ambSoftf: (d.ambSoft || []).map(compileAmb),
}));

const NOT_PERSONAL = new Set([
  'id', 'uuid', 'created_at', 'updated_at', 'deleted_at', 'createdat', 'updatedat', 'status', 'type', 'title', 'slug',
  'price', 'amount', 'quantity', 'currency', 'url', 'key', 'value', 'data', 'count', 'index', 'role', 'is_admin', 'plan',
]);

// ---------------------------------------------------------------------------
// Context: which entity does the field belong to (table / model / schema / object literal)?

/** Entities that describe a natural person: a bare `name` there is a person's name. */
const PERSON_ENTITY = new Set([
  'user', 'profile', 'account', 'member', 'customer', 'contact', 'person', 'employee', 'staff', 'patient', 'student',
  'teacher', 'author', 'subscriber', 'applicant', 'candidate', 'guest', 'owner', 'participant', 'attendee', 'lead',
  'buyer', 'seller', 'driver', 'passenger', 'doctor', 'recipient', 'beneficiary', 'citizen', 'resident', 'visitor',
  'signup', 'registration', 'kullanici', 'uye', 'musteri', 'hasta', 'calisan', 'personel', 'ogrenci', 'kisi',
]);
/** Entities that are not people: their name/description/health-like columns are not personal data. */
const THING_ENTITY = new Set([
  'product', 'price', 'plan', 'item', 'sku', 'category', 'tag', 'project', 'task', 'team', 'organization', 'organisation',
  'org', 'company', 'file', 'bucket', 'event', 'pet', 'animal', 'dog', 'cat', 'horse', 'livestock', 'vehicle', 'car',
  'device', 'plant', 'recipe', 'book', 'movie', 'inventory', 'catalog', 'catalogue', 'feature', 'setting', 'config',
  'configuration', 'permission', 'role', 'country', 'city', 'currency', 'tier', 'coupon', 'channel', 'workspace',
  'migration', 'model', 'brand', 'shop', 'venue', 'room', 'template', 'folder', 'repository', 'repo', 'integration',
  'webhook', 'job', 'queue', 'metric', 'course', 'lesson', 'game', 'song', 'album', 'playlist', 'menu', 'dish',
  'ingredient', 'service', 'collection', 'industry', 'sector', 'department', 'division',
  // credentials / connections / tenancy objects (ApiKey, SSO / directory-sync connections, namespaces, feature flags)
  'key', 'apikey', 'credential', 'connection', 'directory', 'dsync', 'namespace', 'tenant', 'idp', 'saml', 'oidc', 'scope',
  'policy', 'plugin', 'extension', 'dataset', 'endpoint', 'resource', 'flag', 'experiment', 'urun', 'kategori', 'proje', 'gorev', 'dosya', 'sirket', 'hayvan', 'evcil',
  // system / workflow objects: their `name` is a key or title (Notification.name = 'unread_message_count')
  // Not nouns health apps use for personal records (step, level, report, schedule, reminder, alert), nor UI words
  // that name form components (page, section, widget, dashboard …): containerKind matches any token.
  'notification', 'announcement', 'campaign', 'workflow', 'pipeline', 'rule', 'package', 'release', 'deployment',
  'environment', 'region', 'zone', 'server', 'cluster', 'database', 'column', 'variant', 'badge', 'achievement',
  'timer', 'cron', 'bildirim', 'etkinlik', 'kampanya',
  // media (also see MEDIA_ENTITY)
  'video', 'image', 'photo', 'picture', 'thumbnail', 'upload', 'asset', 'banner', 'attachment', 'media', 'document',
]);
/**
 * Entities whose bare `name` is a label someone gives an object (an API key, an SSO connection, a webhook, a chat),
 * not a person's name - but whose other columns may still hold personal content (chat messages, descriptions written
 * by users), so only the bare-name reading is dropped. Matched on the head noun of a table / model / schema name.
 */
const LABEL_ENTITY = new Set([
  'key', 'apikey', 'secret', 'credential', 'token', 'connection', 'directory', 'dsync', 'namespace', 'tenant', 'domain',
  'provider', 'idp', 'sso', 'saml', 'oidc', 'oauth', 'client', 'application', 'app', 'integration', 'webhook', 'endpoint',
  'subscription', 'scope', 'policy', 'permission', 'role', 'group', 'team', 'organization', 'organisation', 'org',
  'workspace', 'space', 'site', 'website', 'environment', 'env', 'project', 'board', 'list', 'label', 'tag', 'folder',
  'channel', 'chat', 'conversation', 'thread', 'room', 'server', 'guild', 'bot', 'assistant', 'prompt', 'dataset',
  'resource', 'source', 'destination', 'pipeline', 'flow', 'form', 'survey', 'questionnaire', 'quiz', 'poll',
  'field', 'attribute', 'property', 'variable', 'flag', 'experiment', 'segment', 'audience', 'plugin', 'extension',
  'module', 'library', 'database', 'store', 'shop', 'location', 'venue', 'place', 'sheet', 'spreadsheet', 'view',
  'report', 'dashboard', 'widget', 'theme', 'layout', 'locale', 'language',
]);
/** Sibling keys that mark an object as a configured thing (key, connection, tenant ...) rather than a person. */
const LABEL_SIBLINGS = new Set([
  'tenant', 'tenant_id', 'product', 'webhook_url', 'webhook_secret', 'webhook', 'hashed_key', 'key_hash', 'api_key', 'secret',
  'client_id', 'client_secret', 'scopes', 'scope', 'permissions', 'redirect_url', 'redirect_uri', 'callback_url', 'endpoint',
  'team_id', 'organization_id', 'org_id', 'workspace_id', 'project_id', 'directory_id', 'connection_id', 'provider',
  'version', 'slug', 'domain', 'last_used_at', 'prefix', 'key_prefix', 'config', 'metadata_url', 'idp_metadata', 'acs_url',
  'entity_id', 'namespace',
]);
/**
 * Sibling keys that mark an object as a configured thing / tool / AI object rather than a person: a {name, url},
 * {name, provider, model}, {name, command, args} (MCP server), {name, slug} or {name, description, inputSchema} (tool).
 */
const THING_SIBLINGS = new Set([
  'url', 'link', 'href', 'base_url', 'server_url', 'api_url', 'provider', 'provider_id', 'model', 'model_id', 'slug', 'command',
  'args', 'arguments', 'transport', 'schema', 'input_schema', 'output_schema', 'parameters', 'mime_type', 'mimetype', 'icon',
  'icon_url', 'logo', 'logo_url', 'sku', 'price', 'tool_call_id', 'tool_calls', 'function', 'favicon', 'repo', 'repository',
  'package', 'manifest', 'capabilities', 'parent_id', 'category', 'categories',
]);
/** Sibling keys that link a record to the person it is about (user_id, owner_id, created_by …). */
const PERSON_LINK_SIBLINGS = new Set([
  'user_id', 'userid', 'uid', 'owner_id', 'author_id', 'created_by', 'creator_id', 'profile_id', 'member_id', 'customer_id',
  'account_id', 'patient_id', 'student_id', 'employee_id', 'kullanici_id',
]);
/** Sibling keys that identify a person on their own (email, phone, real-name parts, credentials, birth date). */
const STRONG_PERSON_SIBLINGS = new Set(['email', 'email_address', 'first_name', 'last_name', 'surname', 'phone', 'phone_number', 'password',
  'password_hash', 'birth_date', 'birthday', 'dob', 'username', 'email_verified', 'gender', 'given_name', 'family_name']);
/** Sibling keys that mark an object as a person. */
const PERSON_SIBLINGS = new Set([
  'email', 'email_address', 'first_name', 'last_name', 'surname', 'phone', 'phone_number', 'avatar', 'avatar_url', 'image',
  'photo', 'photo_url', 'picture', 'password', 'password_hash', 'birth_date', 'birthday', 'dob', 'age', 'gender', 'username',
  'address', 'bio', 'job', 'job_title', 'display_name', 'nickname', 'user_id', 'email_verified',
]);
/** Receivers whose `.message` / `.description` / `.content` is program text (an error, a toast, a log line), not user content. */
const NON_CONTENT_RECEIVER = /^(e|err|error|errors|ex|exc|exception|issue|issues|problem|zod_error|validation_error|warning|warn|toast|alert|notification|log|logger|console|status|i18n|t|intl|translation|translations|commit|git_commit)$/;

const MEDIA_ENTITY = new Set(['video', 'image', 'photo', 'picture', 'thumbnail', 'upload', 'asset', 'file', 'banner', 'attachment', 'media', 'document']);
/** Wrapper words around the real entity noun (filePartSchema → file, UserModel → user). Dropped only if other tokens remain. */
const NOISE_TOKEN = new Set([
  'schema', 'model', 'form', 'input', 'dto', 'props', 'prop', 'type', 'data', 'payload', 'request', 'req', 'body', 'params',
  'value', 'part', 'record', 'row', 'entity', 'doc', 'table', 'tbl', 'collection', 'create', 'update', 'insert', 'select',
  'validator', 'validation', 'interface', 'public', 'auth', 'app', 'base', 'new', 'edit', 'info', 'detail', 'details',
]);
const IRREGULAR = { people: 'person', persons: 'person', children: 'child', men: 'man', women: 'woman', media: 'media', data: 'data', series: 'series', status: 'status', address: 'address' };

function singular(t) {
  if (IRREGULAR[t]) return IRREGULAR[t];
  if (t.length > 4 && t.endsWith('ies')) return t.slice(0, -3) + 'y';
  if (t.length > 4 && /(sses|xes|ches|shes)$/.test(t)) return t.slice(0, -2);
  if (t.length > 3 && t.endsWith('s') && !/(ss|us|is)$/.test(t)) return t.slice(0, -1);
  return t;
}

/** Entity tokens: tokenized, singularised, version suffixes (Message_v2) and wrapper words removed. */
function entityTokens(name) {
  const toks = tokenize(name || '').filter((t) => !/^v\d+$/.test(t) && !/^\d+$/.test(t)).map(singular);
  const core = toks.filter((t) => !NOISE_TOKEN.has(t));
  return core.length ? core : toks;
}

/**
 * Classify an entity (table / model / container name) as 'person', 'thing' or null (unknown).
 * The head noun (last token) decides: user_files → thing, pet_owners → person, product_reviews → unknown.
 */
export function entityKind(name) {
  const toks = entityTokens(name);
  if (!toks.length) return null;
  const head = toks[toks.length - 1];
  if (PERSON_ENTITY.has(head)) return 'person';
  if (THING_ENTITY.has(head)) return 'thing';
  return null;
}

/** Container (schema / object literal / component) context: any person token wins, else any thing token. */
function containerKind(name) {
  const toks = entityTokens(name);
  if (toks.some((t) => PERSON_ENTITY.has(t))) return 'person';
  if (toks.some((t) => THING_ENTITY.has(t)) || /file|attachment|upload|document|category|product|tag|model|bucket/.test(toks.join('_'))) return 'thing';
  return null;
}

const MEDIA_DIM_SIBLINGS = new Set(['width', 'genislik', 'duration', 'aspect_ratio', 'resolution', 'depth', 'fps', 'frame_rate', 'bitrate', 'mime_type', 'media_type']);
const FILE_META_SIBLINGS = new Set(['media_type', 'mime_type', 'mimetype', 'content_type', 'url', 'src', 'size', 'file_size', 'byte_size', 'bytes', 'path', 'extension', 'ext', 'file_url', 'storage_path']);

function siblingFeatures(siblings) {
  const f = { mediaDims: false, fileMeta: false, labelShape: false, personShape: false, strongPerson: false, personLink: false, thingShape: 0, tokens: new Set(), names: new Set() };
  if (!siblings || typeof siblings[Symbol.iterator] !== 'function' || typeof siblings === 'string') return f;
  for (const s of siblings) {
    if (typeof s !== 'string') continue;
    const j = tokenize(s).join('_');
    if (MEDIA_DIM_SIBLINGS.has(j)) f.mediaDims = true;
    if (FILE_META_SIBLINGS.has(j)) f.fileMeta = true;
    if (LABEL_SIBLINGS.has(j)) f.labelShape = true;
    if (PERSON_SIBLINGS.has(j)) f.personShape = true;
    if (STRONG_PERSON_SIBLINGS.has(j)) f.strongPerson = true;
    if (PERSON_LINK_SIBLINGS.has(j)) f.personLink = true;
    if (THING_SIBLINGS.has(j)) f.thingShape++;
    f.names.add(j);
    for (const t of j.split('_')) f.tokens.add(singular(t));
  }
  // An AI / chat message ({role, content, name}): its name is a tool / function / participant label.
  if (f.names.has('role') && (f.names.has('content') || f.names.has('tool_call_id'))) f.thingShape++;
  // Only identifying person fields outvote thing signals (an image / user_id sits on tools, topics and servers too).
  if (f.thingShape && !f.strongPerson) f.labelShape = true;
  return f;
}

/** Route path → entity-ish container ("/api/mcp/servers/[id]" → "mcp_servers"); params and api/version prefixes dropped. */
function routeContainer(route) {
  if (typeof route !== 'string' || !route) return '';
  const segs = route.split('?')[0].split('/').filter((x) => x && !/^[:[{(*$]/.test(x) && !/^(api|v\d+|rest|trpc|graphql|route|index|page)(\.\w+)?$/i.test(x));
  return segs.slice(-2).join('_');
}

function contextOf(ctx) {
  const table = typeof ctx.table === 'string' ? ctx.table : '';
  const explicitContainer = typeof ctx.container === 'string' ? ctx.container : '';
  const fromRoute = !explicitContainer ? routeContainer(ctx.route) : '';
  const container = explicitContainer || fromRoute;
  const tTokens = table ? entityTokens(table) : [];
  const tKind = table ? entityKind(table) : null;
  const cKind = container ? containerKind(container) : null;
  // A known table decides; otherwise the container does.
  const kind = tKind || cKind;
  const cTokens = container ? entityTokens(container) : [];
  const head = tTokens[tTokens.length - 1] || cTokens.slice(-1)[0];
  // Label-named object (ApiKey, DirectoryConnection, createWebhookSchema): its bare `name` is a label. A table decides
  // by its head noun; a container only when it is not a single bare word (`App`, `Provider` are React components).
  const tLabel = tTokens.length > 0 && LABEL_ENTITY.has(tTokens[tTokens.length - 1]) && tKind !== 'person';
  const cLabel = !table && cTokens.length > 0 && cKind !== 'person' && LABEL_ENTITY.has(cTokens[cTokens.length - 1]) &&
    (tokenize(container).length > 1 || !!fromRoute);
  // Every context word (table, container, route, file path) for corroboration / technical-context checks.
  const fileTokens = typeof ctx.file === 'string' ? entityTokens(ctx.file.replace(/\.[a-z0-9]+$/i, '')) : [];
  const ctxTokens = new Set([...tTokens, ...cTokens, ...fileTokens]);
  const sibArr = ctx.siblings && typeof ctx.siblings !== 'string' && typeof ctx.siblings[Symbol.iterator] === 'function' ? [...ctx.siblings] : [];
  const hasContext = !!(table || container || fileTokens.length || sibArr.length);
  const receiver = typeof ctx.receiver === 'string' ? tokenize(ctx.receiver).join('_') : '';
  return {
    table, container, tTokens, kind, hasTable: !!table, label: tLabel || cLabel, ctxTokens, hasContext,
    errorReceiver: !!receiver && NON_CONTENT_RECEIVER.test(receiver),
    media: MEDIA_ENTITY.has(head || ''),
    operatorConfig: ctx.operatorConfig === true || (ctx.operatorConfig !== false && !!table && sibArr.length > 1 && isOperatorConfigTable({ table, columns: sibArr })),
    sib: siblingFeatures(ctx.siblings),
    valueKind: typeof ctx.valueKind === 'string' ? ctx.valueKind.toLowerCase() : '',
  };
}

/** Bare, entity-dependent names: in a products table `name` is a product name. */
const AMBIGUOUS_NAME = new Set(['name', 'isim', 'ad', 'display_name']);
/** Elements that only make sense for a person; dropped in non-person entity tables (pets.gender, products.description). */
const PERSON_ONLY_IN_THING = new Set(['gender', 'birth_date', 'age', 'age_gate', 'nationality', 'marital_status', 'preferences_profile', 'free_text', 'legal_record', 'order_history', 'employment', 'income', 'activity_timestamp', 'approx_location']);

// ---------------------------------------------------------------------------
// Name shape and polysemy: field names that are personal data only in a person context.
// Mechanisms (all framework-independent, decided from the name + whatever context the caller passes):
//   1. option flags            include_income_statement, show_email          → never the data itself
//   2. technical head noun     contract_address, email_provider, location_header → the head decides what the value is
//   3. subject qualifier       product_description (thing), player_photo (public figure), user_city (person)
//   4. polysemy                location / signature / contract / height / weight / steps / job / region / timezone:
//                              kept only when corroborated (person context or qualifier, domain words in the table /
//                              container / route / file / sibling names); dropped in technical contexts (WebAuthn,
//                              crypto, iframe/UI, HTTP redirect, infra) and, for strong polysemy, without any context.

/** Option / feature-flag prefixes: include_income_statement, show_email, enableLocation are settings, not the data. */
const FLAG_PREFIX = new Set(['include', 'exclude', 'show', 'hide', 'enable', 'disable', 'toggle', 'use', 'should', 'can', 'want', 'need', 'require', 'requires']);
/** Technical head nouns: the last token says what the value is (contract_address is an address, email_provider a provider). */
const TECH_HEAD = new Set(['statement', 'header', 'headers', 'schema', 'placeholder', 'option', 'options', 'setting', 'settings', 'config',
  'flag', 'flags', 'provider', 'service', 'endpoint', 'version', 'style', 'class', 'classname', 'icon', 'color', 'colour', 'width', 'selector',
  'regex', 'pattern', 'validator', 'handler', 'callback', 'component', 'button', 'modal', 'dialog', 'tab', 'label', 'hint', 'tooltip',
  'abi', 'bytecode', 'chart', 'column', 'size', 'length', 'limit', 'mask', 'tool', 'client', 'api', 'sdk', 'module', 'plugin', 'factory']);
const URL_HEAD = new Set(['url', 'uri', 'link', 'href', 'path', 'src', 'route', 'endpoint']);
const URL_OK = new Set(['photo', 'voice_video', 'social_profile', 'id_document', 'employment', 'uploaded_image', 'uploaded_file']);
const ADDRESS_OK = new Set(['address', 'email', 'ip_address', 'wallet_address', 'precise_location', 'approx_location']);
function headAllowed(element, last) {
  if (TECH_HEAD.has(last)) return false;
  if (URL_HEAD.has(last) && !URL_OK.has(element)) return false;
  if (last === 'address' && !ADDRESS_OK.has(element)) return false;
  // prompt_fingerprint / content_checksum: a hash of the text, not the text (device / biometric readings: classifyField).
  if (/^(?:fingerprints?|checksum|digest)$/.test(last) && element !== 'device_id' && element !== 'biometric') return false;
  return true;
}

/** Qualifiers that put a field in a person's context: user_location, home_city, patient_weight, customer_signature. */
const PERSON_QUALIFIER = new Set([...PERSON_ENTITY, 'my', 'home', 'personal', 'own', 'self', 'body', 'vucut', 'sender', 'receiver',
  'signer', 'billing', 'shipping', 'delivery', 'residence', 'ikamet', 'teslimat', 'fatura', 'parent', 'guardian', 'child', 'kid', 'baby']);
/** People whose data a catalogue / sports / media app shows from a public dataset (not the app's users). */
const PUBLIC_FIGURE = new Set(['player', 'athlete', 'footballer', 'artist', 'actor', 'actress', 'celebrity', 'character', 'singer',
  'musician', 'band', 'politician', 'scorer', 'oyuncu', 'sanatci', 'hero', 'villain', 'pokemon']);

/** Elements that are an attribute OF the qualifying noun (product_description, event_location, team_photo). */
const THING_QUALIFIABLE = new Set(['free_text', 'approx_location', 'photo', 'legal_record', 'body_metrics', 'gender', 'age', 'birth_date',
  'preferences_profile', 'activity_timestamp', 'nationality']);

/** Leading token that qualifies the rest of the name (player_photo → 'public', product_description → 'thing', user_city → 'person'). */
function qualifierOf(d, tokens) {
  if (tokens.length < 2) return null;
  const rest = tokens.slice(1);
  if (!d.mf.some((f) => f(rest))) return null;
  const q = singular(tokens[0]);
  if (PERSON_QUALIFIER.has(q)) return 'person';
  if (PUBLIC_FIGURE.has(q)) return 'public';
  if (THING_ENTITY.has(q)) return 'thing';
  return null;
}

/**
 * Domain words that corroborate a polysemous reading when they appear in the table / container / route / file /
 * sibling names (or qualify the field name): a `weight` in a fitness log, a `signature` next to an agreement.
 */
const SUPPORT = {
  body_metrics: ['health', 'fitness', 'body', 'workout', 'exercise', 'training', 'patient', 'vital', 'measurement', 'measure', 'bmi',
    'wellness', 'diet', 'nutrition', 'meal', 'symptom', 'medical', 'saglik', 'olcum', 'pregnancy', 'baby', 'growth', 'weigh', 'clinic',
    'doctor', 'therapy', 'habit', 'journal', 'diary', 'checkin', 'wearable', 'healthkit', 'googlefit', 'fit', 'sport', 'athlete'],
  legal_record: ['legal', 'agreement', 'sozlesme', 'lease', 'rental', 'kira', 'term', 'consent', 'document', 'sign', 'signer', 'signed',
    'esign', 'docusign', 'hellosign', 'notary', 'noter', 'court', 'case', 'dava', 'law', 'lawyer', 'avukat', 'contract',
    'signature', 'image', 'img', 'pad', 'drawn', 'scan', 'witness', 'party', 'employment', 'hire', 'offer', 'tenancy', 'loan', 'kvkk'],
  approx_location: ['address', 'street', 'city', 'country', 'postal', 'zip', 'postcode', 'lat', 'latitude', 'lng', 'longitude', 'geo',
    'coord', 'coordinate', 'gps', 'ip', 'visitor', 'checkout', 'shipping', 'billing', 'delivery', 'signup', 'register', 'registration',
    'onboarding', 'travel', 'trip', 'ride', 'geoip', 'geolocation', 'whereabout', 'adres', 'sehir', 'ulke'],
  voice_video: ['transcribe', 'transcription', 'transcript', 'speech', 'stt', 'whisper', 'voice', 'recording', 'record', 'recorder',
    'dictation', 'microphone', 'mic', 'upload', 'form', 'blob', 'file', 'call', 'meeting', 'memo'],
  preferences_profile: ['customer', 'audience', 'marketing', 'crm', 'persona', 'cohort', 'campaign', 'targeting', 'interest',
    'behavior', 'behaviour', 'lifecycle', 'rfm', 'subscriber', 'lead', 'contact', 'member', 'musteri', 'kitle', 'pazarlama'],
  employment: ['resume', 'cv', 'career', 'company', 'employer', 'occupation', 'title', 'position', 'salary', 'experience', 'education',
    'skill', 'linkedin', 'applicant', 'candidate', 'hire', 'hiring', 'recruit', 'meslek', 'isveren'],
};
const SUPPORT_SETS = Object.fromEntries(Object.entries(SUPPORT).map(([k, v]) => [k, new Set(v)]));
/** Keyword families: a table / container named after the measure itself (daily_steps, weights, mood_entries) corroborates it. */
const KEYWORD_FAMILY = {
  body_metrics: new Set(['weight', 'height', 'sleep', 'step', 'calorie', 'mood', 'stress', 'kilo', 'boy', 'uyku', 'adim', 'kalori', 'bmi', 'heart']),
  legal_record: new Set(['contract', 'signature', 'sozlesme', 'imza']),
  approx_location: new Set(['location', 'konum', 'region', 'district', 'timezone']),
  employment: new Set(['job', 'company', 'position', 'headline', 'experience']),
};
/**
 * Technical contexts: words in the table / container / route / file / sibling names that make a polysemous reading
 * a protocol, crypto, UI or infrastructure value (WebAuthn signature, smart-contract address, iframe height, redirect location).
 */
const TECH_CONTEXT = new Set(['webauthn', 'passkey', 'authenticator', 'assertion', 'attestation', 'credential', 'crypto', 'cryptography',
  'blockchain', 'onchain', 'abi', 'solidity', 'ethereum', 'evm', 'web3', 'erc20', 'nft', 'coin', 'nonce', 'challenge', 'hmac', 'jwt', 'jws',
  'jwk', 'digest', 'webhook', 'svix', 'header', 'redirect', 'http', 'iframe', 'viewport', 'window', 'layout', 'css', 'px', 'pixel', 'bridge',
  'frame', 'widget', 'svg', 'tile', 'sprite', 'mcp', 'bucket', 'storage', 'cdn', 'aws', 'gcp', 'azure', 'deploy', 'deployment', 'cron',
  'stock', 'ticker', 'market', 'token', 'platform', 'chain', 'raw_id', 'client_data_json', 'authenticator_data', 'fullscreen']);
function hasTech(set) {
  for (const t of set) if (TECH_CONTEXT.has(t)) return true;
  return false;
}

/**
 * 'keep' | 'drop' for a polysemous reading.
 *   Strong polysemy (d.amb): drop unless corroborated (person context, person qualifier, domain words).
 *   Soft polysemy (d.ambSoft): drop only when a context is given that neither corroborates it nor is a person.
 *   Any polysemous reading in a technical context (not a person table / form) is dropped.
 */
function polysemy(d, tokens, cx, qual) {
  const strong = d.ambf.some((f) => f(tokens));
  const soft = !strong && d.ambSoftf.some((f) => f(tokens));
  if (!strong && !soft) return 'keep';
  if (cx.kind === 'person' || qual === 'person') return 'keep';
  const tech = hasTech(cx.ctxTokens) || hasTech(cx.sib.tokens) || hasTech(cx.sib.names) || tokens.some((t) => TECH_CONTEXT.has(t));
  if (tech) return 'drop';
  if (cx.sib.personShape) return 'keep';
  const sup = SUPPORT_SETS[d.e];
  const fam = KEYWORD_FAMILY[d.e];
  const self = tokens.join('_');
  if (sup) {
    if (tokens.some((t) => sup.has(singular(t)) && !(fam && fam.has(singular(t))))) return 'keep';
    for (const t of cx.ctxTokens) if (sup.has(t) || (fam && fam.has(t))) return 'keep';
    for (const n of cx.sib.names) {
      if (n === self) continue;
      // A domain word in another field, or another measure of the same family (weight + height, sleep + mood).
      if (n.split('_').some((t) => sup.has(singular(t)) || (fam && fam.has(singular(t))))) return 'keep';
    }
  }
  if (cx.sib.personLink && d.e !== 'body_metrics') return 'keep';
  if (strong) return 'drop';
  return cx.hasContext ? 'drop' : 'keep';
}
/** Context words of a multi-step process: its `steps` are process steps, not a step count. */
const PROCESS_TOKEN = new Set(['journey', 'funnel', 'wizard', 'onboarding', 'pipeline', 'workflow', 'flow', 'process', 'tutorial', 'guide', 'recipe',
  'migration', 'checkout', 'stage', 'tour', 'sequence', 'build', 'deploy', 'deployment', 'instruction', 'quest', 'lesson', 'course', 'retention', 'conversion', 'path', 'chain', 'agent', 'tool', 'plan', 'task']);
/** Sibling fields a person writes or is reached by: a bare `name` next to them is a person's name (guestbook, comments, leads). */
const PERSONAL_CONTENT_SIBLINGS = new Set(['message', 'comment', 'comments', 'content', 'body', 'text', 'note', 'notes', 'review', 'feedback',
  'testimonial', 'bio', 'about', 'rating', 'email', 'phone', 'contact', 'company', 'role', 'title', 'avatar', 'image', 'photo', 'signature', 'rsvp',
  'attending', 'guests', 'dietary', 'ip', 'ip_address', 'user_agent', 'address', 'city', 'country', 'website', 'twitter', 'linkedin']);
/** Outbox / mail-log tables: their recipient and body columns hold the addressee and the message. */
const OUTBOX_TABLE = new Set(['email', 'mail', 'outbox', 'sent_email', 'email_log', 'mail_log', 'email_queue', 'mail_queue', 'emailmessage', 'mailmessage', 'sms', 'sms_log', 'sms_message']);
const OUTBOX_RECIPIENT = new Set(['to', 'recipient', 'recipients', 'to_email', 'to_address', 'to_addr', 'cc', 'bcc', 'reply_to', 'send_to', 'mail_to']);
const OUTBOX_BODY = new Set(['body', 'html', 'plain_text', 'text', 'text_body', 'html_body', 'content', 'message', 'html_content', 'text_content']);
/** Value kinds: an enum/literal cannot be a free-text identifier; a number can only be a numeric category. */
const ENUMERABLE = new Set(['gender', 'religion', 'ethnicity', 'political_opinion', 'sexual_orientation', 'union_membership', 'marital_status', 'nationality', 'health', 'body_metrics', 'criminal_record', 'approx_location', 'marketing_consent', 'preferences_profile', 'employment', 'birth_date', 'age', 'age_gate']);
const NUMERIC = new Set(['phone', 'national_id', 'passport_number', 'card_number', 'iban', 'birth_date', 'age', 'address', 'body_metrics', 'health', 'income', 'precise_location', 'payment_info', 'password', 'auth_token']);
/** A trailing id/key token makes the field a reference, not the content (chat_id is not a chat). */
const ID_SUFFIX = new Set(['id', 'uuid', 'ids', 'ref', 'fk', 'key']);
const METADATA_SUFFIX = new Set(['verified', 'confirmed', 'at', 'count', 'enabled', 'sent', 'changed', 'type', 'format', 'template', 'unit', 'exists', 'required', 'visible']);
const UNIT_SUFFIX = new Set(['px', 'pixel', 'pixels', 'pt', 'dp', 'em', 'rem']);
/** Words naming a place / point of interest (not where a person is): place_name, venue, landmark, attraction. */
const PLACE_TOKEN = new Set(['place', 'poi', 'venue', 'landmark', 'attraction', 'destination', 'sight', 'sightseeing', 'restaurant',
  'hotel', 'museum', 'mekan', 'yer']);
const PLACE_RAW_RE = /(?<!work|birth|home|my)place|venue|landmark|attraction|sightseeing/i;
function placeContext(cx, tokens) {
  const self = tokens.join('_');
  for (const n of cx.sib.names) {
    if (n === self) continue;
    if (n.split('_').some((t) => PLACE_TOKEN.has(singular(t)))) return true;
  }
  if ([...cx.ctxTokens].some((t) => PLACE_TOKEN.has(t))) return true;
  return PLACE_RAW_RE.test(`${cx.table} ${cx.container}`);
}
/** Generic text columns that hold what a person wrote when the row is keyed to that person. */
const USER_TEXT_COLUMN = new Set(['title', 'body', 'content', 'text', 'note', 'notes', 'subject']);
const TEXT_SQL_TYPE = /^(text|varchar|character|char|nvarchar|nchar|string|clob|longtext|mediumtext|tinytext|citext|ntext|str)/i;
const PERSON_IMAGE = new Set(['image', 'image_url', 'image_uri', 'picture', 'picture_url', 'img', 'icon_url', 'photo_url']);
/** Image column names that, prefixed by a person noun (userImage, authorPicture, memberImageUrl), are that person's photo. */
const PERSON_PREFIX_IMAGE = new Set(['image', 'image_url', 'image_uri', 'img', 'img_url', 'picture', 'picture_url', 'pic', 'pic_url', 'thumbnail', 'thumbnail_url']);
/** Person nouns that, as a leading token, make the rest of the name about that person (userName, authorImage). */
const PERSON_PREFIX = new Set([...PERSON_ENTITY, 'my', 'own', 'self', 'personal', 'sender', 'receiver', 'signer', 'creator', 'uploader', 'reviewer', 'commenter', 'actor']);
/** Copies of a person's name kept next to their id (a denormalised author snapshot: { userId, userName, userImage }). */
const PERSON_NAME_COPY = /^(user|author|owner|creator|member|sender|actor|customer|profile|commenter|reviewer)_(name|full_name|display_name|username)$/;
/** Siblings that make an object a titled document / record rather than a person ({ title, summary, content, display_name }). */
const DOC_SIBLINGS = new Set(['title', 'summary', 'abstract', 'excerpt', 'content', 'body', 'text', 'extracted_text', 'source_id', 'document_id',
  'file_id', 'file_path', 'storage_path', 'processing_status', 'source_type', 'page_count', 'word_count', 'chunk', 'chunks']);
/** Embedding / vector columns: a table that has one holds the text the vectors were computed from. */
const EMBEDDING_NAME = /^(embedding|embeddings|vector|vectors|text_embedding|content_embedding|chunk_embedding|[a-z0-9_]+_(embedding|vector))$/;
/** Text columns of a vector store (LangChain / LlamaIndex / pgvector conventions: content, page_content, chunk, text). */
const VECTOR_TEXT_COLUMN = new Set(['content', 'page_content', 'pagecontent', 'text', 'chunk', 'chunk_text', 'document', 'body', 'raw_text']);
const NUMERIC_SQL_TYPE = /^(int|integer|smallint|bigint|tinyint|mediumint|serial|bigserial|float|float4|float8|double|decimal|numeric|real|number|int2|int4|int8)$/i;
/** Sort / position columns: `order`, `sortOrder`, `position` as an integer is a display position, never a purchase order. */
const SEQUENCE_WORD = new Set(['display', 'sort', 'step', 'invocation', 'execution', 'run', 'call', 'question', 'section', 'slide', 'tab', 'menu', 'list',
  'view', 'render', 'priority', 'z', 'nav', 'chapter', 'lesson', 'page', 'column', 'row', 'position', 'sequence', 'load', 'loading', 'field', 'image',
  'photo', 'card', 'block', 'stage', 'fallback', 'model', 'provider', 'gosterim', 'sira', 'siralama']);
const COMMERCE_TOKEN = new Set(['order', 'purchase', 'cart', 'checkout', 'payment', 'invoice', 'shop', 'sale', 'sales', 'customer', 'booking', 'basket',
  'receipt', 'siparis', 'sepet', 'odeme', 'fatura', 'musteri']);
const isCommerceTable = (cx) => cx.tTokens.some((t) => COMMERCE_TOKEN.has(t));
const SORT_ORDER_NAME = new Set(['order', 'orders', 'sort', 'sort_order', 'order_index', 'order_idx', 'display_order', 'ordering', 'rank']);
/** `<x>_order` is a purchase order only after a commerce word or a word that counts orders (last_order, open_order). */
const ORDER_EVENT = new Set(['last', 'first', 'latest', 'recent', 'pending', 'open', 'current', 'next', 'previous', 'prev', 'total', 'active', 'placed', 'my', 'new']);
/** Hash-named heads: `<thing>_fingerprint`. */
const FINGERPRINT_HEAD = new Set(['fingerprint', 'fingerprints']);
const DEVICE_QUALIFIER = new Set(['device', 'browser', 'visitor', 'client', 'canvas', 'audio', 'webgl', 'tls', 'ja3', 'user', 'session', 'install', 'installation', 'hardware', 'machine', 'cihaz', 'tarayici']);
const BIOMETRIC_QUALIFIER = new Set(['finger', 'thumb', 'biometric', 'bio', 'palm', 'parmak', 'biyometrik']);
/** Context words of an error report: a bare `name` there is the error's class name. */
const ERROR_CONTEXT = new Set(['error', 'exception', 'crash', 'fault', 'stacktrace', 'hata']);

// ---------------------------------------------------------------------------
// Operator configuration tables (r8): model / provider / endpoint settings the operator maintains.

const CONFIG_META = new Set(['id', 'uuid', 'pk', 'created_at', 'updated_at', 'deleted_at', 'created', 'updated', 'modified_at', 'created_on', 'updated_on', 'inserted_at']);
/** Columns that only make sense for a configured external service / model. */
const CONFIG_STRONG = /^(?:api_(?:url|base|base_url|endpoint|host|version)|base_(?:url|uri)|endpoint(?:_url)?|server_url|host_url|model(?:_(?:name|id|key|slug|type|version|provider|config))?|provider(?:_(?:name|id|type|key))?|temperature|max_(?:output_)?tokens|max_retries|top_[pk]|context_(?:window|length|size)|(?:input|output|prompt|completion)_(?:price|cost)(?:_per_\w+)?|invocation_(?:order|count)|timeout_(?:ms|seconds)|rate_limit(?:_\w+)?)$/;
const CONFIG_WEAK = /^(?:api_key|apikey|api_secret|secret|secret_key|access_key|auth_token|access_token|api_token|token|enabled|is_enabled|active|is_active|is_default|default|priority|weight|(?:\w+_)?order|sort|sort_order|position|rank|name|display_name|label|title|description|version|price|cost|currency|slug|key|value|type|kind|category|config|configuration|settings|options|params|parameters|headers|metadata|region|status|environment|env|url|path|method|timeout|retries|icon|logo|notes|tags|capabilities|supports_\w+|is_\w+|has_\w+|max_\w+|min_\w+|\w+_url)$/;
/** A column that ties the row to somebody: a data subject, the account / tenant it belongs to, or who made it. */
const SUBJECT_LINK = /^(?:\w+_)?(?:user|owner|account|member|customer|profile|person|patient|student|employee|author|creator|client|contact|subscriber|team|org|organization|organisation|workspace|tenant|company|lead|guest|session|uid|kullanici|musteri|uye)(?:_(?:id|uuid|ref|fk|email|name|uid))?$|^(?:userid|ownerid|accountid|uid|\w+_by)$/;
const SUBJECT_CONTENT = /(?:^|_)(?:email|e_mail|eposta|mail|phone|telefon|address|adres|avatar|first|last|surname|password|birth|dob|ip|message|chat|bio|gender)(?:_|$)/;
const CREDENTIAL_HEAD = new Set(['key', 'apikey', 'token', 'credential', 'session', 'secret', 'account', 'connection', 'integration']);

/**
 * Is this table OPERATOR CONFIGURATION: settings of the models, providers and endpoints the operator runs (model name,
 * api url, api key, temperature, price, order, enabled), with no column that ties a row to a data subject?
 * Such a table holds no personal data, whatever its columns are called. Pure predicate: classifyField applies it when a
 * caller passes {table, siblings}; a caller can also pass ctx.operatorConfig (true / false) to decide it, and schema
 * extractors may record the result as Store.operatorConfig.
 *   A user- or tenant-owned integration (user_id + api_key) and an issued-credential table (api_keys, sessions) are not.
 */
export function isOperatorConfigTable({ table, columns } = {}) {
  const toks = entityTokens(typeof table === 'string' ? table : '');
  const head = toks[toks.length - 1];
  if (!head || CREDENTIAL_HEAD.has(head) || toks.some((t) => PERSON_ENTITY.has(t))) return false;
  const names = [];
  for (const c of columns || []) if (typeof c === 'string') names.push(tokenize(c).join('_'));
  const cols = [...new Set(names)].filter((n) => n && !CONFIG_META.has(n));
  if (cols.length < 3) return false;
  if (cols.some((n) => SUBJECT_LINK.test(n) || SUBJECT_CONTENT.test(n))) return false;
  const strong = cols.filter((n) => CONFIG_STRONG.test(n)).length;
  if (!strong) return false;
  const weak = cols.filter((n) => !CONFIG_STRONG.test(n) && CONFIG_WEAK.test(n)).length;
  // A product catalogue has a `model` too: something must point at a called service (endpoint, key, sampling setting).
  const service = cols.some((n) => /^(?:api_|apikey|base_ur|endpoint|secret|access_key|temperature$|max_\w*tokens$|context_|invocation_|top_[pk]$)/.test(n));
  return service && (strong + weak) / cols.length >= 0.6;
}

// ---------------------------------------------------------------------------
// Health / neurodivergence vocabulary (r8, KVKK md.6 / GDPR Art.9), EN + TR. Read only where the row is about a person.

const HEALTH_STRONG = /(?:^|_)(?:adhd|dehb|autis(?:m|tic)[a-z]*|otiz[a-z]*|asperger[a-z]*|dyslex[a-z]*|disleks[a-z]*|dysprax[a-z]*|dispraks[a-z]*|dyscalcul[a-z]*|diskalkul[a-z]*|tourette[a-z]*|ocd|ptsd|bipolar|schizo[a-z]+|sizofren[a-z]*|neurodiver[a-z]*|neurotypes?|psikiyatr[a-z]*|psikolojik[a-z]*|anksiyete[a-z]*|depresyon[a-z]*|kaygi_(?:bozuklu[a-z]*|duzey[a-z]*|puan[a-z]*)|panik_atak|panic_attacks?|phq_?\d+|phq|gad_?\d+|gad_score|insomnia|uyku_bozuklu[a-z]*|sleep_disorders?|eating_disorders?|yeme_bozuklu[a-z]*|self_harm|suicid[a-z]*|intihar[a-z]*|emotional_regulation|duygu_duzenleme[a-z]*|ovulation|contracepti(?:on|ve)s?|miscarriages?|comorbid[a-z]*|hiv_status|hiv|hepatit[a-z]*|diabet[a-z]+|diyabet[a-z]*|epileps[a-z]+|asthma|astim|chronic_(?:condition|illness|pain|disease)s?|special_needs|ozel_gereksinim[a-z]*|wheelchair|hearing_(?:loss|impairment)|visual_impairment|sobriety|substance_(?:use|abuse)|addictions?|menstrual|adet_dongusu)(?:_|$)/;
/** Words that mean a health attribute only next to other health attributes. */
const HEALTH_AMBIGUOUS = /(?:^|_)(?:mood|stress|stres|energy|focus|attention|impulsiv[a-z]*|hyperactiv[a-z]*|emotional|emotions?|duygu|ruh_hali|wellbeing|well_being|burnout|tukenmislik|fatigue|yorgunluk|overwhelm|sensory|sleep_quality|uyku_kalitesi|cycle_(?:length|day)|executive_function|kaygi|anxiety|depression)(?:_|$)/;
const HEALTH_CONTEXT = new Set(['assessment', 'screening', 'symptom', 'wellbeing', 'wellness', 'mental', 'therapy', 'therapist', 'clinic', 'clinical',
  'patient', 'health', 'mood', 'psych', 'psychology', 'psychiatry', 'medical', 'saglik', 'tarama', 'terapi', 'hasta', 'ruh', 'klinik', 'adhd', 'autism']);
/** Contexts where the ambiguous words are game stats, UI state, themes or music. */
const HEALTH_VETO = new Set(['game', 'player', 'character', 'hero', 'enemy', 'theme', 'palette', 'color', 'colour', 'ui', 'layout', 'playlist', 'song',
  'track', 'music', 'genre', 'board', 'keyboard', 'pomodoro', 'contrast', 'motion', 'accessibility', 'test', 'benchmark', 'load', 'kpi', 'xp', 'mana', 'coin']);
const EXPERIMENT_TOKEN = new Set(['experiment', 'variant', 'variation', 'ab', 'abtest', 'split', 'rollout']);
/** Static content / catalogue tables: their health words are subjects of text, not attributes of a person. */
const ARTICLE_HEAD = new Set(['article', 'blog', 'faq', 'glossary', 'dictionary', 'page', 'translation', 'banner', 'makale', 'sayfa']);
const CONTENT_HEAD = new Set([...ARTICLE_HEAD, 'content', 'library', 'resource', 'research', 'paper', 'catalog', 'catalogue', 'topic', 'tag',
  'category', 'question', 'template', 'metadata', 'course', 'lesson', 'definition', 'lookup', 'reference', 'product', 'recipe', 'icerik', 'soru', 'kategori']);
const contentTable = (cx) => cx.tTokens.length > 0 && CONTENT_HEAD.has(cx.tTokens[cx.tTokens.length - 1]);
const isHealthName = (n) => {
  if (HEALTH_STRONG.test(n)) return true;
  const d = COMPILED.find((x) => x.e === 'health');
  const t = n.split('_');
  return d.mf.some((f) => f(t)) && !d.xf.some((f) => f(t));
};
/** Confidence of a special-category health reading, or 0. */
function healthReading(tokens, joined, cx, ctx, isBool) {
  const last = tokens[tokens.length - 1];
  if (tokens.length > 1 && (ID_SUFFIX.has(last) || FLAG_PREFIX.has(tokens[0]) || /^(at|url|path|template|icon|title|text|label|color|type)$/.test(last))) return 0;
  const strong = HEALTH_STRONG.test(joined);
  const ambiguous = !strong && HEALTH_AMBIGUOUS.test(joined);
  if (!strong && !ambiguous) return 0;
  if (cx.errorReceiver || cx.kind === 'thing' || contentTable(cx)) return 0;
  if (/(?:^|_)(?:stress_test|focus_(?:mode|ring|visible|trap|state|timer)|mood_?board|mental_model|energy_(?:drink|price|cost|bill))(?:_|$)/.test(joined)) return 0;
  const person = cx.kind === 'person' || cx.sib.personLink || cx.sib.strongPerson;
  const others = [...cx.sib.names].filter((n) => n !== joined);
  const strongSib = others.some(isHealthName);
  const ambSib = others.filter((n) => HEALTH_AMBIGUOUS.test(n)).length;
  const assess = [...cx.tTokens, ...(cx.hasTable ? [] : cx.ctxTokens)].some((t) => HEALTH_CONTEXT.has(t));
  if (strong) {
    if (cx.hasTable) return person ? (isBool ? 0.6 : 0.7) : 0;
    // Forms / schemas / object literals: the container must be about a person or about health.
    if (!cx.container) return 0;
    return person || assess || strongSib ? 0.6 : 0;
  }
  if (!cx.hasTable || !person || isBool) return 0;
  const veto = [...cx.tTokens, ...cx.sib.tokens].some((t) => HEALTH_VETO.has(t));
  if (veto && !(assess && strongSib)) return 0;
  if (!assess && !strongSib && ambSib < 2) return 0;
  return (assess || strongSib) && (strongSib || ambSib >= 1) ? 0.65 : 0.5;
}

// ---------------------------------------------------------------------------
// Personal links and authored text (r8)

const WEBSITE_NAME = /^(?:(?:personal_|own_|my_)?(?:website|web_site|homepage|home_page|portfolio|personal_site|personal_url|web_sitesi|kisisel_site)(?:_(?:url|link))?|personal_(?:url|link|page)|blog_url)$/;
const SOCIAL_LINK_NAME = /^(?:social_(?:links?|media|accounts?|profiles?)|github|github_(?:url|link|handle|profile)|gitlab(?:_url)?|facebook|facebook_(?:url|link)|youtube_(?:url|channel)|dribbble|behance|sosyal_medya\w*)$/;
/** Entities that have a website as an organisation / listing, not as a person. */
const ORG_TOKEN = new Set(['agency', 'vendor', 'supplier', 'business', 'publisher', 'sponsor', 'partner', 'school', 'store', 'restaurant', 'place',
  'listing', 'tool', 'startup', 'employer', 'affiliate', 'organization', 'organisation', 'org', 'company', 'team', 'workspace', 'product', 'site',
  'club', 'hotel', 'clinic', 'hospital', 'merchant', 'brand', 'provider', 'isletme', 'sirket', 'firma', 'kurum', 'university', 'event', 'directory', 'lead']);
const PROFILE_SIBLING = new Set(['bio', 'about', 'about_me', 'username', 'avatar', 'avatar_url', 'first_name', 'last_name', 'full_name', 'display_name', 'nickname', 'job_title', 'headline', 'birth_date']);
function personalLink(joined, cx, isBool, ctx) {
  const kind = WEBSITE_NAME.test(joined) ? 'website' : SOCIAL_LINK_NAME.test(joined) ? 'social' : null;
  if (!kind || isBool || cx.valueKind === 'number' || cx.kind === 'thing' || cx.label) return null;
  if (ctx.sqlType && NUMERIC_SQL_TYPE.test(ctx.sqlType)) return null;
  if ([...cx.tTokens, ...(cx.container ? entityTokens(cx.container) : [])].some((t) => ORG_TOKEN.has(t))) return null;
  const profileSibs = [...cx.sib.names].filter((n) => PROFILE_SIBLING.has(n)).length;
  // A table: the person's own record, or a record linked to a person that also carries profile fields.
  if (cx.hasTable) return (cx.kind === 'person' && (profileSibs > 0 || cx.sib.strongPerson || cx.sib.personLink || cx.sib.personShape)) || (cx.sib.personLink && profileSibs > 0) || (cx.sib.strongPerson && profileSibs > 1) ? kind : null;
  // A form / schema: a profile form. A lone "website" next to name / email / message is a company site or a honeypot.
  return cx.container && profileSibs > 0 && (cx.kind === 'person' || profileSibs > 1) ? kind : null;
}

/** Author columns under a name PERSON_LINK_SIBLINGS does not list, and participant pairs. */
const AUTHOR_LINK = /^(?:submitted_by|posted_by|written_by|sent_by|sender_id|sender_uid|author_uid|poster_id|writer_id|from_user(?:_id)?|yazar_id|gonderen_id)$/;
const GENERIC_AUTHOR = /^(?:id_from|from_id|from_uid|sender|author)$/;
const RECIPIENT_LINK = /^(?:receiver|receiver_id|recipient_id|to_user(?:_id)?|to_uid|id_to|to_id|alici_id)$/;
const POST_HEAD = new Set(['story', 'post', 'submission', 'comment', 'reply', 'message', 'thread', 'topic', 'review', 'entry', 'bookmark', 'share', 'gonderi', 'yorum', 'mesaj']);
function authorLinked(cx) {
  let generic = false;
  let pair = false;
  for (const n of cx.sib.names) {
    if (AUTHOR_LINK.test(n)) return true;
    if (GENERIC_AUTHOR.test(n)) generic = true;
    if (RECIPIENT_LINK.test(n)) pair = true;
  }
  // from_id / sender / author alone can be a node or a string; with a recipient next to it the row is a message.
  return generic && (pair || (cx.sib.names.has('author') && POST_HEAD.has(cx.tTokens[cx.tTokens.length - 1])));
}
const AUTHORED_TEXT_COLUMN = new Set(['title', 'body', 'content', 'text', 'note', 'notes', 'subject', 'caption', 'reply']);
const AUTHORED_URL_COLUMN = new Set(['url', 'link']);

function build(d, confidence) {
  return {
    element: d.e,
    category: d.c,
    sensitivity: d.s,
    identifier: d.i,
    confidence,
    label: { tr: d.l[0], en: d.l[1] },
    categoryLabel: CATEGORIES[d.c],
  };
}
const BY_ELEMENT = new Map(D.map((d) => [d.e, d]));

/**
 * Synthetic elements that are not derived from a field name, e.g. a table that is personal only because it is keyed
 * to a data subject (`data:user_ref`) or holds an untyped json/blob of user data (`data:opaque_personal_blob`).
 */
/**
 * A person's own web page / profile link (profiles.website, users.homepage, members.portfolio_url). Not a dictionary entry:
 * `website` names a person only inside a person's record, so it is decided by context (personalLink below).
 */
const PERSONAL_WEBSITE = { e: 'website', c: 'identity', s: 'normal', i: 'indirect', k: 0.6, l: ['Kişisel web sitesi / profil bağlantısı', 'Personal website / profile link'] };

const SYNTHETIC = {
  user_ref: { e: 'user_ref', c: 'identity', s: 'normal', i: 'indirect', k: 0.7, l: ['Kullanıcıya bağlı kayıt', 'User-linked record'] },
  opaque_personal_blob: { e: 'opaque_personal_blob', c: 'user-content', s: 'normal', i: 'indirect', k: 0.6, l: ['Opak kişisel veri deposu (json/blob)', 'Opaque personal data store'] },
};
export const SYNTHETIC_ELEMENTS = Object.keys(SYNTHETIC);

/** syntheticElement('user_ref' | 'data:user_ref' | 'opaque_personal_blob') → classification object (same shape as classifyField). */
export function syntheticElement(kind) {
  const d = SYNTHETIC[String(kind || '').replace(/^data:/, '')];
  return d ? build(d, d.k) : null;
}

const cache = new Map();

/**
 * @param {string} name   field / column / variable name
 * @param {{sqlType?: string, table?: string, siblings?: Iterable<string>, valueKind?: 'enum'|'literal'|'boolean'|'number'|'text', container?: string, operatorConfig?: boolean}} [ctx]
 *   table: owning table / model; siblings: other columns or keys of the same table / object;
 *   valueKind: value type hint (z.enum → 'enum', input type=number → 'number'); container: schema / object name.
 * @returns {null | {element, category, sensitivity, identifier, confidence, label:{tr,en}, categoryLabel:{tr,en}}}
 */
export function classifyField(name, ctx = {}) {
  if (!name || typeof name !== 'string' || name.length > 80) return null;
  ctx = ctx || {};
  const cx = contextOf(ctx);
  const key = [name, ctx.sqlType || '', cx.table, cx.container, cx.valueKind, cx.sib.mediaDims ? 'D' : '', cx.sib.fileMeta ? 'F' : '',
    cx.sib.labelShape ? 'L' : '', cx.sib.personShape ? 'P' : '', cx.errorReceiver ? 'E' : '', cx.operatorConfig ? 'O' : '', typeof ctx.file === 'string' ? ctx.file : '',
    [...cx.sib.names].sort().join(',').slice(0, 400)].join('|');
  if (cache.has(key)) return cache.get(key);
  const tokens = tokenize(name);
  const joined = tokens.join('_');
  const last = tokens[tokens.length - 1];
  const isBool = /^(bool|boolean)$/i.test(ctx.sqlType || '') || cx.valueKind === 'boolean';
  let result = null;
  // Operator configuration (AI backends, provider settings …) holds no data subject's data: nothing in it is personal.
  if (cx.operatorConfig) {
    cache.set(key, null);
    return null;
  }
  if (tokens.length && !NOT_PERSONAL.has(joined)) {
    for (const d of COMPILED) {
      if (!d.mf.some((f) => f(tokens))) continue;
      if (d.xf.some((f) => f(tokens))) continue;
      // Booleans/timestamps about a thing are metadata, not the thing (email_verified, phone_confirmed_at).
      const activityTs = d.e === 'activity_timestamp';
      if (activityTs && (isBool || last === 'enabled' || last === 'visible' || last === 'type' || last === 'format')) continue;
      if (METADATA_SUFFIX.has(last) && tokens.length > 1 && !['password', 'auth_token', 'age_gate'].includes(d.e) && !(activityTs && last === 'at')) {
        if (d.e !== 'marketing_consent') continue;
      }
      // chat_id / comment_id / message_key reference a record; they are not its content.
      if (tokens.length > 1 && ID_SUFFIX.has(last) && d.i === 'none' && d.c !== 'identity' && d.c !== 'transaction-security') continue;
      if ((isBool || /^(timestamptz?|date)$/i.test(ctx.sqlType || '')) && !['birth_date', 'marketing_consent', 'activity_timestamp', 'age_gate'].includes(d.e) && d.c !== 'health') continue;
      if ((cx.valueKind === 'enum' || cx.valueKind === 'literal') && !ENUMERABLE.has(d.e)) continue;
      // A closed set of values (z.enum / choices / select) under a polysemous name (segment, region, position, location)
      // is a mode / option list, not a person's attribute, unless the record is a person's.
      if ((cx.valueKind === 'enum' || cx.valueKind === 'literal') && d.ambf.some((f) => f(tokens)) && cx.kind !== 'person' && !cx.sib.strongPerson) continue;
      // A reference to an organisation / school / employer record (school_id, company_id) is a foreign key, not employment data.
      if (d.e === 'employment' && tokens.length > 1 && ID_SUFFIX.has(last)) continue;
      // Last-seen / activity timestamps describe a person only on a person's record: on an aggregate table (insights,
      // referrers, pages, projects) with no person link they are when a thing was last observed.
      if (activityTs && cx.hasTable && cx.kind !== 'person' && !cx.sib.personLink && !cx.sib.strongPerson && !cx.sib.personShape) continue;
      // Step counts of a process (journey / funnel / wizard / onboarding / pipeline steps) are not physical activity.
      if (d.e === 'body_metrics' && tokens.some((t) => /^steps?$/.test(t)) && [...cx.ctxTokens, ...cx.sib.tokens].some((t) => PROCESS_TOKEN.has(t))) continue;
      // Health words in an article / catalogue table describe its content, not a person (faq.symptoms, articles.anxiety).
      if (d.c === 'health' && cx.hasTable && cx.kind !== 'person' && contentTable(cx) &&
        (ARTICLE_HEAD.has(cx.tTokens[cx.tTokens.length - 1]) || (cx.sib.names.size > 1 && !cx.sib.personLink && !cx.sib.strongPerson))) continue;
      // A theme / playlist / game has a mood or a stress level too (themes: mood, palette, color).
      if (d.e === 'body_metrics' && cx.hasTable && tokens.some((t) => /^(?:mood|stress|stres)$/.test(t)) &&
        [...cx.tTokens, ...cx.sib.tokens].some((t) => HEALTH_VETO.has(t)) && !cx.tTokens.some((t) => HEALTH_CONTEXT.has(t))) continue;
      // An A/B experiment has a treatment, not a patient.
      if (d.e === 'health' && tokens.includes('treatment') && [...cx.ctxTokens, ...cx.sib.tokens].some((t) => EXPERIMENT_TOKEN.has(t))) continue;
      if (cx.valueKind === 'number' && !NUMERIC.has(d.e)) continue;
      if (cx.valueKind === 'number' && d.e === 'address' && !tokens.some((t) => /^(zip|postal|postcode|posta)/.test(t))) continue;

      const bareName = d.e === 'full_name' && AMBIGUOUS_NAME.has(joined);
      // `<thing>_fingerprint` (prompt_fingerprint, content_fingerprint, key_fingerprint) is a hash of that thing: neither
      // a fingerprint scan nor a device fingerprint. A device / browser / visitor qualifier keeps the device reading,
      // a finger / biometric qualifier the biometric one.
      if ((d.e === 'biometric' || d.e === 'device_id') && tokens.length > 1 && FINGERPRINT_HEAD.has(last) &&
        !tokens.slice(0, -1).some((t) => DEVICE_QUALIFIER.has(singular(t)) || BIOMETRIC_QUALIFIER.has(singular(t)))) continue;
      // A polysemous word stored as a number (position smallint, region integer) is a rank, slot or code, not the
      // person attribute (job position, home region).
      if (ctx.sqlType && NUMERIC_SQL_TYPE.test(ctx.sqlType) && d.ambf.some((f) => f(tokens))) continue;
      // A bare `name` in an error / exception context (POST /api/client-error {boundary, route, name}, errorSchema) is
      // the error's class name.
      if (bareName && cx.kind !== 'person' && !cx.sib.personShape && !cx.sib.strongPerson && !cx.sib.personLink &&
        ([...cx.ctxTokens].some((t) => ERROR_CONTEXT.has(t)) || cx.sib.names.has('stack') || cx.sib.names.has('digest'))) continue;
      // Shape of the name itself: option flags (include_income_statement, show_email), technical heads (contract_address,
      // email_provider, location_header), subject qualifiers (product_description, player_photo, user_location).
      // A plural rest is a list of values (includeHandles, excludeEmails), not an on/off option.
      if (tokens.length > 1 && FLAG_PREFIX.has(tokens[0]) && singular(last) === last && d.e !== 'marketing_consent' && d.e !== 'age_gate') continue;
      if (tokens.length > 1 && !headAllowed(d.e, last)) continue;
      const qual = qualifierOf(d, tokens);
      // "<thing>_<attribute>" (product_description, event_location) describes the thing; containers that take things
      // (product_cart, item_orders) are still the person's transaction record.
      const kind = qual === 'thing' && cx.kind !== 'person' && THING_QUALIFIABLE.has(d.e) ? 'thing' : cx.kind;
      if (qual === 'public' && cx.kind !== 'person' && !cx.sib.personShape && !cx.sib.personLink) continue;
      // Polysemous readings (location, signature, contract, height, weight, steps, job …) need corroboration.
      if (polysemy(d, tokens, cx, qual) === 'drop') continue;
      // Non-person entities (products, pets, projects, videos …): drop person-only and special-category readings.
      if (kind === 'thing') {
        if (bareName || PERSON_ONLY_IN_THING.has(d.e)) continue;
        if (d.e === 'username' && !tokens.some((t) => t.startsWith('user') || t === 'kullanici')) continue;
        if (SPECIAL_CATEGORIES.has(d.c) && d.c !== 'biometric') continue;
        if (d.e === 'photo' && !tokens.some((t) => t === 'selfie' || t === 'profile')) continue;
      }
      // A bare `name` of a table that is neither a person nor a thing, whose known sibling columns hold nothing a person
      // writes or is reached by (SimpleModel(name), SomeData(name, counter)): a record label, not a person's name.
      if (bareName && cx.hasTable && cx.kind !== 'person' && cx.sib.names.size && !cx.sib.personShape && !cx.sib.personLink && !cx.sib.strongPerson &&
        ![...cx.sib.names].some((n) => n !== joined && (PERSONAL_CONTENT_SIBLINGS.has(n) || n.split('_').some((t) => PERSONAL_CONTENT_SIBLINGS.has(t) && t.length > 3)))) continue;
      // File / attachment shaped objects: {name, mediaType, url} is a file name.
      if (bareName && cx.kind !== 'person' && cx.sib.fileMeta && !cx.sib.strongPerson) continue;
      // Label-named objects (ApiKey.name, a dsync connection {name, tenant, product, webhook_url}): a label, not a person.
      if (bareName && cx.kind !== 'person' && (cx.label || (cx.sib.labelShape && !cx.sib.strongPerson))) continue;
      // A key/value pair ({name, value}: an env var, header, cookie, setting or form attribute; setEnv(name, value)).
      if (bareName && cx.kind !== 'person' && cx.sib.names.has('value') && !cx.sib.personShape && !cx.sib.personLink) continue;
      // Coordinates of a place (a POI, venue, attraction: {placeName, lat, lng}) locate the place, not a person. Only
      // without any person link (person table / qualifier, user_id / email siblings).
      if (d.e === 'precise_location' && cx.kind !== 'person' && qual !== 'person' && !cx.sib.personLink && !cx.sib.strongPerson && placeContext(cx, tokens)) continue;
      // `error.message`, `toast.description`: program text, not something a person wrote.
      if (d.e === 'free_text' && cx.errorReceiver) continue;
      // Media dimensions are not body metrics (videos.height next to width, height_px).
      if (d.e === 'body_metrics' && tokens.some((t) => /^(height|weight|boy|kilo)/.test(t)) && (cx.sib.mediaDims || UNIT_SUFFIX.has(last) || cx.media)) continue;
      // Order / interests readings need a person context: an integer `order` / `sortOrder` column is a display position,
      // and a bare `order` column of a table that is not keyed to a person is a sequence number, not a purchase.
      if (d.e === 'order_history' && cx.hasTable) {
        if (SORT_ORDER_NAME.has(joined) && ((ctx.sqlType && NUMERIC_SQL_TYPE.test(ctx.sqlType)) || cx.valueKind === 'number')) continue;
        // <x>_order as a number, or with a display / sequence word in front (invocation_order, step_order, menu_order), is a
        // sort key unless the table is about commerce.
        if (last === 'order' && tokens.length > 1 && !isCommerceTable(cx) &&
          (SEQUENCE_WORD.has(tokens[tokens.length - 2]) || (ctx.sqlType && NUMERIC_SQL_TYPE.test(ctx.sqlType)) || cx.valueKind === 'number')) continue;
        if ((joined === 'order' || joined === 'orders') && cx.kind !== 'person' && !cx.sib.personLink && !cx.sib.strongPerson) continue;
      }
      // `<x>_order` outside commerce (mode_order, word_order, play_order, batting_order) is an ordering, and so is
      // `ordering` / `reordering`.
      if (d.e === 'order_history') {
        const prev = tokens[tokens.length - 2];
        if (last === 'order' && tokens.length > 1 && !isCommerceTable(cx) && cx.kind !== 'person' && !COMMERCE_TOKEN.has(singular(prev)) && !ORDER_EVENT.has(prev)) continue;
        if (tokens.some((t) => /^(?:re)?ordering$|^ordinal$/.test(t))) continue;
      }
      // A bare name in an object shaped like a titled document ({ source_id, title, summary, content, display_name }) is
      // the document's name, unless another field identifies a person (email, user_id, avatar …).
      if (bareName && cx.kind !== 'person' && !cx.sib.personLink && !cx.sib.strongPerson && [...cx.sib.names].some((n) => DOC_SIBLINGS.has(n)) &&
        ![...cx.sib.names].some((n) => n !== joined && PERSON_SIBLINGS.has(n))) continue;

      const exact = d.m.some((p) => !p.includes('*') && p.replace(/!$/, '') === joined);
      let confidence = d.k ?? (exact ? 0.95 : tokens.length === 1 ? 0.85 : 0.75);
      // Without any table/person context a bare `name` is a weak signal (could be a file, product, tool …).
      if (bareName && !cx.hasTable && cx.kind !== 'person') confidence = Math.min(confidence, 0.5);
      result = build(d, confidence);
      break;
    }
    // Inverse rules: generic columns that are personal because of the table they live in.
    if (!result && cx.hasTable && cx.kind === 'person' && PERSON_IMAGE.has(joined) && cx.valueKind !== 'number') {
      result = build(BY_ELEMENT.get('photo'), 0.75);
    }
    // A person-prefixed image (userImage, authorPicture, memberImageUrl, creator_img) is that person's photo, in any
    // context except a numeric value.
    if (!result && tokens.length >= 2 && PERSON_PREFIX.has(singular(tokens[0])) && PERSON_PREFIX_IMAGE.has(tokens.slice(1).join('_')) &&
      cx.valueKind !== 'number' && !isBool && !(ctx.sqlType && NUMERIC_SQL_TYPE.test(ctx.sqlType))) {
      result = build(BY_ELEMENT.get('photo'), 0.8);
    }
    // A bare image next to a person id and a copy of that person's name ({ userId, userName, image }): a denormalised
    // author snapshot, so the image is the person's photo (not a post / product image, which has no name copy).
    if (!result && cx.hasTable && PERSON_IMAGE.has(joined) && cx.sib.personLink && cx.kind !== 'thing' && !cx.media && cx.valueKind !== 'number' &&
      [...cx.sib.names].some((n) => PERSON_NAME_COPY.test(n))) {
      result = build(BY_ELEMENT.get('photo'), 0.7);
    }
    // Vector store rows (pgvector / LangChain `documents`: content + metadata + embedding): the text the embeddings were
    // computed from is whatever users put into the knowledge base, so it is user content even in a "documents" table.
    if (!result && cx.hasTable && VECTOR_TEXT_COLUMN.has(joined) && [...cx.sib.names].some((n) => EMBEDDING_NAME.test(n)) &&
      !isBool && cx.valueKind !== 'number' && (!ctx.sqlType || TEXT_SQL_TYPE.test(ctx.sqlType))) {
      result = build(BY_ELEMENT.get('free_text'), 0.7);
    }
    // Outbox / mail-log tables (Email(to, subject, html, plain_text, status)): the recipient column is the addressee's
    // e-mail (or phone for SMS), and the body columns of a table that also has a recipient are the message sent to them.
    if (!result && cx.hasTable && !isBool && cx.valueKind !== 'number' && (OUTBOX_RECIPIENT.has(joined) || OUTBOX_BODY.has(joined))) {
      const outbox = cx.tTokens.some((t) => OUTBOX_TABLE.has(t)) || OUTBOX_TABLE.has(cx.tTokens.join('_'));
      const sms = cx.tTokens.includes('sms');
      if (outbox && OUTBOX_RECIPIENT.has(joined)) result = build(BY_ELEMENT.get(sms ? 'phone' : 'email'), 0.75);
      else if (outbox && OUTBOX_BODY.has(joined) && [...cx.sib.names].some((n) => OUTBOX_RECIPIENT.has(n) || n === 'email' || n === 'phone') &&
        (!ctx.sqlType || TEXT_SQL_TYPE.test(ctx.sqlType))) result = build(BY_ELEMENT.get('free_text'), 0.65);
    }
    if (!result && cx.hasTable && joined === 'identifier' && (cx.tTokens.includes('verification') || (cx.tTokens.includes('magic') && cx.tTokens.includes('link')))) {
      result = build(BY_ELEMENT.get('email'), 0.7);
    }
  }
  // Health / neurodivergence vocabulary that needs a person link and corroboration (adhd, phq9_score, emotional_regulation,
  // stress_level next to other screening scores …). A name-only body_metrics reading gives way to the corroborated one.
  if (tokens.length && (!result || result.element === 'body_metrics')) {
    const h = healthReading(tokens, joined, cx, ctx, isBool);
    if (h) result = build(BY_ELEMENT.get('health'), h);
  }
  // A person's own website / homepage / portfolio / social links, in that person's record only.
  if (!result && tokens.length) {
    const w = personalLink(joined, cx, isBool, ctx);
    if (w === 'website') result = build(PERSONAL_WEBSITE, PERSONAL_WEBSITE.k);
    else if (w === 'social') result = build(BY_ELEMENT.get('social_profile'), 0.65);
  }
  // Text of a post / message in a table whose author or participants are linked under another name (submitted_by,
  // sender_id + receiver_id, idFrom + idTo).
  if (!result && tokens.length && cx.hasTable && cx.kind !== 'thing' && !cx.media && !cx.label && !isBool && cx.valueKind !== 'number' && cx.valueKind !== 'enum' &&
    cx.valueKind !== 'literal' && (!ctx.sqlType || TEXT_SQL_TYPE.test(ctx.sqlType)) && authorLinked(cx) &&
    (AUTHORED_TEXT_COLUMN.has(joined) || (AUTHORED_URL_COLUMN.has(joined) && POST_HEAD.has(cx.tTokens[cx.tTokens.length - 1]) && cx.sib.names.has('title')))) {
    result = build(BY_ELEMENT.get('free_text'), 0.65);
  }
  // Generic text columns (title / body / content / note / text) of a record keyed to a person (user_id, author_id …)
  // are what that person wrote: Note.body, Post.title. Only with a real table + person-FK sibling, never a bare `title`.
  if (!result && tokens.length && cx.hasTable && cx.sib.personLink && USER_TEXT_COLUMN.has(joined) && cx.kind !== 'thing' && !cx.media &&
    !isBool && cx.valueKind !== 'number' && cx.valueKind !== 'enum' && cx.valueKind !== 'literal' &&
    (!ctx.sqlType || TEXT_SQL_TYPE.test(ctx.sqlType))) {
    result = build(BY_ELEMENT.get('free_text'), 0.7);
  }
  cache.set(key, result);
  return result;
}

export function isSpecial(category) {
  return SPECIAL_CATEGORIES.has(category);
}

// ---------------------------------------------------------------------------
// Helpers for extractors / legal reasoning (contracts; all pure, defensive on input).

/**
 * Is this route a liveness / readiness / status probe (`/health`, `/api/healthz`, `/status`, `/ping`)?
 * Such routes never imply processing of health data (KVKK md.6 / GDPR Art.9). `/api/health/records`,
 * `/health-log` or a body-carrying POST to `/health` are not probes. method optional.
 */
const PROBE_SEG = new Set(['health', 'healthz', 'healthcheck', 'health-check', 'health_check', '_health', '__health', 'livez',
  'readyz', 'startupz', 'liveness', 'readiness', 'ping', 'status', 'heartbeat', 'alive', 'ready', 'up', 'version', 'statusz']);
const PROBE_SUFFIX = new Set(['check', 'live', 'ready', 'liveness', 'readiness', 'status', 'db', 'deep', 'ping', 'detail', 'details', 'startup']);
const PREFIX_SEG = /^(api|v\d+|internal|_|-|system|sys|monitoring|ops|admin|public|private|rest|svc|service)$/i;
export function isHealthcheckPath(path, method) {
  if (typeof path !== 'string' || !path) return false;
  if (method && /^(POST|PUT|PATCH|DELETE)$/i.test(String(method))) return false;
  const segs = path.split('?')[0].split('/').map((s) => s.trim().toLowerCase()).filter((s) => s && !PREFIX_SEG.test(s));
  if (!segs.length) return false;
  const i = segs.findIndex((s) => PROBE_SEG.has(s.replace(/\.(json|txt)$/, '')));
  // The probe is the route itself (/api/health), not a status sub-resource of a record (/api/patients/:id/status).
  if (i !== 0) return false;
  return segs.slice(i + 1).every((s) => PROBE_SUFFIX.has(s));
}

/** Is this field an age-gate answer ("I am over 18", ageVerified) rather than the age / birth date itself? */
export function isAgeGateField(name) {
  return classifyField(name, { valueKind: 'boolean' })?.element === 'age_gate';
}

/** `error.message` / `toast.description`: a receiver whose text properties are program text, not user content. */
export function isNonContentReceiver(receiver) {
  if (typeof receiver !== 'string' || !receiver) return false;
  return NON_CONTENT_RECEIVER.test(tokenize(receiver).join('_'));
}

/**
 * Who owns a bare `name` in this object / model / schema: 'person' | 'label' | 'thing' | null.
 * 'label' and 'thing' mean the name is not a person's name (ApiKey, dsync connection, webhook, team, product).
 */
export function nameOwnerKind(owner, siblings) {
  if (!owner && !siblings) return null;
  const cx = contextOf({ table: typeof owner === 'string' ? owner : '', siblings });
  if (cx.kind === 'person' || cx.sib.personShape) return 'person';
  if (cx.kind === 'thing') return 'thing';
  if (cx.label || (cx.sib.labelShape && !cx.sib.personShape)) return 'label';
  return null;
}
