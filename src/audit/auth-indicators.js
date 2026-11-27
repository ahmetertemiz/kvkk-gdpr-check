// Signals that the app handles user accounts (shared by the coverage assessment and the erasure check).
// With no data elements found they make the coverage gap much more likely to be a parser miss than a privacy-free app;
// with no account table they say the accounts live at a provider (Clerk, Supabase Auth, Firebase Auth …).
export const AUTH_INDICATORS = [
  ['password_hash', /\b(?:generate_|check_)?password_hash\b/],
  ['flask_login', /\bflask[_-]login\b|\bUserMixin\b/i],
  ['django.contrib.auth', /\bdjango\.contrib\.auth\b/],
  ['bcrypt', /\bbcrypt/i],
  ['argon2', /\bargon2\b/i],
  ['passport', /\bpassport(?:-[\w-]+)?['"]|\bpassport\.(?:use|authenticate)\b/],
  ['next-auth', /['"](?:next-auth|@auth\/[\w-]+)['"]/],
  ['devise', /\bdevise\b/],
  ['lucia', /['"](?:lucia|lucia-auth|@lucia-auth\/[\w-]+)['"]/],
  ['firebase-auth', /['"]firebase\/auth['"]|@react-native-firebase\/auth|package:firebase_auth\/|\bFirebaseAuth\.(?:instance|getInstance)\b|^\s*firebase_auth\s*:/m],
  ['supabase-auth', /\bsupabase\.auth\.(?:signUp|signInWith\w+|signIn)\b|\bSupabase\.instance\.client\.auth\b|\b(?:useSupabaseUser|serverSupabaseUser|useSupabaseAuthClient)\s*\(/],
  ['clerk', /['"]@clerk\/[\w-]+['"]/],
  ['better-auth', /['"]better-auth(?:\/[\w-]+)?['"]/],
  ['laravel-auth', /\bAuth::(?:attempt|login|user)\b|\bHash::make\b/],
  ['simplejwt', /\brest_framework(?:_simplejwt|_jwt)\b/],
];

/** Labels of the account signals in these files (code and manifests). */
export function authIndicatorsIn(files = [], strip = (c) => c) {
  const text = (files || []).filter((f) => f && typeof f.content === 'string' && (f.kind === 'code' || f.kind === 'manifest')).map((f) => (f.kind === 'manifest' ? strip(f.content, f.rel) : f.content));
  return AUTH_INDICATORS.filter(([, re]) => text.some((c) => re.test(c))).map(([label]) => label);
}
