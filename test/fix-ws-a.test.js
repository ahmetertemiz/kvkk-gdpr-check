// WS-A: context-aware PII classifier (PII-1 … PII-9).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyField, syntheticElement, entityKind, SYNTHETIC_ELEMENTS } from '../src/audit/classify/pii.js';

const el = (name, ctx) => classifyField(name, ctx)?.element ?? null;
const cols = (table, names) => names.map((n) => el(n, { table, siblings: names })).filter(Boolean);

test('PII-1: non-person tables do not yield person data', () => {
  assert.deepEqual(cols('products', ['name', 'description']), []);
  assert.deepEqual(cols('prices', ['description', 'currency']), []);
  assert.deepEqual(cols('pets', ['name', 'gender', 'is_vaccinated', 'birth_date', 'personality']), []);
  assert.equal(el('is_vaccinated', { table: 'pets', sqlType: 'boolean' }), null);
  assert.equal(el('name', { table: 'Project' }), null);
  assert.equal(el('content', { table: 'tasks' }), null);
});

test('PII-1: explicit person patterns survive in any table', () => {
  assert.equal(el('first_name', { table: 'pets' }), 'full_name');
  assert.equal(el('owner_phone', { table: 'pets' }), 'phone');
  assert.equal(el('customer_name', { table: 'orders_items' }), 'full_name');
});

test('PII-1: person tables and inverse rules', () => {
  assert.deepEqual(cols('users', ['name', 'image']), ['full_name', 'photo']);
  assert.equal(el('name', { table: 'profiles' }), 'full_name');
  assert.equal(classifyField('name', { table: 'profiles' }).confidence, 0.95);
  assert.equal(el('identifier', { table: 'verification_tokens' }), 'email');
  assert.equal(el('identifier', { table: 'VerificationToken' }), 'email');
  assert.equal(el('identifier', { table: 'sessions' }), null);
  assert.equal(el('image', { table: 'posts' }), null);
  assert.equal(el('image', {}), null);
});

test('PII-1: bare name outside table context is a weak signal; context goes into the cache key', () => {
  assert.equal(classifyField('name').confidence, 0.5);
  assert.equal(el('name', { table: 'products' }), null);
  assert.equal(el('name', { table: 'users' }), 'full_name');
  assert.equal(el('name'), 'full_name');
});

test('PII-2: identifier suffix is a reference, not content', () => {
  for (const n of ['chatId', 'chat_id', 'conversation_id', 'comment_id', 'review_id', 'message_id']) assert.equal(el(n), null, n);
  assert.equal(el('national_id'), 'national_id');
  assert.equal(el('device_id'), 'device_id');
  assert.equal(el('api_key'), 'auth_token');
  assert.equal(el('stripe_customer_id'), 'payment_info');
});

test('PII-3: crypto signatures are not legal records', () => {
  assert.equal(el('stripe-signature'), null);
  assert.equal(el('stripe_signature'), null);
  assert.equal(el('x_hub_signature'), null);
  assert.equal(el('webhookSignature'), null);
  assert.equal(el('user_signature'), 'legal_record');
});

test('PII-4: media dimensions are not body metrics', () => {
  assert.deepEqual(cols('videos', ['width', 'height', 'duration']), []);
  assert.equal(el('height', { table: 'clips', siblings: ['width', 'height'] }), null);
  assert.equal(el('height_px'), null);
  assert.equal(el('image_height'), null);
  assert.equal(el('height', { table: 'patients' }), 'body_metrics');
  assert.equal(el('weight', { table: 'measurements', siblings: ['weight', 'measured_at'] }), 'body_metrics');
});

test('PII-5: label-style message names', () => {
  assert.equal(el('printMessage'), null);
  assert.equal(el('toast_message'), null);
  assert.equal(el('message_template'), null);
  assert.equal(el('message'), 'free_text');
});

test('PII-6: value kind', () => {
  assert.equal(el('name', { valueKind: 'enum' }), null);
  assert.equal(el('email', { valueKind: 'literal' }), null);
  assert.equal(el('gender', { valueKind: 'enum' }), 'gender');
  assert.equal(el('name', { valueKind: 'number' }), null);
  assert.equal(el('phone', { valueKind: 'number' }), 'phone');
  // Round 3 made `age` its own element (an age is not a date of birth).
  assert.equal(el('age', { valueKind: 'number' }), 'age');
  assert.equal(el('zip', { valueKind: 'number' }), 'address');
  assert.equal(el('email_verified', { valueKind: 'boolean' }), null);
  assert.equal(el('name', { valueKind: 'text' }), 'full_name');
});

test('PII-7: persona is a whole-token match', () => {
  assert.equal(el('personality'), null);
  assert.equal(el('persona'), 'preferences_profile');
  assert.equal(el('user_personas'), 'preferences_profile');
});

test('PII-8: synthetic elements', () => {
  assert.deepEqual(SYNTHETIC_ELEMENTS.sort(), ['opaque_personal_blob', 'user_ref']);
  const u = syntheticElement('data:user_ref');
  assert.equal(u.element, 'user_ref');
  assert.equal(u.category, 'identity');
  assert.equal(u.identifier, 'indirect');
  assert.equal(u.sensitivity, 'normal');
  assert.equal(u.label.en, 'User-linked record');
  assert.ok(u.categoryLabel);
  const b = syntheticElement('opaque_personal_blob');
  assert.equal(b.element, 'opaque_personal_blob');
  assert.equal(b.label.en, 'Opaque personal data store');
  assert.equal(syntheticElement('nope'), null);
});

test('PII-9: container / sibling context for name', () => {
  assert.equal(el('name', { siblings: ['name', 'mediaType', 'url'] }), null);
  assert.equal(el('name', { container: 'filePartSchema' }), null);
  assert.equal(el('name', { container: 'attachments' }), null);
  assert.equal(el('name', { container: 'userSchema' }), 'full_name');
  assert.equal(el('name', { table: 'authors', siblings: ['name', 'url'] }), 'full_name');
});

test('entityKind helper', () => {
  assert.equal(entityKind('auth.users'), 'person');
  assert.equal(entityKind('pet_owners'), 'person');
  assert.equal(entityKind('user_files'), 'thing');
  assert.equal(entityKind('categories'), 'thing');
  assert.equal(entityKind('Message_v2'), null);
});
