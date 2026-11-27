// 0.2.1: a miss whose table or recipient the inventory names counts as "only in the inventory" (bench gate and bench:real).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inInventory, missOrigin } from '../bench/lib.js';
import { scoreMisses } from '../bench/real.js';

const model = {
  noAutoCleanup: [{ store: 'tablo daily_game_submissions', elements: ['user_ref'], file: 'supabase/migrations/001.sql', line: 3 }],
  inventory: [{ name: 'email', stores: ['VerificationToken.identifier', 'users.email'] }],
  transfers: [{ vendor: 'Cloudflare Turnstile', vendorId: 'turnstile', evidence: [] }],
  namedVendors: [{ vendor: 'Google Login', evidence: [] }],
};
const miss = (expect) => ({ id: 'x#1', severity: 'medium', title: 't', expect });

test('a keyword that is the whole name of an inventory table or recipient', () => {
  assert.ok(inInventory(miss({ anyOf: [{ rules: ['AUD-RET-01'], keywords: ['daily_game_submissions|friend_league_members'] }] }), model));
  assert.ok(inInventory(miss({ keywords: ['dailyGameSubmission'] }), model), 'case, separators and plural do not matter');
  assert.ok(inInventory(miss({ keywords: ['Turnstile'] }), model), 'a distinctive word of a recipient name');
  assert.ok(inInventory(miss({ keywords: ['users'] }), model), 'a store of the data inventory');
});

test('a word inside a longer name, a generic service word or a data kind is not the name', () => {
  assert.ok(!inInventory(miss({ keywords: ['token'] }), model), 'token is inside VerificationToken');
  assert.ok(!inInventory(miss({ keywords: ['login'] }), model), 'login says what kind of service, not which one');
  assert.ok(!inInventory(miss({ keywords: ['email'] }), model), 'a data element is not a table');
  assert.ok(!inInventory(miss({ keywords: ['pro'] }), model), 'too short to be a name');
});

test('a leaf without keywords matches the tables its file declares', () => {
  assert.ok(inInventory(miss({ rules: ['AUD-RET-01'], file: 'supabase/migrations/001.sql' }), model));
  assert.ok(!inInventory(miss({ rules: ['AUD-RET-01'], file: 'src/other.ts' }), model));
});

test('missOrigin: finding first, then review, then inventory; bench:real counts the three columns', () => {
  const m = miss({ anyOf: [{ rules: ['AUD-RET-01'], keywords: ['daily_game_submissions'] }] });
  const loc = { ruleId: 'AUD-RET-01', file: 'a.sql', line: 1, label: 'tablo daily_game_submissions' };
  assert.equal(missOrigin(m, { locations: [loc], review: [], model }), 'scored');
  assert.equal(missOrigin(m, { locations: [], review: [loc], model }), 'review');
  assert.equal(missOrigin(m, { locations: [], review: [], model }), 'register');
  assert.equal(missOrigin(m, { locations: [], review: [], model: null }), null);
  const out = scoreMisses({ quick: { scored: [], review: [] }, audit: { scored: [], review: [] }, model }, [m, miss({ keywords: ['nothing_here'] })]);
  assert.deepEqual([out.finding.length, out.review.length, out.inventory.length, out.open.length], [0, 0, 1, 1]);
});
