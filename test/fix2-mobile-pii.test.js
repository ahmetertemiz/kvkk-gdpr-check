// fix2 mobile-pii: declared permissions vs reached APIs, dead modules, voice streams to AI, pii.js entity/activity.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';
import { classifyField, entityKind } from '../src/audit/classify/pii.js';

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-fix2-mp-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return dir;
}
const el = (name, ctx) => classifyField(name, ctx)?.element ?? null;

// Enough relative imports for dead-module detection to engage.
const SCREENS = {
  'app/_layout.tsx': `import { A } from '../components/A';\nimport { B } from '../components/B';\nimport { C } from '../lib/c';\nimport { D } from '../lib/d';\nimport { E } from '../lib/e';\nexport default function L() { return null; }`,
  'components/A.tsx': `export const A = 1;`,
  'components/B.tsx': `export const B = 1;`,
  'lib/c.ts': `export const C = 1;`,
  'lib/d.ts': `export const D = 1;`,
  'lib/e.ts': `export const E = 1;`,
};
const APP_JSON = JSON.stringify({ expo: { name: 'x', ios: { infoPlist: { NSCameraUsageDescription: 'c', NSLocationWhenInUseUsageDescription: 'l', NSPhotoLibraryUsageDescription: 'p' } }, android: { permissions: ['CAMERA', 'ACCESS_FINE_LOCATION', 'RECORD_AUDIO'] } } }, null, 2);

test('declared permissions without reached API are unused; reached ones carry evidence', async () => {
  const dir = tmpProject({
    ...SCREENS,
    'app.json': APP_JSON,
    'package.json': JSON.stringify({ dependencies: { expo: '52', 'expo-image-picker': '1', 'expo-location': '1', 'expo-av': '1' } }),
    'app/upload.tsx': `import * as ImagePicker from 'expo-image-picker';\nimport { Video } from 'expo-av';\nexport async function pick() { return ImagePicker.launchImageLibraryAsync({}); }`,
    // never imported by anyone → dead; its location call does not count
    'hooks/useLocation.ts': `import * as Location from 'expo-location';\nexport function useLocation() { return Location.getCurrentPositionAsync({}); }`,
  });
  const { graph, ctx } = await buildGraph(dir);
  assert.ok(ctx.shared.deadModules.has('hooks/useLocation.ts'));
  assert.ok(!ctx.shared.deadModules.has('components/A.tsx'));
  const cam = graph.node('source:device:camera');
  assert.equal(cam.unused, true);
  assert.equal(cam.declared, true);
  assert.ok(cam.unusedReason?.en);
  assert.equal(graph.node('source:device:location').unused, true);
  assert.equal(graph.node('source:device:microphone').unused, true, 'expo-av playback is not recording');
  const photos = graph.node('source:device:photos');
  assert.equal(photos.unused, false);
  assert.ok(photos.reached.some((e) => e.file === 'app/upload.tsx'));
  // declared-but-unused still collects (minimisation checks rely on it)
  assert.deepEqual(graph.out('source:device:location', 'collects').map((n) => n.id), ['data:precise_location']);
});

test('live usage keeps a permission used; config files and config plugins do not count', async () => {
  const dir = tmpProject({
    ...SCREENS,
    'app.json': APP_JSON,
    'package.json': JSON.stringify({ dependencies: { expo: '52' } }),
    'app.config.ts': `export default { android: { permissions: ['ACCESS_FINE_LOCATION', 'RECORD_AUDIO'] } };`,
    'plugins/withPerms.js': `const { withAndroidManifest } = require('@expo/config-plugins');\nmodule.exports = (c) => withAndroidManifest(c, (m) => { m.perm = 'CAMERA'; return m; });`,
    'app/map.tsx': `import * as Location from 'expo-location';\nexport async function where() { const { status } = await Location.requestForegroundPermissionsAsync(); return Location.getCurrentPositionAsync({}); }`,
  });
  const { graph } = await buildGraph(dir);
  assert.equal(graph.node('source:device:location').unused, false);
  assert.equal(graph.node('source:device:camera').unused, true);
  assert.equal(graph.node('source:device:microphone').unused, true);
});

test('package-only hit with no reached API collects nothing; no client code → not evaluated', async () => {
  const dir = tmpProject({
    ...SCREENS,
    'package.json': JSON.stringify({ dependencies: { expo: '52', 'expo-av': '1' } }),
    'app/player.tsx': `import { Video } from 'expo-av';\nexport const P = () => null;`,
  });
  const { graph } = await buildGraph(dir);
  const mic = graph.node('source:device:microphone');
  assert.equal(mic.unused, true);
  assert.equal(mic.declared, false);
  assert.deepEqual(graph.out(mic.id, 'collects'), []);

  const dir2 = tmpProject({ 'android/app/src/main/AndroidManifest.xml': `<manifest><uses-permission android:name="android.permission.CAMERA"/></manifest>` });
  const g2 = (await buildGraph(dir2)).graph;
  assert.equal(g2.node('source:device:camera').unused, undefined);
  assert.deepEqual(g2.out('source:device:camera', 'collects').map((n) => n.id), ['data:photo']);
});

test('video-call SDK import counts as camera + microphone use', async () => {
  const dir = tmpProject({
    ...SCREENS,
    'app.json': APP_JSON,
    'package.json': JSON.stringify({ dependencies: { 'react-native': '0.76' } }),
    'app/call.tsx': `import { Room } from 'livekit-client';\nexport const r = new Room();`,
  });
  const { graph } = await buildGraph(dir);
  assert.equal(graph.node('source:device:camera').unused, false);
  assert.equal(graph.node('source:device:microphone').unused, false);
});

test('hybrid plugins count; a manifest next to non-mobile code only is not evaluated', async () => {
  const dir = tmpProject({
    ...SCREENS,
    'android/app/src/main/AndroidManifest.xml': `<manifest><uses-permission android:name="android.permission.CAMERA"/><uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/></manifest>`,
    'package.json': JSON.stringify({ dependencies: { '@capacitor/core': '6', '@capacitor/camera': '6' } }),
    'app/photo.ts': `import { Camera } from '@capacitor/camera';
export const take = () => Camera.getPhoto({});`,
  });
  const { graph } = await buildGraph(dir);
  assert.equal(graph.node('source:device:camera').unused, false);
  assert.equal(graph.node('source:device:location').unused, true);

  const dir2 = tmpProject({
    ...SCREENS,
    'ios/App/Info.plist': `<plist><dict><key>NSLocationWhenInUseUsageDescription</key><string>x</string></dict></plist>`,
    'package.json': JSON.stringify({ dependencies: { express: '4' } }),
    'server/index.js': `const express = require('express');
express().listen(3000);`,
  });
  const g2 = (await buildGraph(dir2)).graph;
  assert.equal(g2.node('source:device:location').unused, undefined, 'native iOS code we cannot read');
});

test('web getUserMedia audio streamed to an AI realtime model → voice element flows to the AI sink', async () => {
  const dir = tmpProject({
    ...SCREENS,
    'package.json': JSON.stringify({ dependencies: { openai: '4.0.0' } }),
    'app/voice.tsx': `import { useVoice } from '../hooks/use-voice';\nexport default function V() { return useVoice(); }`,
    'hooks/use-voice.ts': `export function useVoice() {\n  return navigator.mediaDevices.getUserMedia({\n    audio: { echoCancellation: true },\n  }).then((s) => fetch('/api/realtime', { method: 'POST' }));\n}`,
    'server/realtime.ts': `import OpenAI from 'openai';\nconst openai = new OpenAI();\nexport async function session() {\n  return openai.beta.realtime.sessions.create({ model: 'gpt-4o-realtime-preview' });\n}`,
  });
  const { graph } = await buildGraph(dir);
  const mic = graph.node('source:device:microphone');
  assert.ok(mic, 'web microphone source');
  assert.equal(mic.unused, false);
  assert.ok(mic.platforms.includes('web'));
  const ai = graph.nodesOf('Sink', (n) => n.kind === 'vendor' && n.category === 'ai');
  assert.ok(ai.length, 'AI sink extracted');
  const flows = graph.edgesFrom('data:voice_video', 'flowsTo');
  assert.ok(flows.some((e) => ai.some((s) => s.id === e.to) && e.sourceId === mic.id));
  assert.deepEqual(graph.out(mic.id, 'collects').map((n) => n.id), ['data:voice_video']);
});

test('web getUserMedia without an audio-AI sink collects nothing (no unused-data noise for p2p calls)', async () => {
  const dir = tmpProject({
    ...SCREENS,
    'package.json': JSON.stringify({ dependencies: { openai: '4.0.0' } }),
    'app/call.tsx': `export async function call(pc) { const s = await navigator.mediaDevices.getUserMedia({ audio: true, video: true }); s.getTracks().forEach((t) => pc.addTrack(t, s)); }`,
    'server/chat.ts': `import OpenAI from 'openai';\nconst openai = new OpenAI();\nexport const ask = (q) => openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: q }] });`,
  });
  const { graph } = await buildGraph(dir);
  assert.ok(graph.node('source:device:microphone'));
  assert.ok(graph.node('source:device:camera'));
  assert.deepEqual(graph.out('source:device:microphone', 'collects'), []);
  assert.deepEqual(graph.edgesFrom('data:voice_video', 'flowsTo'), []);
});

test('pii: name on notification / event / job entities is not a person name', () => {
  for (const t of ['notification', 'notifications', 'Notification', 'NotificationType', 'event', 'jobs', 'tasks', 'workflow', 'campaigns']) {
    assert.equal(el('name', { table: t }), null, t);
  }
  assert.equal(entityKind('user_notifications'), 'thing');
  assert.equal(el('name', { table: 'users' }), 'full_name');
  assert.equal(el('first_name', { table: 'notifications' }), 'full_name');
  // health-app record tables keep their special-category readings
  assert.equal(el('heart_rate', { table: 'health_reports' }), 'health');
  assert.equal(el('steps', { table: 'daily_steps' }), 'body_metrics');
  // UI component containers are not things
  assert.equal(el('message', { container: 'SupportPage' }), 'free_text');
});

test('pii: last_seen / last_active / last_login / last_online are activity tracking data', () => {
  for (const n of ['last_seen', 'lastSeen', 'last_seen_at', 'last_active', 'lastActiveAt', 'last_activity', 'last_login', 'last_login_at', 'lastLoginAt', 'last_online', 'son_gorulme']) {
    assert.equal(el(n, { table: 'users' }), 'activity_timestamp', n);
  }
  const c = classifyField('last_seen', { table: 'user', sqlType: 'timestamptz' });
  assert.equal(c.element, 'activity_timestamp');
  assert.equal(c.category, 'transaction-security');
  assert.ok(c.label.tr && c.label.en);
  assert.equal(el('last_login_ip', { table: 'users' }), 'ip_address');
  assert.equal(el('last_seen_message_id'), null);
  assert.equal(el('last_seen', { table: 'devices' }), null, 'device heartbeat is not a person');
  assert.equal(el('last_seen_enabled', { sqlType: 'boolean' }), null);
  assert.equal(el('last_name'), 'full_name');
  assert.equal(el('last_updated'), null);
});
