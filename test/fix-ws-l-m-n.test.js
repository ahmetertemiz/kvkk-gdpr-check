// Field-validation fixes: forms (FRM-1…5), declarations (DCL-1, DCL-2), language-agnostic recipients (EXT-1).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';
import { isPlaceholderNotice, analysePolicyText } from '../src/audit/extract/declarations.js';
import { isSelfHostedHost } from '../src/audit/extract/endpoints-ext.js';

function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-wslmn-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return dir;
}

const collects = (g, id) => g.edgesFrom(id, 'collects').map((e) => e.to).sort();
const flowsInto = (g, sinkId) => [...new Set(g.edges.filter((e) => e.type === 'flowsTo' && e.to === sinkId).map((e) => e.from))].sort();

// ---------------------------------------------------------------------------
test('FRM-1: React Native screen without <form> becomes an implicit form', async () => {
  const dir = fixture({
    'app/register.tsx': `import { useState } from "react";
import { View, TextInput, TouchableOpacity, Text } from "react-native";
import { signUp } from "@/lib/api/auth";
export default function RegisterScreen() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const handleRegister = async () => { await signUp(email, password, username); };
  return (
    <View>
      <TextInput placeholder="Username" value={username} onChangeText={setUsername} />
      <TextInput value={email} onChangeText={setEmail} keyboardType="email-address" />
      <TextInput value={password} onChangeText={setPassword} secureTextEntry />
      <TouchableOpacity onPress={handleRegister}><Text>Sign up</Text></TouchableOpacity>
    </View>
  );
}`,
    'app/profile.tsx': `import { TextInput } from "react-native-paper";
import { useState } from "react";
export const Profile = () => {
  const [form, setForm] = useState({});
  return <>
    <TextInput value={form.text} onChangeText={(t) => setForm({ ...form, phone: t })} keyboardType="phone-pad" />
    <TextInput value={value} onChangeText={onChange} textContentType="emailAddress" />
  </>;
};`,
    'app/search.tsx': `import { TextInput } from "react-native";
export function Search() { return <TextInput value={query} onChangeText={setQuery} placeholder="Search" />; }`,
    'lib/api/auth.ts': 'export async function signUp(email, password, username) {}',
  });
  const { graph } = await buildGraph(dir);
  const src = graph.node('source:form:app/register.tsx#RegisterScreen');
  assert.ok(src, 'implicit form created');
  assert.equal(src.implicit, true);
  assert.equal(src.platform, 'react-native');
  assert.deepEqual(src.fields.map((f) => f.name), ['username', 'email', 'password']);
  assert.deepEqual(src.fields.map((f) => f.type), ['text', 'email', 'password']);
  assert.deepEqual(collects(graph, src.id), ['data:email', 'data:password', 'data:username']);
  assert.equal(src.action, 'signUp');
  assert.equal(src.actionFile, 'lib/api/auth.ts');

  const prof = graph.node('source:form:app/profile.tsx#Profile');
  assert.ok(prof, 'onChangeText object-spread setter and textContentType name the fields');
  assert.deepEqual(collects(graph, prof.id), ['data:email', 'data:phone']);

  assert.ok(!graph.node('source:form:app/search.tsx#Search'), 'a search box is not a collection point');
});

test('FRM-1: files with a <form> keep the classic path; no RN form without an RN import', async () => {
  const dir = fixture({
    'web/a.tsx': 'export function A(){ return <form><input name="email" /><Foo onChangeText={setPhone} /></form>; }',
    'web/b.tsx': 'export function B(){ return <MyInput value={email} onChangeText={setEmail} />; }',
  });
  const { graph } = await buildGraph(dir);
  assert.ok(graph.node('source:form:web/a.tsx#A'));
  assert.equal([...graph.nodes.values()].filter((n) => n.implicit).length, 0);
});

// ---------------------------------------------------------------------------
test('FRM-2: type-aware fields (skip non-data types, numeric id "name", label preferred over id)', async () => {
  const dir = fixture({
    'src/Modal.tsx': `export function M() {
  return <form id="column-width-modal">
    <TextField id="name" type="number" label="Width" />
    <input type="hidden" name="email" />
    <input type="submit" name="name" />
    <input type="color" name="favourite_colour" />
    <TextField id="nm" label="Full name" />
    <input id="email" />
    <input name="phone" type="tel" />
  </form>;
}`,
  });
  const { graph } = await buildGraph(dir);
  const src = graph.node('source:form:src/Modal.tsx#column-width-modal');
  assert.deepEqual(src.fields.map((f) => f.name), ['name', 'nm', 'email', 'phone']);
  const edges = graph.edgesFrom(src.id, 'collects');
  assert.deepEqual(edges.map((e) => e.to).sort(), ['data:email', 'data:full_name', 'data:phone']);
  assert.ok(!edges.some((e) => e.field === 'name'), 'type=number "name" (column width) is not a full name');
  const idOnly = edges.find((e) => e.field === 'email');
  assert.ok(idOnly.evidence[0].confidence <= 0.6, 'name taken only from id has lowered confidence');
});

// ---------------------------------------------------------------------------
test('FRM-3: WTForms and Django form classes; templated macro forms are skipped', async () => {
  const dir = fixture({
    'app/auth/forms.py': `from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, HiddenField, IntegerField
from flask_babel import lazy_gettext as _l

class RegistrationForm(FlaskForm):
    username = StringField(_l('Username'), validators=[DataRequired()])
    email = StringField(_l('Email'), validators=[DataRequired(), Email()])
    password = PasswordField(_l('Password'), validators=[DataRequired()])
    password2 = PasswordField(
        _l('Repeat Password'), validators=[DataRequired(),
                                           EqualTo('password')])
    newsletter = BooleanField('Newsletter', default=True)
    token = HiddenField()
    name = IntegerField('Quantity')
    submit = SubmitField(_l('Register'))

    def validate_username(self, username):
        user = None
`,
    'shop/forms.py': `from django import forms

class ContactForm(forms.Form):
    phone = forms.CharField(max_length=20)
    secret = forms.CharField(widget=forms.PasswordInput)

class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['email', 'birth_date']
`,
    'app/templates/bootstrap_wtf.html': `{% macro quick_form(form, id) %}<form id="{{ id }}" method="post">{{ form.hidden_tag() }}{% for f in form %}{{ f() }}{% endfor %}</form>{% endmacro %}`,
    'app/templates/base.html': '<form method="get" action="/search">{{ g.search_form.q(size=20) }}</form>',
  });
  const { graph } = await buildGraph(dir);
  const reg = graph.node('source:form:app/auth/forms.py#RegistrationForm');
  assert.ok(reg);
  assert.equal(reg.hasPrivacyLink, null, 'unknown for server-side form classes');
  assert.deepEqual(reg.fields.map((f) => f.name), ['username', 'email', 'password', 'password2', 'newsletter', 'name']);
  assert.deepEqual(reg.preChecked, ['newsletter']);
  const regData = collects(graph, reg.id);
  assert.ok(regData.includes('data:email') && regData.includes('data:username') && regData.includes('data:password'));
  assert.ok(!regData.includes('data:full_name'), 'IntegerField "name" is a number');
  const contact = graph.node('source:form:shop/forms.py#ContactForm');
  assert.deepEqual(contact.fields.map((f) => [f.name, f.type]), [['phone', 'text'], ['secret', 'password']]);
  assert.ok(collects(graph, 'source:form:shop/forms.py#ProfileForm').includes('data:email'));
  const htmlForms = [...graph.nodes.values()].filter((n) => n.type === 'Source' && /\.html#/.test(n.id));
  assert.deepEqual(htmlForms.map((n) => n.id), [], 'template-rendered forms without literal inputs are not Sources');
});

// ---------------------------------------------------------------------------
test('FRM-4/FRM-5: zod value kinds and AI tool input schemas', async () => {
  const dir = fixture({
    'src/fns.ts': `import { z } from "zod";
const NAMES = ["analyze-site", "score"] as const;
export const callFn = z.object({ name: z.enum(NAMES), email: z.string().email(), flag: z.boolean(), age: z.coerce.number() });
export const sender = z.object({ name: z.string(), role: z.literal("admin") });`,
    'lib/tools/weather.ts': `import { tool, generateObject } from "ai";
import { z } from "zod";
export const getWeather = tool({
  description: "weather",
  inputSchema: z.object({ city: z.string().optional(), latitude: z.number(), longitude: z.number() }),
  execute: async (input) => input,
});
const params = z.object({ email: z.string() });
export const notify = tool({ parameters: params, execute: async () => 1 });
export async function suggest() {
  return generateObject({ schema: z.object({ description: z.string(), name: z.string() }) });
}`,
  });
  const { graph } = await buildGraph(dir);
  const callFn = graph.node('source:schema:src/fns.ts#callFn');
  assert.deepEqual(callFn.fields.map((f) => [f.name, f.vtype]), [['name', 'enum'], ['email', 'text'], ['flag', 'boolean'], ['age', 'number']]);
  const callData = collects(graph, callFn.id);
  assert.ok(!callData.includes('data:full_name'), 'z.enum "name" (function ids) is not a person name');
  assert.ok(callData.includes('data:email'));
  assert.ok(collects(graph, 'source:schema:src/fns.ts#sender').includes('data:full_name'), 'z.string name is still a name');

  const weather = graph.node('source:schema:lib/tools/weather.ts#getWeather');
  assert.equal(weather.kind, 'ai-tool-input');
  assert.equal(graph.node('source:schema:lib/tools/weather.ts#params')?.kind, 'ai-tool-input', 'schema variable passed as parameters');
  assert.ok(![...graph.nodes.values()].some((n) => n.type === 'Source' && /suggest|schema@/.test(n.id)), 'LLM output schema is not a source');
});

// ---------------------------------------------------------------------------
test('DCL-1: lorem ipsum / content-free privacy pages are placeholders', async () => {
  const lorem = 'Privacy Consent Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Volutpat sed cras ornare arcu. Information we collect Amet justo donec enim diam. How we use your Information Ut sem nulla pharetra diam sit amet nisl suscipit adipiscing.';
  assert.equal(isPlaceholderNotice(lorem, analysePolicyText(lorem, [])), true);
  const empty = 'Privacy Policy. This page will describe how things work here. Last updated soon. Stay tuned for more details about this page and what it covers.';
  assert.equal(isPlaceholderNotice(empty, analysePolicyText(empty, [])), true);
  const real = 'We collect your email address and name in order to provide the service. You have the right to access and erase your data. Contact privacy@acme.com.';
  assert.equal(isPlaceholderNotice(real, analysePolicyText(real, [])), false);

  const dir = fixture({ 'content/pages/privacy.mdx': `---\ntitle: Privacy\n---\n\n${lorem}\n`, 'components/footer.tsx': 'export const F = () => <a href="https://acme.com/privacy">Privacy</a>;' });
  const { graph } = await buildGraph(dir);
  const d = graph.node('declaration:policy:content/pages/privacy.mdx');
  assert.equal(d.placeholder, true);
  assert.equal(graph.edgesTo ? graph.edgesTo(d.id, 'declaredIn').length : graph.edges.filter((e) => e.to === d.id).length, 0, 'filler declares nothing');
  assert.ok(!graph.node('declaration:policy:external'), 'a textual (even placeholder) notice exists: no external stand-in');
});

test('DCL-2: notice hosted outside the repo', async () => {
  const dir = fixture({
    'src/config/firebaseui.ts': 'export const ui = { tosUrl: EXTERNAL_LINKS.terms, privacyPolicyUrl: EXTERNAL_LINKS.privacy };',
    'src/layouts/AuthLayout.tsx': `export const L = () => <footer>
  <Link href={EXTERNAL_LINKS.privacy}>Privacy</Link>
  <a href="https://policies.google.com/privacy">Google Privacy Policy</a>
  <a href="/terms">Terms</a>
</footer>;`,
  });
  const { graph } = await buildGraph(dir);
  const d = graph.node('declaration:policy:external');
  assert.ok(d);
  assert.equal(d.external, true);
  assert.equal(d.placeholder, false);
  assert.equal(d.urlExpr, 'EXTERNAL_LINKS.privacy');
  assert.ok(d.refs.length >= 2);
  assert.ok(!d.refs.some((r) => /google/.test(r.url || '')), "Google's own policy is not the app's notice");

  const stub = fixture({ 'app/privacy/page.tsx': 'export default function P(){ redirect("https://acme.io/legal/privacy"); }' });
  const s = (await buildGraph(stub)).graph.node('declaration:policy:external');
  assert.equal(s?.url, 'https://acme.io/legal/privacy', 'short PATH_PRIVACY stub kept as external');

  const none = fixture({ 'src/a.tsx': 'export const A = () => <a href="/privacy">Privacy</a>;' });
  assert.ok(!(await buildGraph(none)).graph.node('declaration:policy:external'), 'a dead relative link is not a notice');
});

test('DCL: the audit-app privacy page stays a real (non-placeholder) notice', async () => {
  const { graph } = await buildGraph(path.resolve('examples/audit-app'));
  const d = graph.node('declaration:policy:src/app/privacy/page.tsx');
  assert.equal(d.placeholder, false);
  assert.ok(!graph.node('declaration:policy:external'));
});

// ---------------------------------------------------------------------------
test('EXT-1: Python and template recipients (microblog-like)', async () => {
  const dir = fixture({
    'app/translate.py': `import requests
from flask import current_app

def translate(text, source_language, dest_language):
    # see https://api.cognitive.microsofttranslator.com docs
    auth = {'Ocp-Apim-Subscription-Key': current_app.config['MS_TRANSLATOR_KEY']}
    r = requests.post(
        'https://api.cognitive.microsofttranslator.com'
        '/translate?api-version=3.0&from={}&to={}'.format(
            source_language, dest_language), headers=auth, json=[
                {'Text': text}])
    return r.json()
`,
    'app/models.py': `class User(db.Model):
    """Docs: https://api.openai.com is not called here."""
    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return f'https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}'

    def ping(self):
        msg = "Read more at https://stripe.com/docs"
        return requests.get('http://localhost:9200/health')
`,
    'app/templates/base.html': `<html><head>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="canonical" href="https://www.googletagmanager.com/x">
<!-- <script src="https://js.stripe.com/v3"></script> -->
</head><body>
<a href="https://www.youtube.com/channel/x">Our channel</a>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body></html>`,
    'requirements.txt': 'Flask==3.0.0\nstripe==7.0.0\nelasticsearch==8.11.0\n',
    'requirements-dev.txt': 'sentry-sdk==1.0\n',
    'Gemfile': "source 'https://rubygems.org'\ngem 'twilio-ruby'\ngroup :development, :test do\n  gem 'posthog-ruby'\nend\n",
  });
  const { graph } = await buildGraph(dir);
  const has = (id) => graph.has(`sink:vendor:${id}`);
  // Hosts the vendor DB knows (gravatar / ms-translator / jsdelivr are WS-K additions; assert only when present).
  const { vendorForUrl } = await import('../src/data/vendors.js');
  if (vendorForUrl('https://www.gravatar.com/avatar/x')) {
    assert.ok(has('gravatar'));
    assert.deepEqual(flowsInto(graph, 'sink:vendor:gravatar'), ['data:email'], 'email reaches Gravatar through the digest variable');
  }
  if (vendorForUrl('https://api.cognitive.microsofttranslator.com/t')) assert.ok(has('ms-translator'));
  if (vendorForUrl('https://cdn.jsdelivr.net/npm/x')) {
    const s = graph.node(`sink:vendor:${vendorForUrl('https://cdn.jsdelivr.net/npm/x').id}`);
    assert.equal(s.channel, 'browser');
  }
  assert.ok(!has('openai'), 'docstring URL ignored');
  assert.ok(!has('youtube'), 'a plain <a href> is a link, not a load');
  assert.ok(!has('google-analytics'), 'rel=canonical is not a load');
  const stripe = graph.node('sink:vendor:stripe');
  assert.ok(stripe, 'stripe from requirements.txt');
  assert.ok(stripe.evidence.every((e) => e.file === 'requirements.txt'), 'commented script and prose URL ignored');
  assert.ok(stripe.evidence[0].confidence <= 0.5, 'manifest sinks are low confidence');
  assert.equal(stripe.consentRequired, false);
  assert.ok(!has('elastic'), 'self-hostable client package is not a transfer');
  assert.ok(!has('sentry'), 'dev requirements ignored');
  assert.ok(has('twilio') && !has('posthog'), 'Gemfile dev/test group ignored');
});

test('EXT-1: TRF-01 fires for a Python app sending email to a US vendor', async () => {
  const { audit } = await import('../src/audit/index.js');
  const dir = fixture({
    'app/notify.py': `import requests

def send_welcome(user):
    requests.post('https://api.openai.com/v1/chat/completions', json={'messages': [{'content': user.email}]})
`,
  });
  const res = await audit(dir);
  const trf = res.findings.find((f) => (f.rule?.id || f.id) === 'AUD-TRF-01');
  assert.ok(trf, 'TRF-01 fires');
  assert.ok(JSON.stringify(trf).includes('OpenAI'));
});

test('EXT-1: self-hosted hosts are not transfers', () => {
  for (const h of ['localhost', '127.0.0.1', '10.0.0.4', '192.168.1.2', '172.20.0.1', 'es.internal', 'example.com', 'api.{{host}}']) assert.equal(isSelfHostedHost(h), true, h);
  for (const h of ['api.openai.com', 'www.gravatar.com', '172.32.0.1']) assert.equal(isSelfHostedHost(h), false, h);
});
