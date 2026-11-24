/**
 * Forms extractor: JSX/TSX/HTML forms (react-hook-form, Formik, shadcn FormField, server actions),
 * zod/yup validation schemas, and cookie-consent UI components.
 *
 * Also: React Native screens without <form> (implicit form per component built from TextInput & co.),
 * and server-side Python form classes (WTForms / Flask-WTF, Django forms / ModelForm).
 *
 * Writes:
 *   Source  source:form:<file>#<name>    {kind:'form', file, line, action, actionFile, submitsTo, method, fields:[{name,type,line}], preChecked:[], hasPrivacyLink,
 *                                         implicit?: true, platform?: 'react-native'|'python', library?: 'wtforms'|'django'}
 *                                         hasPrivacyLink is null when it cannot be known (server-side form classes)
 *   Source  source:schema:<file>#<name>  {kind:'schema', library:'zod'|'yup', fields:[{name,line,vtype?}]}
 *   Source  source:schema:<file>#<name>  {kind:'ai-tool-input', ...}   schema passed as inputSchema/parameters to an AI SDK tool():
 *                                         arguments filled in by the LLM, not a user-facing collection point
 *   Control control:consent-ui:<file>    {kind:'consent-ui', hasAccept, hasReject, hasSettings, library, acceptText, rejectText, settingsText}
 *   edges   collects (Source → DataElement)
 * ctx.shared.forms   = [{sourceId, file, line, name, submitsTo, action, actionFile, method, fields:[{name,type,line}]}]
 * ctx.shared.schemas = [{sourceId, file, line, name, library, kind, fields:[{name,line,vtype?}]}]
 * ctx.shared.consentUi = [{controlId, file, line, hasAccept, hasReject, hasSettings, library}]
 *
 * Classification passes ctx.valueKind ('number'|'boolean'|'enum'|'literal'|'text'), ctx.container and ctx.siblings
 * to classifyField (contract §5.1) and also applies a local value-kind guard so a numeric/closed-set input is never
 * recorded as a free-text identity element.
 */
import path from 'node:path';
import { parseFile, walk, jsxName, attr, jsxText, strValue, line } from './_jsx.js';

export const name = 'forms';
export const order = 30;

const FIELD_ELEMENTS = new Set(['input', 'textarea', 'select', 'Input', 'Textarea', 'TextArea', 'Select', 'Checkbox', 'Switch', 'RadioGroup', 'Field', 'TextField', 'PhoneInput', 'DatePicker', 'FormField', 'Controller']);
// Input types that never carry typed personal data.
const SKIP_TYPES = new Set(['hidden', 'submit', 'button', 'reset', 'color', 'range', 'image']);
const TEMPLATED = /\{\{|\{%|<%|\$\{/;
// React Native input components by library: imported name → field element.
const RN_LIBS = {
  'react-native': ['TextInput'],
  'react-native-paper': ['TextInput'],
  'native-base': ['Input', 'TextArea'],
  '@rneui/themed': ['Input'],
  '@rneui/base': ['Input'],
  'react-native-elements': ['Input'],
  '@gluestack-ui/themed': ['InputField', 'TextareaInput'],
  tamagui: ['Input', 'TextArea'],
};
const RN_TEXT_CONTENT_TYPE = {
  emailAddress: 'email', username: 'username', password: 'password', newPassword: 'password', telephoneNumber: 'phone',
  name: 'full_name', givenName: 'first_name', familyName: 'last_name', middleName: 'middle_name', nickname: 'nickname',
  fullStreetAddress: 'address', streetAddressLine1: 'address', streetAddressLine2: 'address', addressCity: 'city',
  postalCode: 'postal_code', creditCardNumber: 'card_number', birthdate: 'birth_date', birthdateDay: 'birth_date', jobTitle: 'job_title',
};
const RN_AUTOCOMPLETE = {
  email: 'email', username: 'username', password: 'password', 'new-password': 'password', 'current-password': 'password', tel: 'phone',
  'tel-national': 'phone', 'tel-device': 'phone', name: 'full_name', 'name-given': 'first_name', 'given-name': 'first_name', 'name-family': 'last_name',
  'family-name': 'last_name', 'street-address': 'address', 'address-line1': 'address', 'postal-code': 'postal_code', 'cc-number': 'card_number',
  birthdate: 'birth_date', 'birthdate-full': 'birth_date', 'bday': 'birth_date', gender: 'gender', 'sms-otp': 'otp', 'one-time-code': 'otp',
};
// value={text} / value={value} say nothing about what the input holds.
const GENERIC_VALUE_NAMES = /^(value|val|text|input|inputValue|inputText|newValue|state|local|draft|current|data|field|v|t|s)$/;
// Python form field classes (WTForms + Django) → HTML-ish input type. null = not a data field.
const PY_FIELD_TYPES = {
  StringField: 'text', TextAreaField: 'textarea', PasswordField: 'password', EmailField: 'email', TelField: 'tel', URLField: 'url', SearchField: 'search',
  IntegerField: 'number', DecimalField: 'number', FloatField: 'number', IntegerRangeField: 'number', DecimalRangeField: 'number',
  BooleanField: 'checkbox', NullBooleanField: 'checkbox', DateField: 'date', DateTimeField: 'date', DateTimeLocalField: 'date', TimeField: 'time', MonthField: 'date',
  SelectField: 'select', SelectMultipleField: 'select', RadioField: 'radio', ChoiceField: 'select', MultipleChoiceField: 'select', TypedChoiceField: 'select',
  ModelChoiceField: 'select', ModelMultipleChoiceField: 'select', QuerySelectField: 'select',
  FileField: 'file', MultipleFileField: 'file', ImageField: 'file',
  CharField: 'text', SlugField: 'text', RegexField: 'text', UUIDField: 'text', GenericIPAddressField: 'text', JSONField: 'textarea',
  SubmitField: null, HiddenField: null, CSRFTokenField: null, FormField: null, FieldList: null,
};
// Local value-kind guard (backs up classify ctx.valueKind): elements a numeric / closed-set / boolean input cannot hold.
const FREE_TEXT_IDENTITY = new Set(['full_name', 'email', 'username', 'free_text', 'address', 'password', 'photo', 'voice_video', 'social_profile', 'user_agent', 'auth_token']);
const NOT_CLOSED_SET = new Set([...FREE_TEXT_IDENTITY, 'phone', 'national_id', 'card_number', 'iban', 'passport_number', 'ip_address', 'device_id', 'wallet_address', 'id_document']);

function compatibleWithValueKind(cls, valueKind) {
  if (!cls || !valueKind || valueKind === 'text') return !!cls;
  if (valueKind === 'number') return !FREE_TEXT_IDENTITY.has(cls.element);
  if (valueKind === 'enum' || valueKind === 'literal') return !NOT_CLOSED_SET.has(cls.element);
  if (valueKind === 'boolean') return cls.element === 'marketing_consent' || cls.sensitivity === 'special';
  return true;
}

function valueKindOfType(type) {
  if (type === 'number') return 'number';
  if (type === 'checkbox' || type === 'switch') return 'boolean';
  if (type === 'select' || type === 'radio') return 'enum';
  return undefined;
}
const PRIVACY_HREF = /(privacy|gizlilik|kvkk|aydinlatma|aydınlatma|cookie|cerez|çerez)/i;
const PRIVACY_TEXT = /(aydınlatma metni|aydinlatma metni|gizlilik politikas|privacy policy|privacy notice|kvkk)/i;
const ACCEPT = /\b(kabul|accept|allow|izin ver|tümünü kabul|tumunu kabul|agree|onayla|tamam|ok|got it|anladım)\b/i;
const REJECT = /\b(reddet|reject|decline|deny|refuse|tümünü reddet|sadece zorunlu|yalnızca zorunlu|only necessary|necessary only|essential only)\b/i;
const SETTINGS = /\b(ayarlar|tercih|settings|preferences|customi[sz]e|yönet|manage)\b/i;
const CONSENT_TEXT = /(çerez|cerez|cookie|consent|rıza|riza)/i;
const CONSENT_LIBS = { 'vanilla-cookieconsent': true, 'react-cookie-consent': null, klaro: true, 'klaro/dist/klaro-no-css': true, cookieconsent: true, '@cookiehub/react': true, 'react-cookie-banner': null, 'cookies-eu-banner': null };

function typeElement(field) {
  if (field.type === 'email') return 'email';
  if (field.type === 'tel') return 'phone';
  if (field.type === 'password') return 'password';
  return null;
}

/**
 * Classify a form/schema field using its name, input type, value kind and (for id-only names) its label.
 * f = {name, type?, vtype?, label?, fromId?, typeHint?}; extra = {container, siblings}.
 */
function classifyFieldWithType(ctx, f, extra = {}) {
  const valueKind = f.vtype || valueKindOfType(f.type);
  const opts = { ...extra, ...(valueKind ? { valueKind } : {}) };
  let cls = null;
  if (f.fromId && typeof f.label === 'string' && f.label.trim()) {
    // An id is a DOM handle, the label says what the input is: prefer the label when it is not personal.
    cls = ctx.classify(f.label.trim(), opts);
    if (!cls) return null;
  } else {
    cls = ctx.classify(f.name, opts);
    if (cls && f.fromId) cls = { ...cls, confidence: Math.min(cls.confidence, 0.6) };
  }
  const te = typeElement(f) || f.typeHint || null;
  if (!cls && te) cls = ctx.classify(te, opts);
  return compatibleWithValueKind(cls, valueKind) ? cls : null;
}

function resolveImport(ctx, fromFile, spec) {
  if (!spec) return null;
  let base;
  if (spec.startsWith('.')) base = path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), spec));
  else if (spec.startsWith('@/') || spec.startsWith('~/')) base = spec.slice(2);
  else return null;
  const candidates = [];
  for (const prefix of spec.startsWith('.') ? [''] : ['src/', 'app/', '']) {
    const b = prefix + base;
    candidates.push(b, ...['.ts', '.tsx', '.js', '.jsx', '.mjs'].map((e) => b + e), ...['/index.ts', '/index.tsx', '/index.js'].map((e) => b + e));
  }
  const rels = new Set(ctx.files.map((f) => f.rel));
  return candidates.find((c) => rels.has(c)) || null;
}

function urlOf(arg) {
  if (!arg) return null;
  const s = strValue(arg);
  if (s != null) return s;
  if (arg.type === 'TemplateLiteral') return arg.quasis.map((q) => q.value.cooked).join(':param');
  return null;
}

function findSubmitUrls(fnNode) {
  const urls = [];
  if (!fnNode) return urls;
  walk(fnNode, (n) => {
    if (n.type !== 'CallExpression') return;
    const c = n.callee;
    let isNet = false;
    let method = null;
    if (c.type === 'Identifier' && (c.name === 'fetch' || c.name === '$fetch' || c.name === 'ofetch')) isNet = true;
    if (c.type === 'MemberExpression' && ['axios', 'ky', 'api', 'http', 'client'].includes(c.object.name) && ['post', 'put', 'patch', 'get', 'delete', 'request'].includes(c.property.name)) {
      isNet = true;
      method = c.property.name.toUpperCase();
    }
    if (!isNet) return;
    const u = urlOf(n.arguments[0]);
    if (!u) return;
    if (!method) {
      const opts = n.arguments[1];
      const m = opts?.type === 'ObjectExpression' && opts.properties.find((p) => p.key?.name === 'method');
      method = (m && strValue(m.value)?.toUpperCase()) || 'GET';
    }
    urls.push({ url: u, method, line: line(n) });
  });
  return urls;
}

function fieldFromElement(el) {
  const tag = jsxName(el.openingElement.name);
  const base = tag.split('.').pop();
  if (!FIELD_ELEMENTS.has(base)) return null;
  let fname = null;
  for (const a of el.openingElement.attributes) {
    if (a.type === 'JSXSpreadAttribute' && a.argument.type === 'CallExpression') {
      const callee = a.argument.callee;
      const cname = callee.type === 'Identifier' ? callee.name : callee.property?.name;
      if (cname === 'register' || cname === 'getInputProps' || cname === 'getFieldProps') fname = strValue(a.argument.arguments[0]);
    }
  }
  const nameAttr = attr(el, 'name');
  if (!fname && typeof nameAttr.value === 'string') fname = nameAttr.value;
  let fromId = false;
  // Controlled wrapper inputs (<TextField label="Email" value={form.email} onChange={…}/>): the bound state names the field.
  if (!fname) {
    const v = attr(el, 'value');
    const bound = v.expr ? exprFieldName(v.expr) : null;
    if (bound && !GENERIC_VALUE_NAMES.test(bound)) fname = bound;
  }
  if (!fname) {
    const id = attr(el, 'id');
    if (typeof id.value === 'string' && !/\{\{|\$\{/.test(id.value)) {
      fname = id.value;
      fromId = true;
    }
  }
  let type = attr(el, 'type').value;
  if (typeof type !== 'string') type = base === 'textarea' || base === 'Textarea' || base === 'TextArea' ? 'textarea' : /select/i.test(base) ? 'select' : /radio/i.test(base) ? 'radio' : /checkbox|switch/i.test(base) ? 'checkbox' : base === 'PhoneInput' ? 'tel' : base === 'DatePicker' ? 'date' : 'text';
  type = type.toLowerCase();
  if (SKIP_TYPES.has(type)) return null;
  if (!fname && ['email', 'tel', 'password'].includes(type)) fname = type === 'tel' ? 'phone' : type;
  if (!fname) return null;
  const labelAttr = attr(el, 'label');
  const ariaLabel = attr(el, 'aria-label');
  const label = typeof labelAttr.value === 'string' ? labelAttr.value : typeof ariaLabel.value === 'string' ? ariaLabel.value : undefined;
  const dc = attr(el, 'defaultChecked');
  const ch = attr(el, 'checked');
  const preChecked = (dc.present && dc.value !== false) || ch.value === true;
  return { name: fname, type, line: line(el), preChecked, ...(fromId ? { fromId, label } : {}) };
}

// ---- React Native ----

function lcFirst(s) {
  return s ? s[0].toLowerCase() + s.slice(1) : s;
}

/** Name of the state a value expression reads: email, form.email, values['email'] → 'email'. */
function exprFieldName(e) {
  if (!e) return null;
  if (e.type === 'Identifier') return e.name;
  if ((e.type === 'MemberExpression' || e.type === 'OptionalMemberExpression') && !e.computed && e.property.type === 'Identifier') return e.property.name;
  if (e.type === 'MemberExpression' && e.computed) return strValue(e.property);
  if (e.type === 'TSNonNullExpression' || e.type === 'TSAsExpression') return exprFieldName(e.expression);
  if (e.type === 'LogicalExpression' || e.type === 'ConditionalExpression') return exprFieldName(e.left || e.consequent);
  if (e.type === 'CallExpression' && e.callee.type === 'Identifier' && e.callee.name === 'String') return exprFieldName(e.arguments[0]);
  return null;
}

/** onChangeText={setEmail} / {(t) => setEmail(t)} / {(t) => setForm({...form, email: t})} / {handleChange('email')} → 'email'. */
function changeHandlerName(e) {
  if (!e) return null;
  if (e.type === 'Identifier') return /^set([A-Z]\w*)$/.test(e.name) ? lcFirst(e.name.slice(3)) : null;
  if (e.type === 'CallExpression') {
    const s = strValue(e.arguments[0]);
    if (s) return s;
    return null;
  }
  if (e.type === 'ArrowFunctionExpression' || e.type === 'FunctionExpression') {
    const param = e.params[0]?.type === 'Identifier' ? e.params[0].name : null;
    let found = null;
    walk(e.body, (n) => {
      if (found) return false;
      if (param && n.type === 'ObjectProperty' && n.value?.type === 'Identifier' && n.value.name === param) {
        found = n.key.name || strValue(n.key);
        return false;
      }
      if (n.type === 'CallExpression') {
        const c = n.callee;
        if (c.type === 'Identifier' && /^set([A-Z]\w*)$/.test(c.name) && n.arguments[0]?.type !== 'ObjectExpression' && n.arguments[0]?.type !== 'ArrowFunctionExpression') {
          found = lcFirst(c.name.slice(3));
          return false;
        }
        const s = strValue(n.arguments[0]);
        if (s && param && n.arguments.some((a) => a.type === 'Identifier' && a.name === param) && /^[a-zA-Z_][\w.]*$/.test(s)) {
          found = s.split('.').pop();
          return false;
        }
      }
    });
    return found;
  }
  return null;
}

/** Field from a React Native text input (or any element taking onChangeText in an RN file). */
function rnFieldFromElement(el) {
  const strAttr = (n) => {
    const a = attr(el, n);
    return typeof a.value === 'string' ? a.value : null;
  };
  const value = attr(el, 'value');
  let onChange = attr(el, 'onChangeText');
  // Project wrapper components (FormField, Input, TextField …) forward the change callback under their own prop name.
  if (!onChange.present) {
    for (const a of el.openingElement?.attributes || []) {
      if (a.type === 'JSXAttribute' && WRAPPER_CHANGE_ATTR.test(jsxName(a.name)) && a.value?.expression) {
        onChange = { present: true, expr: a.value.expression };
        break;
      }
    }
  }
  const tct = strAttr('textContentType');
  const ac = strAttr('autoComplete') || strAttr('autoCompleteType');
  const kb = strAttr('keyboardType') || strAttr('inputMode');
  const secure = attr(el, 'secureTextEntry');
  const isSecure = secure.present && secure.value !== false;
  let type = isSecure ? 'password' : /email/.test(kb || '') ? 'email' : /phone|tel/.test(kb || '') ? 'tel' : /numeric|number|decimal/.test(kb || '') ? 'number' : attr(el, 'multiline').present ? 'textarea' : 'text';
  const fromValue = exprFieldName(value.expr);
  const candidates = [
    fromValue && !GENERIC_VALUE_NAMES.test(fromValue) ? fromValue : null,
    changeHandlerName(onChange.expr),
    tct && RN_TEXT_CONTENT_TYPE[tct],
    ac && RN_AUTOCOMPLETE[ac],
    type === 'email' ? 'email' : type === 'tel' ? 'phone' : null,
    isSecure ? 'password' : null,
  ];
  let fname = candidates.find((c) => c && !GENERIC_VALUE_NAMES.test(c)) || null;
  let fromPlaceholder = false;
  if (!fname) {
    const ph = strAttr('placeholder') || strAttr('label') || strAttr('accessibilityLabel') || strAttr('title');
    if (ph && ph.length <= 40) {
      fname = ph;
      fromPlaceholder = true;
    }
  }
  if (!fname) return null;
  if (type === 'text' && tct === 'password') type = 'password';
  return { name: fname, type, line: line(el), preChecked: false, ...(fromPlaceholder ? { fromPlaceholder } : {}) };
}

// Change-callback props of input wrapper components: onChangeText, handleChangeText, onValueChange, onChange, setValue …
const WRAPPER_CHANGE_ATTR = /^(on|handle)(Change|ChangeText|TextChange|ValueChange|Input)$|^onChange[A-Z]\w*$|^handle[A-Z]\w*Change\w*$/;

/**
 * A call site of a project input wrapper component (<FormField title="Email" value={form.email} handleChangeText={…}/>):
 * a capitalised element that is not from a third-party package, binds `value` to an expression and passes a change
 * callback. The wrapper's definition only sees generic props (value, placeholder), so the field is named here.
 */
function isWrapperInput(el, tag, imports) {
  if (!/^[A-Z]/.test(tag) || tag.includes('.')) return false;
  const src = imports.get(tag);
  if (src && !/^(\.|@\/|~\/)/.test(src)) return false;
  const value = attr(el, 'value');
  if (!value.present || !value.expr) return false;
  return (el.openingElement?.attributes || []).some((a) => a.type === 'JSXAttribute' && WRAPPER_CHANGE_ATTR.test(jsxName(a.name)) && a.value?.expression);
}

// ---- zod / yup value kind (FRM-4) and AI tool schemas (FRM-5) ----

/** Validator chain → {vtype, typeHint}: z.enum(...) → enum, z.coerce.number() → number, z.string().email() → text + email hint. */
function validatorKind(node) {
  const chain = [];
  let cur = node;
  let base = null;
  let baseArgs = [];
  for (let i = 0; cur && i < 30; i++) {
    if (cur.type === 'CallExpression') {
      const c = cur.callee;
      if (c.type === 'Identifier') {
        chain.push(c.name);
        base = c.name;
        baseArgs = cur.arguments;
        break;
      }
      if (c.type !== 'MemberExpression' || c.property.type !== 'Identifier') break;
      chain.push(c.property.name);
      base = c.property.name;
      baseArgs = cur.arguments;
      cur = c.object;
    } else if (cur.type === 'MemberExpression' && cur.property.type === 'Identifier') {
      cur = cur.object; // z.coerce.number()
    } else break;
  }
  if (!base) return {};
  const typeHint = chain.includes('email') ? 'email' : undefined;
  if (chain.includes('oneOf')) return { vtype: 'enum', typeHint };
  if (/^(enum|nativeEnum)$/.test(base)) return { vtype: 'enum', typeHint };
  if (base === 'literal') return { vtype: 'literal', typeHint };
  if (/^(boolean|bool)$/.test(base)) return { vtype: 'boolean', typeHint };
  if (/^(number|bigint|int)$/.test(base)) return { vtype: 'number', typeHint };
  if (base === 'union' && baseArgs[0]?.type === 'ArrayExpression' && baseArgs[0].elements.length && baseArgs[0].elements.every((e) => validatorKind(e).vtype === 'literal')) return { vtype: 'literal', typeHint };
  if (base === 'array' && baseArgs[0]) return validatorKind(baseArgs[0]);
  if (base === 'string') return { vtype: 'text', typeHint };
  return { typeHint };
}

const AI_TOOL_CALLEE = /^(tool|createTool|dynamicTool|defineTool)$/;

function calleeName(c) {
  if (!c) return null;
  if (c.type === 'Identifier') return c.name;
  if (c.type === 'MemberExpression' && c.property.type === 'Identifier') return c.property.name;
  return null;
}

/** Variables referenced as inputSchema/parameters of an AI SDK tool({...}) call in this file. */
function aiToolSchemaVars(ast) {
  const vars = new Set();
  walk(ast, (n) => {
    if (n.type !== 'CallExpression' || !AI_TOOL_CALLEE.test(calleeName(n.callee) || '')) return;
    for (const a of n.arguments) {
      if (a.type !== 'ObjectExpression') continue;
      for (const p of a.properties) {
        if (p.type === 'ObjectProperty' && /^(inputSchema|parameters)$/.test(p.key.name || strValue(p.key) || '') && p.value.type === 'Identifier') vars.add(p.value.name);
      }
    }
  });
  return vars;
}

function isAiToolSchema(n, parents, toolSchemaVars) {
  const decl = [...parents].reverse().find((p) => p.type === 'VariableDeclarator');
  if (decl?.id?.type === 'Identifier' && toolSchemaVars.has(decl.id.name)) return true;
  const prop = parents[parents.length - 1];
  if (prop?.type !== 'ObjectProperty' || prop.value !== n) return false;
  const key = prop.key.name || strValue(prop.key);
  if (key === 'inputSchema') return true; // AI SDK 5 / MCP tool definitions
  if (key !== 'parameters') return false;
  const call = parents[parents.length - 3];
  return call?.type === 'CallExpression' && AI_TOOL_CALLEE.test(calleeName(call.callee) || '');
}

/** Structured-output schema of an LLM call (generateObject({schema}), Output.object({schema})): what the model returns, not input. */
function isLlmOutputSchema(parents) {
  return parents.some((p) => p.type === 'CallExpression' && (
    /^(generateObject|streamObject)$/.test(calleeName(p.callee) || '')
    || (p.callee.type === 'MemberExpression' && p.callee.object.type === 'Identifier' && p.callee.object.name === 'Output')
  ));
}

function hasPrivacyLinkIn(node) {
  let found = false;
  walk(node, (c) => {
    if (found || c.type !== 'JSXElement') return;
    const t = jsxName(c.openingElement.name);
    if (/^(a|Link|NextLink|ExternalLink)$/.test(t)) {
      const href = attr(c, 'href').value;
      if ((typeof href === 'string' && PRIVACY_HREF.test(href)) || PRIVACY_TEXT.test(jsxText(c))) found = true;
    } else if (/^(Text|TouchableOpacity|Pressable)$/.test(t) && PRIVACY_TEXT.test(jsxText(c))) found = true;
  });
  return found;
}

const RN_SKIP_CALLEES = /^(use[A-Z]\w*|set[A-Z]\w*|router|navigation|Alert|console|toast|t|i18n|clsx|cn)$/;

/** Imported function a submit handler calls (signUp(email, password) from @/lib/api/auth) → {action, actionFile}. */
function rnSubmitAction(ctx, file, compNode, imports) {
  const handlerNames = new Set();
  const inline = [];
  walk(compNode, (c) => {
    if (c.type !== 'JSXAttribute' || !/^(onPress|onSubmit|onSubmitEditing|onClick)$/.test(jsxName(c.name))) return;
    const e = c.value?.expression;
    if (e?.type === 'Identifier') handlerNames.add(e.name);
    else if (e) inline.push(e);
  });
  const bodies = [...inline];
  walk(compNode, (c) => {
    if (c.type === 'VariableDeclarator' && c.id?.type === 'Identifier' && handlerNames.has(c.id.name) && c.init) bodies.push(c.init);
    if (c.type === 'FunctionDeclaration' && c.id && handlerNames.has(c.id.name)) bodies.push(c.body);
  });
  for (const b of bodies) {
    let hit = null;
    walk(b, (c) => {
      if (hit) return false;
      if (c.type !== 'CallExpression' || c.callee.type !== 'Identifier') return;
      const nm = c.callee.name;
      if (RN_SKIP_CALLEES.test(nm) || !imports.has(nm)) return;
      const actionFile = resolveImport(ctx, file.rel, imports.get(nm));
      if (actionFile) hit = { action: nm, actionFile };
    });
    if (hit) return hit;
  }
  return { action: null, actionFile: null };
}

function extractRnForms(ctx, file, ast, imports, snip) {
  const { graph, ev } = ctx;
  const rnInputs = new Set();
  let isRn = false;
  walk(ast, (n) => {
    if (n.type !== 'ImportDeclaration') return;
    const names = RN_LIBS[n.source.value];
    if (!names) return;
    isRn = true;
    for (const s of n.specifiers) if (s.type === 'ImportSpecifier' && names.includes(s.imported.name || s.imported.value)) rnInputs.add(s.local.name);
  });
  if (!isRn) return;
  const byComp = new Map();
  walk(ast, (n, parents) => {
    if (n.type !== 'JSXElement') return;
    const tag = jsxName(n.openingElement.name);
    const isInput = rnInputs.has(tag) || attr(n, 'onChangeText').present || isWrapperInput(n, tag, imports);
    if (!isInput) return;
    const f = rnFieldFromElement(n);
    if (!f) return;
    // Enclosing component = outermost function.
    const idx = parents.findIndex((p) => /^(FunctionDeclaration|FunctionExpression|ArrowFunctionExpression)$/.test(p.type));
    const comp = idx >= 0 ? parents[idx] : ast.program;
    if (!byComp.has(comp)) {
      const owner = idx > 0 ? parents[idx - 1] : null;
      const declarator = parents.slice(0, Math.max(idx, 0)).reverse().find((p) => p.type === 'VariableDeclarator' && p.id?.type === 'Identifier');
      const compName = (comp.type === 'FunctionDeclaration' && comp.id?.name) || declarator?.id.name || (owner?.type === 'ExportDefaultDeclaration' && 'default') || 'screen';
      byComp.set(comp, { compName, line: line(comp), fields: [] });
    }
    const entry = byComp.get(comp);
    if (!entry.fields.some((x) => x.name === f.name)) entry.fields.push(f);
  });
  for (const [comp, { compName, line: compLine, fields }] of byComp) {
    const siblings = fields.map((f) => f.name);
    const classified = fields.map((f) => ({ f, cls: classifyFieldWithType(ctx, f, { siblings }) })).filter((x) => x.cls);
    if (!classified.length) continue; // a search box or a chat composer without personal fields: not a collection point
    const sourceId = `source:form:${file.rel}#${compName}`;
    const urls = findSubmitUrls(comp);
    const post = urls.find((u) => u.method !== 'GET') || null;
    const { action, actionFile } = rnSubmitAction(ctx, file, comp, imports);
    const flds = fields.map(({ name: fn, type, line: l }) => ({ name: fn, type, line: l }));
    graph.addNode({
      id: sourceId, type: 'Source', kind: 'form', name: compName, file: file.rel, line: compLine, implicit: true, platform: 'react-native',
      action, actionFile, submitsTo: post?.url || null, method: post?.method || 'POST', fields: flds, preChecked: [], hasPrivacyLink: hasPrivacyLinkIn(comp),
      evidence: [ev(file.rel, fields[0].line, snip(fields[0].line), 'static', 0.85, 'React Native inputs (no <form> element)')],
    });
    for (const { f, cls } of classified) {
      const conf = f.fromPlaceholder ? Math.min(cls.confidence, 0.6) : cls.confidence;
      const e = ev(file.rel, f.line, snip(f.line), 'static', conf);
      graph.addEdge({ from: sourceId, to: graph.dataElement(cls, f.name, e), type: 'collects', field: f.name, evidence: [e] });
    }
    (ctx.shared.forms ||= []).push({ sourceId, file: file.rel, line: compLine, name: compName, submitsTo: post?.url || null, action, actionFile, method: post?.method || 'POST', fields: flds });
  }
}

function extractJsx(ctx, file) {
  const ast = parseFile(file);
  if (!ast) return;
  const { graph, ev } = ctx;
  const imports = new Map();
  walk(ast, (n) => {
    if (n.type === 'ImportDeclaration') for (const s of n.specifiers) imports.set(s.local.name, n.source.value);
  });
  const lines = file.content.split('\n');
  const snip = (l) => lines[l - 1]?.trim();

  // ---- forms ----
  let formIndex = 0;
  walk(ast, (n, parents) => {
    if (n.type !== 'JSXElement') return;
    const tag = jsxName(n.openingElement.name);
    const isForm = tag === 'form' || (tag === 'Form' && imports.get('Form') === 'formik');
    if (!isForm) return;
    formIndex++;
    const fnNode = [...parents].reverse().find((p) => /Function|ArrowFunction/.test(p.type));
    const compName = [...parents].reverse().map((p) => (p.type === 'FunctionDeclaration' ? p.id?.name : p.type === 'VariableDeclarator' ? p.id?.name : null)).find(Boolean);
    const fields = [];
    walk(n, (c) => {
      if (c.type !== 'JSXElement' || c === n) return;
      const f = fieldFromElement(c);
      if (f && !fields.some((x) => x.name === f.name)) fields.push(f);
    });
    let action = null;
    let submitsTo = null;
    let method = attr(n, 'method').value || null;
    const act = attr(n, 'action');
    if (typeof act.value === 'string') submitsTo = act.value;
    else if (act.expr?.type === 'Identifier') action = act.expr.name;
    const onSubmit = attr(n, 'onSubmit');
    let handlerName = null;
    if (onSubmit.expr?.type === 'CallExpression' && onSubmit.expr.arguments[0]?.type === 'Identifier') handlerName = onSubmit.expr.arguments[0].name;
    else if (onSubmit.expr?.type === 'Identifier') handlerName = onSubmit.expr.name;
    if (!action && handlerName && imports.has(handlerName)) action = handlerName;
    const urls = findSubmitUrls(fnNode || ast);
    const post = urls.find((u) => u.method !== 'GET') || urls[0];
    if (!submitsTo && post) {
      submitsTo = post.url;
      method = method || post.method;
    }
    const actionFile = action ? resolveImport(ctx, file.rel, imports.get(action)) : null;
    let hasPrivacyLink = false;
    walk(fnNode || ast, (c) => {
      if (c.type !== 'JSXElement') return;
      const t = jsxName(c.openingElement.name);
      if (/^(a|Link|NextLink)$/.test(t)) {
        const href = attr(c, 'href').value;
        if ((typeof href === 'string' && PRIVACY_HREF.test(href)) || PRIVACY_TEXT.test(jsxText(c))) hasPrivacyLink = true;
      }
    });
    if (!hasPrivacyLink && PRIVACY_TEXT.test(jsxText(n))) hasPrivacyLink = true;

    const fname = (typeof attr(n, 'name').value === 'string' && attr(n, 'name').value) || (typeof attr(n, 'id').value === 'string' && attr(n, 'id').value) || `${compName || 'form'}${formIndex > 1 ? '-' + formIndex : ''}`;
    const sourceId = `source:form:${file.rel}#${fname}`;
    const preChecked = fields.filter((f) => f.preChecked).map((f) => f.name);
    graph.addNode({
      id: sourceId, type: 'Source', kind: 'form', name: fname, file: file.rel, line: line(n), action, actionFile, submitsTo, method: method ? String(method).toUpperCase() : null,
      fields: fields.map(({ name: fn, type, line: l }) => ({ name: fn, type, line: l })), preChecked, hasPrivacyLink,
      evidence: [ev(file.rel, line(n), snip(line(n)), 'static', 0.95)],
    });
    const siblings = fields.map((f) => f.name);
    for (const f of fields) {
      const cls = classifyFieldWithType(ctx, f, { container: fname, siblings });
      if (!cls) continue;
      const e = ev(file.rel, f.line, snip(f.line), 'static', cls.confidence);
      const did = graph.dataElement(cls, f.name, e);
      graph.addEdge({ from: sourceId, to: did, type: 'collects', field: f.name, preChecked: f.preChecked || undefined, evidence: [e] });
    }
    (ctx.shared.forms ||= []).push({ sourceId, file: file.rel, line: line(n), name: fname, submitsTo, action, actionFile, method: method ? String(method).toUpperCase() : null, fields: fields.map(({ name: fn, type, line: l }) => ({ name: fn, type, line: l })) });
  });

  // ---- React Native: no <form>, so each component with text inputs is an implicit form ----
  if (!formIndex) extractRnForms(ctx, file, ast, imports, snip);

  // ---- zod / yup schemas ----
  const toolSchemaVars = aiToolSchemaVars(ast);
  walk(ast, (n, parents) => {
    if (n.type !== 'CallExpression') return;
    const c = n.callee;
    let library = null;
    if (c.type === 'MemberExpression' && c.property.name === 'object' && c.object.type === 'Identifier' && /^(z|zod)$/.test(c.object.name)) library = 'zod';
    else if (c.type === 'MemberExpression' && c.property.name === 'object' && c.object.type === 'Identifier' && /^(yup|Yup)$/.test(c.object.name)) library = 'yup';
    else if (c.type === 'MemberExpression' && c.property.name === 'shape' && c.object.type === 'CallExpression' && /^(yup\.)?object$/.test(c.object.callee.name || `${c.object.callee.object?.name}.${c.object.callee.property?.name}`)) library = 'yup';
    if (!library) return;
    const obj = n.arguments[0];
    if (obj?.type !== 'ObjectExpression') return;
    if (isLlmOutputSchema(parents)) return false;
    const props =obj.properties.filter((p) => p.type === 'ObjectProperty');
    const fields = props.map((p) => {
      const { vtype, typeHint } = validatorKind(p.value);
      return { name: p.key.name || strValue(p.key), line: line(p), ...(vtype ? { vtype } : {}), ...(typeHint ? { typeHint } : {}) };
    }).filter((f) => f.name);
    const decl = [...parents].reverse().find((p) => p.type === 'VariableDeclarator');
    const sname = decl?.id?.name || `schema@${line(n)}`;
    const siblings = fields.map((f) => f.name);
    const classified = fields.map((f) => ({ f, cls: classifyFieldWithType(ctx, f, { container: sname, siblings }) })).filter((x) => x.cls);
    if (!classified.length) return;
    const aiTool = isAiToolSchema(n, parents, toolSchemaVars);
    const kind = aiTool ? 'ai-tool-input' : 'schema';
    const sourceId = `source:schema:${file.rel}#${sname}`;
    const flds = fields.map(({ name: fn, line: l, vtype }) => ({ name: fn, line: l, ...(vtype ? { vtype } : {}) }));
    graph.addNode({
      id: sourceId, type: 'Source', kind, library, name: sname, file: file.rel, line: line(n), fields: flds,
      evidence: [ev(file.rel, line(n), snip(line(n)), 'static', 0.9, aiTool ? 'AI tool input schema: arguments come from the model, not a user form' : undefined)],
    });
    for (const { f, cls } of classified) {
      const e = ev(file.rel, f.line, snip(f.line), 'static', aiTool ? Math.min(cls.confidence, 0.6) : cls.confidence);
      graph.addEdge({ from: sourceId, to: graph.dataElement(cls, f.name, e), type: 'collects', field: f.name, evidence: [e] });
    }
    (ctx.shared.schemas ||= []).push({ sourceId, file: file.rel, line: line(n), name: sname, library, kind, fields: flds });
    return false;
  });

  // ---- consent UI ----
  const libImport = [...imports.values()].find((src) => src in CONSENT_LIBS);
  const buttons = [];
  walk(ast, (n) => {
    if (n.type !== 'JSXElement') return;
    const t = jsxName(n.openingElement.name);
    if (/^(button|Button)$/.test(t) || (/^(a|span|div)$/.test(t) && attr(n, 'onClick').present)) buttons.push({ text: jsxText(n), line: line(n) });
  });
  const allText = jsxText(ast.program);
  let ui = null;
  if (libImport) {
    const declineAttr = /enableDeclineButton|declineButtonText|acceptNecessary|showDenyAll|hideDeclineAll\s*=\s*\{?false/.test(file.content);
    ui = { library: libImport, hasAccept: true, hasReject: CONSENT_LIBS[libImport] === true || declineAttr, hasSettings: /preferences|settingsModal|showPreferences|customi[sz]e/i.test(file.content), line: 1 };
  } else if (CONSENT_TEXT.test(allText) && buttons.some((b) => ACCEPT.test(b.text) || REJECT.test(b.text))) {
    const a = buttons.find((b) => ACCEPT.test(b.text) && !REJECT.test(b.text));
    const r = buttons.find((b) => REJECT.test(b.text));
    const s = buttons.find((b) => SETTINGS.test(b.text));
    ui = { library: null, hasAccept: !!a, hasReject: !!r, hasSettings: !!s, acceptText: a?.text, rejectText: r?.text, settingsText: s?.text, line: (a || r || buttons[0]).line };
  }
  if (ui) {
    const controlId = `control:consent-ui:${file.rel}`;
    graph.addNode({ id: controlId, type: 'Control', kind: 'consent-ui', file: file.rel, ...ui, evidence: [ev(file.rel, ui.line, snip(ui.line), 'static', 0.85)] });
    (ctx.shared.consentUi ||= []).push({ controlId, file: file.rel, line: ui.line, hasAccept: ui.hasAccept, hasReject: ui.hasReject, hasSettings: ui.hasSettings, library: ui.library });
  }
}

// ---- Python form classes (WTForms / Flask-WTF, Django) ----

/** Text of a call starting at `start` (index of the opening paren) up to its balanced close; capped. */
function balancedCall(src, start) {
  let depth = 0;
  for (let i = start; i < src.length && i < start + 2000; i++) {
    const ch = src[i];
    if (ch === '(') depth++;
    else if (ch === ')' && --depth === 0) return src.slice(start + 1, i);
  }
  return src.slice(start + 1, start + 2000);
}

function pyLabel(args) {
  const m = args.match(/^\s*(?:_l?|gettext|gettext_lazy|lazy_gettext|_lazy)?\(?\s*(['"])(.*?)\1/) || args.match(/\blabel\s*=\s*(?:_l?|gettext_lazy|lazy_gettext)?\(?\s*(['"])(.*?)\1/);
  return m ? m[2] : undefined;
}

function extractPython(ctx, file) {
  const { graph, ev } = ctx;
  const src = file.content;
  const lines = src.split('\n');
  const library = /\b(wtforms|flask_wtf)\b/.test(src) ? 'wtforms' : 'django';
  const classRe = /^class\s+(\w+)\s*\(([^)]*)\)\s*:/gm;
  let m;
  while ((m = classRe.exec(src))) {
    const [, cls, bases] = m;
    if (!/(^|[\s,.])(\w*Form)\s*(,|$)/.test(bases.trim()) && !/\bForm\b/.test(bases)) continue;
    const startLine = src.slice(0, m.index).split('\n').length;
    // Class body: following lines that are blank or indented.
    let end = startLine;
    while (end < lines.length && (lines[end].trim() === '' || /^\s/.test(lines[end]))) end++;
    const bodyStart = m.index + m[0].length;
    const bodyEnd = lines.slice(0, end).join('\n').length;
    const body = src.slice(bodyStart, bodyEnd);
    const fields = [];
    const fieldRe = /^([ \t]+)(\w+)\s*=\s*(?:[\w.]+\.)?(\w+Field)\s*\(/gm;
    let f;
    let classIndent = null;
    while ((f = fieldRe.exec(body))) {
      const [, indent, fname, fieldClass] = f;
      classIndent ??= indent.length;
      if (indent.length !== classIndent) continue; // nested class (Meta) or method body
      if (!(fieldClass in PY_FIELD_TYPES) && !/Field$/.test(fieldClass)) continue;
      let type = fieldClass in PY_FIELD_TYPES ? PY_FIELD_TYPES[fieldClass] : 'text';
      if (type === null) continue; // Submit / Hidden / CSRF / nested forms
      const args = balancedCall(body, f.index + f[0].length - 1);
      if (/PasswordInput/.test(args)) type = 'password';
      else if (/HiddenInput/.test(args)) continue;
      else if (/EmailInput/.test(args)) type = 'email';
      const lineNo = src.slice(0, bodyStart + f.index + f[1].length).split('\n').length;
      const preChecked = type === 'checkbox' && /\bdefault\s*=\s*True\b|\binitial\s*=\s*True\b/.test(args);
      fields.push({ name: fname, type, label: pyLabel(args), line: lineNo, preChecked });
    }
    // Django ModelForm: class Meta: fields = ['email', 'phone']
    const meta = body.match(/class\s+Meta\s*:[\s\S]*?\bfields\s*=\s*[[(]([^\])]*)[\])]/);
    if (meta) {
      for (const q of meta[1].matchAll(/['"](\w+)['"]/g)) {
        if (!fields.some((x) => x.name === q[1])) fields.push({ name: q[1], type: 'text', line: src.slice(0, bodyStart + meta.index).split('\n').length, preChecked: false });
      }
    }
    if (!fields.length) continue;
    const sourceId = `source:form:${file.rel}#${cls}`;
    const flds = fields.map(({ name: n, type, line: l }) => ({ name: n, type, line: l }));
    graph.addNode({
      id: sourceId, type: 'Source', kind: 'form', name: cls, file: file.rel, line: startLine, platform: 'python', library,
      action: null, actionFile: null, submitsTo: null, method: 'POST', fields: flds, preChecked: fields.filter((x) => x.preChecked).map((x) => x.name),
      hasPrivacyLink: null, // rendered by a template we do not link to the class
      evidence: [ev(file.rel, startLine, lines[startLine - 1]?.trim(), 'static', 0.9)],
    });
    const siblings = fields.map((x) => x.name);
    for (const fl of fields) {
      const c = classifyFieldWithType(ctx, { name: fl.name, type: fl.type }, { container: cls, siblings });
      if (!c) continue;
      const e = ev(file.rel, fl.line, lines[fl.line - 1]?.trim(), 'static', c.confidence);
      graph.addEdge({ from: sourceId, to: graph.dataElement(c, fl.name, e), type: 'collects', field: fl.name, preChecked: fl.preChecked || undefined, evidence: [e] });
    }
    (ctx.shared.forms ||= []).push({ sourceId, file: file.rel, line: startLine, name: cls, submitsTo: null, action: null, actionFile: null, method: 'POST', fields: flds });
  }
}

function extractHtml(ctx, file) {
  const { graph, ev } = ctx;
  const re = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let m;
  let idx = 0;
  const lineAt = (off) => file.content.slice(0, off).split('\n').length;
  const lines = file.content.split('\n');
  while ((m = re.exec(file.content))) {
    idx++;
    const attrs = m[1];
    const get = (s, a) => s.match(new RegExp(`\\b${a}\\s*=\\s*["']([^"']*)["']`, 'i'))?.[1];
    const formLine = lineAt(m.index);
    const fields = [];
    const fre = /<(input|textarea|select)\b([^>]*)>/gi;
    let f;
    while ((f = fre.exec(m[2]))) {
      const type = get(f[2], 'type') || (f[1].toLowerCase() === 'input' ? 'text' : f[1].toLowerCase());
      const nameAttr = get(f[2], 'name');
      const idAttr = get(f[2], 'id');
      let fname = nameAttr && !TEMPLATED.test(nameAttr) ? nameAttr : null;
      const fromId = !fname && !!idAttr && !TEMPLATED.test(idAttr);
      if (fromId) fname = idAttr;
      if (!fname && ['email', 'tel', 'password'].includes(type)) fname = type === 'tel' ? 'phone' : type;
      if (!fname || SKIP_TYPES.has(type.toLowerCase())) continue;
      const label = get(f[2], 'aria-label');
      fields.push({ name: fname, type: type.toLowerCase(), line: lineAt(m.index + m[1].length + f.index), preChecked: /\bchecked\b/i.test(f[2]), ...(fromId ? { fromId, label } : {}) });
    }
    const declared = get(attrs, 'name') || get(attrs, 'id');
    // A macro/partial like <form id="{{ id }}"> with no literal inputs is a template, not a form.
    // Same for a form whose inputs are all rendered by the template engine ({{ form.q() }}, {{ form.hidden_tag() }}):
    // the server-side form class (extractPython) is the collection point.
    if (!fields.length && ((declared && TEMPLATED.test(declared)) || TEMPLATED.test(m[2]))) continue;
    const fname = declared && !TEMPLATED.test(declared) ? declared : `form-${idx}`;
    const sourceId = `source:form:${file.rel}#${fname}`;
    const hasPrivacyLink = /href\s*=\s*["'][^"']*(privacy|gizlilik|kvkk|aydinlatma|cookie|cerez)/i.test(m[2]) || PRIVACY_TEXT.test(m[2]);
    graph.addNode({
      id: sourceId, type: 'Source', kind: 'form', name: fname, file: file.rel, line: formLine, action: null, actionFile: null,
      submitsTo: get(attrs, 'action') || null, method: (get(attrs, 'method') || 'GET').toUpperCase(),
      fields: fields.map(({ name: n, type, line: l }) => ({ name: n, type, line: l })), preChecked: fields.filter((x) => x.preChecked).map((x) => x.name), hasPrivacyLink,
      evidence: [ev(file.rel, formLine, lines[formLine - 1]?.trim(), 'static', 0.9)],
    });
    const siblings = fields.map((x) => x.name);
    for (const fl of fields) {
      const cls = classifyFieldWithType(ctx, fl, { container: fname, siblings });
      if (!cls) continue;
      const e = ev(file.rel, fl.line, lines[fl.line - 1]?.trim(), 'static', cls.confidence);
      graph.addEdge({ from: sourceId, to: graph.dataElement(cls, fl.name, e), type: 'collects', field: fl.name, preChecked: fl.preChecked || undefined, evidence: [e] });
    }
    (ctx.shared.forms ||= []).push({ sourceId, file: file.rel, line: formLine, name: fname, submitsTo: get(attrs, 'action') || null, action: null, actionFile: null, method: (get(attrs, 'method') || 'GET').toUpperCase(), fields: fields.map(({ name: n, type, line: l }) => ({ name: n, type, line: l })) });
  }
}

// ---------------------------------------------------------------------------
// Sensitive option lists (r8): a list of diagnoses, beliefs, origins … the user picks from and the app keeps.
//
// The values of a closed list say what the stored field is even when its name does not (`value`, `kind`,
// `selected`): ['ADHD', 'Autism', 'Dyslexia'] behind a control whose value is written is special-category data
// (KVKK md.6 / GDPR Art.9). Required: ≥ 2 distinct terms of one category in one list, the list drives a control the user
// picks from, and the picked value is submitted or stored (in the same component, in the parent that passes the
// handler, or by a schema enum / model choices). Anything less produces nothing: an article tag list, a menu, a search
// filter, a demo table and marketing copy all carry the same words.
//
// Writes (extract): Source source:options:<file>#<name> {kind:'option-list', name, category, terms: count, writeKey, table?}
//                   + collects → DataElement (confidence 0.65; 0.7 with the stored column / table)
//        (linkSensitiveOptions, run by indirect-sources.js once every schema / flow store exists): flowsTo / represents
//                   to the column or table the value is written to.
// Contract: ctx.shared.sensitiveOptions = [{sourceId, elementId, file, line, writeKey, table}].

const SPECIAL_TERMS = {
  health: ['adhd', 'add adhd', 'dehb', 'dikkat eksikligi', 'attention deficit', 'autism', 'autistic', 'autism spectrum', 'asd', 'otizm', 'asperger', 'dyslexia', 'disleksi',
    'dyspraxia', 'dispraksi', 'dyscalculia', 'diskalkuli', 'depression', 'depresyon', 'anxiety', 'anxiety disorder', 'anksiyete', 'kaygi bozuklugu', 'bipolar',
    'bipolar disorder', 'bipolar bozukluk', 'schizophrenia', 'sizofreni', 'ptsd', 'ocd', 'okb', 'epilepsy', 'epilepsi', 'diabetes', 'type 1 diabetes', 'type 2 diabetes',
    'diyabet', 'seker hastaligi', 'asthma', 'astim', 'hypertension', 'high blood pressure', 'hipertansiyon', 'cancer', 'kanser', 'hiv', 'hiv aids', 'hepatitis', 'hepatit',
    'migraine', 'migren', 'eating disorder', 'yeme bozuklugu', 'tourette', 'tourettes', 'tourette syndrome', 'insomnia', 'uykusuzluk', 'multiple sclerosis', 'parkinson',
    'alzheimer', 'heart disease', 'kalp hastaligi', 'wheelchair user', 'visual impairment', 'visually impaired', 'gorme engelli', 'hearing impairment', 'hearing impaired',
    'isitme engelli', 'physical disability', 'bedensel engelli', 'zihinsel engelli', 'down syndrome', 'down sendromu', 'cerebral palsy', 'pcos', 'endometriosis',
    'celiac disease', 'colyak', 'crohns disease', 'substance abuse', 'addiction', 'bagimlilik', 'panic disorder', 'panik atak', 'pregnant', 'hamile', 'kidney disease', 'stroke', 'arthritis'],
  religion: ['muslim', 'islam', 'musluman', 'christian', 'christianity', 'hristiyan', 'hristiyanlik', 'jewish', 'judaism', 'musevi', 'yahudi', 'hindu', 'hinduism', 'buddhist',
    'buddhism', 'budist', 'sikh', 'sikhism', 'atheist', 'atheism', 'ateist', 'agnostic', 'agnostik', 'catholic', 'katolik', 'protestant', 'sunni', 'shia', 'alevi', 'deist'],
  ethnicity: ['caucasian', 'african american', 'black or african american', 'hispanic', 'hispanic or latino', 'latino', 'latina', 'latinx', 'pacific islander',
    'native hawaiian', 'native american', 'american indian or alaska native', 'south asian', 'east asian', 'middle eastern', 'cerkes', 'ermeni', 'biracial', 'multiracial'],
  'sex-life': ['heterosexual', 'homosexual', 'gay', 'lesbian', 'bisexual', 'pansexual', 'asexual', 'demisexual', 'heteroseksuel', 'escinsel', 'biseksuel', 'aseksuel', 'lezbiyen'],
  political: ['democrat', 'republican', 'libertarian', 'socialist', 'communist', 'conservative party', 'labour party', 'green party', 'akp', 'chp', 'mhp', 'dem parti', 'iyi parti',
    'sosyalist', 'milliyetci', 'ulkucu', 'komunist'],
  union: ['union member', 'trade union member', 'sendika uyesi', 'turk is', 'hak is', 'kesk', 'memur sen'],
};
const TERM_CATEGORY = new Map(Object.entries(SPECIAL_TERMS).flatMap(([c, ts]) => ts.map((t) => [t, c])));
/** Field name that the classifier knows for each category (label, sensitivity and element id come from it). */
const CATEGORY_FIELD = { health: 'diagnosis', religion: 'religion', ethnicity: 'ethnicity', 'sex-life': 'sexual_orientation', political: 'political_opinion', union: 'union_membership' };
// Quick gate: a quoted or tag-enclosed term somewhere in the file.
const TERM_GATE = /['"`>](?:adhd|dehb|autis|otizm|dysle|disleksi|dysprax|depress|depresyon|anxiety|anksiyete|bipolar|epilep|diabet|diyabet|ast(?:h)?m|hypertens|cancer|kanser|hiv|muslim|müslüman|islam|christian|hristiyan|jewish|hindu|buddh|atheis|ateist|agnosti|catholic|katolik|caucasian|african|hispanic|latin|native|hetero|homosex|gay|lesbian|bisex|biseks|eşcinsel|pansex|asex|democrat|republican|socialist|sosyalist|akp|chp|mhp|union|sendika|görme|işitme|bedensel|visual|hearing|wheelchair|pregnan|hamile|ptsd|ocd|alevi|sunni)/i;

/** Lower-case, TR-folded, punctuation-free form of an option text ("Type 2 Diabetes" → "type 2 diabetes"). */
function normTerm(s) {
  return String(s).replace(/[İIı]/g, 'i').toLowerCase().replace(/ş/g, 's').replace(/ğ/g, 'g').replace(/ü/g, 'u').replace(/ö/g, 'o').replace(/ç/g, 'c')
    .replace(/\([^)]*\)/g, ' ').replace(/['’]/g, '').replace(/[^a-z0-9]+/g, ' ').trim();
}
/** {category, count, size} when the texts hold ≥ 2 distinct terms of one special category, else null. */
export function sensitiveTerms(texts) {
  const by = new Map();
  let size = 0;
  for (const t of texts || []) {
    if (typeof t !== 'string' || !t.trim() || t.length > 60) continue;
    size++;
    const n = normTerm(t);
    const c = TERM_CATEGORY.get(n);
    if (!c) continue;
    if (!by.has(c)) by.set(c, new Set());
    by.get(c).add(n);
  }
  let best = null;
  for (const [category, set] of by) if (set.size >= 2 && (!best || set.size > best.count)) best = { category, count: set.size, size };
  // A long list that merely contains two such words (a tag cloud, a dictionary) is not a list of them.
  return best && best.count / best.size >= 0.25 ? best : null;
}

/** Names of lists that classify content, filter a directory or describe services: never the user's own attribute. */
const NOT_OWN_LIST = /tag|topic|categor|genre|filter|search|sort|article|blog|faq|menu|nav|slide|testimonial|feature|service|specialt|specialis|specializ|expertise|department|resource|keyword|glossary|content|pricing|treatment|program|course|event|locale|language|country|emoji|icon|color|colour/i;
const NOT_OWN_FILE = /(?:^|\/)(?:blog|blogs|articles?|posts?|content|contents|docs?|faq|marketing|landing|i18n|locales?|lang|translations?|seeds?|seeders?|fixtures?|mocks?|__mocks__|stories|storybook|demo|demos|examples?|samples?|scripts?|glossary)(?:\/|\.)|\.(?:stories|story|mock|fixture|seed|d)\.[cm]?[jt]sx?$|(?:^|\/)[^/]*(?:test|mock|fixture|seed)s?[^/]*\.[a-z]+$/i;
const PICK_TAG = /^(?:option|SelectItem|MenuItem|Option|Radio|RadioGroupItem|RadioButton|Checkbox|ToggleGroupItem|ListboxOption|ComboboxItem|CommandItem|Chip|Toggle|ToggleButton|Select\.Item|Select\.Option|Picker\.Item|Radio\.Group|Checkbox\.Group|FormControlLabel)$/;
const PICK_ATTR = /^(?:on(?:Click|Press|Select|Change|CheckedChange|ValueChange|SelectedChange|Toggle|PressIn)|handle[A-Z]\w*)$/;
const LIST_PROP = /^(?:options|items|data|choices|values|list)$/;
const PICK_WIDGET = /select|combobox|radio|checkbox|dropdown|picker|autocomplete|chips|multiselect|togglegroup/i;
const WRITE_RE = /\.\s*(?:insert|upsert|update|create|createMany|save|set|mutate|mutateAsync)\s*\(|\b(?:addDoc|setDoc|updateDoc)\s*\(|\baxios\s*\.\s*(?:post|put|patch)\s*\(|\bmethod\s*:\s*['"](?:POST|PUT|PATCH)['"]|\b(?:AsyncStorage|localStorage)\s*\.\s*setItem\s*\(|\bINSERT\s+INTO\b/;
const FN_TYPE = /^(?:FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|ObjectMethod|ClassMethod)$/;

const stripTs = (n) => {
  let c = n;
  while (c && /^(?:TSAsExpression|TSSatisfiesExpression|TSNonNullExpression|TSTypeAssertion|ParenthesizedExpression)$/.test(c.type)) c = c.expression;
  return c;
};
/** Texts of an array literal: strings, or the label / value / name of its objects. */
function listTexts(node) {
  const arr = stripTs(node);
  if (arr?.type !== 'ArrayExpression' || arr.elements.length < 2) return null;
  const out = [];
  for (const e0 of arr.elements) {
    const e = stripTs(e0);
    const s = strValue(e);
    if (s != null) { out.push(s); continue; }
    if (e?.type === 'ObjectExpression') {
      const p = e.properties.filter((x) => x.type === 'ObjectProperty');
      const get = (k) => strValue(stripTs(p.find((x) => (x.key?.name || x.key?.value) === k)?.value));
      const t = get('label') ?? get('name') ?? get('title') ?? get('text') ?? get('value') ?? get('id');
      if (t != null) { out.push(TERM_CATEGORY.has(normTerm(t)) ? t : (get('value') ?? t)); continue; }
    }
    return null; // a computed element: not a closed list
  }
  return out;
}

function identIn(node, name) {
  let hit = false;
  walk(node, (n) => {
    if (hit) return false;
    if (n.type === 'Identifier' && n.name === name) hit = true;
  });
  return hit;
}
/** Object keys a function body writes the identifier under: mutate({ kind: t }) → ['kind']; shorthand ({ religion }). */
function writeKeys(body, name) {
  const keys = [];
  walk(body, (n) => {
    if (n.type !== 'CallExpression' && n.type !== 'OptionalCallExpression') return;
    for (const a of n.arguments) {
      walk(a, (o) => {
        if (o.type !== 'ObjectProperty') return;
        const v = stripTs(o.value);
        if ((v?.type === 'Identifier' && v.name === name) || (v?.type === 'ArrayExpression' && v.elements.some((x) => x?.type === 'SpreadElement' || x?.name === name) && identIn(v, name))) keys.push(o.key?.name || o.key?.value);
      });
    }
  });
  return keys.filter((k) => typeof k === 'string' && !/^(?:id|key|queryKey|label|name|title|text|value)$/.test(k));
}

/** Does the source text between two offsets perform a write? */
const writesIn = (src, node) => WRITE_RE.test(src.slice(node.start, node.end));

/**
 * Where a picked value goes: {stored, key} for the component that owns the handler / state.
 *   handlers: function names called with the item;  states: state variables the control is bound to.
 */
function storedIn(file, ast, { handlers, states, inlineKeys }) {
  const src = file.content;
  let key = null;
  let stored = false;
  const fns = new Map();
  walk(ast, (n) => {
    if (n.type === 'FunctionDeclaration' && n.id) fns.set(n.id.name, n);
    if (n.type === 'VariableDeclarator' && n.id?.type === 'Identifier' && n.init) {
      const i = stripTs(n.init);
      const f = FN_TYPE.test(i.type) ? i : i.type === 'CallExpression' && /^(?:useCallback|useMemo|useEvent|debounce)$/.test(i.callee?.name || '') && FN_TYPE.test(i.arguments[0]?.type || '') ? i.arguments[0] : null;
      if (f) fns.set(n.id.name, f);
    }
  });
  const setters = new Set();
  for (const h of handlers) {
    const f = fns.get(h);
    if (!f) continue;
    const p = f.params[0]?.type === 'Identifier' ? f.params[0].name : f.params[0]?.left?.name;
    if (writesIn(src, f)) {
      stored = true;
      if (p) key = key || writeKeys(f.body, p)[0] || null;
    }
    // The handler puts the value into state: setSelected([...selected, item]) / setForm({ ...form, religion: v }).
    walk(f.body, (c) => {
      if (c.type === 'CallExpression' && c.callee.type === 'Identifier' && /^set[A-Z]/.test(c.callee.name) && p && c.arguments.some((a) => identIn(a, p))) {
        setters.add(lcFirst(c.callee.name.slice(3)));
        const ks = writeKeys({ type: 'ExpressionStatement', expression: c }, p);
        if (ks.length) key = key || ks[0];
      }
    });
  }
  for (const s of states) setters.add(s);
  // State written: the state variable (or the object it lives in) is an argument of a write call.
  if (setters.size) {
    walk(ast, (c) => {
      if (c.type !== 'CallExpression' && c.type !== 'OptionalCallExpression') return;
      const text = src.slice(c.start, Math.min(c.end, c.start + 2500));
      const head = src.slice(c.callee.start, c.callee.end);
      const isWrite = /(?:^|\.)\s*(?:insert|upsert|update|create|createMany|save|mutate|mutateAsync|post|put|patch|setItem)$/.test(head) || /^(?:addDoc|setDoc|updateDoc)$/.test(head) ||
        (/^(?:fetch|\$fetch)$/.test(head) && /method\s*:\s*['"](?:POST|PUT|PATCH)['"]/.test(text)) || /^(?:on(?:Submit|Save|Complete|Next|Finish)|save\w*|submit\w*|update\w*|create\w*)$/.test(head);
      if (!isWrite || /^set[A-Z]/.test(head)) return;
      for (const s of setters) {
        if (!c.arguments.some((a) => identIn(a, s))) continue;
        // A call to an own helper counts only when that helper (or a module it comes from) is named like a save.
        stored = true;
        if (!key) {
          walk(c, (o) => {
            if (o.type !== 'ObjectProperty' || key) return;
            const v = stripTs(o.value);
            if (v?.type === 'Identifier' && v.name === s) key = o.key?.name || o.key?.value || null;
          });
        }
      }
    });
  }
  return { stored, key: key || inlineKeys?.[0] || null };
}

/** Files that import a module by its base name. */
function importersOf(ctx, rel) {
  const base = rel.split('/').pop().replace(/\.[^.]+$/, '');
  const re = new RegExp(String.raw`(?:from\s*|import\s*\(?\s*|require\s*\(\s*)['"][^'"]*\/${base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:\.\w+)?['"]`);
  return ctx.files.filter((f) => f.rel !== rel && !f.test && /\.(?:[jt]sx?|mjs)$/.test(f.rel) && re.test(f.content || ''));
}

function emitOptions(ctx, file, { name, line: ln, hit, key, where, table }) {
  const { graph, ev } = ctx;
  const base = ctx.classify(CATEGORY_FIELD[hit.category]);
  if (!base) return;
  // Stored in a content / directory table (articles.tag, therapists.specialty): not the picker's own attribute.
  if (optionStore(ctx, key).content) return;
  const cls = { ...base, confidence: key || table ? 0.7 : 0.65 };
  const snippet = file.content.split(/\r?\n/)[ln - 1]?.trim().slice(0, 160);
  const e = ev(file.rel, ln, snippet, 'static', cls.confidence, `option list with ${hit.count} special-category (${hit.category}) terms; the picked value is ${where}`);
  const sourceId = `source:options:${file.rel}#${name}`;
  if (graph.node(sourceId)) return;
  graph.addNode({ id: sourceId, type: 'Source', kind: 'option-list', name, category: hit.category, terms: hit.count, writeKey: key || null, file: file.rel, line: ln, fields: [{ name: key || name, line: ln }], evidence: [e] });
  const elementId = graph.dataElement(cls, key || name, e);
  graph.addEdge({ from: sourceId, to: elementId, type: 'collects', field: key || name, evidence: [e] });
  (ctx.shared.sensitiveOptions ||= []).push({ sourceId, elementId, file: file.rel, line: ln, writeKey: key || null, table: table || null, confidence: cls.confidence });
}

function optionListsJs(ctx, file) {
  const ast = parseFile(file);
  if (!ast) return;
  const src = file.content;
  const lists = []; // {name, node, hit, line}
  const aliases = new Map(); // derived variable → list name
  walk(ast, (n, parents) => {
    if (n.type === 'VariableDeclarator' && n.init) {
      const init = stripTs(n.init);
      if (n.id?.type === 'Identifier') {
        const texts = listTexts(init);
        const hit = texts && sensitiveTerms(texts);
        if (hit) lists.push({ name: n.id.name, hit, line: line(n) });
        // [...LIST, 'Other'] / LIST.filter(…) / LIST.map(…)
        else if (init.type === 'ArrayExpression' && init.elements.some((x) => x?.type === 'SpreadElement' && x.argument.type === 'Identifier')) aliases.set(n.id.name, init.elements.find((x) => x?.type === 'SpreadElement' && x.argument.type === 'Identifier').argument.name);
        else if (init.type === 'CallExpression' && init.callee.type === 'MemberExpression' && init.callee.object.type === 'Identifier' && /^(?:filter|map|slice|sort|concat)$/.test(init.callee.property?.name || '')) aliases.set(n.id.name, init.callee.object.name);
      } else if (n.id?.type === 'ArrayPattern' && init.type === 'CallExpression' && /^useState$|\.useState$/.test(src.slice(init.callee.start, init.callee.end)) && init.arguments[0]?.type === 'Identifier' && n.id.elements[0]?.type === 'Identifier') {
        aliases.set(n.id.elements[0].name, init.arguments[0].name);
      }
      return;
    }
    if (n.type === 'TSEnumDeclaration') {
      const hit = sensitiveTerms(n.members.map((m) => strValue(m.initializer) ?? m.id?.name ?? m.id?.value ?? ''));
      if (hit) lists.push({ name: n.id.name, hit, line: line(n), isEnum: true });
      return;
    }
    // Schema enums: z.enum([...]) / Joi.valid(...) as a schema field, pgEnum('x', [...]), Mongoose / Sequelize enum lists.
    if (n.type === 'ArrayExpression') {
      const p = parents[parents.length - 1];
      const callee = p?.type === 'CallExpression' ? src.slice(p.callee.start, p.callee.end) : '';
      const isSchemaEnum = /^(?:z|zod|yup|Yup)\.(?:enum|nativeEnum)$|\.oneOf$|^(?:pgEnum|mysqlEnum|sqliteEnum)$/.test(callee);
      const modelEnum = p?.type === 'ObjectProperty' && (p.key?.name || p.key?.value) === 'enum';
      if (!isSchemaEnum && !modelEnum) return;
      const texts = listTexts(n);
      const hit = texts && sensitiveTerms(texts);
      if (!hit) return;
      const field = [...parents].reverse().find((x) => x.type === 'ObjectProperty' && (x.key?.name || x.key?.value) !== 'enum');
      const arg0 = p.type === 'CallExpression' ? strValue(p.arguments[0]) : null;
      const fname = field?.key?.name || field?.key?.value || arg0;
      if (!fname || NOT_OWN_LIST.test(fname)) return;
      const decl = [...parents].reverse().find((x) => x.type === 'VariableDeclarator');
      if (NOT_OWN_LIST.test(decl?.id?.name || '')) return;
      emitOptions(ctx, file, { name: fname, line: line(n), hit, key: fname, where: 'a field of a validation / database schema' });
    }
  });
  const root = (nm) => {
    let cur = nm;
    for (let i = 0; i < 4 && cur; i++) {
      const l = lists.find((x) => x.name === cur);
      if (l) return l;
      cur = aliases.get(cur);
    }
    return null;
  };
  // Lists used here from another module: import { CONDITIONS } from './constants'.
  walk(ast, (n) => {
    if (n.type !== 'ImportDeclaration') return;
    for (const s of n.specifiers) {
      if (s.type !== 'ImportSpecifier') continue;
      const imported = s.imported.name || s.imported.value;
      if (lists.some((l) => l.name === s.local.name) || NOT_OWN_LIST.test(imported)) continue;
      const target = resolveImport(ctx, file.rel, n.source.value);
      const tf = target && ctx.files.find((f) => f.rel === target);
      if (!tf || NOT_OWN_FILE.test(tf.rel) || !TERM_GATE.test(tf.content || '')) continue;
      const tast = parseFile(tf);
      if (!tast) continue;
      walk(tast, (d) => {
        if (d.type === 'VariableDeclarator' && d.id?.type === 'Identifier' && d.id.name === imported && d.init) {
          const texts = listTexts(d.init);
          const hit = texts && sensitiveTerms(texts);
          if (hit) lists.push({ name: s.local.name, hit, line: line(d), from: tf });
        }
        if (d.type === 'TSEnumDeclaration' && d.id.name === imported) {
          const hit = sensitiveTerms(d.members.map((m) => strValue(m.initializer) ?? m.id?.name ?? ''));
          if (hit) lists.push({ name: s.local.name, hit, line: line(d), from: tf, isEnum: true });
        }
      });
    }
  });

  // JSX controls driven by a list.
  const seen = new Set();
  walk(ast, (n, parents) => {
    let list = null;
    let body = null;
    let param = null;
    if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && n.callee.property?.name === 'map' && FN_TYPE.test(n.arguments[0]?.type || '')) {
      const obj = stripTs(n.callee.object);
      const inline = listTexts(obj);
      if (inline) {
        const hit = sensitiveTerms(inline);
        if (hit) list = { name: `list@${line(n)}`, hit, line: line(n), anonymous: true };
      } else if (obj?.type === 'Identifier') list = root(obj.name);
      else if (obj?.type === 'CallExpression' && /^Object\.(?:values|keys|entries)$/.test(src.slice(obj.callee.start, obj.callee.end)) && obj.arguments[0]?.type === 'Identifier') list = root(obj.arguments[0].name);
      if (!list) return;
      body = n.arguments[0];
      const p0 = body.params[0];
      param = p0?.type === 'Identifier' ? p0.name : p0?.type === 'ObjectPattern' ? p0.properties.map((x) => x.value?.name).find(Boolean) : p0?.type === 'ArrayPattern' ? p0.elements[0]?.name : null;
    } else if (n.type === 'JSXElement') {
      const tag = jsxName(n.openingElement.name);
      const prop = (n.openingElement.attributes || []).find((a) => a.type === 'JSXAttribute' && LIST_PROP.test(jsxName(a.name)) && a.value?.expression);
      const pex = prop && stripTs(prop.value.expression);
      if (pex?.type === 'Identifier' && PICK_WIDGET.test(tag)) list = root(pex.name);
      else if (/^(?:select|Select|RadioGroup|Select\.Root)$/.test(tag)) {
        // Literal children: <select name="faith"><option>Muslim</option>…
        const texts = [];
        walk(n, (o) => {
          if (o.type === 'JSXElement' && o !== n && PICK_TAG.test(jsxName(o.openingElement.name))) texts.push(jsxText(o) || String(attr(o, 'value').value ?? ''));
        });
        const hit = sensitiveTerms(texts);
        if (hit) list = { name: (typeof attr(n, 'name').value === 'string' && attr(n, 'name').value) || `select@${line(n)}`, hit, line: line(n) };
      }
      if (!list) return;
      body = n;
    } else return;
    const owner = [...parents].reverse().find((p) => FN_TYPE.test(p.type) && p !== body) || ast.program;

    // The control and what it is bound to.
    const handlers = new Set();
    const states = new Set();
    const inlineKeys = [];
    let control = false;
    let inlineWrite = false;
    const props = new Set();
    const readControl = (el, isContainer) => {
      for (const a of el.openingElement.attributes || []) {
        if (a.type !== 'JSXAttribute') continue;
        const an = jsxName(a.name);
        const ex = a.value?.expression;
        if (PICK_ATTR.test(an) && ex) {
          control = true;
          if (ex.type === 'Identifier') handlers.add(ex.name);
          else {
            if (writesIn(src, ex)) inlineWrite = true;
            walk(ex, (c) => {
              if (c.type === 'CallExpression' && c.callee.type === 'Identifier') handlers.add(c.callee.name);
              if (c.type === 'CallExpression' && c.callee.type === 'Identifier' && /^set[A-Z]/.test(c.callee.name)) states.add(lcFirst(c.callee.name.slice(3)));
              if (c.type === 'CallExpression' && param) inlineKeys.push(...writeKeys({ type: 'ExpressionStatement', expression: c }, param));
            });
            const pn = FN_TYPE.test(ex.type) && ex.params[0]?.type === 'Identifier' ? ex.params[0].name : null;
            if (pn) inlineKeys.push(...writeKeys(ex.body, pn));
            // setForm({ ...form, religion: e.target.value })
            walk(ex, (o) => {
              if (o.type === 'ObjectProperty' && o.value && /\.target\.value$/.test(src.slice(o.value.start, o.value.end))) inlineKeys.push(o.key?.name || o.key?.value);
            });
          }
        }
        if (an === 'name' && strValue(a.value) && isContainer) { inlineKeys.unshift(strValue(a.value)); control = true; }
        if ((an === 'value' || an === 'selectedValue' || an === 'defaultValue' || an === 'modelValue') && ex && isContainer) {
          control = true;
          const base = ex.type === 'MemberExpression' ? stripTs(ex.object) : ex;
          if (base?.type === 'Identifier') states.add(base.name);
          const fld = exprFieldName(ex);
          if (fld && ex.type === 'MemberExpression') inlineKeys.push(fld);
        }
        if (a.type === 'JSXAttribute' && an === 'onSelect') control = true;
      }
      for (const a of el.openingElement.attributes || []) {
        if (a.type === 'JSXSpreadAttribute' && a.argument.type === 'CallExpression' && /register$|getFieldProps$/.test(src.slice(a.argument.callee.start, a.argument.callee.end))) {
          control = true;
          const s = strValue(a.argument.arguments[0]);
          if (s) inlineKeys.unshift(s);
          props.add('register');
        }
        if (a.type === 'JSXSpreadAttribute' && a.argument.type === 'Identifier' && a.argument.name === 'field') { control = true; props.add('register'); }
      }
    };
    if (n.type === 'JSXElement') readControl(n, true);
    else {
      walk(body, (c) => {
        if (c.type !== 'JSXElement') return;
        const t = jsxName(c.openingElement.name);
        const pick = PICK_TAG.test(t) || (t === 'input' && /^(?:checkbox|radio)$/.test(String(attr(c, 'type').value)));
        // A clickable element that hands the item to a handler (a chip / badge / card).
        const clicks = param && (c.openingElement.attributes || []).some((a) => a.type === 'JSXAttribute' && PICK_ATTR.test(jsxName(a.name)) && a.value?.expression && identIn(a.value.expression, param));
        if (pick || clicks) readControl(c, pick && /Checkbox|input|Radio/i.test(t));
        if (pick) control = control || t === 'option' || /Item$|Option$/.test(t);
      });
      // The select / radio group around the items holds the binding.
      for (const p of [...parents].reverse()) {
        if (p.type !== 'JSXElement') continue;
        const t = jsxName(p.openingElement.name);
        if (PICK_WIDGET.test(t) && !/Content|Item|Trigger|Value|Label/.test(t)) { readControl(p, true); break; }
        // react-hook-form: <FormField name="x" render={…}> / <Controller name="x">
        if (/^(?:FormField|Controller|Field)$/.test(t)) {
          const s = attr(p, 'name').value;
          if (typeof s === 'string') { inlineKeys.unshift(s); props.add('register'); control = true; }
          break;
        }
      }
      const ff = [...parents].reverse().find((p) => p.type === 'JSXElement' && /^(?:FormField|Controller)$/.test(jsxName(p.openingElement.name)));
      if (ff && typeof attr(ff, 'name').value === 'string') { inlineKeys.unshift(attr(ff, 'name').value); props.add('register'); control = true; }
    }
    if (!control) return;
    const label = list.anonymous ? inlineKeys[0] || [...states][0] || list.name : list.name;
    const bound = [list.name, ...handlers, ...states, ...inlineKeys].join(' ');
    if (NOT_OWN_LIST.test(bound.replace(/\bsearchable\b/g, '')) || seen.has(label)) return;

    // Submitted with a form: native form (not a GET search form) or react-hook-form.
    const form = [...parents].reverse().find((p) => p.type === 'JSXElement' && /^(?:form|Form)$/.test(jsxName(p.openingElement.name)));
    const formGet = form && /^get$/i.test(String(attr(form, 'method').value || ''));
    const namedInForm = !!form && !formGet && (props.has('register') || (inlineKeys.length > 0 && (attr(form, 'action').present || attr(form, 'onSubmit').present || attr(form, 'method').present)));
    let r = { stored: inlineWrite, key: inlineKeys.find((k) => typeof k === 'string') || null };
    let where = 'written by the component';
    if (!r.stored) {
      const s = storedIn(file, ast, { handlers, states, inlineKeys });
      if (s.stored) r = s;
    } else {
      const s = storedIn(file, ast, { handlers, states, inlineKeys });
      r.key = r.key || s.key;
    }
    if (!r.stored && namedInForm && (props.has('register') ? WRITE_RE.test(src) || /handleSubmit/.test(src) : true)) {
      r = { stored: true, key: r.key };
      where = 'submitted with a form';
    }
    if (!r.stored) {
      // The component hands the item to a callback prop; the parent that renders it writes it.
      const ownProps = new Set();
      const p0 = owner.params?.[0];
      if (p0?.type === 'ObjectPattern') for (const x of p0.properties) if (x.value?.type === 'Identifier') ownProps.add(x.value.name);
      const callbacks = new Set([...handlers].filter((h) => ownProps.has(h)));
      // One local wrapper: const pick = (t) => { onPick(t); }
      walk(owner, (c) => {
        if (c.type !== 'VariableDeclarator' && c.type !== 'FunctionDeclaration') return;
        const nm = c.id?.name;
        if (!handlers.has(nm)) return;
        walk(c.type === 'FunctionDeclaration' ? c.body : c.init, (k) => {
          if (k.type === 'CallExpression' && k.callee.type === 'Identifier' && ownProps.has(k.callee.name)) callbacks.add(k.callee.name);
        });
      });
      if (callbacks.size) {
        for (const pf of importersOf(ctx, file.rel)) {
          if (NOT_OWN_FILE.test(pf.rel)) continue;
          const past = parseFile(pf);
          if (!past) continue;
          const ph = new Set();
          const pk = [];
          let inlineW = false;
          walk(past, (c) => {
            if (c.type !== 'JSXAttribute' || !callbacks.has(jsxName(c.name)) || !c.value?.expression) return;
            const ex = c.value.expression;
            if (ex.type === 'Identifier') ph.add(ex.name);
            else {
              if (writesIn(pf.content, ex)) inlineW = true;
              const pn = FN_TYPE.test(ex.type) && ex.params[0]?.type === 'Identifier' ? ex.params[0].name : null;
              if (pn) pk.push(...writeKeys(ex.body, pn));
              walk(ex, (k) => { if (k.type === 'CallExpression' && k.callee.type === 'Identifier') ph.add(k.callee.name); });
            }
          });
          if (!ph.size && !inlineW) continue;
          if (NOT_OWN_LIST.test([...ph, ...pk].join(' '))) continue;
          const s = inlineW ? { stored: true, key: pk[0] || null } : storedIn(pf, past, { handlers: ph, states: new Set(), inlineKeys: pk });
          if (s.stored) { r = s; where = `written by ${pf.rel.split('/').pop()}`; break; }
        }
      }
    }
    if (!r.stored || (r.key && NOT_OWN_LIST.test(r.key))) return;
    seen.add(label);
    emitOptions(ctx, list.from || file, { name: label, line: list.line, hit: list.hit, key: r.key, where });
  });
}

/** Vue / Svelte / HTML: lists and literal selects bound to a model inside a form / component that writes. */
function optionListsMarkup(ctx, file) {
  const src = file.content;
  const lineOf = (i) => src.slice(0, i).split('\n').length;
  const isHtml = /\.html?$|\.(?:erb|twig|blade|jinja2?|j2|njk|hbs|ejs|php)$/i.test(file.rel);
  const formWrites = /<form\b(?![^>]*method\s*=\s*["']get["'])/i.test(src) || /@submit|on:submit|onsubmit|use:enhance/.test(src) || WRITE_RE.test(src);
  // <select name= / v-model= / bind:value=> … literal <option>s
  for (const m of src.matchAll(/<select\b([^>]*)>([\s\S]{0,4000}?)<\/select>/gi)) {
    const texts = [...m[2].matchAll(/<option\b[^>]*>([^<{]*)/gi)].map((x) => x[1].trim());
    const hit = sensitiveTerms(texts);
    if (!hit) continue;
    const nm = /\b(?:name|v-model(?:\.\w+)?|bind:value)\s*=\s*(?:["']|\{)([\w.]+)/.exec(m[1])?.[1]?.split('.').pop();
    const before = src.slice(0, m.index);
    const form = before.lastIndexOf('<form');
    const inForm = form >= 0 && before.indexOf('</form', form) < 0 && !/method\s*=\s*["']get["']/i.test(src.slice(form, src.indexOf('>', form) + 1));
    if (!nm || NOT_OWN_LIST.test(nm) || !(inForm || (!isHtml && WRITE_RE.test(src)))) continue;
    emitOptions(ctx, file, { name: nm, line: lineOf(m.index), hit, key: nm, where: 'submitted with a form' });
  }
  if (isHtml) return;
  for (const m of src.matchAll(/\b(?:const|let)\s+(\w+)\s*(?::[^=\n]+)?=\s*(?:ref\(\s*|reactive\(\s*)?\[([^\]]{4,3000})\]/g)) {
    const texts = [...m[2].matchAll(/(?:\b(?:label|name|title|text|value)\s*:\s*)?(['"`])((?:(?!\1)[^\\\n]){2,60})\1/g)].map((x) => x[2]);
    const hit = sensitiveTerms(texts);
    if (!hit || NOT_OWN_LIST.test(m[1]) || !formWrites) continue;
    const loop = new RegExp(String.raw`(?:v-for\s*=\s*["'][^"']*\b(?:in|of)\s+${m[1]}\b|\{#each\s+${m[1]}\s+as\b|:(?:options|items)\s*=\s*["']${m[1]}["'])`).exec(src);
    if (!loop) continue;
    const win = src.slice(Math.max(0, loop.index - 500), loop.index + 700);
    const model = /(?:v-model(?:\.\w+)?\s*=\s*["']|bind:(?:group|value|checked)\s*=\s*\{)([\w.]+)/.exec(win)?.[1];
    if (!model) continue;
    const base = model.split('.')[0];
    const key = model.split('.').pop();
    if (NOT_OWN_LIST.test(model)) continue;
    // The bound model must reach a write or the enclosing form.
    const writes = [...src.matchAll(new RegExp(WRITE_RE.source, 'g'))].some((w) => new RegExp(`\\b${base}\\b`).test(src.slice(w.index, w.index + 500)));
    if (!writes && !/<form\b(?![^>]*method\s*=\s*["']get["'])/i.test(src)) continue;
    emitOptions(ctx, file, { name: m[1], line: lineOf(m.index), hit, key, where: writes ? 'written by the component' : 'submitted with a form' });
  }
}

/** Python: choices lists used by a model / form field. */
function optionListsPython(ctx, file) {
  const src = file.content;
  const lineOf = (i) => src.slice(0, i).split('\n').length;
  const defs = new Map();
  for (const m of src.matchAll(/^[ \t]*(\w+)\s*(?::[^=\n]+)?=\s*[[(]([\s\S]{4,3000}?)[\])]\s*$/gm)) {
    const hit = sensitiveTerms([...m[2].matchAll(/(['"])((?:(?!\1)[^\\\n]){2,60})\1/g)].map((x) => x[2]));
    if (hit) defs.set(m[1], { hit, line: lineOf(m.index + m[0].indexOf(m[1])) });
  }
  for (const m of src.matchAll(/class\s+(\w+)\s*\(\s*(?:models\.)?(?:TextChoices|StrEnum|str\s*,\s*Enum|Enum)\s*\)\s*:\s*\n((?:[ \t]+[^\n]*\n|\s*\n){2,60})/g)) {
    const hit = sensitiveTerms([...m[2].matchAll(/(['"])((?:(?!\1)[^\\\n]){2,60})\1/g)].map((x) => x[2]));
    if (hit) defs.set(m[1], { hit, line: lineOf(m.index) });
  }
  for (const [nm, d] of defs) {
    if (NOT_OWN_LIST.test(nm)) continue;
    const use = new RegExp(String.raw`^[ \t]+(\w+)\s*(?::\s*[^=\n]+)?=\s*(?:\w+\.)*(?:\w*Field|Column|mapped_column)\s*\([^\n]*(?:choices\s*=\s*(?:\w+\.)*${nm}\b|Enum\(\s*${nm}\b|\b${nm}\.choices)`, 'm').exec(src);
    if (!use || NOT_OWN_LIST.test(use[1])) continue;
    const cls = [...src.slice(0, use.index).matchAll(/^class\s+(\w+)/gm)].pop()?.[1] || '';
    if (NOT_OWN_LIST.test(cls) || /Filter/.test(cls)) continue;
    emitOptions(ctx, file, { name: nm, line: d.line, hit: d.hit, key: use[1], where: 'a field of a model / form class' });
  }
}

const CONTENT_TABLE = /(?:^|_)(?:articles?|posts?|blogs?|pages?|faqs?|tags?|categor(?:y|ies)|products?|recipes?|courses?|lessons?|events?|resources?|questions?|topics?|services?|providers?|specialt(?:y|ies)|doctors?|therapists?|clinics?)$/i;
const snakeCase = (x) => String(x).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
const bareTable = (t) => String(t || '').split('.').pop().toLowerCase();

/**
 * Where a picked value is stored: the schema column named like the write key, narrowed by the write that carries the key
 * (from('table').insert({ key: … }), db.table.create({ data: { key: … } })).
 * @returns {{cols: object[], table: string|null, wev: object|null, content: boolean}}
 */
function optionStore(ctx, writeKey) {
  const { graph, ev } = ctx;
  const out = { cols: [], table: null, wev: null, content: false };
  if (!writeKey) return out;
  const key = snakeCase(writeKey);
  const all = graph.nodesOf('Store', (n) => n.kind === 'column' && snakeCase(n.column || '') === key);
  let cols = all.filter((c) => !CONTENT_TABLE.test(String(c.table)));
  if (cols.length !== 1) {
    const k = String(writeKey).replace(/[^\w]/g, '');
    const re = new RegExp(String.raw`(?:\.from\(\s*['"\x60]([\w.]+)['"\x60]\s*\)\s*\.(?:insert|upsert|update)|\b(?:prisma|db|tx)\.(\w+)\.(?:create|update|upsert)|\bcollection\([^)\n]*['"\x60]([\w-]+)['"\x60][^\n]{0,60}?)\s*\([\s\S]{0,400}?\b${k}\s*[:,}]`);
    const found = new Map();
    for (const f of ctx.files) {
      if (f.test || f.kind !== 'code' || !/\.(?:[cm]?[jt]sx?|vue|svelte)$/.test(f.rel) || !(f.content || '').includes(k) || NOT_OWN_FILE.test(f.rel)) continue;
      const m = re.exec(f.content);
      const t = m && (m[1] || m[2] || m[3]);
      if (t && !found.has(t)) found.set(t, { f, line: f.content.slice(0, m.index).split('\n').length });
    }
    if (found.size === 1) {
      const [t, w] = [...found][0];
      out.table = t;
      out.wev = ev(w.f.rel, w.line, w.f.content.split(/\r?\n/)[w.line - 1]?.trim().slice(0, 160), 'static', 0.7, `the picked value is written to ${t}.${writeKey}`);
      cols = cols.filter((c) => bareTable(c.table) === bareTable(t));
    } else if (cols.length > 1) cols = [];
  }
  out.cols = cols;
  out.content = out.table ? CONTENT_TABLE.test(out.table) : all.length > 0 && all.every((c) => CONTENT_TABLE.test(String(c.table)));
  return out;
}

/**
 * Link sensitive option lists to the column / table their value is written to. Called by indirect-sources.js (order 60),
 * when schema and flow stores exist.
 */
export function linkSensitiveOptions(ctx) {
  const { graph, ev } = ctx;
  for (const o of ctx.shared?.sensitiveOptions || []) {
    if (!o.writeKey) continue;
    const { cols, table, wev, content } = optionStore(ctx, o.writeKey);
    if (content) continue;
    const srcEv = graph.node(o.sourceId)?.evidence?.[0];
    if (cols.length === 1) {
      const c = cols[0];
      const e = wev || ev(c.file || o.file, c.line || o.line, c.evidence?.[0]?.snippet, 'static', 0.65, `column the option list value is written to (${o.writeKey})`);
      graph.addEdge({ from: o.elementId, to: c.id, type: 'flowsTo', sourceId: o.sourceId, evidence: [srcEv, e].filter(Boolean) });
      if (!graph.edgesFrom(c.id, 'represents').some((r) => r.to === o.elementId)) graph.addEdge({ from: c.id, to: o.elementId, type: 'represents', evidence: [e] });
    } else if (table) {
      const t = graph.nodesOf('Store', (n) => (n.kind === 'table' || n.kind === 'collection') && bareTable(n.table) === bareTable(table))[0];
      if (t) graph.addEdge({ from: o.elementId, to: t.id, type: 'flowsTo', sourceId: o.sourceId, evidence: [srcEv, wev].filter(Boolean) });
    }
  }
}

function extractOptionLists(ctx) {
  for (const f of ctx.files) {
    if (f.kind !== 'code' || f.test || !f.content || f.content.length > 400_000 || NOT_OWN_FILE.test(f.rel)) continue;
    const js = /\.(?:jsx?|tsx?|mjs|cjs)$/.test(f.rel);
    const usesImportedList = js && /\.map\(|options=|items=/.test(f.content) && /import\s*\{/.test(f.content) && ctx.shared._sensitiveModules?.some((re) => re.test(f.content));
    if (!TERM_GATE.test(f.content) && !usesImportedList) continue;
    try {
      if (js) optionListsJs(ctx, f);
      else if (/\.py$/.test(f.rel)) optionListsPython(ctx, f);
      else if (/\.(?:vue|svelte|html?|erb|twig|blade|jinja2?|j2|njk|hbs|ejs|php)$/i.test(f.rel)) optionListsMarkup(ctx, f);
    } catch (e) {
      ctx.warn?.(`forms: option lists ${f.rel}: ${e.message}`);
    }
  }
}

/** Modules that export a list with sensitive terms: files importing them by base name are scanned too. */
function indexSensitiveModules(ctx) {
  ctx.shared._sensitiveModules = [];
  for (const f of ctx.files) {
    if (f.kind !== 'code' || f.test || NOT_OWN_FILE.test(f.rel) || !/\.(?:[cm]?[jt]sx?)$/.test(f.rel) || !/\bexport\b/.test(f.content || '') || !TERM_GATE.test(f.content)) continue;
    let base = f.rel.split('/').pop().replace(/\.[^.]+$/, '');
    if (base === 'index') base = f.rel.split('/').slice(-2)[0];
    ctx.shared._sensitiveModules.push(new RegExp(`from\\s*['"][^'"]*\\b${base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:\\.\\w+)?['"]`));
  }
}

export function extract(ctx) {
  ctx.shared.forms ||= [];
  ctx.shared.schemas ||= [];
  ctx.shared.consentUi ||= [];
  for (const f of ctx.files) {
    if (f.kind !== 'code') continue;
    if (f.test) continue;
    if (/\.(html?|erb|twig|blade|jinja2?|j2|njk|hbs|ejs|php)$/i.test(f.rel)) {
      if (/<form\b/i.test(f.content)) extractHtml(ctx, f);
      continue;
    }
    if (/\.py$/.test(f.rel)) {
      if (/\b(wtforms|flask_wtf|django\.forms)\b|\bfrom django import forms\b|\bforms\.(Form|ModelForm)\b/.test(f.content)) {
        try {
          extractPython(ctx, f);
        } catch (e) {
          ctx.warn(`forms: ${f.rel}: ${e.message}`);
        }
      }
      continue;
    }
    if (!/\.(jsx?|tsx?|mjs|cjs)$/.test(f.rel)) continue;
    if (!/<form\b|<Form\b|z\.object|yup\.|object\(\)\.shape|cookie|çerez|cerez|consent|Consent|TextInput|onChangeText|\b(?:on|handle)\w*(?:Change|Input)\w*\s*=\s*\{/i.test(f.content)) continue;
    try {
      extractJsx(ctx, f);
    } catch (e) {
      ctx.warn(`forms: ${f.rel}: ${e.message}`);
    }
  }
  try {
    indexSensitiveModules(ctx);
    extractOptionLists(ctx);
  } catch (e) {
    ctx.warn?.(`forms: option lists: ${e.message}`);
  }
}
