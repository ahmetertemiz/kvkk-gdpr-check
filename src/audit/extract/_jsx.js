// Private AST helpers for the schema/forms/declarations extractors (not loaded as an extractor).
import { parse } from '@babel/parser';

const cache = new Map();

/** Parse a JS/TS/JSX file with plugins chosen by extension. Returns null on failure. */
export function parseFile(file) {
  const key = file.rel + ':' + file.content.length;
  if (cache.has(key)) return cache.get(key);
  const ext = file.rel.split('.').pop().toLowerCase();
  const attempts =
    ext === 'ts' || ext === 'mts' || ext === 'cts'
      ? [['typescript'], ['jsx', 'typescript']]
      : ext === 'tsx'
        ? [['jsx', 'typescript']]
        : [['jsx'], ['jsx', 'typescript'], ['typescript']];
  let ast = null;
  for (const plugins of attempts) {
    try {
      ast = parse(file.content, {
        sourceType: 'unambiguous',
        errorRecovery: true,
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
        plugins: [...plugins, 'decorators-legacy', 'classProperties', 'topLevelAwait'],
      });
      break;
    } catch {
      ast = null;
    }
  }
  cache.set(key, ast);
  return ast;
}

/** Depth-first walk. visitor(node, parents) — parents[parents.length-1] is the direct parent. */
export function walk(node, visitor, parents = []) {
  if (!node || typeof node.type !== 'string') return;
  if (visitor(node, parents) === false) return;
  parents.push(node);
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end' || key === 'leadingComments' || key === 'trailingComments' || key === 'innerComments' || key === 'extra') continue;
    const v = node[key];
    if (Array.isArray(v)) for (const c of v) walk(c, visitor, parents);
    else if (v && typeof v.type === 'string') walk(v, visitor, parents);
  }
  parents.pop();
}

export function jsxName(n) {
  if (!n) return '';
  if (n.type === 'JSXIdentifier') return n.name;
  if (n.type === 'JSXMemberExpression') return jsxName(n.object) + '.' + jsxName(n.property);
  if (n.type === 'JSXNamespacedName') return n.namespace.name + ':' + n.name.name;
  return '';
}

/** Static string value of an expression (string literal / simple template), else null. */
export function strValue(n) {
  if (!n) return null;
  if (n.type === 'StringLiteral') return n.value;
  if (n.type === 'TemplateLiteral' && n.expressions.length === 0) return n.quasis.map((q) => q.value.cooked).join('');
  if (n.type === 'JSXExpressionContainer') return strValue(n.expression);
  return null;
}

/** Get a JSX attribute: returns {present, value (string|true|null), node}. */
export function attr(el, name) {
  for (const a of el.openingElement?.attributes || el.attributes || []) {
    if (a.type === 'JSXAttribute' && jsxName(a.name) === name) {
      if (a.value == null) return { present: true, value: true, node: a };
      const s = strValue(a.value);
      if (s != null) return { present: true, value: s, node: a };
      const e = a.value.expression;
      if (e?.type === 'BooleanLiteral') return { present: true, value: e.value, node: a };
      return { present: true, value: null, expr: e, node: a };
    }
  }
  return { present: false };
}

/** Text content (JSXText + string literal children) of a JSX subtree. */
export function jsxText(node) {
  const out = [];
  walk(node, (n) => {
    if (n.type === 'JSXText') out.push(n.value);
    else if (n.type === 'JSXExpressionContainer' && n.expression?.type === 'StringLiteral') out.push(n.expression.value);
  });
  return out.join(' ').replace(/\s+/g, ' ').trim();
}

/** Name of a called function: foo(), a.b.foo() → 'foo' / full dotted path via calleePath. */
export function calleePath(callee) {
  if (!callee) return '';
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression') {
    const prop = callee.property.type === 'Identifier' ? callee.property.name : strValue(callee.property) || '?';
    return calleePath(callee.object) + '.' + prop;
  }
  if (callee.type === 'CallExpression') return calleePath(callee.callee) + '()';
  return '';
}

export function line(n) {
  return n?.loc?.start?.line || 1;
}
