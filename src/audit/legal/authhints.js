/**
 * Auth-guard hints in a handler body, framework-independent.
 *
 * The route extractor recognises known auth idioms. On an unseen framework a handler guarded by a
 * project-specific helper (`requireUserId(request)`, `const user = await getUser()`, `ctx.auth`, a
 * `withAuth(...)` wrapper) looks unauthenticated. Instead of trusting that absence, the SEC-03 check asks
 * here whether the handler calls anything that looks like a session / identity guard; if so, the
 * "no auth" conclusion is unresolved and goes to review instead of becoming a finding.
 *
 *   authHintIn(source, line) → {name, line, snippet} | null
 *   handlerRegion(source, line) → {start, lines[]}
 */

// Strong names: verbs that only guards use, combined with an identity noun. Any arguments.
const STRONG_RE = /\b((?:require|ensure|assert|protect|guard|authenticate|authorize|authorise|must|enforce|with)(?=[A-Z_])\w*?(?:User|Auth|Session|Login|LoggedIn|Account|Admin|Role|Viewer|Identity|Principal|Member|Claims|Permission)(?![a-z])\w*|requireAuth|isAuthenticated|ensureLoggedIn|loginRequired|authenticated|authMiddleware)\s*\(/;
// Weak names: getters that read the caller's identity. Only count with no args or a request-like arg.
const WEAK_RE = /\b((?:get|fetch|load|read|current|verify|check|validate|use|resolve)(?=[A-Z_])\w*?(?:User|Auth|Session|Viewer|Identity|Principal|Claims|Me)(?![a-z])\w*|auth|currentUser|getServerSession|getSession|getAuth|validateRequest)\s*\(\s*(?:\)|(?:req|request|event|ctx|context|c|headers|cookies|args|authOptions|opts|options)\b|\{\s*(?:req|request|headers|event|ctx)\b|await\s+headers\(\))/;
// Member access on a session-bearing object, and declarative guards.
const MEMBER_RE = /\bctx\.auth\b|\b(?:req|request|event\.locals|locals|context|c\.var|res\.locals)\.(?:user|session|auth|userId|currentUser)\b|\bc\.get\(\s*['"](?:user|session|jwtPayload)['"]\s*\)|@login_required|\bDepends\(\s*get_current_\w+|\[Authorize\]|before_action\s+:authenticate|@PreAuthorize|@Secured/;
// Data lookups with an identity noun are not guards (getUserById, listUsers, createUser …).
const NOT_GUARD_RE = /By[A-Z]\w*\s*\(|Users\s*\(|(?:List|All|Count|Create|Insert|Delete|Remove|Update)\w*\s*\(/;
const TOP_LEVEL_RE = /^(?:export\s|(?:async\s+)?function\s|def\s|class\s|@app\.|@router\.|router\.|app\.(?:get|post|put|patch|delete)\()/;

/** Lines of the handler that starts at `line` (1-based): up to the next top-level definition, max 150 lines. */
export function handlerRegion(source, line) {
  const all = String(source || '').split(/\r?\n/);
  const start = Math.max(0, (Number(line) || 1) - 1);
  const out = [];
  for (let i = start; i < all.length && out.length < 150; i++) {
    const l = all[i];
    if (i > start && TOP_LEVEL_RE.test(l)) break;
    out.push(l);
  }
  return { start: start + 1, lines: out };
}

function matchLine(l) {
  if (/^\s*(?:\/\/|#|\*)/.test(l)) return null;
  const strong = l.match(STRONG_RE);
  const weak = !strong && l.match(WEAK_RE);
  const member = !strong && !weak && l.match(MEMBER_RE);
  const m = strong || weak || member;
  if (!m) return null;
  if ((strong || weak) && NOT_GUARD_RE.test(m[0])) return null;
  return (m[1] || m[0]).replace(/\s*\($/, '');
}

/**
 * The first auth-guard-like call / access in the handler, or null. The two lines above the handler
 * (decorators, a wrapper such as `export const POST = withAuth(`) are checked too.
 */
export function authHintIn(source, line) {
  if (!source || !line) return null;
  const all = String(source).split(/\r?\n/);
  const n = Number(line);
  for (let i = Math.max(0, n - 3); i < n - 1; i++) {
    const name = /^\s*@|=\s*\w+\(/.test(all[i] || '') ? matchLine(all[i]) : null;
    if (name) return { name, line: i + 1, snippet: all[i].trim().slice(0, 160) };
  }
  const { start, lines } = handlerRegion(source, n);
  for (let i = 0; i < lines.length; i++) {
    const name = matchLine(lines[i]);
    if (name) return { name, line: start + i, snippet: lines[i].trim().slice(0, 160) };
  }
  return null;
}

// Client-controlled record identifiers read inside a handler.
const ID_NAME = String.raw`\w*(?:id|Id|ID|Ids|ids|IDs|_id|uuid|Uuid|slug)`;
const ID_ACCESS_RE = new RegExp(String.raw`\b(?:params|query|args|input|body|searchParams|data|payload|variables)\s*(?:\.\s*get\(\s*['"\x60]|\.|\[\s*['"\x60])${ID_NAME}\b|\bformData\.get\(\s*['"\x60]${ID_NAME}['"\x60]|\breq(?:uest)?\.(?:params|query|body)\.${ID_NAME}\b|\{\s*[^}]*\b${ID_NAME}\b[^}]*\}\s*=\s*(?:await\s+)?(?:req(?:uest)?\.(?:json|body|query|params)|params|args|input|body|data)\b`);
const SIGNATURE_RE = new RegExp(String.raw`^[^{=]*?\(([^)]*)\)`);

/**
 * Does the handler take a record identifier from the client (path/query/body/form/args or a function
 * parameter of a server action)? Used to decide whether an "ownership not checked" (IDOR) suspicion has
 * an attack input at all.
 */
export function clientIdInputIn(source, line) {
  if (!source || !line) return false;
  const { lines } = handlerRegion(source, Number(line));
  if (!lines.length) return false;
  const sig = lines.slice(0, 3).join(' ').match(SIGNATURE_RE);
  if (sig && new RegExp(String.raw`\b${ID_NAME}\b`).test(sig[1].replace(/:\s*[^,]+/g, ''))) return true;
  return lines.some((l) => ID_ACCESS_RE.test(l));
}

// ---------------------------------------------------------------------------------------------
// Throw-on-deny access checks (r7).
//
// A handler can enforce access without comparing an owner field itself: it asks a helper whether the caller may
// touch the record and stops when the answer is no (`const access = await getXAccess({userId: ctx.session.userId,
// id: input.id}); if (!access) throw new TRPCError({code: 'FORBIDDEN'})`), or it calls a helper that throws on deny
// (`await assertCanEdit(user.id, params.id)`). Both are access checks of a recognised form.
//
//   accessDenyIn(source, line, {resolve}) → {kind: 'owner'|'auth', name, line, snippet} | null
//     'owner'  the stopped condition (or the throwing helper) takes a client record id AND the caller's identity
//     'auth'   a deny branch that answers 401 / Unauthorized (an authentication check of some form)
//   resolve(name) → helper body text (optional; lets a bare `await assertX(identity, id)` count when its body throws)
// ---------------------------------------------------------------------------------------------

// A deny branch: throw / raise / abort, or an explicit 401 / 403 answer.
const DENY_RE = /\bthrow\b|\braise\b|\babort\s*\(\s*40[134]\b|\.(?:status|code)\s*\(\s*40[134]\s*\)|\bsendStatus\s*\(\s*40[134]\b|\bstatus(?:_?code|Code)?\s*[:=]\s*(?:status\.)?(?:HTTP_)?40[134]\b|,\s*40[134]\s*\)|\b(?:forbidden|unauthori[sz]ed|notFound)\s*\(|\berror\s*\(\s*40[134]\b|\bredirect\s*\(/i;
const DENY_401_RE = /\b(?:Unauthori[sz]ed|Unauthenticated|NotAuthenticated|AuthenticationFailed|UNAUTHORIZED)\b|\b401\b|\blogin_required\b|\bredirect\s*\(\s*['"`][^'"`]*(?:login|sign-?in|auth)/i;
// A helper body that denies: throws an access error or answers 401 / 403.
const HELPER_DENY_RE = /\bthrow\s+(?:new\s+)?\w*(?:Forbidden|Unauthori[sz]ed|Unauthenticated|AccessDenied|PermissionDenied|NotAllowed|TRPCError|HttpException|ForbiddenException|UnauthorizedException|NotFound)\w*|\bthrow\s+(?:new\s+)?\w*Error\s*\(\s*\{?\s*(?:code\s*:\s*)?['"](?:FORBIDDEN|UNAUTHORIZED|NOT_FOUND)['"]|\braise\s+\w*(?:PermissionDenied|Forbidden|NotAuthenticated|Unauthori[sz]ed|HTTPException|Http404|NotFound|AuthenticationFailed)\w*|\babort\s*\(\s*40[134]\b|\.(?:status|code)\s*\(\s*40[13]\s*\)|\bstatus(?:_?code|Code)?\s*[:=]\s*40[13]\b|\bcode\s*:\s*['"](?:FORBIDDEN|UNAUTHORIZED)['"]/;
// The caller's identity: session / principal members, an authenticated principal decorated on the request.
const IDENTITY_EXPR_RE = /\b(?:ctx|context|req|request|event\.locals|locals|c\.var|res\.locals|self\.request|info\.context)\s*\??\.\s*(?:session|user|auth|userId|user_id|currentUser|identity|viewer|principal|client|account|tenant|organization|org)\b|\bsession\s*\??\.\s*(?:user|userId|user_id|uid)\b|\bidentity\s*\??\.\s*(?:subject|id|tokenIdentifier|userId)\b|\b(?:currentUser|current_user|viewer)\b|\b(?:user|me|caller|principal|account)\s*\??\.\s*(?:id|uid|_id|sub|pk)\b|\bauth\s*\(\s*\)|\bauth\.uid\b|\bclaims\s*\??\.\s*sub\b/;
const CLIENT_ID_EXPR_RE = new RegExp(String.raw`\b(?:params|query|args|input|body|searchParams|data|payload|variables|request\.(?:body|query|params)|req\.(?:body|query|params)|kwargs)\s*(?:\??\.\s*|\[\s*['"\x60])${ID_NAME}\b|\b${ID_NAME}\b`);
const ACCESS_HELPER_NAME_RE = /^(?:assert|ensure|require|check|verify|validate|authori[sz]e|guard|enforce|can|has|is)[A-Z_]\w*?(?:Access|Owner|Ownership|Owns|Permission|Permissions|Member|Membership|Admin|Role|Allowed|Belongs|Edit|Manage|Write|Read|View|Delete|Authorized|Authorised)\w*$/;
const SIBLING_DEF_RE = /^\s*(?:export\s|(?:async\s+)?function\b|def\s|async\s+def\s|class\s|@|(?:const|let|var)\s|[\w$]+\s*:\s*[\w$.]+(?:Procedure|Action|Mutation|Query|mutation|query|action|internalMutation|internalQuery)\b|[\w$]+\s*\([^)]*\)\s*\{)/;

function indentOf(l) {
  return (String(l).match(/^\s*/) || [''])[0].replace(/\t/g, '  ').length;
}
/** The handler's own lines: stops at the next sibling definition at the same or a lower indentation. */
function ownRegion(source, line) {
  const { start, lines } = handlerRegion(source, line);
  if (!lines.length) return { start, lines };
  const base = indentOf(lines[0]);
  let end = lines.length;
  for (let i = 1; i < lines.length; i++) {
    const l = lines[i];
    if (!l.trim()) continue;
    if (indentOf(l) <= base && SIBLING_DEF_RE.test(l)) {
      end = i;
      break;
    }
  }
  return { start, lines: lines.slice(0, end) };
}
/** Identity variables bound in the region (`const user = await requireUser(req)`, `const { userId } = auth()`). */
function identityVars(lines) {
  const out = new Set();
  for (const l of lines) {
    const m = l.match(/^\s*(?:const|let|var)?\s*(\{[^}]*\}|\[[^\]]*\]|[\w$]+)\s*(?::[^=]+)?=\s*(.+)$/);
    if (!m) continue;
    if (!(IDENTITY_EXPR_RE.test(m[2]) || matchLine(m[2]))) continue;
    for (const nm of m[1].replace(/[{}[\]]/g, ' ').split(/[,\s]+/)) {
      const n = nm.split(':').pop().trim();
      if (/^[A-Za-z_$][\w$]*$/.test(n)) out.add(n);
    }
  }
  return out;
}
function refsIdentity(text, idVars) {
  if (IDENTITY_EXPR_RE.test(text)) return true;
  for (const v of idVars) if (new RegExp(String.raw`(?<![\w$.])${v.replace(/\$/g, '\\$')}\b`).test(text)) return true;
  return false;
}
function refsClientId(text, idVars) {
  // Remove identity references first, so `user.id` / `userId` from the session do not count as the client id.
  let t = String(text).replace(new RegExp(IDENTITY_EXPR_RE.source, 'g'), ' ');
  for (const v of idVars) t = t.replace(new RegExp(String.raw`(?<![\w$.])${v.replace(/\$/g, '\\$')}(?:\s*\??\.\s*[\w$]+)*`, 'g'), ' ');
  return CLIENT_ID_EXPR_RE.test(t);
}
/** Arguments text of the first call on a line (balanced parentheses, may span following lines). */
function callArgs(lines, i, from = 0) {
  const text = lines.slice(i, i + 12).join('\n');
  const open = text.indexOf('(', from);
  if (open < 0) return null;
  let depth = 0;
  for (let k = open; k < text.length; k++) {
    if (text[k] === '(') depth++;
    else if (text[k] === ')' && --depth === 0) return { name: (text.slice(0, open).match(/([\w$]+)\s*$/) || [])[1] || null, args: text.slice(open + 1, k) };
  }
  return null;
}

export function accessDenyIn(source, line, { resolve = null } = {}) {
  if (!source || !line) return null;
  const { start, lines } = ownRegion(source, Number(line));
  if (!lines.length) return null;
  const idVars = identityVars(lines);
  let authHit = null;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (/^\s*(?:\/\/|#|\*)/.test(l)) continue;
    // (1) `if (!x)` / `if not x:` / `if (!(await canX(...)))` followed by a deny within the next lines.
    const cond = l.match(/\bif\s*\(?\s*(.+?)\)?\s*(?:\{|:|$|throw|return|raise)/);
    if (cond) {
      const block = lines.slice(i, i + 4).join('\n');
      const after = block.slice(block.indexOf(cond[0]) + cond[0].length - 1);
      if (DENY_RE.test(after) || DENY_RE.test(l.slice(l.indexOf(cond[0]) + cond[0].length - 1))) {
        const c = cond[1];
        // Inline call in the condition.
        if (/\(/.test(c) && refsIdentity(c, idVars) && refsClientId(c, idVars)) {
          return { kind: 'owner', name: (c.match(/([\w$]+)\s*\(/) || [])[1] || 'check', line: start + i, snippet: l.trim().slice(0, 160) };
        }
        // A negated / null-tested variable bound from a call that takes both the identity and the client id.
        const v = (c.match(/^\s*(?:!\s*|not\s+)([\w$]+)\b(?:\s*\??\.\s*[\w$]+)*\s*$/) || c.match(/^\s*([\w$]+)\s*(?:={2,3}\s*(?:null|undefined|false)|is\s+None)\s*$/) || [])[1];
        if (v) {
          for (let j = i - 1; j >= 0; j--) {
            const decl = lines[j].match(new RegExp(String.raw`^\s*(?:const|let|var)?\s*(?:\{[^}]*\b${v}\b[^}]*\}|${v})\s*(?::[^=]+)?=\s*(?:await\s+)?`));
            if (!decl) continue;
            const call = callArgs(lines, j, decl[0].length);
            if (call && refsIdentity(call.args, idVars) && refsClientId(call.args, idVars)) {
              return { kind: 'owner', name: call.name || v, line: start + j, snippet: lines[j].trim().slice(0, 160) };
            }
            break;
          }
        }
        if (!authHit && DENY_401_RE.test(block)) authHit = { kind: 'auth', name: 'deny', line: start + i, snippet: l.trim().slice(0, 160) };
      }
    }
    // (2) A bare access-helper call statement with the identity and the client id: `await assertCanEdit(user.id, id)`.
    const bare = l.match(/^\s*(?:await\s+)?(?:[\w$]+\s*\.\s*)*([\w$]+)\s*\(/);
    if (bare && !/^(?:if|for|while|switch|return|catch|function|await)$/.test(bare[1])) {
      const call = callArgs(lines, i);
      if (call && refsIdentity(call.args, idVars) && refsClientId(call.args, idVars)) {
        const body = typeof resolve === 'function' ? resolve(bare[1]) : null;
        if ((body && HELPER_DENY_RE.test(body)) || (!body && ACCESS_HELPER_NAME_RE.test(bare[1]))) {
          return { kind: 'owner', name: bare[1], line: start + i, snippet: l.trim().slice(0, 160) };
        }
      }
    }
  }
  return authHit;
}

/** Does a helper body deny access (throws an access error or answers 401 / 403)? */
export function bodyDenies(text) {
  return HELPER_DENY_RE.test(String(text || ''));
}

// ---------------------------------------------------------------------------------------------
// One generic answer (r8): the answer to an unknown account is the same (message and status) as the answer to a bad
// token / credential in the same function, so it does not reveal whether the account exists.
//
//   genericAnswerAt(source, line) → {line, message, status} of the other, identical answer | null
// ---------------------------------------------------------------------------------------------

const ACCOUNT_MISSING_COND_RE = /!\s*\(?\s*(?:await\s+)?(?:\w*(?:[uU]ser|[aA]ccount|[mM]ember|[cC]ustomer|[pP]rofile))\b(?!\s*\.\s*\w)|\b\w*(?:user|account|member|customer)\w*\s*={2,3}\s*(?:null|undefined)|\bnot\s+\w*(?:user|account|member|customer)\w*\b(?!\.)|\b\w*(?:user|account)\w*\s+is\s+None\b/;
const STATUS_NUM_RE = /\b(?:status(?:_?code|Code)?|code)\s*[:=(]\s*(?:status\.)?(?:HTTP_)?([45]\d\d)|\bHTTPException\(\s*(?:status\.)?(?:HTTP_)?([45]\d\d)|\.(?:status|code|sendStatus)\(\s*([45]\d\d)|\babort\(\s*([45]\d\d)|,\s*([45]\d\d)\s*\)|\b(?:error|fail)\(\s*([45]\d\d)|\bnew\s+(\w*(?:Error|Exception))\s*\(/;
const ANY_STR_RE = /(['"`])((?:(?!\1)[^\\\n]|\\.){4,200})\1/g;
const FN_HEAD_RE = /^\s*(?:@|(?:export\s+)?(?:default\s+)?(?:async\s+)?function\b|(?:async\s+)?def\s|class\s|(?:export\s+)?(?:const|let|var)\s+\w+\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*(?::[^=]+)?=>|(?:(?:public|private|protected|static|async)\s+)*[\w$]+\s*\([^)]*\)\s*(?::[^{]+)?\{\s*$|[\w$]+\s*:\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>)|[\w$.]+\.(?:get|post|put|patch|delete|all|use)\()/;

function answerIn(lines, i) {
  const win = lines.slice(i, i + 5);
  let message = null;
  let at = null;
  for (let k = 0; k < win.length && !message; k++) {
    if (/^\s*(?:\/\/|#|\*)/.test(win[k]) || (k > 0 && /^\s*(?:\}|(?:el)?if\b|else\b)/.test(win[k]))) {
      if (k > 0 && !/^\s*(?:\/\/|#|\*)/.test(win[k])) break;
      continue;
    }
    const code = win[k];
    for (const m of code.matchAll(ANY_STR_RE)) {
      if (/\s/.test(m[2]) || /^[A-Z_]{6,}$/.test(m[2])) {
        message = m[2];
        at = i + k;
        break;
      }
    }
  }
  if (!message) return null;
  return { message, at, status: statusNear(lines, at) };
}
/** Status of the answer at `at`: its own line, the lines of the same statement above it, then just below. */
function statusNear(lines, at) {
  const of = (k) => {
    const l = lines[k] || '';
    if (/^\s*(?:\/\/|#|\*)/.test(l)) return null;
    const m = l.match(STATUS_NUM_RE);
    return m ? m.slice(1).find(Boolean) || null : null;
  };
  const own = of(at);
  if (own) return own;
  for (let k = at - 1; k >= Math.max(0, at - 4); k--) {
    if (/^\s*(?:el)?if\b|;\s*$|^\s*\}|^\s*(?:else|except|catch)\b/.test(lines[k])) break;
    const s = of(k);
    if (s) return s;
  }
  for (let k = at + 1; k <= at + 2 && k < lines.length; k++) {
    if (/^\s*(?:\}|(?:el)?if\b|return\b|raise\b|throw\b)/.test(lines[k])) break;
    const s = of(k);
    if (s) return s;
  }
  return null;
}
/** The condition an answer stands under (nearest if / elif / catch / except above, within 6 lines). */
function condAbove(lines, at, start) {
  for (let j = at; j >= Math.max(start, at - 6); j--) {
    if (/\b(?:if|elif|catch|except|unless)\b|\?\s*$/.test(lines[j]) && !/^\s*(?:\/\/|#|\*)/.test(lines[j])) return lines[j];
  }
  return '';
}

export function genericAnswerAt(source, line) {
  if (!source || !line) return null;
  const lines = String(source).split(/\r?\n/);
  const n = Math.min(lines.length, Number(line)) - 1;
  let start = n;
  for (; start > 0 && start > n - 120; start--) if (FN_HEAD_RE.test(lines[start]) && !/^\s*(?:if|for|while|switch|catch|return|raise|throw)\b/.test(lines[start])) break;
  const base = indentOf(lines[start]);
  let end = start + 1;
  for (; end < lines.length && end < start + 200; end++) {
    const l = lines[end];
    if (l.trim() && end > n && indentOf(l) <= base && FN_HEAD_RE.test(l)) break;
  }
  // The answer may sit a line or two above the location (the location is the condition or the message itself).
  const mine = answerIn(lines, n) || answerIn(lines, Math.max(start, n - 1));
  if (!mine) return null;
  for (let i = start; i < end; i++) {
    if (Math.abs(i - mine.at) < 1 || !lines[i].includes(mine.message)) continue;
    const other = answerIn(lines, i);
    if (!other || other.at === mine.at || other.message !== mine.message || other.status !== mine.status) continue;
    // One of the two is about the missing account, the other about a bad token / credential.
    const c1 = condAbove(lines, mine.at, start);
    const c2 = condAbove(lines, other.at, start);
    const missing = [c1, c2].filter((c) => ACCOUNT_MISSING_COND_RE.test(c)).length;
    const credential = [c1, c2].find((c) => c && !ACCOUNT_MISSING_COND_RE.test(c));
    if (missing !== 1 || !credential) continue;
    if (!/token|code|otp|pass|pwd|credential|valid|verif|match|compare|expire|email|catch|except|decod|payload|hash|secret/i.test(credential)) continue;
    return { line: other.at + 1, message: other.message, status: other.status };
  }
  return null;
}
