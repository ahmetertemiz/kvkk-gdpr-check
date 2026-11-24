/**
 * Declared support per application stack (round 9).
 *
 * The tiers are measured, not claimed: counts are first-sight verdicts on projects nobody had tuned on (rounds n, r4-r8;
 * scored and review locations alike; gate and label-audit rounds excluded), summed per stack family by
 * scripts/measure-stack-support.js. The rule was fixed before looking at which stack lands where:
 *   supported     >= 3 projects and Wilson lower90 of the precision >= 0.70
 *   limited       >= 2 projects and lower90 >= 0.55
 *   experimental  everything else, including stacks never measured
 * An experimental stack makes the score unreliable: the number would suggest an accuracy nobody has measured.
 * 'supported' still means several confirmed issues per project are missed (missesPerRepo).
 */
export const SUPPORT_MIN_REPOS = 3;
export const SUPPORT_LOWER90 = 0.7;
export const LIMITED_MIN_REPOS = 2;
export const LIMITED_LOWER90 = 0.55;
/** A server family counts when it holds at least this share of the endpoints that were read. */
export const FAMILY_MIN_SHARE = 0.2;

/** id, label, repos, tp, fp, misses: output of scripts/measure-stack-support.js. */
export const SUPPORT = {
  'astro': { label: 'Astro', repos: 1, tp: 10, fp: 2, misses: 3 },
  'convex': { label: 'Convex', repos: 1, tp: 42, fp: 6, misses: 9 },
  'django': { label: 'Django', repos: 3, tp: 30, fp: 14, misses: 26 },
  'expo-rn': { label: 'Expo / React Native', repos: 4, tp: 31, fp: 2, misses: 15 },
  'express': { label: 'Express', repos: 4, tp: 55, fp: 20, misses: 31 },
  'fastapi': { label: 'FastAPI', repos: 1, tp: 8, fp: 14, misses: 4 },
  'fastify': { label: 'Fastify / Koa', repos: 1, tp: 19, fp: 37, misses: 5 },
  'flask': { label: 'Flask', repos: 1, tp: 20, fp: 6, misses: 8 },
  'flutter': { label: 'Flutter', repos: 3, tp: 14, fp: 2, misses: 14 },
  'hono': { label: 'Hono', repos: 1, tp: 7, fp: 2, misses: 2 },
  'laravel': { label: 'Laravel', repos: 2, tp: 21, fp: 14, misses: 13 },
  'nestjs': { label: 'NestJS', repos: 3, tp: 21, fp: 16, misses: 21 },
  'nextjs': { label: 'Next.js', repos: 8, tp: 214, fp: 39, misses: 40 },
  'nuxt': { label: 'Nuxt', repos: 1, tp: 0, fp: 1, misses: 7 },
  'react-spa': { label: 'React SPA (Vite, Lovable, Bolt)', repos: 8, tp: 154, fp: 38, misses: 34 },
  'remix': { label: 'Remix / React Router', repos: 3, tp: 41, fp: 15, misses: 11 },
  'sveltekit': { label: 'SvelteKit', repos: 3, tp: 55, fp: 12, misses: 17 },
};

const Z = 1.645;
function lower90(tp, n) {
  if (!n) return 0;
  const p = tp / n, z2 = Z * Z;
  return Math.max(0, (p + z2 / (2 * n) - Z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / (1 + z2 / n));
}

export function tierOf(c) {
  if (!c || !c.repos) return 'experimental';
  const l = lower90(c.tp, c.tp + c.fp);
  if (c.repos >= SUPPORT_MIN_REPOS && l >= SUPPORT_LOWER90) return 'supported';
  if (c.repos >= LIMITED_MIN_REPOS && l >= LIMITED_LOWER90) return 'limited';
  return 'experimental';
}

// Family of a server framework, as endpoints name it and as manifests name it.
const SERVER = [
  ['laravel', /laravel/, /^(?:laravel\/framework|illuminate\/)/i],
  ['rails', /rails/, /^rails$/i],
  ['django', /^django/, /^django$/i],
  ['flask', /^flask$/, /^flask$/i],
  ['fastapi', /^fastapi$/, /^fastapi$/i],
  ['nestjs', /^nest/, /^@nestjs\/core$/],
  ['nuxt', /^(?:nuxt|nitro|h3)/, /^nuxt3?$/],
  ['sveltekit', /^sveltekit/, /^@sveltejs\/kit$/],
  ['remix', /^(?:remix|react-router)/, /^@(?:remix-run|react-router)\/(?:node|serve|dev|cloudflare|server-runtime)$/],
  ['astro', /^astro/, /^astro$/],
  ['convex', /^convex/, /^convex$/],
  ['hono', /^hono$/, /^hono$/],
  ['fastify', /^(?:fastify|@fastify|koa|hapi|@hapi)/, /^(?:fastify|koa|@hapi\/hapi)$/],
  ['nextjs', /^(?:nextjs|trpc)/, /^next$/],
  ['express', /^(?:express|node)$/, /^express$/],
];
const CLIENT = [
  ['flutter', /^(?:flutter|supabase_flutter|firebase_core|cloud_firestore|firebase_auth)$/],
  ['expo-rn', /^(?:expo|react-native)$/],
  ['react-spa', /^(?:vite|react-scripts|@vitejs\/plugin-react(?:-swc)?)$/],
];

/**
 * @param {{deps?:Set<string>}} stack  @param {object[]} endpoints
 * @returns {{tier:string, families:{id,label,tier,repos,tp,fp,missesPerRepo}[]}|null}  null: nothing recognisable
 */
export function stackSupport(stack, endpoints = []) {
  const deps = [...(stack?.deps || [])];
  const has = (re) => deps.some((d) => re.test(d));
  const ids = [];
  const n = endpoints.length;
  for (const [id, fw] of SERVER) {
    const k = endpoints.filter((e) => fw.test(String(e.framework || ''))).length;
    if (n && k / n >= FAMILY_MIN_SHARE) ids.push(id);
  }
  // No endpoint was read, or the endpoints do not name their host (GraphQL): the manifest says what the server is.
  if (!ids.length) for (const [id, , dep] of SERVER) if (has(dep)) ids.push(id);
  for (const [id, dep] of CLIENT) if (has(dep) && !(id === 'react-spa' && ids.some((x) => ['nextjs', 'sveltekit', 'remix', 'astro', 'nuxt'].includes(x)))) ids.push(id);
  // A meta framework contains its bundler; a native client wins over the web bundler next to it.
  const list = [...new Set(ids)].filter((id) => !(id === 'react-spa' && (ids.includes('expo-rn') || ids.includes('flutter'))));
  if (!list.length) {
    if (!n) return null;
    list.push(String(endpoints[0].framework || 'unknown'));
  }
  const families = list.map((id) => {
    const c = SUPPORT[id] || { label: id, repos: 0, tp: 0, fp: 0, misses: 0 };
    return { id, label: c.label, tier: tierOf(c), repos: c.repos, tp: c.tp, fp: c.fp, missesPerRepo: c.repos ? Math.round((10 * c.misses) / c.repos) / 10 : null };
  });
  const order = ['experimental', 'limited', 'supported'];
  return { tier: order.find((x) => families.some((f) => f.tier === x)), families };
}
