// kvkk-ignore-file
/**
 * Technology detection and per-layer coverage.
 *
 *   detectStack(files)                → { techs: Tech[], deps:Set, imports:Map, languages }
 *   assessLayers(graph, files, stack) → { schema, routes, dbWrites, forms, ui, vendors, declarations }
 *
 * Each layer is { status, count, gaps:[{tech, label, reason}], detail? } where status is
 *   'found'               the layer was seen and no detected technology of that layer is missing
 *   'partial'             something was found, but a detected technology of the layer produced nothing, or what was
 *                         found is not usable (round 8): a table the code uses has no parsed column ('no-columns'),
 *                         the only endpoints are middleware / wildcard / framework-handler mounts ('middleware-only'),
 *                         (round 9) route registrations without an endpoint ('routes-unread'), endpoints whose own handler
 *                         was not found ('handlers-unread') or whose authentication stayed undecided ('auth-unknown'),
 *                         a vendor reached no transfer row, flow or deletion row ('not-consumed', vendorConsumption,
 *                         applied by index.js after the checks ran), or deletes rest on a partial schema
 *                         ('schema-partial')
 *   'none'                nothing was found and nothing suggests the layer exists
 *   'unsupported:<tech>'  a technology of this layer is in use, but nothing of it reached the graph
 *
 * The detection is generic: package names from every manifest kind (package.json, requirements,
 * pyproject, Gemfile, composer.json, go.mod, gradle), import specifiers in code (Deno `npm:` / `jsr:` /
 * esm.sh / deno.land URLs normalised), marker files (convex/, wrangler.toml, firebase.json …) and
 * technology-specific API calls. What the graph contains is then attributed to each technology
 * (store family, evidence file paths, imports of the file the fact came from). A technology that is
 * in use but has nothing attributed is a coverage gap: absence-based conclusions on that layer are
 * not trustworthy (see calibrate.js).
 */
import fs from 'node:fs';
import path from 'node:path';
import { routeCensus } from './route-census.js';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

/**
 * Technology table. Fields:
 *   id, label
 *   layer      'data' (provides stores + writes) | 'server' (provides routes) | 'both'
 *   family     data: 'sql' (any table store counts) | 'doc' (collections, attributed) | 'own' (attributed only)
 *   pkg        package-name regex (any ecosystem)
 *   marker     path regex of a marker file (counts as detection and use)
 *   use        code regex that proves real use (when absent, an import of `pkg` in code is the proof)
 *   evidence   path regex: graph facts with evidence in these files belong to the tech
 *   fw         Endpoint.framework regex (server techs)
 *   extractors extractor module names (src/audit/extract/<name>.js) that model this tech
 *   lang       source language the tech implies (for unsupported-language attribution)
 */
// A Node HTTP framework instance that registers no route with a literal path of its own (it only hosts another
// framework's request handler: Remix / React Router / Next / Astro adapters, static files, middleware) is listed as a
// technology but is not a routes-layer gap.
const ROUTE_USE = /\.(?:get|post|put|patch|delete|del|all|route|options|head)\s*\(\s*(?:\{\s*(?:method|url|path)\b|['"`]\/)|\.route\s*\(\s*\{/;

export const TECHS = [
  // ---- data layers, JS/TS ----
  { id: 'convex', label: 'Convex', layer: 'both', family: 'own', pkg: /^convex$/, marker: /(^|\/)convex\/schema\.[jt]s$/, use: /from\s+['"](?:convex\/|\.\.?\/_generated\/server)|\b(?:mutation|query|internalMutation|internalQuery|action)\s*\(\s*\{/, evidence: /(^|\/)convex\//, fw: /^convex/, extractors: ['convex'] },
  { id: 'supabase', label: 'Supabase (Postgres)', layer: 'data', family: 'sql', pkg: /^@supabase\/supabase-js$|^@supabase\/ssr$|^@supabase\/auth-helpers|^@nuxtjs\/supabase$|^supabase_flutter$|^supabase-kt$|^io\.github\.jan-tennert\.supabase:|^supabase-swift$/, marker: /(^|\/)supabase\/migrations\/[^/]+\.sql$/, use: /\.from\(\s*['"`][\w.]+['"`]\s*\)|\.rpc\(|\bSupabase\.instance\.client\b|\b(?:useSupabaseClient|serverSupabaseClient|serverSupabaseServiceRole|useSupabaseAuthClient)\s*(?:<[^>()]*>)?\s*\(/, needsUse: true, extractors: ['sql'] },
  { id: 'prisma', label: 'Prisma', layer: 'data', family: 'sql', pkg: /^@prisma\/client$|^prisma$/, marker: /\.prisma$/, use: /\bprisma\.\w+\.(?:find|create|update|upsert|delete)|new PrismaClient\b/, extractors: ['prisma'] },
  { id: 'drizzle', label: 'Drizzle', layer: 'data', family: 'sql', pkg: /^drizzle-orm$/, extractors: ['drizzle'] },
  { id: 'knex', label: 'Knex / Objection', layer: 'data', family: 'sql', pkg: /^(knex|objection)$/, use: /\bcreateTable\s*\(|\bknex\s*\(|extends\s+Model\b|\.query\(\)\.(?:insert|where|patch)/, extractors: ['knex'] },
  { id: 'typeorm', label: 'TypeORM', layer: 'data', family: 'sql', pkg: /^typeorm$/, use: /@Entity\s*\(|getRepository\s*\(|DataSource\s*\(/, extractors: ['typeorm'] },
  { id: 'sequelize', label: 'Sequelize', layer: 'data', family: 'sql', pkg: /^sequelize(-typescript)?$/, use: /sequelize\.define\s*\(|extends\s+Model\b|DataTypes\./, extractors: ['sequelize'] },
  { id: 'mikro-orm', label: 'MikroORM', layer: 'data', family: 'sql', pkg: /^@mikro-orm\//, extractors: ['mikro-orm'] },
  { id: 'kysely', label: 'Kysely', layer: 'data', family: 'sql', pkg: /^kysely$/, extractors: ['kysely'] },
  { id: 'pg', label: 'PostgreSQL (raw SQL)', layer: 'data', family: 'sql', pkg: /^(pg|postgres|pg-promise|@neondatabase\/serverless|@vercel\/postgres|slonik)$/, extractors: ['sql'] },
  { id: 'mysql', label: 'MySQL (raw SQL)', layer: 'data', family: 'sql', pkg: /^(mysql2?|mariadb|@planetscale\/database)$/, extractors: ['sql'] },
  { id: 'sqlite', label: 'SQLite', layer: 'data', family: 'sql', pkg: /^(better-sqlite3|sqlite3|sqlite|bun:sqlite|expo-sqlite)$/, extractors: ['sql'] },
  { id: 'libsql', label: 'Turso / libSQL', layer: 'data', family: 'sql', pkg: /^@libsql\/client$/, extractors: ['sql'] },
  { id: 'd1', label: 'Cloudflare D1', layer: 'data', family: 'sql', marker: /(^|\/)wrangler\.(toml|jsonc?)$/, markerContent: /d1_databases/, extractors: ['sql'] },
  { id: 'mongodb', label: 'MongoDB', layer: 'data', family: 'doc', pkg: /^(mongoose|mongodb|@typegoose\/typegoose|mongoist)$/, extractors: ['mongoose'] },
  // Dart / Kotlin / Swift: cloud_firestore (pub), com.google.firebase:firebase-firestore (Gradle), Firebase/Firestore (CocoaPods).
  { id: 'firestore', label: 'Firestore', layer: 'data', family: 'doc', hosted: ['firebase'], pkg: /^(firebase|firebase-admin|@react-native-firebase\/firestore|@google-cloud\/firestore|@firebase\/firestore|cloud_firestore|com\.google\.firebase:firebase-firestore(?:-ktx)?|Firebase\/Firestore|FirebaseFirestore)$/, use: /firebase\/firestore|getFirestore\s*\(|\.firestore\s*\(\s*\)|@react-native-firebase\/firestore|@google-cloud\/firestore|firestore\(\)|\bFirebaseFirestore\.(?:instance|getInstance\s*\()|\bFirestore\.firestore\s*\(|\bFirebase\.firestore\b|package:cloud_firestore\//, needsUse: true, extractors: ['firestore'] },
  // Firebase Authentication: no store of its own here, but Google processes the account data (hosted processor).
  { id: 'firebase-auth', label: 'Firebase Authentication', layer: 'service', hosted: ['firebase'], pkg: /^(firebase|firebase_auth|@react-native-firebase\/auth|com\.google\.firebase:firebase-auth(?:-ktx)?|Firebase\/Auth|FirebaseAuth)$/, use: /['"]firebase\/auth['"]|@react-native-firebase\/auth|\bFirebaseAuth\.(?:instance|getInstance\s*\()|\bAuth\.auth\s*\(\s*\)|\bFirebase\.auth\b|package:firebase_auth\//, needsUse: true },
  { id: 'firebase-rtdb', label: 'Firebase Realtime Database', layer: 'data', family: 'own', hosted: ['firebase'], pkg: /^(firebase|firebase-admin|@react-native-firebase\/database|firebase_database)$/, use: /firebase\/database['"]|getDatabase\s*\(|\.database\s*\(\s*\)\.ref\(|@react-native-firebase\/database|\bFirebaseDatabase\.instance\b|package:firebase_database\//, needsUse: true, strict: true, extractors: ['firebase-rtdb'] },
  { id: 'dynamodb', label: 'DynamoDB', layer: 'data', family: 'own', pkg: /^(@aws-sdk\/client-dynamodb|@aws-sdk\/lib-dynamodb|dynamoose|electrodb|aws-sdk|boto3)$/, use: /DynamoDB(?:Client|DocumentClient)?\b|dynamoose\.|boto3\.(?:resource|client)\(\s*['"]dynamodb/, needsUse: true, extractors: ['dynamodb'] },
  { id: 'appwrite', label: 'Appwrite', layer: 'data', family: 'own', hosted: ['appwrite'], pkg: /^(appwrite|node-appwrite|react-native-appwrite)$/, use: /\bDatabases\s*\(|\.createDocument\s*\(|\.listDocuments\s*\(/, needsUse: true, extractors: ['appwrite'] },
  { id: 'pocketbase', label: 'PocketBase', layer: 'data', family: 'own', pkg: /^pocketbase$/, use: /\.collection\(\s*['"`]/, extractors: ['pocketbase'] },
  { id: 'hasura', label: 'Hasura', layer: 'data', family: 'own', marker: /(^|\/)hasura\/(metadata|migrations)\//, extractors: ['hasura'] },
  { id: 'sanity', label: 'Sanity', layer: 'data', family: 'own', pkg: /^(@sanity\/client|next-sanity|sanity)$/, use: /defineType\s*\(|createClient\s*\(|\.fetch\(\s*`?\*\[/, extractors: ['sanity'] },
  { id: 'strapi', label: 'Strapi', layer: 'both', family: 'own', pkg: /^@strapi\/strapi$/, marker: /(^|\/)src\/api\/[^/]+\/content-types\//, extractors: ['strapi'] },
  { id: 'directus', label: 'Directus', layer: 'data', family: 'own', pkg: /^@directus\/sdk$/, extractors: ['directus'] },
  { id: 'xata', label: 'Xata', layer: 'data', family: 'own', pkg: /^@xata\.io\/client$/, extractors: ['xata'] },
  { id: 'fauna', label: 'Fauna', layer: 'data', family: 'own', pkg: /^(faunadb|fauna)$/, extractors: ['fauna'] },
  // ---- data layers, other ecosystems ----
  { id: 'sqlalchemy', label: 'SQLAlchemy', layer: 'data', family: 'sql', pkg: /^(sqlalchemy|flask-sqlalchemy|sqlmodel|alembic)$/i, lang: 'python', extractors: ['orm-python'] },
  { id: 'django', label: 'Django ORM', layer: 'both', family: 'sql', pkg: /^django$/i, use: /models\.Model\b/, lang: 'python', extractors: ['orm-python'], fw: /^django$/ },
  { id: 'peewee', label: 'Peewee / Tortoise', layer: 'data', family: 'sql', pkg: /^(peewee|tortoise-orm)$/i, lang: 'python', extractors: ['orm-python'] },
  { id: 'pymongo', label: 'MongoDB (Python)', layer: 'data', family: 'doc', pkg: /^(pymongo|motor|mongoengine|beanie)$/i, lang: 'python', extractors: ['mongo-python'] },
  { id: 'activerecord', label: 'Rails / ActiveRecord', layer: 'both', family: 'sql', pkg: /^(rails|activerecord)$/, marker: /(^|\/)db\/schema\.rb$|(^|\/)app\/models\/[^/]+\.rb$/, lang: 'ruby', extractors: ['activerecord', 'rails'] },
  { id: 'eloquent', label: 'Laravel / Eloquent', layer: 'both', family: 'sql', pkg: /^laravel\/framework$|^illuminate\/database$/, marker: /(^|\/)database\/migrations\/[^/]+\.php$/, lang: 'php', extractors: ['eloquent', 'laravel'] },
  { id: 'doctrine', label: 'Doctrine', layer: 'data', family: 'sql', pkg: /^doctrine\/orm$/, lang: 'php', extractors: ['doctrine'] },
  { id: 'jpa', label: 'Spring / JPA', layer: 'both', family: 'sql', pkg: /spring-boot-starter-data-jpa|hibernate-core|spring-boot-starter-web/, use: /@Entity\b|@RestController\b/, exts: ['java', 'kt'], lang: 'java', extractors: ['jpa', 'spring'] },
  { id: 'gorm', label: 'GORM / Go SQL', layer: 'data', family: 'sql', pkg: /^(gorm\.io\/gorm|github\.com\/jackc\/pgx|entgo\.io\/ent|github\.com\/jmoiron\/sqlx)/, lang: 'go', extractors: ['gorm', 'go'] },
  { id: 'ecto', label: 'Ecto', layer: 'data', family: 'sql', marker: /(^|\/)priv\/repo\/migrations\/[^/]+\.exs$/, lang: 'elixir', extractors: ['ecto'] },
  // ---- server / route layers ----
  { id: 'supabase-functions', label: 'Supabase Edge Functions', layer: 'server', pkg: /^@supabase\/functions-js$/, marker: /(^|\/)supabase\/functions\/[^/]+\/index\.[jt]s$/, fw: /^supabase-edge$/, evidence: /(^|\/)supabase\/functions\// },
  { id: 'firebase-functions', label: 'Firebase Cloud Functions', layer: 'server', pkg: /^firebase-functions$/, use: /\bon(?:Call|Request|DocumentCreated|DocumentWritten)\s*\(|functions\.https\./, needsUse: true, fw: /^firebase-functions$/ },
  { id: 'trpc', label: 'tRPC', layer: 'server', pkg: /^@trpc\/server$/, use: /\b(?:public|protected|admin)Procedure\b|\.procedure\b/, needsUse: true, fw: /trpc/ },
  { id: 'graphql', label: 'GraphQL server', layer: 'server', pkg: /^(@apollo\/server|apollo-server(-\w+)?|graphql-yoga|type-graphql|@nestjs\/graphql|mercurius|pothos|@pothos\/core)$/, fw: /graphql/ },
  { id: 'nestjs', label: 'NestJS', layer: 'server', pkg: /^@nestjs\/core$/, use: /@Controller\s*\(/, needsUse: true, fw: /nest/ },
  { id: 'rails', label: 'Rails controllers', layer: 'server', marker: /(^|\/)app\/controllers\/[^/]+\.rb$/, lang: 'ruby', fw: /rails/ },
  { id: 'laravel', label: 'Laravel routes', layer: 'server', marker: /(^|\/)routes\/(web|api)\.php$/, lang: 'php', fw: /laravel/ },
  { id: 'go-http', label: 'Go HTTP server', layer: 'server', pkg: /^(github\.com\/gin-gonic\/gin|github\.com\/labstack\/echo|github\.com\/gofiber\/fiber|github\.com\/go-chi\/chi|github\.com\/gorilla\/mux)/, lang: 'go', fw: /^go/ },
  // Astro: an exported GET/POST alone is not Astro (a Next app-router route.ts has the same shape). A use file must be a
  // .astro file, import from 'astro' / 'astro:*', or sit under src/pages | src/actions of an Astro package root (a
  // directory holding astro.config.* or a package.json that depends on astro); see inScope().
  { id: 'astro', label: 'Astro endpoints / actions', layer: 'server', pkg: /^astro$/, use: /\bexport\s+(?:const|async\s+function|function)\s+(?:GET|POST|PUT|PATCH|DELETE|ALL)\b|\bdefineAction\s*\(/, needsUse: true, scope: 'astro', fw: /^astro/ },
  // Nuxt / Nitro server routes (server/api, server/routes: defineEventHandler). routes.js models them as framework
  // 'nuxt'; when it produced none, the routes layer says so instead of a silent 0.
  { id: 'nuxt-server', label: 'Nuxt server routes', layer: 'server', pkg: /^(?:nuxt|nuxt3|nitropack|nitro|h3)$/, use: /\b(?:defineEventHandler|eventHandler|defineCachedEventHandler)\s*\(/, needsUse: true, fw: /^(?:nuxt|nitro|h3)/ },
  // Node HTTP frameworks. routes.js names Express-style endpoints after the import origin of the router ('fastify',
  // 'express', 'koa' …), or 'node' when the instance arrives as a parameter (a plugin / route module).
  { id: 'fastify', label: 'Fastify', layer: 'server', pkg: /^fastify$/, use: /\b(?:fastify|Fastify)\s*\(\s*[{)]|\bFastify(?:Instance|PluginAsync|PluginCallback|Request|Reply)\b/, routeUse: ROUTE_USE, fw: /^(?:fastify|@fastify|node)$/ },
  { id: 'express', label: 'Express', layer: 'server', pkg: /^express$/, use: /\bexpress\s*\(\s*\)|\bexpress\.Router\s*\(|\bRouter\s*\(\s*\)/, needsUse: true, importOnly: true, routeUse: ROUTE_USE, fw: /^(?:express|node)$/ },
  { id: 'koa', label: 'Koa', layer: 'server', pkg: /^(?:koa|@koa\/router|koa-router)$/, use: /\bnew\s+(?:Koa|Router)\s*\(/, needsUse: true, importOnly: true, routeUse: ROUTE_USE, fw: /^(?:koa|@koa|koa-router|node)$/ },
  { id: 'hapi', label: 'hapi', layer: 'server', pkg: /^@hapi\/hapi$/, use: /\bHapi\.server\s*\(|\bserver\.route\s*\(/, needsUse: true, importOnly: true, routeUse: ROUTE_USE, fw: /^(?:@hapi|hapi)$/ },
  { id: 'elysia', label: 'Elysia', layer: 'server', pkg: /^elysia$/, use: /\bnew\s+Elysia\s*\(/, needsUse: true, importOnly: true, routeUse: ROUTE_USE, fw: /^elysia$/ },
  { id: 'hono', label: 'Hono', layer: 'server', pkg: /^hono$/, use: /\bnew\s+Hono\s*(?:<[^>]*>)?\s*\(/, needsUse: true, fw: /^hono$/ },
  { id: 'remix', label: 'Remix / React Router (loaders, actions)', layer: 'server', pkg: /^@remix-run\/(?:node|server-runtime|cloudflare|deno|react)$|^@react-router\/(?:node|serve|dev|cloudflare)$/, use: /\bexport\s+(?:async\s+)?function\s+(?:loader|action)\b|\bexport\s+const\s+(?:loader|action)\s*[:=]/, needsUse: true, fw: /^remix$|^react-router/ },
  { id: 'appwrite-functions', label: 'Appwrite Functions', layer: 'server', marker: /(^|\/)appwrite\.json$/, markerContent: /"functions"\s*:\s*\[\s*\{/, fw: /^appwrite/ },
  // Server frameworks of other ecosystems: named so that "in use, but no endpoint read" is a gap and not a silent 0 (round 9).
  { id: 'flask', label: 'Flask', layer: 'server', pkg: /^flask$/i, use: /\b(?:Flask|Blueprint)\s*\(/, needsUse: true, importOnly: true, lang: 'python', fw: /^flask$/ },
  { id: 'fastapi', label: 'FastAPI', layer: 'server', pkg: /^fastapi$/i, use: /\b(?:FastAPI|APIRouter)\s*\(/, needsUse: true, importOnly: true, lang: 'python', fw: /^fastapi$/ },
  { id: 'django-urls', label: 'Django', layer: 'server', pkg: /^django$/i, use: /\burlpatterns\b[^=\n]*\+?=/, needsUse: true, importOnly: true, lang: 'python', fw: /^django$/ },
  { id: 'python-web', label: 'Python web framework', layer: 'server', pkg: /^(?:starlette|litestar|sanic|quart|bottle|falcon|tornado|cherrypy|pyramid)$/i, use: /\b(?:Starlette|Litestar|Sanic|Quart|Bottle|Configurator)\s*\(|\bfalcon\.(?:asgi\.)?App\s*\(|\btornado\.web\.Application\s*\(|\bcherrypy\.quickstart\s*\(/, needsUse: true, importOnly: true, lang: 'python', fw: /^(?:starlette|litestar|sanic|quart|bottle|falcon|tornado|cherrypy|pyramid)$/ },
  { id: 'aiohttp-web', label: 'aiohttp server', layer: 'server', pkg: /^aiohttp$/i, use: /\bweb\.Application\s*\(/, needsUse: true, importOnly: true, lang: 'python', fw: /^aiohttp$/ },
  { id: 'php-web', label: 'PHP web framework', layer: 'server', pkg: /^(?:symfony\/framework-bundle|slim\/slim|codeigniter4\/framework|yiisoft\/yii2|cakephp\/cakephp)$/, use: /#\[Route\(|@Route\(|->(?:get|post|map|group)\(\s*['"]\/|extends\s+\w*Controller\b/, needsUse: true, exts: ['php'], lang: 'php', fw: /^(?:symfony|slim|codeigniter|yii|cakephp)/ },
  { id: 'aspnet', label: 'ASP.NET', layer: 'server', use: /\[ApiController\]|\[Http(?:Get|Post|Put|Patch|Delete)\b|\.Map(?:Get|Post|Put|Delete)\s*\(/, needsUse: true, exts: ['cs'], lang: 'c#', fw: /aspnet/ },
  { id: 'sinatra', label: 'Sinatra', layer: 'server', pkg: /^sinatra$/, use: /^\s*(?:get|post|put|patch|delete)\s+['"]\//m, needsUse: true, exts: ['rb'], lang: 'ruby', fw: /sinatra/ },
  { id: 'phoenix', label: 'Phoenix', layer: 'server', marker: /(^|\/)lib\/[^/]+_web\/router\.ex$/, lang: 'elixir', fw: /phoenix/ },
  { id: 'spring-web', label: 'Spring MVC', layer: 'server', use: /@(?:Rest)?Controller\b/, needsUse: true, exts: ['java', 'kt'], lang: 'java', fw: /spring/ },
];

// Languages the engine parses (graph extractors exist) vs. languages it only skims.
const SUPPORTED_EXT = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue', 'svelte', 'astro', 'py', 'prisma']);
const UNSUPPORTED_EXT = { rb: 'ruby', erb: 'ruby', php: 'php', blade: 'php', twig: 'php', go: 'go', java: 'java', kt: 'kotlin', kts: 'kotlin', swift: 'swift', dart: 'dart', cs: 'c#', ex: 'elixir', exs: 'elixir' };
const UI_EXT = new Set(['jsx', 'tsx', 'vue', 'svelte', 'astro', 'html', 'htm', 'erb', 'blade', 'twig', 'dart', 'swift']);

/** Normalise an import specifier to a package name (Deno npm:/jsr:/esm.sh/deno.land/x, @version, subpaths). */
export function normalizeSpecifier(spec) {
  let s = String(spec || '').trim();
  if (!s || s.startsWith('.') || s.startsWith('/') || s.startsWith('#') || s.startsWith('~') || s.startsWith('$')) return null;
  s = s.replace(/^(?:npm|jsr|node):/, '');
  const url = s.match(/^https?:\/\/(?:esm\.sh|cdn\.skypack\.dev|esm\.run|cdn\.jsdelivr\.net\/npm|unpkg\.com|deno\.land\/x|jspm\.dev(?:\/npm:)?|ga\.jspm\.io\/npm:)\/(?:v\d+\/)?(.+)$/i);
  if (url) s = url[1];
  else if (/^https?:/.test(s)) return null;
  s = s.split(/[?#]/)[0];
  const parts = s.split('/');
  let name = parts[0].startsWith('@') && parts.length > 1 ? `${parts[0]}/${parts[1]}` : parts[0];
  // strip @version (but keep the scope's leading @)
  name = name.replace(/^(@?[^@]+)@.*$/, '$1');
  if (name.startsWith('@') && name.includes('/')) {
    const [scope, pkg] = name.split('/');
    name = `${scope}/${pkg.replace(/@.*$/, '')}`;
  }
  return name || null;
}

const IMPORT_RES = [
  /\bfrom\s+['"]([^'"]+)['"]/g,
  /\bimport\s+['"]([^'"]+)['"]/g,
  /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\bimport\(\s*['"]([^'"]+)['"]\s*\)/g,
];
const PY_IMPORT_RE = /^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))/gm;

const MANIFEST_NAMES = new Set(['deno.json', 'deno.jsonc', 'import_map.json', 'Pipfile', 'Cargo.toml', 'pubspec.yaml', 'Podfile', 'Directory.Packages.props']);

/**
 * Config text with its comments blanked out (line count kept), so that a commented-out section or dependency never counts
 * as configuration. Handles `#` (TOML, YAML, .properties / .env, Dockerfile, Gemfile, Podfile, Pipfile, requirements),
 * `//` and block comments (JSONC, Gradle, JS config modules) and XML comments (project files). String-aware: a `#` or
 * `//` inside a quoted value stays. Files of any other kind are returned unchanged.
 */
export function stripConfigComments(content, rel = '') {
  const c = String(content ?? '');
  const base = path.basename(String(rel).replace(/\\/g, '/'));
  if (/\.(?:cs|fs|vb)proj$|\.(?:xml|props|plist)$/i.test(base)) return c.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, ' '));
  const hash = /\.(?:toml|ya?ml|properties|ini|cfg|conf|tf)$/i.test(base) || /^\.env(?:\.|$)/.test(base) || /^(?:Pipfile|Gemfile|Podfile|Dockerfile|Procfile)(?:\.|$)/.test(base) || /^requirements[\w.-]*\.txt$/.test(base);
  const slash = /\.(?:jsonc?|json5|gradle|kts)$/i.test(base) || /\.config\.[cm]?[jt]s$/i.test(base);
  if (!hash && !slash) return c;
  const yaml = /\.ya?ml$/i.test(base);
  let out = '';
  let quote = null; // quote character(s) the scanner is inside of
  for (let i = 0; i < c.length; i++) {
    const ch = c[i];
    if (quote) {
      if (ch === '\\' && quote[0] !== "'" ) { out += ch + (c[i + 1] ?? ''); i++; continue; }
      if (c.startsWith(quote, i)) { out += quote; i += quote.length - 1; quote = null; continue; }
      // an ordinary string literal never spans lines (a stray apostrophe must not swallow the rest of the file)
      if (ch === '\n' && quote.length === 1 && quote !== '`') quote = null;
      out += ch;
      continue;
    }
    if (ch === '"' || ch === "'" || (slash && ch === '`')) {
      // YAML / plain text: an apostrophe inside a word is not a string delimiter
      if (ch === "'" && /\w/.test(c[i - 1] || '')) { out += ch; continue; }
      quote = hash && !yaml && c.startsWith(ch.repeat(3), i) ? ch.repeat(3) : ch;
      out += quote;
      i += quote.length - 1;
      continue;
    }
    if (hash && ch === '#' && (i === 0 || /\s/.test(c[i - 1]) || /\.toml$/i.test(base) || /^Pipfile$/.test(base))) {
      while (i < c.length && c[i] !== '\n') { out += c[i] === '\r' ? '\r' : ' '; i++; }
      if (i < c.length) out += '\n';
      continue;
    }
    if (slash && ch === '/' && c[i + 1] === '/') {
      while (i < c.length && c[i] !== '\n') { out += c[i] === '\r' ? '\r' : ' '; i++; }
      if (i < c.length) out += '\n';
      continue;
    }
    if (slash && ch === '/' && c[i + 1] === '*') {
      const end = c.indexOf('*/', i + 2);
      const stop = end < 0 ? c.length : end + 2;
      out += c.slice(i, stop).replace(/[^\n]/g, ' ');
      i = stop - 1;
      continue;
    }
    out += ch;
  }
  return out;
}

function extOf(rel) {
  const b = path.basename(rel);
  return b.includes('.') ? b.split('.').pop().toLowerCase() : '';
}

/** Package names declared in a manifest file (any ecosystem). */
function manifestDeps(f) {
  const out = [];
  const base = path.basename(f.rel);
  const c = stripConfigComments(f.content, f.rel);
  try {
    if (base === 'package.json') {
      const j = JSON.parse(c);
      for (const k of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) out.push(...Object.keys(j[k] || {}));
    } else if (base === 'composer.json') {
      const j = JSON.parse(c);
      out.push(...Object.keys(j.require || {}), ...Object.keys(j['require-dev'] || {}));
    }
  } catch { /* malformed manifest */ }
  if (base === 'requirements.txt' || /^requirements[\w-]*\.txt$/.test(base)) {
    for (const l of c.split(/\r?\n/)) { const m = l.match(/^\s*([A-Za-z0-9_.-]+)/); if (m && !l.trim().startsWith('#')) out.push(m[1].toLowerCase()); }
  }
  if (base === 'pyproject.toml' || base === 'Pipfile') {
    for (const m of c.matchAll(/["']?([A-Za-z0-9_.-]+)["']?\s*(?:[<>=~^!]=?|=\s*["'{*]|\[)/g)) out.push(m[1].toLowerCase());
  }
  if (base === 'Gemfile') for (const m of c.matchAll(/^\s*gem\s+['"]([^'"]+)['"]/gm)) out.push(m[1]);
  if (base === 'go.mod') for (const m of c.matchAll(/^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]+\/[^\s]+)\s+v\d/gm)) out.push(m[1]);
  if (/^build\.gradle(\.kts)?$/.test(base)) for (const m of c.matchAll(/['"]([\w.-]+:[\w.-]+)(?::[^'"]*)?['"]/g)) out.push(m[1]);
  // pubspec.yaml (Dart / Flutter): keys one level under dependencies / dev_dependencies / dependency_overrides.
  if (base === 'pubspec.yaml') {
    let inDeps = false;
    for (const l of c.split(/\r?\n/)) {
      if (/^\S/.test(l)) { inDeps = /^(?:dependencies|dev_dependencies|dependency_overrides)\s*:/.test(l); continue; }
      if (!inDeps) continue;
      const m = l.match(/^ {1,4}([A-Za-z_][\w]*)\s*:/);
      if (m && !/^ {5,}/.test(l)) out.push(m[1]);
    }
  }
  // Podfile (CocoaPods): pod 'Firebase/Firestore'
  if (base === 'Podfile') for (const m of c.matchAll(/^\s*pod\s+['"]([^'"]+)['"]/gm)) out.push(m[1]);
  // Cargo.toml: [dependencies] name = …, [dependencies.name]
  if (base === 'Cargo.toml') {
    let inDeps = false;
    for (const l of c.split(/\r?\n/)) {
      const sec = l.match(/^\s*\[([^\]]+)\]/);
      if (sec) {
        const dm = sec[1].match(/^(?:[\w.-]+\.)?(?:dev-|build-)?dependencies(?:\.([\w-]+))?$/);
        inDeps = !!dm && !dm[1];
        if (dm && dm[1]) out.push(dm[1]);
        continue;
      }
      if (!inDeps) continue;
      const m = l.match(/^\s*([A-Za-z0-9_-]+)\s*=/);
      if (m) out.push(m[1]);
    }
  }
  // .NET project files: <PackageReference Include="Name" … />
  if (/\.(?:cs|fs|vb)proj$/i.test(base) || base === 'Directory.Packages.props') for (const m of c.matchAll(/<Package(?:Reference|Version)\s+Include\s*=\s*["']([^"']+)["']/g)) out.push(m[1]);
  if (base === 'deno.json' || base === 'import_map.json' || base === 'deno.jsonc') {
    for (const m of c.matchAll(/["']((?:npm|jsr):[^"']+|https?:\/\/[^"']+)["']/g)) { const n = normalizeSpecifier(m[1]); if (n) out.push(n); }
  }
  return out;
}

/** Quoted entries of a `modules: [...]` array in a framework config (nuxt.config.ts). */
export function configModules(content) {
  const out = [];
  const m = /\bmodules\s*:\s*\[/.exec(String(content || ''));
  if (!m) return out;
  const body = argText(String(content), m.index + m[0].length - 1, 4000);
  for (const x of body.matchAll(/['"`](@?[\w.-]+(?:\/[\w.-]+)?)['"`]/g)) { const n = normalizeSpecifier(x[1]); if (n) out.push(n); }
  return out;
}

/**
 * Astro scope: is a file that matched the Astro API shape really Astro? `.astro` files, files importing 'astro' /
 * 'astro:*', and files under src/pages or src/actions of an Astro package root (directory of an astro.config.* or of a
 * package.json depending on astro). A Next.js app-router route.ts elsewhere in the same monorepo is not.
 */
export function astroScope(files = []) {
  const roots = [];
  for (const f of files) {
    if (!f || !f.rel) continue;
    const base = path.basename(f.rel);
    const dir = f.rel.slice(0, f.rel.length - base.length);
    if (/^astro\.config\.[cm]?[jt]s$/.test(base)) roots.push(dir);
    else if (base === 'package.json') {
      try {
        const j = JSON.parse(f.content || '{}');
        if (['dependencies', 'devDependencies'].some((k) => j?.[k] && Object.prototype.hasOwnProperty.call(j[k], 'astro'))) roots.push(dir);
      } catch { /* malformed manifest */ }
    }
  }
  return (f, imps) => {
    if (/\.astro$/i.test(f.rel)) return true;
    if (imps && [...imps].some((x) => x === 'astro' || /^astro:/.test(x))) return true;
    if (/(?:^|[\s,{])from\s+['"]astro(?::[\w-]+)?['"]/.test(f.content || '')) return true;
    return roots.some((r) => f.rel.startsWith(`${r}src/pages/`) || f.rel.startsWith(`${r}src/actions/`));
  };
}

/**
 * Detect technologies in use.
 * @returns {{techs:{id,label,layer,family,useFiles:number,files:string[],marker:boolean}[], deps:Set<string>, importsByFile:Map<string,Set<string>>, languages:{supported:number, unsupported:Object<string,number>}, uiFiles:number}}
 */
export function detectStack(files = []) {
  const deps = new Set();
  const importsByFile = new Map();
  const languages = { supported: 0, unsupported: {} };
  let uiFiles = 0;
  // Dart counts as a parsed language only when a Dart extractor is installed (feature detection).
  const dartParsed = extractorNames().has('dart');
  for (const f of files) {
    const base = path.basename(f.rel);
    if (f.kind === 'manifest' || MANIFEST_NAMES.has(base) || /\.(?:cs|fs|vb)proj$/i.test(base)) for (const d of manifestDeps(f)) deps.add(d);
    // Framework module lists (nuxt.config: modules: ['@nuxtjs/supabase', …]) declare integrations without an import.
    if (/^nuxt\.config\.[cm]?[jt]s$/.test(base)) for (const d of configModules(stripConfigComments(f.content, f.rel))) deps.add(d);
    if (f.kind !== 'code') continue;
    const ext = extOf(f.rel);
    if (SUPPORTED_EXT.has(ext) || (ext === 'dart' && dartParsed)) languages.supported++;
    else if (UNSUPPORTED_EXT[ext] && !(ext === 'dart' && dartParsed)) languages.unsupported[UNSUPPORTED_EXT[ext]] = (languages.unsupported[UNSUPPORTED_EXT[ext]] || 0) + 1;
    if (UI_EXT.has(ext) || (/\.(?:jsx?|tsx)$/.test(f.rel) && /<[A-Z][\w.]*[\s/>]|<(?:div|form|input|button|View|Text)\b/.test(f.content || '')) || (ext === 'ts' && /<(?:div|form|input|button)\b/.test(f.content || ''))) uiFiles++;
    const imps = new Set();
    const c = f.content || '';
    if (ext === 'py') {
      for (const m of c.matchAll(PY_IMPORT_RE)) { const n = (m[1] || m[2] || '').split('.')[0]; if (n) imps.add(n.toLowerCase()); }
    } else if (!['sql', 'prisma', 'rules', 'graphql', 'gql', 'html', 'htm'].includes(ext)) {
      for (const re of IMPORT_RES) for (const m of c.matchAll(re)) { const n = normalizeSpecifier(ext === 'dart' ? m[1].replace(/^package:/, '') : m[1]); if (n && !/^dart:/.test(n)) imps.add(n); }
    }
    if (imps.size) importsByFile.set(f.rel, imps);
  }
  const allImports = new Set();
  for (const s of importsByFile.values()) for (const x of s) allImports.add(x);

  const scopes = { astro: astroScope(files) };
  const techs = [];
  for (const t of TECHS) {
    const pkgHit = t.pkg ? [...deps, ...allImports].some((d) => t.pkg.test(d)) : false;
    const markerFiles = t.marker ? files.filter((f) => t.marker.test(f.rel) && (!t.markerContent || t.markerContent.test(stripConfigComments(f.content, f.rel)))).map((f) => f.rel) : [];
    const useOnly = !t.pkg && !t.marker; // detected by API use alone (e.g. Spring annotations)
    if (!pkgHit && !markerFiles.length && !useOnly) continue;
    // Proof of use: marker files, files importing the package, or files calling the tech-specific API.
    const useFiles = new Set(markerFiles);
    for (const f of files) {
      if (f.kind !== 'code') continue;
      if (t.exts && !t.exts.includes(extOf(f.rel))) continue;
      const imps = importsByFile.get(f.rel);
      const imported = !!(t.pkg && imps && [...imps].some((x) => t.pkg.test(x)));
      const apiUse = !!(t.use && t.use.test(f.content || ''));
      let ok = t.needsUse ? apiUse && (!t.importOnly || imported) : imported || (apiUse && (pkgHit || useOnly));
      if (ok && t.scope && scopes[t.scope]) ok = scopes[t.scope](f, imps);
      if (ok) useFiles.add(f.rel);
    }
    if (!useFiles.size) continue;
    const ownRoutes = t.routeUse ? files.some((f) => useFiles.has(f.rel) && t.routeUse.test(f.content || '')) : true;
    techs.push({ id: t.id, label: t.label, layer: t.layer, family: t.family || null, ownRoutes, useFiles: useFiles.size, files: [...useFiles].slice(0, 5), marker: markerFiles.length > 0, useExts: [...new Set([...useFiles].map(extOf))] });
  }
  return { techs, deps, importsByFile, languages, uiFiles };
}

let _extractorNames = null;
/** Names of the installed extractor modules (feature detection for "is this tech modelled at all"). */
export function extractorNames() {
  if (_extractorNames) return _extractorNames;
  try {
    _extractorNames = new Set(fs.readdirSync(path.join(here, '..', 'extract')).filter((f) => f.endsWith('.js') && !f.startsWith('_')).map((f) => f.replace(/\.js$/, '')));
  } catch {
    _extractorNames = new Set();
  }
  return _extractorNames;
}

const techDef = (id) => TECHS.find((t) => t.id === id);
const evFiles = (n) => [n?.file, ...(n?.evidence || []).map((e) => e?.file)].filter(Boolean);

/** Does a graph node (store / endpoint) belong to the technology? */
function attributed(node, def, importsByFile) {
  const files = evFiles(node);
  const tag = `${node.tech || ''} ${node.orm || ''} ${node.provider || ''} ${node.source || ''} ${node.framework || ''}`.toLowerCase();
  if (tag.includes(def.id)) return true;
  if (def.fw && node.framework && def.fw.test(String(node.framework))) return true;
  if (def.evidence && files.some((f) => def.evidence.test(f))) return true;
  if (def.marker && files.some((f) => def.marker.test(f))) return true;
  if (!def.strict && def.pkg && files.some((f) => [...(importsByFile.get(f) || [])].some((x) => def.pkg.test(x)))) return true;
  return false;
}

// Store kinds that hold records (tables, document collections) and their columns. Entities are what a layer count means.
const isRecord = (s) => s && (s.kind === 'table' || s.kind === 'collection' || s.kind === 'column');

// Gap reasons that come from artefacts the engine saw but did not analyse (contract C2) or from SDKs it cannot place.
export const NOT_PARSED_REASONS = new Set(['not-parsed', 'unknown-sdk', 'unknown-vendor']);

function statusOf(count, gaps) {
  const unsup = gaps.find((g) => g.reason === 'unsupported');
  if (unsup && !count) return `unsupported:${unsup.tech}`;
  // A technology of the layer is in use but nothing of it reached the graph: that is the definition of
  // 'unsupported:<tech>' (header), not a silent 'none' / 0.
  if (gaps.length && !count) return `unsupported:${gaps[0].tech}`;
  if (gaps.length) return 'partial'; // something of the layer was found, a detected technology of it produced nothing
  return count ? 'found' : 'none';
}

/**
 * Abstract model classes (Django `class Meta: abstract = True`, SQLAlchemy `__abstract__ = True`) define no table of
 * their own. An extractor may already flag them (`abstract: true`); otherwise the class body is checked here.
 */
function abstractChecker(files) {
  const byRel = new Map();
  for (const f of files || []) if (f && f.rel) byRel.set(f.rel, f);
  const memo = new Map();
  return (s) => {
    if (s.abstract === true) return true;
    if (s.abstract === false || !s.file || !/\.py$/.test(s.file)) return false;
    const name = s.model || s.name;
    if (!name) return false;
    const key = `${s.file}#${name}`;
    if (memo.has(key)) return memo.get(key);
    const body = pyClassBody(byRel.get(s.file)?.content || '', name);
    const abs = !!body && (/^\s+abstract\s*=\s*True\b/m.test(body) || /^\s+__abstract__\s*=\s*True\b/m.test(body));
    memo.set(key, abs);
    return abs;
  };
}

function pyClassBody(src, name) {
  const re = new RegExp(`^class\\s+${String(name).replace(/[^\w]/g, '')}\\s*[(:][^\\n]*\\n`, 'im');
  const m = re.exec(src);
  if (!m) return null;
  const rest = src.slice(m.index + m[0].length);
  const end = rest.search(/^\S/m);
  return end < 0 ? rest : rest.slice(0, end);
}

/* ---------------------------------------------------------------- unparsed artefacts (contract C2) */

const MOBILE_LANG = { dart: 'Dart', kt: 'Kotlin', kts: 'Kotlin', swift: 'Swift' };
// Platform shells generated around a cross-platform app (Flutter / React Native): MainActivity, AppDelegate, plugin
// registrants. They hold no app logic, so they are not "unparsed app code".
const PLATFORM_SHELL = /(^|\/)(?:android|ios|macos|windows|linux|web)\//;
const GENERATED_CODE = /(?:^|\/)(?:GeneratedPluginRegistrant\.\w+|firebase_options\.dart)$|\.(?:g|freezed|gr|config|mocks)\.dart$/;
// Option keys that carry a credential for a remote service: an SDK constructed with one talks to that service.
const NET_KEY_NAMES = /^(?:token|apiKey|api_key|apikey|dsn|accessToken|access_token|authToken|auth_token|writeKey|write_key|ingestKey|ingest_key)$/;
const NET_KEY = /\b(?:token|apiKey|api_key|apikey|dsn|accessToken|access_token|authToken|auth_token|writeKey|write_key|ingestKey|ingest_key)["']?\s*[:=]/;
// Values that are no credential: placeholders, booleans, or an object / array (a schema field definition).
const PLACEHOLDER_VALUE = /^\s*(?:null|undefined|None|false|False|true|True|0|''|""|``)\s*[,})\n]|^\s*[{[]/;
const NODE_BUILTIN = /^(?:assert|buffer|child_process|cluster|crypto|dgram|dns|events|fs|http|http2|https|net|os|path|process|querystring|readline|stream|string_decoder|timers|tls|url|util|v8|vm|worker_threads|zlib)$/;
// Packages that take a token but do not send data to a third party (local crypto / sessions / test doubles).
const KNOWN_LOCAL = /^(?:jsonwebtoken|jose|jwt-decode|jwt-simple|bcrypt(?:js)?|argon2|@node-rs\/\w+|lucia|oslo|@oslojs\/\w+|iron-session|express-session|cookie(?:-parser|-session)?|csrf|csurf|tiny-csrf|uuid|nanoid|zod|yup|joi|crypto-js|otplib|speakeasy|@simplewebauthn\/\w+|passport(?:-[\w-]+)?|next-auth|@auth\/[\w-]+|better-auth|vitest|jest|msw|nock|pyjwt|jwt|itsdangerous|passlib|secrets|hashlib|hmac)$/i;

function importedBindings(c, ext) {
  const out = new Map(); // local identifier -> package
  const raw = new Map(); // local identifier -> raw specifier
  if (ext === 'py') {
    for (const m of c.matchAll(/^\s*from\s+([\w.]+)\s+import\s+\(?([^\n)]+)/gm)) {
      const pkg = m[1].split('.')[0].toLowerCase();
      for (const part of m[2].split(',')) { const nm = part.trim().split(/\s+as\s+/).pop().trim(); if (/^\w+$/.test(nm)) out.set(nm, pkg); }
    }
    for (const m of c.matchAll(/^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?/gm)) out.set(m[2] || m[1].split('.')[0], m[1].split('.')[0].toLowerCase());
    return { out, raw };
  }
  for (const m of c.matchAll(/\bimport\s+(?:type\s+)?([\w$]+)?\s*,?\s*(?:\{([^}]*)\}|\*\s+as\s+([\w$]+))?\s*from\s*['"]([^'"]+)['"]/g)) {
    const pkg = normalizeSpecifier(m[4]);
    if (!pkg) continue;
    const names = [m[1], m[3], ...(m[2] || '').split(',').map((part) => part.trim().replace(/^type\s+/, '').split(/\s+as\s+/).pop().trim())];
    for (const nm of names) if (nm && /^[\w$]+$/.test(nm)) { out.set(nm, pkg); raw.set(nm, m[4]); }
  }
  for (const m of c.matchAll(/\b(?:const|let|var)\s+(?:([\w$]+)|\{([^}]*)\})\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)/g)) {
    const pkg = normalizeSpecifier(m[3]);
    if (!pkg) continue;
    const names = [m[1], ...(m[2] || '').split(',').map((part) => part.trim().split(/\s*:\s*/).pop().trim())];
    for (const nm of names) if (nm && /^[\w$]+$/.test(nm)) { out.set(nm, pkg); raw.set(nm, m[3]); }
  }
  return { out, raw };
}

/** Text of the argument list starting at `open` (index of '('), bounded; nested brackets are followed. */
function argText(c, open, max = 800) {
  let depth = 0;
  for (let i = open; i < Math.min(c.length, open + max); i++) {
    const ch = c[i];
    if (ch === '(' || ch === '{' || ch === '[') depth++;
    else if (ch === ')' || ch === '}' || ch === ']') { depth--; if (!depth) return c.slice(open, i + 1); }
  }
  return c.slice(open, open + max);
}

/**
 * Credential option keys passed directly to the call: keys of an object literal that is itself an argument (JS:
 * `f({ token: x })`, `f(a, { apiKey: k })`) or keyword arguments (Python: `f(token=x)`), whose value is not a
 * placeholder (null, false, '', 0). Keys of nested objects (headers, callbacks …) do not count.
 */
function credentialKeys(args, py) {
  const out = [];
  const stack = [];
  let quote = null;
  for (let i = 0; i < args.length; i++) {
    const ch = args[i];
    if (quote) { if (ch === '\\') i++; else if (ch === quote) quote = null; continue; }
    const atKeyLevel = py ? stack.length === 1 && stack[0] === '(' : stack.length === 2 && stack[0] === '(' && stack[1] === '{';
    if (ch === '"' || ch === "'" || ch === '`') {
      if (atKeyLevel && !py) {
        const m = /^(["'])(\w+)\1\s*:/.exec(args.slice(i));
        if (m && NET_KEY_NAMES.test(m[2]) && !PLACEHOLDER_VALUE.test(args.slice(i + m[0].length))) out.push(m[2]);
      }
      quote = ch;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') { stack.push(ch); continue; }
    if (ch === ')' || ch === ']' || ch === '}') { stack.pop(); continue; }
    if (!atKeyLevel || !/[A-Za-z_]/.test(ch) || /[\w$.]/.test(args[i - 1] || '')) continue;
    const m = /^(\w+)\s*([:=])(?![:=])/.exec(args.slice(i));
    if (!m) { const w = /^\w+/.exec(args.slice(i)); i += (w ? w[0].length : 1) - 1; continue; }
    if ((py ? m[2] === '=' : m[2] === ':') && NET_KEY_NAMES.test(m[1]) && !PLACEHOLDER_VALUE.test(args.slice(i + m[0].length))) out.push(m[1]);
    i += m[1].length - 1;
  }
  return out;
}

/**
 * Third-party packages that are constructed / initialised with a credential option (token, apiKey, dsn …) and that
 * the vendor catalog does not know: a network SDK the engine cannot place. Returns [{pkg, files:[rel]}].
 * Local modules (Python packages / files of the repo itself, path aliases) are not third-party SDKs; a package must be
 * declared in a manifest, or imported through npm: / jsr: / a CDN URL.
 */
export function unknownNetworkSdks(files, { vendorForPackage = null, isKnownTech = () => false, deps = null } = {}) {
  const found = new Map();
  const localPy = new Set();
  for (const f of files || []) {
    if (!f || !/\.py$/.test(f.rel)) continue;
    for (const part of f.rel.split('/')) localPy.add(part.replace(/\.py$/, '').toLowerCase());
  }
  const norm = (x) => String(x).toLowerCase().replace(/[-_.]+/g, '');
  const depList = deps ? [...deps].map(norm) : [];
  const declared = (pkg, ext, rawSpec) => {
    if (ext === 'py') return !localPy.has(pkg) && depList.some((d) => d === norm(pkg) || d === `python${norm(pkg)}` || d.startsWith(norm(pkg)));
    return (!!deps && deps.has(pkg)) || /^(?:npm|jsr):|^https?:/.test(rawSpec || '');
  };
  for (const f of files || []) {
    if (!f || f.kind !== 'code') continue;
    const ext = extOf(f.rel);
    if (!['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'svelte', 'vue', 'astro', 'py'].includes(ext)) continue;
    const c = f.content || '';
    if (!NET_KEY.test(c)) continue;
    const { out: binds, raw } = importedBindings(c, ext);
    for (const [local, pkg] of binds) {
      if (!pkg || pkg.startsWith('@/') || /:/.test(pkg) || NODE_BUILTIN.test(pkg) || KNOWN_LOCAL.test(pkg) || isKnownTech(pkg)) continue;
      if (!declared(pkg, ext, raw.get(local))) continue;
      let v = null;
      if (typeof vendorForPackage === 'function') { try { v = vendorForPackage(pkg); } catch { v = null; } }
      if (v) continue; // catalog vendor: traced, or reported as not-traced by the catalog check
      const esc = local.replace(/\$/g, '\\$');
      // Constructors (class names) and SDK factories / initialisers only: an ordinary function that takes a 'token'
      // argument (a template render, a sign-in helper) is not a client.
      const ctorLike = /^[A-Z]/.test(local) || /^(?:create|init|setup|configure)(?:[A-Z_]|$)/.test(local);
      const member = ctorLike ? '(?:\\.(?:init|Client|configure|setup))?' : '\\.(?:init|Client|configure|setup)';
      const callRe = ext === 'py'
        ? new RegExp(`(?<![\\w.])${esc}${member}\\s*\\(`, 'g')
        : new RegExp(`(?:\\bnew\\s+${esc}(?:\\.\\w+)?|(?<![\\w$.])${esc}${member})\\s*(?:<[^>()]*>)?\\s*\\(`, 'g');
      for (const m of c.matchAll(callRe)) {
        const args = argText(c, m.index + m[0].length - 1);
        if (!credentialKeys(args, ext === 'py').length) continue;
        if (!found.has(pkg)) found.set(pkg, new Set());
        found.get(pkg).add(f.rel);
        break;
      }
    }
  }
  return [...found].map(([pkg, set]) => ({ pkg, files: [...set] }));
}

/** Python ORM model classes (transitively derived from a model base) that no Store was built for. */
export function unparsedPythonModels(files, graph) {
  const py = (files || []).filter((f) => f && f.kind === 'code' && /\.py$/.test(f.rel) && !/(^|\/)migrations\//.test(f.rel));
  if (!py.length) return { count: 0, files: [] };
  const declarative = py.some((f) => /\bdeclarative_base\s*\(|\bDeclarativeBase\b/.test(f.content || ''));
  const classes = [];
  for (const f of py) {
    const c = f.content || '';
    const mongo = /^\s*(?:from|import)\s+(?:mongoengine|beanie|odmantic)\b/m.test(c);
    for (const m of c.matchAll(/^class\s+(\w+)\s*\(([^)]*)\)\s*:/gm)) {
      const bases = m[2].split(',').map((b) => b.trim()).filter((b) => b && !/=/.test(b));
      const kw = m[2];
      const rest = c.slice(m.index + m[0].length);
      const end = rest.search(/^\S/m);
      const body = end < 0 ? rest : rest.slice(0, end);
      classes.push({ name: m[1], bases, kw, body, file: f.rel, mongo });
    }
  }
  const ROOT = /(?:^|\.)(?:Model|AbstractBaseUser|AbstractUser)$/;
  const isRoot = (c, b) => ROOT.test(b) || (declarative && b === 'Base') || (b === 'SQLModel' && /\btable\s*=\s*True\b/.test(c.kw)) || (c.mongo && /(?:^|\.)(?:Document|DynamicDocument)$/.test(b));
  const model = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    for (const c of classes) {
      if (model.has(c.name)) continue;
      if (c.bases.some((b) => isRoot(c, b) || model.has(b.split('.').pop()))) { model.add(c.name); changed = true; }
    }
  }
  const stores = graph ? graph.nodesOf('Store', (s) => s.kind === 'table' || s.kind === 'collection') : [];
  const known = new Set();
  for (const s of stores) for (const k of [s.model, s.name, s.table]) if (k) known.add(String(k).toLowerCase().replace(/[^a-z0-9]/g, ''));
  const matches = (name) => {
    const n = name.toLowerCase();
    if (known.has(n) || known.has(`${n}s`) || known.has(`${n}es`)) return true;
    for (const k of known) if (k.endsWith(n) && k.length - n.length <= 20) return true; // app_label prefix (Django)
    return false;
  };
  const out = [];
  for (const c of classes) {
    if (!model.has(c.name)) continue;
    if (/^\s+(?:abstract|proxy)\s*=\s*True\b/m.test(c.body) || /^\s+__abstract__\s*=\s*True\b/m.test(c.body)) continue;
    if (!/^\s+\w+\s*(?::[^=\n]+)?=\s*[\w.]+\s*\(/m.test(c.body)) continue; // no field assignment at all
    if (matches(c.name)) continue;
    out.push(c);
  }
  return { count: out.length, files: [...new Set(out.map((c) => c.file))] };
}

/** Is the JSON text a workflow export (n8n and alike: a nodes array plus a connections map)? */
function workflowExport(content) {
  const c = String(content || '');
  if (c.length > 2_000_000 || !/"nodes"\s*:/.test(c) || !/"connections"\s*:/.test(c)) return null;
  let j;
  try { j = JSON.parse(c); } catch { return null; }
  const list = Array.isArray(j) ? j : [j];
  let n8n = false;
  let ok = false;
  for (const w of list) {
    if (!w || typeof w !== 'object' || !Array.isArray(w.nodes) || !w.connections || typeof w.connections !== 'object') continue;
    if (!w.nodes.some((n) => n && typeof n.type === 'string')) continue;
    ok = true;
    if (w.nodes.some((n) => /^(?:n8n-nodes-|@n8n\/)/.test(String(n?.type || '')))) n8n = true;
  }
  return ok ? { n8n } : null;
}

/**
 * Generic detectors for artefacts the engine saw but did not analyse. They run here so that coverage honesty does not
 * depend on any extractor reporting itself. Entries: {layer, kind, label, files, count}.
 */
export function detectUnparsed(graph, files, stack, { vendorForPackage = null, pythonModelsUnparsed = 0 } = {}) {
  const out = [];
  const evidenceFiles = (type) => {
    const set = new Set();
    for (const n of graph.nodesOf(type)) for (const f of evFiles(n)) set.add(f);
    return set;
  };
  const sinkFiles = evidenceFiles('Sink');
  const storeFiles = evidenceFiles('Store');

  // 1) workflow exports (n8n …) not consumed by any sink
  const wf = { n8n: [], other: [] };
  for (const f of files || []) {
    if (!f || !/\.json$/i.test(f.rel) || f.kind === 'manifest') continue;
    const w = workflowExport(f.content);
    if (!w || sinkFiles.has(f.rel)) continue;
    (w.n8n ? wf.n8n : wf.other).push(f.rel);
  }
  if (wf.n8n.length) out.push({ layer: 'vendors', kind: 'n8n-workflow', label: { tr: 'n8n iş akışları', en: 'n8n workflows' }, files: wf.n8n, count: wf.n8n.length });
  if (wf.other.length) out.push({ layer: 'vendors', kind: 'workflow-export', label: { tr: 'iş akışı dışa aktarımları', en: 'workflow exports' }, files: wf.other, count: wf.other.length });

  // 2) mobile-language code with nothing attributed to it
  const dartParsed = extractorNames().has('dart');
  // android/ ios/ … are generated shells only around a cross-platform app (Flutter, React Native / Expo, Capacitor);
  // in a native project the same directories hold the app itself.
  const deps = stack?.deps || new Set();
  const crossPlatform = (files || []).some((f) => f && path.basename(f.rel) === 'pubspec.yaml')
    || [...deps].some((d) => /^(?:react-native|expo|@capacitor\/core|@ionic\/[\w-]+|@nativescript\/core|cordova(?:-[\w-]+)?)$/.test(d));
  const byLang = new Map();
  for (const f of files || []) {
    if (!f || f.kind !== 'code') continue;
    const ext = extOf(f.rel);
    const lang = MOBILE_LANG[ext];
    if (!lang || (ext === 'dart' && dartParsed)) continue;
    if ((crossPlatform && PLATFORM_SHELL.test(f.rel)) || GENERATED_CODE.test(f.rel)) continue;
    if (!byLang.has(lang)) byLang.set(lang, []);
    byLang.get(lang).push(f.rel);
  }
  for (const [lang, rels] of byLang) {
    if (rels.length < 3) continue;
    if (rels.some((r) => sinkFiles.has(r) || storeFiles.has(r))) continue;
    const label = { tr: `${lang} kodu`, en: `${lang} code` };
    out.push({ layer: 'dbWrites', kind: `code:${lang.toLowerCase()}`, label, files: rels, count: rels.length });
    out.push({ layer: 'vendors', kind: `code:${lang.toLowerCase()}`, label, files: rels, count: rels.length });
  }

  // 3) Python model classes without a table
  const usesPyOrm = (stack?.techs || []).some((t) => techDef(t.id)?.lang === 'python' && (techDef(t.id)?.layer === 'data' || techDef(t.id)?.layer === 'both'));
  if (usesPyOrm || pythonModelsUnparsed) {
    const pm = unparsedPythonModels(files, graph);
    const count = Math.max(pm.count, Number(pythonModelsUnparsed) || 0);
    if (count) out.push({ layer: 'schema', kind: 'python-models', label: { tr: 'Python modelleri', en: 'Python models' }, files: pm.files, count });
  }

  // 4) network SDKs outside the vendor catalog
  const techPkg = TECHS.filter((t) => t.pkg).map((t) => t.pkg);
  const sdks = unknownNetworkSdks(files, { vendorForPackage, isKnownTech: (p) => techPkg.some((re) => re.test(p)), deps: stack?.deps || null });
  const sinks = graph.nodesOf('Sink');
  for (const s of sdks) {
    const base = s.pkg.replace(/^@/, '').split(/[/-]/)[0].toLowerCase();
    // traced by a catalog sink in the same file (e.g. an extractor resolved it): not a gap
    const traced = sinks.some((n) => !n.unknownVendor && (n.package === s.pkg || n.pkg === s.pkg || (base.length >= 4 && String(n.vendorId || n.id || '').toLowerCase().includes(base))));
    if (traced) continue;
    out.push({ layer: 'vendors', kind: 'unknown-sdk', reason: 'unknown-sdk', label: s.pkg, files: s.files, count: s.files.length });
  }

  // 4b) a privacy notice by name that produced no declaration node: found, but not read
  if (!graph.nodesOf('Declaration').length) {
    const nf = noticeFiles(files).map((f) => f.rel);
    if (nf.length) out.push({ layer: 'declarations', kind: 'notice-file', label: { tr: 'Aydınlatma metni dosyası bulundu, ayrıştırılamadı', en: 'Privacy notice file found, not parsed' }, files: nf, count: nf.length });
  }

  // 5) data-access shapes recognised here but resolved by no extractor (framework composables / injected clients)
  // Evidence that the data layer of a file was resolved: a store defined there, or an edge into / out of a store.
  // Log sinks modelled as stores (console …) do not count: they say nothing about the database.
  const recordStore = (n) => n?.type === 'Store' && (isRecord(n) || n.kind === 'bucket');
  const dataEv = new Set();
  for (const n of graph.nodesOf('Store', recordStore)) for (const f of evFiles(n)) dataEv.add(f);
  for (const e of graph.edges || []) {
    if (e.type !== 'flowsTo' && e.type !== 'writes' && e.type !== 'reads') continue;
    if (!recordStore(graph.node(e.to)) && !recordStore(graph.node(e.from))) continue;
    if (e.file) dataEv.add(e.file);
    for (const x of e.evidence || []) if (x?.file) dataEv.add(x.file);
  }
  for (const shape of ACCESS_SHAPES) {
    if (shape.pkg && ![...deps].some((d) => shape.pkg.test(d))) continue;
    const rels = (files || []).filter((f) => f && f.kind === 'code' && shape.use.test(f.content || '')).map((f) => f.rel);
    if (!rels.length || rels.some((r) => dataEv.has(r))) continue;
    for (const layer of shape.layers) out.push({ layer, kind: shape.kind, label: shape.label, files: rels, count: rels.length });
  }
  return out;
}

/**
 * Data-access shapes the stack detector recognises without any extractor having to: when every file using the shape
 * left no store, write or sink evidence in the graph, the shape is recognised-but-unsupported and its layers get a
 * 'not-parsed' gap (so they never read 'none' / 0 silently). Extend by adding a row; never key on a project.
 */
export const ACCESS_SHAPES = [
  {
    kind: 'nuxt-supabase', layers: ['schema', 'dbWrites'], pkg: /^(?:@nuxtjs\/supabase|nuxt|nuxt3)$/,
    use: /\b(?:useSupabaseClient|serverSupabaseClient|serverSupabaseServiceRole|useSupabaseAuthClient)\s*(?:<[^>()]*>)?\s*\(/,
    label: { tr: 'Nuxt Supabase erişimi (useSupabaseClient / serverSupabaseClient)', en: 'Supabase via Nuxt composables (useSupabaseClient / serverSupabaseClient)' },
  },
  {
    kind: 'vuefire', layers: ['schema', 'dbWrites'], pkg: /^(?:vuefire|nuxt-vuefire)$/,
    use: /\b(?:useFirestore|useCollection|useDocument)\s*\(/,
    label: { tr: 'VueFire Firestore erişimi (useFirestore / useCollection)', en: 'Firestore via VueFire composables (useFirestore / useCollection)' },
  },
];

const labelText = (l, lang = 'en') => (l && typeof l === 'object' ? l[lang] || l.en || l.tr || '' : String(l || ''));

/** Merge extractor-reported entries (ctx.shared.unparsed) with the generic ones; one entry per (layer, kind). */
export function mergeUnparsed(reported, generic) {
  const out = [];
  const seen = new Set();
  for (const e of [...(Array.isArray(reported) ? reported : []), ...(generic || [])]) {
    if (!e || typeof e !== 'object' || !e.layer) continue;
    const key = `${e.layer}|${e.kind || labelText(e.label)}|${e.kind === 'unknown-sdk' ? labelText(e.label) : ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ layer: String(e.layer), kind: String(e.kind || 'artefact'), label: e.label || e.kind || 'artefact', files: Array.isArray(e.files) ? e.files.slice(0, 20) : [], count: Number(e.count) || (Array.isArray(e.files) ? e.files.length : 0), ...(e.reason ? { reason: e.reason } : {}) });
  }
  return out;
}

function applyUnparsed(layer, entries, name) {
  const mine = entries.filter((e) => e.layer === name);
  if (!mine.length) return layer;
  for (const e of mine) layer.gaps.push({ tech: e.kind, label: labelText(e.label), labels: typeof e.label === 'object' ? e.label : null, reason: e.reason || 'not-parsed', layer: name, kind: e.kind, files: e.files, count: e.count });
  if (!String(layer.status).startsWith('unsupported:')) layer.status = layer.count > 0 ? 'partial' : `unsupported:${labelText(mine[0].label)}`;
  return layer;
}

/* ------------------------------------------------------------------------------- usable facts per layer (round 8) */

// Objects every database brings along, and the bookkeeping tables of migration tools: not part of the app's schema.
const SYSTEM_TABLE = /^(?:pg_|sqlite_|_prisma_|__drizzle|knex_migrations|sequelizemeta$|schema_migrations$|flyway_|alembic_version$|django_migrations$|ar_internal_metadata$|dual$|generate_series$|unnest$|json_each$)|^(?:information_schema|pg_catalog|auth|storage|cron|realtime|vault|extensions|net|supabase_\w+|system|sys|mysql|performance_schema)\./i;
const CODE_EDGE = new Set(['flowsTo', 'writes', 'deletes', 'reads', 'readBy', 'usedBy', 'exposes', 'exports', 'expires']);
const escRe = (x) => String(x).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Record stores the app code reads or writes that the engine knows only from that code (or from a policy) and for which
 * not one column was parsed: their fields, links and retention columns are unknown. Not listed: managed / external /
 * synthetic stores, views, tables declared in a schema file, join tables a relation declares, database system tables,
 * names that are a CTE or a table function in the SQL that mentions them, and schemaless collections with traced fields.
 */
export function storesWithoutColumns(graph, files = [], keep = () => true, dropped = new Set()) {
  const hasCols = new Set();
  const inFlow = new Set();
  const touched = new Set();
  for (const e of graph.edges || []) {
    if (e.type === 'hasColumn') { hasCols.add(e.from); continue; }
    if (!CODE_EDGE.has(e.type)) continue;
    for (const id of [e.from, e.to]) touched.add(id);
    if (e.type === 'flowsTo') inFlow.add(e.to);
  }
  for (const e of graph.edges || []) if (e.type === 'represents') inFlow.add(e.from);
  const models = new Set(graph.nodesOf('Store').map((s) => String(s.model || s.table || s.name || '').toLowerCase()).filter(Boolean));
  const code = (files || []).filter((f) => f && f.kind === 'code');
  const out = [];
  for (const s of graph.nodesOf('Store', (n) => n.kind === 'table' || n.kind === 'collection')) {
    if (!keep(s) || hasCols.has(s.id) || s.external || s.view === true || s.viewOf) continue;
    const name = String(s.table || s.name || '');
    if (!name || !/^[\w.$/{}:-]+$/.test(name) || SYSTEM_TABLE.test(name)) continue;
    // declared in a schema file: the DDL / model was read, whatever it contains
    if (s.file && !s.inferred) continue;
    // created, then dropped / renamed by a migration that was read: the code's reference is stale, nothing was left unparsed
    if (dropped.has(name.toLowerCase()) || dropped.has(name.toLowerCase().replace(/^public\./, ''))) continue;
    if (s.joinTable || s.join || s.implicit || s.throughRelation || s.relation) continue;
    const jt = /^_([A-Za-z]\w*)To([A-Z]\w*)$/.exec(name);
    if (jt && models.has(jt[1].toLowerCase()) && models.has(jt[2].toLowerCase())) continue;
    const used = s.inferred === true || (Array.isArray(s.codeOps) && s.codeOps.length) || (Array.isArray(s.ops) && s.ops.length) || touched.has(s.id);
    if (!used) continue;
    // a document collection has no DDL: the fields the code writes are its schema
    if (s.kind === 'collection' && inFlow.has(s.id)) continue;
    const q = escRe(name.split('.').pop());
    const cte = new RegExp(`(?:\\bwith\\s+(?:recursive\\s+)?|\\)\\s*,\\s*)["'\`]?${q}["'\`]?\\s*(?:\\([^)]*\\)\\s*)?as\\s+(?:not\\s+)?(?:materialized\\s*)?\\(`, 'i');
    const fn = new RegExp(`\\b(?:from|join)\\s+${q}\\s*\\(`, 'i');
    const through = new RegExp(`\\b(?:through|joinTable|join_table|JoinTable|belongsToMany|secondary|db_table|pivot)\\b[^\\n;]{0,60}['"\`]${q}['"\`]`);
    if (code.some((f) => { const c = f.content || ''; return c.toLowerCase().includes(name.split('.').pop().toLowerCase()) && (cte.test(c) || fn.test(c) || through.test(c)); })) continue;
    out.push(s);
  }
  return out;
}

// Thresholds of the routes-layer self checks (round 9). A gap is a share of what exists, with a floor so that a single odd
// registration is a note in the code, not a reason to call a whole layer partial.
export const UNREAD_MIN = 2;
export const UNREAD_SHARE = 0.1;
export const AUTH_UNKNOWN_MIN = 5;
export const AUTH_UNKNOWN_SHARE = 0.25;

const HEALTH_PATH = /(?:^|\/)(?:health|healthz|healthcheck|health-check|health_check|ping|ready|readyz|readiness|livez|liveness|metrics|favicon\.ico|robots\.txt|sitemap\.xml)\/?$/i;
const STATIC_PATH = /^\/?(?:static|public|assets|dist|_next|images|uploads)(?:\/\*.*)?$/i;

/**
 * Endpoint nodes that are not routes of the app: middleware mounts (`ALL /admin/*`, `USE /x`, `*`), splat catch-alls,
 * static and health handlers, and the mount point of a framework's own request handler ([...nextauth], tRPC / auth
 * catch-all). They say nothing about the app's own handlers. A GraphQL operation node is always a route.
 */
export function isMountEndpoint(e) {
  if (!e) return true;
  if (e.protocol === 'graphql') return false;
  if (e.middleware === true || e.mount === true || e.isMount === true) return true;
  const p = String(e.path || '').trim();
  const m = String(e.method || '').toUpperCase();
  if (m === 'USE') return true;
  if (p === '*' || p === '/*' || p === '/**' || p === '(.*)' || p === '/(.*)') return true;
  if (['ALL', 'ANY', '*'].includes(m) && /(?:\*|\(\.\*\))$/.test(p)) return true;
  if (/\[\[?\.\.\.(?:nextauth|better-?auth|trpc|logto|kinde\w*|auth0)\]\]?/i.test(p)) return true;
  if (/\/(?:auth|trpc)\/\[\[?\.\.\.\w+\]\]?$/i.test(p)) return true;
  if (/\/trpc\/(?:[^/]+\/)*(?:\[\[?(?:\.\.\.)?trpc\]?\]|\*|:trpc\*?|\{trpc\})$/i.test(p)) return true;
  return HEALTH_PATH.test(p) || STATIC_PATH.test(p);
}

// Packages that map controllers to paths in a config object, decorators or file names instead of router calls.
const ROUTE_MAP_PKG = /^(?:express-routes-mapper|routing-controllers|inversify-express-utils|sails|@adonisjs\/(?:core|http-server|framework)|@loopback\/(?:rest|core)|loopback|tsoa|@tsed\/(?:common|core|platform-express)|openapi-backend|swagger-routes-express|swagger-tools|express-openapi|@feathersjs\/[\w-]+|express-file-routing|connexion|masonite|@foal\/core)$/i;
const CONTROLLER_FILE = /(?:^|\/)(?:controllers?|handlers?|resolvers?)\/[^/]+\.(?:[cm]?[jt]s|py|rb|php|go|java|kt)$|(?:^|\/)[\w.-]*[cC]ontrollers?\.(?:[cm]?[jt]s|py|rb|php|go|java|kt)$/;
const CLIENT_DIR = /(?:^|\/)(?:app\/javascript|client|frontend|web|www|public|resources\/js|assets)\//;
const HANDLER_SHAPE = /\(\s*(?:req|request|_req|ctx|context)\b[^)]{0,80}\b(?:res|response|reply|next)\b|@(?:Get|Post|Put|Patch|Delete|All)\s*\(|\bdef\s+\w+\s*\(\s*(?:self\s*,\s*)?request\b|\bRequest\s+\$request\b|\bHttpServletRequest\b|\*gin\.Context|http\.ResponseWriter/;

function handlerFiles(files) {
  return (files || []).filter((f) => f && f.kind === 'code' && !f.test && CONTROLLER_FILE.test(f.rel) && !CLIENT_DIR.test(f.rel) && HANDLER_SHAPE.test(f.content || ''));
}

// Vendor categories whose use is examined by the consent checks (a browser loads their resource) or that only serve files.
const PASSIVE_CATEGORY = new Set(['fonts', 'consent', 'embed', 'cdn']);
const HOSTING_VENDOR = /^(?:vercel|netlify|fly|fly-io|render|railway|heroku|github-pages|cloudflare-pages|digitalocean|hetzner|jsdelivr|unpkg|cdnjs|jquery-cdn|cloudflare)$/i;
const CONFIG_ONLY_FILE = /(?:^|\/)(?:package(?:-lock)?\.json|composer\.json|requirements[^/]*\.txt|pyproject\.toml|Pipfile|Gemfile|go\.mod|Cargo\.toml|pubspec\.yaml|Podfile|build\.gradle(?:\.kts)?|vercel\.json|netlify\.toml|fly\.toml|render\.yaml|wrangler\.(?:toml|jsonc?)|Dockerfile|docker-compose[^/]*\.ya?ml|\.env[^/]*|[^/]+\.config\.[cm]?[jt]s)$/i;

const PUBLIC_READ = /(?:^|[^\w$.])(?:fetch|\$fetch|ofetch|axios(?:\.get)?|got|ky|requests\.get|httpx\.get)\(\s*(?:[\w$.]+|'[^']*'|"[^"]*"|`[^`$]*`)\s*\)/;

/**
 * Third parties the engine saw but did not use: a catalog vendor with no traced element, no transfer row (traced,
 * implied, OAuth, hosting or `untraced`) and no row in the deletion matrix reached none of the conclusions, so what it
 * receives is unknown. Not counted: fonts / CDN / consent / embed vendors and browser-loaded resources (the consent checks
 * examine those), pure hosting, vendors only declared in a manifest or config file, and sinks without a vendor identity
 * (raw hosts; unknown vendors already are a gap).
 * @param {{transfers?:object[], deletionRows?:object[]}} model rows of buildTransfers / the deletion matrix
 * @returns {object[]} gaps for layers.vendors
 */
export function vendorConsumption(graph, { transfers = [], deletionRows = [] } = {}) {
  const used = new Set();
  for (const r of transfers || []) if (r) for (const k of [r.sinkId, r.sink?.id, r.vendorId]) if (k) used.add(String(k));
  for (const r of deletionRows || []) if (r) for (const k of [r.id, r.sinkId, r.sink?.id, typeof r.sink === 'string' ? r.sink : null]) if (k) used.add(String(k));
  for (const e of graph.edges || []) {
    if (['flowsTo', 'suppliedBy', 'collects', 'deletes'].includes(e.type)) for (const id of [e.to, e.from]) if (String(id).startsWith('sink:')) used.add(String(id));
  }
  const out = [];
  for (const n of graph.nodesOf('Sink', (x) => x.kind === 'vendor')) {
    if (n.unknownVendor === true || n.selfHosted || n.oauth || n.implied || n.usage === 'manifest' || (!n.usage && n.channel === 'manifest')) continue;
    if (used.has(String(n.id)) || (n.vendorId && used.has(String(n.vendorId)))) continue;
    if (PASSIVE_CATEGORY.has(String(n.category || '')) || HOSTING_VENDOR.test(String(n.vendorId || ''))) continue;
    if ((Array.isArray(n.loads) && n.loads.length) || (n.consentRequired === true && (n.initUngated !== undefined || n.channel === 'browser'))) continue;
    const fs_ = evFiles(n);
    if (fs_.length && fs_.every((f) => CONFIG_ONLY_FILE.test(f))) continue;
    const snippets = (n.evidence || []).map((e) => String(e?.snippet || '')).filter(Boolean);
    // a keyless read of a public API (one argument, no options): nothing but a URL is sent
    if (snippets.length && snippets.every((x) => PUBLIC_READ.test(x))) continue;
    // a mail transport that is configured but never asked to send
    if (n.category === 'email' && (n.relayOnly || n.generic) && n.usage !== 'called' && snippets.length && !snippets.some((x) => /send/i.test(x))) continue;
    out.push({ tech: n.vendorId || n.id, label: labelText(n.vendorName || n.label || n.name || n.vendorId || n.id), labels: n.vendorName && typeof n.vendorName === 'object' ? n.vendorName : null, reason: 'not-consumed', layer: 'vendors', file: n.file || fs_[0] || null });
  }
  return out;
}

/** Add the not-consumed vendor gaps to layers.vendors (idempotent). Returns true when the layer changed. */
export function applyVendorConsumption(layers, gaps) {
  const v = layers?.vendors;
  if (!v || !Array.isArray(gaps)) return false;
  v.gaps = Array.isArray(v.gaps) ? v.gaps : [];
  let changed = false;
  for (const g of gaps) {
    if (v.gaps.some((x) => x.tech === g.tech)) continue;
    v.gaps.push(g);
    changed = true;
  }
  if (changed && !String(v.status).startsWith('unsupported:')) v.status = 'partial';
  if (changed) delete v.covered;
  return changed;
}

const NOTICE_NAME = /^(?:privacy|privacy[-_ ]?(?:policy|notice|statement)|gizlilik(?:[-_ ]?(?:politikasi|politikas\u0131|bildirimi))?|kvkk(?:[-_ ]?[\w-]+)?|aydinlatma(?:[-_ ]?metni)?|datenschutz(?:erkl(?:ae|\u00e4)rung)?|politica-de-privacidad|politique-de-confidentialite)$/i;

/** Files that are a privacy notice by name and place (a document, or a page of that name) and hold real text. */
export function noticeFiles(files) {
  return (files || []).filter((f) => {
    if (!f || !f.rel || f.test) return false;
    const parts = f.rel.split('/');
    const base = parts[parts.length - 1];
    const stem = base.replace(/\.blade\.php$|\.[^.]+$/, '').replace(/\.(?:tr|en|de|fr|es)$/i, '');
    const doc = /\.(?:mdx?|html?|txt|rst)$/i.test(base);
    const page = /\.(?:tsx|jsx|vue|svelte|astro|dart|erb|hbs|ejs)$|\.blade\.php$/i.test(base);
    const inPages = parts.slice(0, -1).some((x) => /^(?:pages|views|screens|routes|app|content|legal|\(legal\))$/i.test(x));
    const byName = NOTICE_NAME.test(stem) && (doc || (page && inPages && !parts.some((x) => /^(?:components?|illustrations|icons|sections|_sections|settings)$/i.test(x))));
    const byDir = parts.length > 1 && NOTICE_NAME.test(parts[parts.length - 2]) && /^(?:page|index|\+page)\./i.test(base);
    if (!byName && !byDir) return false;
    const text = String(f.content || '').replace(/<(?:script|style)[\s\S]*?<\/(?:script|style)>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
    return text.length >= 400;
  });
}

/**
 * Per-layer coverage: compare what the stack says should exist with what the graph contains.
 * Counts are entities: tables / collections / buckets for schema (columns in detail.columns), distinct write operations
 * (store, file, line) for dbWrites.
 * @param {{vendorForPackage?:Function, unparsed?:object[], dropped?:Set<string>}} opts  unparsed: merged C2 entries (mergeUnparsed); dropped: tables a migration dropped (ctx.shared.sqlDropped)
 * @returns {{schema, routes, dbWrites, forms, ui, vendors, declarations, deletes}}
 */
export function assessLayers(graph, files, stack, { vendorForPackage = null, unparsed = null, dropped = null } = {}) {
  const ex = extractorNames();
  const imp = stack.importsByFile;
  const isAbstract = abstractChecker(files);
  const keep = (s) => !s.managed && !s.synthetic && !/^auth\.users$/i.test(s.table || '') && !isAbstract(s);
  const allStores = graph.nodesOf('Store');
  const tables = allStores.filter((s) => s.kind === 'table' && keep(s));
  const collections = allStores.filter((s) => s.kind === 'collection' && keep(s));
  const buckets = allStores.filter((s) => s.kind === 'bucket' && keep(s) && !s.external);
  const records = [...tables, ...collections];
  const recordIds = new Set(records.map((s) => s.id));
  // columns of kept tables only (an abstract table's columns are not entities of the schema either)
  const colOwner = new Map();
  for (const e of graph.edges || []) if (e.type === 'hasColumn') colOwner.set(e.to, e.from);
  const columns = allStores.filter((s) => s.kind === 'column' && (!colOwner.has(s.id) || recordIds.has(colOwner.get(s.id))));
  const endpoints = graph.nodesOf('Endpoint');

  // ---- schema ----
  const schemaGaps = [];
  for (const t of stack.techs.filter((x) => x.layer === 'data' || x.layer === 'both')) {
    const def = techDef(t.id);
    if (!def.family) continue;
    let mine;
    if (def.family === 'sql') mine = tables.length ? tables.filter((s) => attributed(s, def, imp)).length || tables.length : 0;
    else if (def.family === 'doc') {
      const own = collections.filter((s) => attributed(s, def, imp)).length;
      const docTechs = stack.techs.filter((x) => techDef(x.id)?.family === 'doc').length;
      mine = own || (docTechs === 1 ? collections.length : 0);
    } else mine = [...records, ...buckets].filter((s) => attributed(s, def, imp)).length;
    t.stores = mine;
    if (!mine) {
      // The tech is used only from code in a language no extractor parses (e.g. Firestore from Dart): unsupported.
      const exts = t.useExts || [];
      const unparsedLang = exts.length > 0 && exts.every((x) => UNSUPPORTED_EXT[x] && !(x === 'dart' && ex.has('dart')));
      const supported = (def.extractors || []).some((e) => ex.has(e)) && !unparsedLang;
      schemaGaps.push({ tech: t.id, label: t.label, reason: supported ? 'no-stores' : 'unsupported', layer: 'schema' });
    }
  }
  const entityCount = records.length + buckets.length;
  // Tables the code uses without one parsed column: the schema is only partly known.
  const bare = storesWithoutColumns(graph, files, (s) => recordIds.has(s.id), new Set([...(dropped || [])].map((d) => String(d).toLowerCase())));
  const bareNames = bare.map((s) => String(s.table || s.name)).sort();
  if (bare.length) {
    const label = `${bareNames.slice(0, 5).join(', ')}${bareNames.length > 5 ? ` +${bareNames.length - 5}` : ''}`;
    schemaGaps.push({ tech: 'no-columns', label, reason: 'no-columns', layer: 'schema', names: bareNames.slice(0, 5), count: bareNames.length });
  }
  const schema = {
    status: statusOf(entityCount, schemaGaps), count: entityCount, gaps: schemaGaps,
    detail: { tables: tables.length, collections: collections.length, buckets: buckets.length, columns: columns.length, ...(bare.length ? { withoutColumns: bare.length } : {}) },
  };
  // Nothing else is missing: the gap means more may be wrong than was reported, not that a conclusion about a table that
  // was seen is wrong (on the bench 16 of the 17 such conclusions were right). So the layer reads 'partial' and
  // the score is unreliable, while absence conclusions stay where they are; those that need every column depend on
  // 'schemaColumns' (layerCovered).
  if (bare.length && schemaGaps.every((g) => g.reason === 'no-columns')) schema.covered = true;

  // ---- routes ----
  const routeGaps = [];
  for (const t of stack.techs.filter((x) => x.layer === 'server' || x.layer === 'both')) {
    const def = techDef(t.id);
    if (!def.fw && !def.evidence && !def.marker) continue;
    if (t.ownRoutes === false) { t.endpoints = 0; continue; } // hosts another framework only (ROUTE_USE)
    const mine = endpoints.filter((e) => attributed(e, { ...def, pkg: def.layer === 'both' ? def.pkg : null }, imp)).length;
    t.endpoints = mine;
    if (!mine && t.id === 'graphql' && endpoints.some((e) => e.protocol === 'graphql')) { t.endpoints = endpoints.filter((e) => e.protocol === 'graphql').length; continue; }
    if (!mine) routeGaps.push({ tech: t.id, label: t.label, reason: 'unsupported', layer: 'routes' });
  }
  const mounts = endpoints.filter(isMountEndpoint).length;
  const realRoutes = endpoints.length - mounts;
  const routes = { status: statusOf(realRoutes, routeGaps), count: realRoutes, gaps: routeGaps, ...(mounts ? { detail: { mounts } } : {}) };
  // Only middleware / mounts / health handlers (or nothing) was seen while the project has handler files or maps its
  // controllers to paths elsewhere: the app's routes were not read.
  // Round 9: what the extractors could not read, seen from outside them.
  const real = endpoints.filter((e) => !isMountEndpoint(e));
  // (1) registrations in the source text without an endpoint
  const census = routeCensus(files, endpoints);
  if (census.unread >= UNREAD_MIN && census.unread >= UNREAD_SHARE * census.declared) {
    const n = census.files.slice(0, 2).map((x) => x.file).join(', ');
    routeGaps.push({
      tech: 'route-registrations', reason: 'routes-unread', layer: 'routes', count: census.unread, declared: census.declared, files: census.files.slice(0, 20).map((x) => x.file),
      label: `${census.unread}/${census.declared}`,
      labels: { tr: `${census.declared} rota kaydının ${census.unread} tanesi: ${n}`, en: `${census.unread} of ${census.declared} route registrations: ${n}` },
    });
    routes.status = 'partial';
  }
  // (2) endpoints whose handler, defined in this project, was not found
  const unreadHandlers = real.filter((e) => e.handlerUnread === true);
  if (unreadHandlers.length >= UNREAD_MIN && unreadHandlers.length >= UNREAD_SHARE * real.length) {
    routeGaps.push({
      tech: 'route-handlers', reason: 'handlers-unread', layer: 'routes', count: unreadHandlers.length, files: [...new Set(unreadHandlers.map((e) => e.file))].slice(0, 20),
      label: `${unreadHandlers.length}/${real.length}`,
      labels: { tr: `${real.length} uç noktanın ${unreadHandlers.length} tanesi`, en: `${unreadHandlers.length} of ${real.length} endpoints` },
    });
    routes.status = 'partial';
  }
  // (3) endpoints whose authentication could not be decided. The endpoints themselves were read, so absence conclusions
  // about what exists stay; only the score and the coverage statement change.
  const unknownAuth = real.filter((e) => e.auth === 'unknown' && e.handlerUnread !== true);
  if (unknownAuth.length >= AUTH_UNKNOWN_MIN && unknownAuth.length >= AUTH_UNKNOWN_SHARE * real.length) {
    const others = routeGaps.length > 0;
    routeGaps.push({
      tech: 'route-auth', reason: 'auth-unknown', layer: 'routes', count: unknownAuth.length, files: [...new Set(unknownAuth.map((e) => e.file))].slice(0, 20),
      label: `${unknownAuth.length}/${real.length}`,
      labels: { tr: `${real.length} uç noktanın ${unknownAuth.length} tanesi`, en: `${unknownAuth.length} of ${real.length} endpoints` },
    });
    routes.status = 'partial';
    if (!others) routes.covered = true;
  }
  if (!realRoutes && !routeGaps.length) {
    const mapper = [...new Set([...stack.deps, ...[...imp.values()].flatMap((x) => [...x])])].find((d) => ROUTE_MAP_PKG.test(d));
    const handlers = handlerFiles(files);
    if ((mounts && (mapper || handlers.length)) || (mapper && handlers.length)) {
      routeGaps.push({ tech: mapper || 'controllers', label: mapper || handlers.slice(0, 3).map((f) => path.basename(f.rel)).join(', '), reason: 'middleware-only', layer: 'routes', files: handlers.slice(0, 20).map((f) => f.rel), count: handlers.length });
      routes.status = 'partial';
    } else if (mounts) routes.covered = true; // everything there was has been seen; there is no route of the app's own
  }

  // ---- dbWrites: distinct (store, file, line) operations from flowsTo-into-record edges ∪ 'writes' edges (C1) ----
  const ops = new Set();
  const ownerOf = (id) => {
    const n = graph.node(id);
    if (!n || n.type !== 'Store') return null;
    if (n.kind === 'column') return colOwner.get(id) || (n.table ? `table:${n.table}` : id);
    return isRecord(n) ? id : null;
  };
  for (const e of graph.edges || []) {
    if (e.type !== 'flowsTo' && e.type !== 'writes') continue;
    const owner = ownerOf(e.to);
    if (!owner) continue;
    const evs = (e.evidence || []).filter((x) => x && x.file);
    if (e.file) evs.push({ file: e.file, line: e.line });
    if (!evs.length) ops.add(`${owner}|${e.from}|`);
    for (const x of evs) ops.add(`${owner}|${x.file}|${x.line ?? ''}`);
  }
  const writes = ops.size;
  const writeGaps = schemaGaps.filter((g) => g.reason === 'unsupported').map((g) => ({ ...g, layer: 'dbWrites' }));
  // Tables were modelled for a detected ORM / database client, yet not one write reached them: the write calls use a
  // shape the flow analysis does not know. That is a coverage gap ('partial'), not "the app writes nothing".
  if (!writeGaps.length && !writes && records.length) {
    for (const t of stack.techs.filter((x) => (x.layer === 'data' || x.layer === 'both') && x.stores > 0)) writeGaps.push({ tech: t.id, label: t.label, reason: 'no-writes', layer: 'dbWrites' });
  }
  const dbWrites = {
    status: writeGaps.some((g) => g.reason === 'unsupported') ? `unsupported:${writeGaps.find((g) => g.reason === 'unsupported').tech}` : writes ? 'found' : writeGaps.length ? 'partial' : 'none',
    count: writes, gaps: writeGaps,
  };

  // ---- forms / sources ----
  const sources = graph.nodesOf('Source');
  const forms = { status: sources.length ? 'found' : 'none', count: sources.length, gaps: [] };

  // ---- ui ----
  const ui = { status: stack.uiFiles ? 'found' : 'none', count: stack.uiFiles, gaps: [] };

  // ---- vendors ----
  const sinks = graph.nodesOf('Sink', (n) => n.kind === 'vendor' || n.kind === 'http');
  const vendorIds = new Set(sinks.map((n) => n.vendorId).filter(Boolean));
  const vendorGaps = [];
  if (typeof vendorForPackage === 'function') {
    const missing = new Map();
    for (const [rel, imps] of imp) {
      for (const p of imps) {
        let v = null;
        try { v = vendorForPackage(p); } catch { v = null; }
        const id = typeof v === 'string' ? v : v?.id || v?.vendorId;
        if (!id || vendorIds.has(id) || missing.has(id)) continue;
        missing.set(id, { tech: id, label: p, reason: 'not-traced', layer: 'vendors', file: rel });
      }
    }
    vendorGaps.push(...missing.values());
  }
  // A hosted backend (BaaS) is itself a processor: when its SDK is in use but no sink of it reached the graph, the
  // third-party layer missed it.
  for (const t of stack.techs) {
    const def = techDef(t.id);
    if (!def?.hosted) continue;
    const ids = def.hosted;
    if (graph.nodesOf('Sink').some((n) => ids.includes(n.vendorId) || ids.some((id) => String(n.id).includes(id)))) continue;
    if (vendorGaps.some((g2) => ids.includes(g2.tech))) continue;
    vendorGaps.push({ tech: ids[0], label: t.label, reason: 'not-traced', layer: 'vendors' });
  }
  // Sinks an extractor could not attribute to a catalog vendor (WS1: unknownVendor) leave the layer partial.
  for (const n of graph.nodesOf('Sink', (x) => x.unknownVendor === true)) {
    const label = n.label || n.name || n.package || n.host || n.id;
    const tech = n.package || n.host || n.id;
    if (vendorGaps.some((g2) => g2.tech === tech)) continue;
    vendorGaps.push({ tech, label: labelText(label), reason: 'unknown-vendor', layer: 'vendors', file: n.file || n.evidence?.[0]?.file });
  }
  const vendors = { status: vendorGaps.length ? (sinks.length ? 'partial' : `unsupported:${vendorGaps[0].label}`) : sinks.length ? 'found' : 'none', count: sinks.length, gaps: vendorGaps };

  // ---- declarations ----
  const decls = graph.nodesOf('Declaration');
  const declarations = { status: decls.length ? 'found' : 'none', count: decls.length, gaps: [] };

  // ---- unparsed artefacts (C2): every entry is a gap on its layer ----
  // An extractor that now models GraphQL operations as endpoints supersedes an older "GraphQL not supported" entry.
  const hasGraphql = endpoints.some((e) => e.protocol === 'graphql');
  const entries = (Array.isArray(unparsed) ? unparsed : []).filter((e) => !(hasGraphql && e.layer === 'routes' && /graphql/i.test(`${e.kind} ${labelText(e.label)}`)));
  const byName = { schema, routes, dbWrites, forms, ui, vendors, declarations };
  for (const name of Object.keys(byName)) applyUnparsed(byName[name], entries, name);

  // ---- deletes (pseudo-layer): the deletion detector saw at least one delete in this code base ----
  const delControls = graph.nodesOf('Control', (c) => c.kind === 'deletion-flow').length;
  // personal: data elements in the graph; lets calibrate.js keep an unverifiable "no deletion flow" as a review item
  // when the delete layer is not covered (instead of saying nothing).
  // No deletion control seen while record writes were traced: the delete layer was observable (covered: an absence
  // conclusion about deletion may rest on it) but nothing was found, so its status is 'none', never 'found (0)'.
  const deletes = delControls
    ? { status: 'found', count: delControls, gaps: [], personal: graph.nodesOf('DataElement').length }
    : { status: dbWrites.status === 'found' ? 'none' : dbWrites.status, count: 0, gaps: [], personal: graph.nodesOf('DataElement').length, ...(dbWrites.status === 'found' ? { covered: true } : {}) };

  // The deletion matrix is built from the schema: rows of tables that were not read are missing from it.
  if (deletes.status === 'found' && layerGapStatus(schema.status)) {
    deletes.status = 'partial';
    deletes.gaps.push({ tech: 'schema', label: 'schema', labels: { tr: 'veritabanı şeması', en: 'database schema' }, reason: 'schema-partial', layer: 'deletes' });
    if (schema.covered) deletes.covered = true;
  }

  return normalizeLayers({ schema, routes, dbWrites, forms, ui, vendors, declarations, deletes });
}

/**
 * 'found' with a count of 0 is never a status: it becomes 'none'. Pure and idempotent; renderers apply it too, so a
 * result produced by an older engine does not show "found (0)" either. A layer that was searched completely and is
 * still usable as an absence basis keeps `covered: true`.
 */
export function normalizeLayers(layers) {
  if (!layers || typeof layers !== 'object') return layers;
  for (const l of Object.values(layers)) {
    if (!l || typeof l !== 'object') continue;
    if (l.status === 'found' && typeof l.count === 'number' && l.count === 0) {
      l.status = 'none';
      if (!(l.gaps || []).length) l.covered = true;
    }
  }
  return layers;
}

/** Is the layer usable as the basis of an absence conclusion? */
export function layerCovered(layers, name) {
  // pseudo-layer: the schema with the columns of every table the code uses
  if (name === 'schemaColumns') return layerCovered(layers, 'schema') && !(layers?.schema?.gaps || []).some((g) => g.reason === 'no-columns');
  if (!layers || !layers[name]) return true; // unknown → do not block (older callers / tests)
  return layers[name].status === 'found' || layers[name].covered === true;
}

/** Core layers: a partial or unsupported one makes the score unreliable (index.js assessCoverage). */
export const CORE_LAYERS = ['schema', 'routes', 'dbWrites', 'vendors'];

/** Is a layer status a coverage gap ('partial' or 'unsupported:*')? */
export function layerGapStatus(status) {
  const s = String(status || '');
  return s === 'partial' || s.startsWith('unsupported:');
}
