/**
 * Stack-aware remediation snippets. Fix texts must name the mechanism of the stack the app actually
 * uses (no `supabase.auth.getUser()` advice on a NextAuth / Clerk / Convex app, no `pg_cron` on
 * Firestore, no `ON DELETE CASCADE` on MongoDB).
 *
 * Inputs (all optional, feature-detected):
 *   fact:tech-stack  {data:[techId], server:[techId], all:[techId]}   (src/audit/index.js, stack.js)
 *   fact:auth-stack  {libs:[…], frameworks:[…]}                       (extract/routes.js)
 *   store nodes      kind table/collection, evidence files            (fallback inference)
 */

const T = (tr, en) => ({ tr, en });

/** {data:Set, server:Set, auth:Set, frameworks:Set} for the graph. */
export function stackProfile(g) {
  const tech = g?.node?.('fact:tech-stack');
  const auth = g?.node?.('fact:auth-stack');
  const data = new Set(Array.isArray(tech?.data) ? tech.data : []);
  const server = new Set(Array.isArray(tech?.server) ? tech.server : []);
  const libs = new Set(Array.isArray(auth?.libs) ? auth.libs : []);
  const frameworks = new Set(Array.isArray(auth?.frameworks) ? auth.frameworks : []);
  if (Array.isArray(tech?.auth)) for (const a of tech.auth) libs.add(a);
  if (!data.size && g?.nodesOf) {
    // Fallback: infer from the stores the extractors produced.
    for (const s of g.nodesOf('Store', (n) => n.kind === 'table' || n.kind === 'collection')) {
      const files = (s.evidence || []).map((e) => e?.file || '').join(' ');
      if (/\.prisma\b/.test(files)) data.add('prisma');
      else if (/supabase\//.test(files) || s.rls != null) data.add('supabase');
      else if (s.kind === 'collection') data.add(/firestore|firebase/i.test(`${s.id} ${files} ${s.source || ''}`) ? 'firestore' : 'mongodb');
      else if (/\.sql\b/.test(files)) data.add('pg');
    }
    if (libs.has('supabase')) data.add('supabase');
    if (libs.has('firebase') && !data.size) data.add('firestore');
  }
  return { data, server, auth: libs, frameworks };
}

const has = (set, ...ids) => ids.some((i) => set.has(i));

/** How to enforce a retention period on this stack. */
export function retentionHow(g) {
  const { data } = stackProfile(g);
  const parts = [];
  if (has(data, 'supabase')) parts.push(T('pg_cron ile zamanlanmış silme', 'a pg_cron scheduled delete'));
  else if (has(data, 'prisma', 'drizzle', 'knex', 'typeorm', 'sequelize', 'mikro-orm', 'kysely', 'pg', 'mysql', 'sqlite', 'libsql', 'd1', 'sqlalchemy', 'django', 'peewee', 'activerecord', 'eloquent', 'doctrine', 'jpa', 'gorm', 'ecto')) parts.push(T('süresi dolan satırları silen zamanlanmış bir iş (cron; ör. createdAt < now() - süre)', 'a scheduled job (cron) that deletes expired rows (e.g. createdAt < now() - period)'));
  if (has(data, 'mongodb', 'pymongo')) parts.push(T('MongoDB TTL index (expireAfterSeconds)', 'a MongoDB TTL index (expireAfterSeconds)'));
  if (has(data, 'firestore', 'firebase-rtdb')) parts.push(T('Firestore TTL politikası veya zamanlanmış Cloud Function', 'a Firestore TTL policy or a scheduled Cloud Function'));
  if (has(data, 'convex')) parts.push(T('süresi dolan belgeleri silen bir Convex cron işi (cronJobs)', 'a Convex cron job (cronJobs) that deletes expired documents'));
  if (has(data, 'dynamodb')) parts.push(T('DynamoDB TTL özniteliği', 'a DynamoDB TTL attribute'));
  if (!parts.length) parts.push(T('süresi dolan kayıtları silen veya anonimleştiren zamanlanmış bir iş', 'a scheduled job that deletes or anonymises expired records'));
  return T(parts.map((p) => p.tr).join(' / '), parts.map((p) => p.en).join(' / '));
}

/** How to make deletion cascade to records linked to the user on this stack. */
export function cascadeHow(g) {
  const { data } = stackProfile(g);
  const parts = [];
  if (has(data, 'prisma')) parts.push(T('Prisma ilişkisinde onDelete: Cascade', 'onDelete: Cascade on the Prisma relation'));
  if (has(data, 'drizzle')) parts.push(T("Drizzle references(..., { onDelete: 'cascade' })", "Drizzle references(..., { onDelete: 'cascade' })"));
  if (has(data, 'knex')) parts.push(T(".references(...).onDelete('CASCADE') (knex migration)", ".references(...).onDelete('CASCADE') in the knex migration"));
  if (has(data, 'typeorm', 'sequelize', 'mikro-orm')) parts.push(T("ilişkide onDelete: 'CASCADE'", "onDelete: 'CASCADE' on the relation"));
  if (has(data, 'django')) parts.push(T('ForeignKey(on_delete=models.CASCADE)', 'ForeignKey(on_delete=models.CASCADE)'));
  if (has(data, 'activerecord')) parts.push(T('has_many ..., dependent: :destroy', 'has_many ..., dependent: :destroy'));
  if (has(data, 'eloquent')) parts.push(T('->cascadeOnDelete() (migration)', '->cascadeOnDelete() in the migration'));
  if (!parts.length && has(data, 'supabase', 'pg', 'mysql', 'sqlite', 'libsql', 'd1', 'sqlalchemy', 'peewee', 'jpa', 'gorm', 'ecto', 'kysely')) parts.push(T('yabancı anahtarlarda ON DELETE CASCADE', 'ON DELETE CASCADE on the foreign keys'));
  if (has(data, 'mongodb', 'pymongo')) parts.push(T('silme işleminde bağlı belgeleri açıkça silin (deleteMany({ userId }))', 'delete linked documents explicitly in the deletion (deleteMany({ userId }))'));
  if (has(data, 'firestore')) parts.push(T('kullanıcı belgesini alt koleksiyonlarıyla birlikte silin (recursiveDelete / "Delete User Data" eklentisi)', 'delete the user document together with its subcollections (recursiveDelete / the "Delete User Data" extension)'));
  if (has(data, 'convex')) parts.push(T('silme mutation\'ında ilgili belgeleri de silin', 'delete the related documents inside the deletion mutation'));
  if (!parts.length) parts.push(T('bağlı kayıtları silme fonksiyonunda açıkça silin', 'delete linked records explicitly in the deletion function'));
  return T(parts.map((p) => p.tr).join(' / '), parts.map((p) => p.en).join(' / '));
}

/** How to keep stored files private on this stack. */
export function bucketHow(g, bucket) {
  const { data, auth } = stackProfile(g);
  const files = (bucket?.evidence || []).map((e) => e?.file || '').join(' ');
  if (has(data, 'supabase') || has(auth, 'supabase') || /supabase\/|\.sql\b/.test(files)) {
    return T('Bucket\'ı private yapın, storage RLS politikalarıyla sahibine kısıtlayın ve kısa süreli signed URL kullanın.', 'Make the bucket private, restrict it to the owner with storage RLS policies and use short-lived signed URLs.');
  }
  if (has(data, 'firestore') || has(auth, 'firebase') || /storage\.rules/.test(files)) {
    return T('storage.rules ile erişimi sahibine kısıtlayın (request.auth.uid == userId) ve herkese açık indirme URL\'leri paylaşmayın.', 'Restrict access to the owner in storage.rules (request.auth.uid == userId) and do not hand out public download URLs.');
  }
  return T('Depoyu/bucket\'ı private yapın (S3/R2: Block Public Access), erişimi sahibine kısıtlayın ve kısa süreli imzalı (presigned) URL kullanın.', 'Make the bucket private (S3/R2: Block Public Access), restrict access to the owner and use short-lived presigned URLs.');
}

const SESSION_HELPERS = {
  supabase: 'supabase.auth.getUser()', nextauth: 'getServerSession(authOptions) / auth()', clerk: 'auth() / currentUser() (@clerk)',
  lucia: 'validateRequest() / lucia.validateSession()', 'better-auth': 'auth.api.getSession({ headers })', firebase: 'admin.auth().verifyIdToken()',
  kinde: 'getKindeServerSession()', 'nuxt-auth': 'requireUserSession(event)', passport: 'passport.authenticate() / req.isAuthenticated()',
  auth0: 'getSession() (@auth0)', appwrite: 'account.get() with the session', pocketbase: 'pb.authStore.isValid', 'flask-login': '@login_required',
  django: '@login_required / LoginRequiredMixin', 'python-jwt': 'Depends(get_current_user)', jwt: 'a JWT verification middleware (jwt.verify)',
  convex: 'ctx.auth.getUserIdentity()',
};
const FRAMEWORK_HELPERS = {
  sveltekit: 'event.locals (hooks.server.ts)', nuxt: 'a server/middleware or per-handler check that throws createError({ statusCode: 401 })',
  express: 'an auth middleware on the router (router.use(auth))', remix: 'requireUserId(request) in the action/loader',
  'supabase-edge': 'supabase.auth.getUser(token) from the Authorization header', 'firebase-functions': 'context.auth / request.auth in the callable',
};

/** Stack-aware "verify the session" helper list for remediation text (neutral when the stack is unknown). */
export function sessionHelperText(g) {
  const { auth, frameworks, data, server } = stackProfile(g);
  const libs = [...auth];
  if (has(data, 'convex') || has(server, 'convex')) libs.push('convex');
  const tips = [...new Set(libs.filter((l) => SESSION_HELPERS[l]).map((l) => SESSION_HELPERS[l]))];
  if (!tips.length) for (const fw of frameworks) if (FRAMEWORK_HELPERS[fw]) tips.push(FRAMEWORK_HELPERS[fw]);
  return tips.slice(0, 3).join('; ');
}
