// PSM panel backend: servers, nodes, traffic, subscriptions, the one-click
// install command, and the task queue each server's psm-agent syncs with. The
// panel never connects to a server: agents connect out to it (like Xboard's
// node backends), so no server needs a subdomain or an open port.
import { Hono, type Context } from 'hono'
import { decrypt, encrypt } from './crypto'
import { ensureSchema, storedTokenKey } from './schema'
import {
  adminConfigured, clearFailures, clearedCookie, ipKey, passwordIgnored, passwordMatches, recordFailure, revokeSessions,
  sessionCookie, syncAdminPassword, tooManyFailures, validSession,
} from './auth'
import { buildSubscription, pickFormat, renameLink, type SubNode } from './subscription'
import { BUILTIN_TEMPLATES, FORMAT_LABELS, TEMPLATE_FORMATS, type TemplateFormat } from './templates'
import { activeFields, currentVariant, findVariant, trafficTag, validateNode, type NodeInput } from '../../shared/protocols'
import {
  bareHost, goodHost, goodPort, parseHostPort, RELAY_PORTS, relayProblems, type RelayEngine, type RelayFields, type RelayMode,
} from '../../shared/relays'
import { findSniCandidates, SNI_ENGINES } from './sni'
import { linkVia, nodeVia, type Via } from './relayed'

// not exported: every export of a Worker's main module is taken for an entrypoint
// Shown in 系统设置 as 面板版本; bump it whenever the panel gains something, so
// that it answers "did my deploy take effect?" — the only marker a user has.
const PANEL_VERSION = '0.10.2'

// The psm-agent release this panel expects its servers to run: the 服务器 page
// offers an upgrade to every joined server reporting anything else. Bump it
// together with the agent-v… release the panel's install command installs.
const AGENT_VERSION = '0.12.0'

export type Env = {
  DB: D1Database
  ASSETS: Fetcher
  /** the admin password (secret; the Deploy to Cloudflare form asks for it) */
  ADMIN_PASSWORD?: string
  /** the key for D1 (secret, optional): filled in from D1's own when not set */
  TOKEN_KEY: string
  /** the panel's public address, used in the install command (default: the request's origin) */
  PANEL_URL?: string
  /** where bootstrap.sh is served */
  INSTALL_URL?: string
  /** seconds between agent syncs when there is nothing to do (default 30) */
  SYNC_INTERVAL?: string
  /** tests only: a stand-in for Netlas's API (the REALITY target search) */
  SNI_NETLAS_BASE?: string
}

type ServerRow = {
  id: number; name: string; agent_token_hash: string | null; hostname: string | null
  agent_version: string | null; note: string; last_seen: string | null; created_at: string
  psm_version: string | null; status_enc: string | null; status_at: string | null
  leaving: number; leave_error: string | null
  relay_port_min: number | null; relay_port_max: number | null; last_ip: string | null
  asn: number | null; country: string | null; sync_window: string | null; sync_count: number
  check_enc: string | null; check_at: string | null; check_error: string | null
}
type NodeRow = {
  id: number; server_id: number; protocol: string; variant: string; engine: string; psm_protocol: string
  name: string; address: string; port: number; public_port: number | null; traffic_limit_gb: number
  labels: string; params_enc: string; link_enc: string | null; outbound_enc: string | null; clash_enc: string | null
  status: string; last_error: string | null; created_at: string
  traffic_used: number; traffic_paused: number; traffic_at: string | null; reset_day: number
  mount_443: number
}
type RelayRow = {
  id: number; server_id: number; name: string; listen_port: number; remote_host: string; remote_port: number
  remote_server_id: number | null; udp: number; tls: number; tls_sni: string; tls_insecure: number
  status: string; last_error: string | null; created_at: string
  meter_bytes: number; traffic_bytes: number
  last_rtt_ms: number | null; last_jitter_ms: number | null; last_loss_pct: number | null; last_sample_at: string | null
  engine: string; mode: string; targets: string; strategy: string; probe: number; auto_port: number
  exit_server_id: number | null; exit_host: string; exit_port: number | null; exit_auto_port: number
  transport: string; ws_host: string; ws_path: string; secret_enc: string | null; exit_cert: string | null
  exit_status: string; exit_error: string | null; pending_entry: string
  exit_rtt_ms: number | null; exit_loss_pct: number | null
  speed_mbps: number; limit_gb: number; reset_day: number; expires_at: string | null
  quota_used: number | null; paused: string; target_health: string | null
  node_id: number | null; entry_host: string; in_sub: number
}
type TaskRow = { id: number; server_id: number; node_id: number | null; relay_id: number | null; kind: string; payload_enc: string; status: string }
type AgentResult = { task_id: number; ok: boolean; link?: string; outbound?: unknown; clash?: unknown; error?: string; output?: unknown }
type TrafficEntry = { tag?: unknown; used_bytes?: unknown; paused?: unknown }
/** One measurement of a relay's hop, as `psm relay probe --json` reports it. */
type RelaySample = {
  tag?: unknown; rtt_ms?: unknown; jitter_ms?: unknown; loss_pct?: unknown; bytes?: unknown
  used_bytes?: unknown; paused?: unknown; pause_reason?: unknown; targets?: unknown
}
type C = Context<{ Bindings: Env }>

const app = new Hono<{ Bindings: Env }>()

const fail = (code: string, message: string, extra: Record<string, unknown> = {}) => ({ error: { code, message, ...extra } })
const SERVER_NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/
const JOIN_TTL_HOURS = 24
const FAST_INTERVAL = 3        // seconds between syncs while a server has tasks under way
const TASK_RETRY_MINUTES = 5   // a task claimed but not reported for this long is handed out again
const GB = 1024 ** 3
const MASK = '••••••'          // how the page sees a stored password
const SYNCS_PER_MINUTE = 120   // more from one agent token is not a psm-agent: it is told to slow down

// Agents sync every SYNC_INTERVAL seconds when idle (30 by default; each sync
// is one Worker request and one D1 write, so a longer interval leaves the free
// quotas for more servers) and every FAST_INTERVAL seconds while tasks are
// under way. A server is online while it synced within three intervals.
function syncInterval(env: Env): number {
  const n = Number(env.SYNC_INTERVAL)
  return Number.isFinite(n) && n >= 5 && n <= 300 ? Math.round(n) : 30
}

app.onError((err, c) => {
  console.error(err)
  return c.json(fail('internal', 'internal error'), 500)
})

// ── helpers ──────────────────────────────────────────────────────────────────
async function sha256Hex(s: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))
  return [...d].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function randomToken(bytes = 32): string {
  const b = crypto.getRandomValues(new Uint8Array(bytes))
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function getSetting(env: Env, key: string): Promise<string | null> {
  const r = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first<{ value: string }>()
  return r?.value ?? null
}

/** The address servers and subscribers use: the setting, PANEL_URL, or this request's origin. */
async function panelUrl(c: C): Promise<string> {
  return (await getSetting(c.env, 'panel_url')) || c.env.PANEL_URL || new URL(c.req.url).origin
}

async function installCommand(c: C, token: string): Promise<string> {
  const install = c.env.INSTALL_URL ?? 'https://psm.jinqians.com'
  return `bash <(curl -fsSL ${install}) --panel ${await panelUrl(c)} --join ${token}`
}

async function audit(env: Env, action: string, target = '', detail = '', actor = 'admin') {
  await env.DB.prepare('INSERT INTO audit (actor, action, target, detail) VALUES (?, ?, ?, ?)')
    .bind(actor, action, target.slice(0, 120), detail.slice(0, 500)).run()
}

/**
 * The join token in a server's install command: the one it has while that
 * stays valid for another hour, or a new one. Every node or relay added to a
 * server that has not joined yet shows the same command — forty nodes do not
 * mint forty live tokens (the audit's L7) — and a command already handed out
 * keeps working. The token is kept encrypted to be shown again; D1 never has
 * it in clear. `fresh`: a new token, and every older one stops working (安装命令
 * → 重新生成). The first one used makes the server join and voids the rest.
 */
async function joinToken(env: Env, serverId: number, fresh = false): Promise<string> {
  if (!fresh) {
    const live = await env.DB.prepare(
      `SELECT token_enc FROM join_tokens WHERE server_id = ? AND used_at IS NULL AND token_enc IS NOT NULL
          AND expires_at > datetime('now', '+1 hours') ORDER BY expires_at DESC LIMIT 1`).bind(serverId).first<{ token_enc: string }>()
    if (live) {
      try { return await decrypt(env.TOKEN_KEY, live.token_enc) } catch { /* written under another key: a new one */ }
    }
  }
  const token = randomToken()
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM join_tokens WHERE expires_at <= datetime('now')`),
    ...(fresh ? [env.DB.prepare(`DELETE FROM join_tokens WHERE server_id = ? AND used_at IS NULL`).bind(serverId)] : []),
    env.DB.prepare(`INSERT INTO join_tokens (token_hash, server_id, expires_at, token_enc) VALUES (?, ?, datetime('now', '+${JOIN_TTL_HOURS} hours'), ?)`)
      .bind(await sha256Hex(token), serverId, await encrypt(env.TOKEN_KEY, token)),
  ])
  return token
}

const serverStatusSQL = (env: Env) => `CASE WHEN s.leaving = 1 THEN 'leaving' WHEN s.agent_token_hash IS NULL THEN 'pending'
  WHEN s.last_seen >= datetime('now', '-${syncInterval(env) * 3} seconds') THEN 'online' ELSE 'offline' END`

/** A row id from the URL or a body: a positive integer, or null (never NaN into a query). */
function idOf(v: unknown): number | null {
  const s = String(v ?? '')
  return /^[1-9]\d{0,15}$/.test(s) ? Number(s) : null
}

async function getServer(env: Env, id: unknown): Promise<ServerRow | null> {
  const n = idOf(id)
  return n === null ? null : env.DB.prepare('SELECT * FROM servers WHERE id = ?').bind(n).first<ServerRow>()
}

async function getNode(env: Env, id: unknown): Promise<NodeRow | null> {
  const n = idOf(id)
  return n === null ? null : env.DB.prepare('SELECT * FROM nodes WHERE id = ?').bind(n).first<NodeRow>()
}

/** A task, as a statement to run alone or in a batch with others. */
async function taskStmt(env: Env, serverId: number, nodeId: number | null, task: Record<string, unknown>, relayId: number | null = null) {
  return env.DB.prepare('INSERT INTO tasks (server_id, node_id, relay_id, kind, payload_enc) VALUES (?, ?, ?, ?, ?)')
    .bind(serverId, nodeId, relayId, task.kind as string, await encrypt(env.TOKEN_KEY, JSON.stringify(task)))
}

async function enqueue(env: Env, serverId: number, nodeId: number | null, task: Record<string, unknown>, relayId: number | null = null): Promise<number> {
  const r = await (await taskStmt(env, serverId, nodeId, task, relayId)).run()
  return Number(r.meta.last_row_id)
}

const linkFormat = (n: { psm_protocol: string }) => (n.psm_protocol === 'snell' ? 'surge' : 'uri')

/**
 * The tasks that put a node on its server: the node itself (psm-agent installs
 * a missing core first; a standalone node is the standalone server), then its
 * traffic metering and limit.
 */
async function applyStmts(env: Env, n: NodeRow, data: Record<string, unknown>, kind: 'add' | 'update' = 'add') {
  const common = { protocol: n.psm_protocol, server: n.address, format: linkFormat(n) }
  const task = n.engine === 'standalone'
    ? { kind: 'standalone.install', tag: n.name, data, ...common }
    : kind === 'update'
      ? { kind: 'node.update', core: n.engine, tag: n.name, data, ...common }
      // mount443 is not a node setting but how PSM must create it (--mount-443)
      : { kind: 'node.add', core: n.engine, data, mount443: !!n.mount_443, ...common }
  return [await taskStmt(env, n.server_id, n.id, task), await taskStmt(env, n.server_id, n.id, trafficTask(n))]
}

async function queueApply(env: Env, n: NodeRow, data: Record<string, unknown>, kind: 'add' | 'update' = 'add') {
  await env.DB.batch(await applyStmts(env, n, data, kind))
}

/**
 * Ask a server for its nodes' client exports again (share link, sing-box
 * outbound, mihomo proxy). A PSM update can change them without the node
 * changing — a certificate pin in the links, a node newly written as a mihomo
 * proxy — and the panel only stores what the agent sent at the node's last add
 * or edit. Standalone servers export the same as before.
 */
async function queueExports(env: Env, serverId: number) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM nodes WHERE server_id = ? AND status = 'applied' AND engine != 'standalone'`).bind(serverId).all<NodeRow>()
  const stmts = await Promise.all(results.map((n) => taskStmt(env, serverId, n.id,
    { kind: 'node.export', core: n.engine, protocol: n.psm_protocol, tag: n.name, server: n.address, format: linkFormat(n) })))
  if (stmts.length) await env.DB.batch(stmts)
}

function trafficTask(n: NodeRow) {
  return { kind: 'traffic.set', tag: trafficTag(n), limit_bytes: Math.round(Math.min(n.traffic_limit_gb || 0, 1e6) * GB), reset_day: n.reset_day || 1 }
}

/** The node store fields for a node (as validated when it was entered). */
async function nodeData(env: Env, n: NodeRow): Promise<Record<string, unknown>> {
  const params = JSON.parse(await decrypt(env.TOKEN_KEY, n.params_enc)) as Record<string, unknown>
  const v = validateNode({
    protocol: n.protocol, variant: n.variant, engine: n.engine as NodeInput['engine'], name: n.name,
    address: n.address, port: n.port, public_port: n.public_port ?? undefined, params,
  })
  if (!v.ok) throw new Error(`stored node ${n.id} no longer validates: ${v.errors.join('; ')}`)
  return v.data
}

/** A node row for the list: nothing decrypted (a list of many nodes costs no AES), no link. */
function listNode(n: NodeRow) {
  const { params_enc: _p, link_enc: _l, outbound_enc: _o, clash_enc: _c, ...rest } = n
  return { ...rest, traffic_paused: !!n.traffic_paused, mount_443: !!n.mount_443,
    labels: JSON.parse(n.labels) as string[], has_link: !!n.link_enc }
}

/** A node row for its edit form: params decrypted, secrets masked, no link. */
async function publicNode(env: Env, n: NodeRow) {
  const params = JSON.parse(await decrypt(env.TOKEN_KEY, n.params_enc)) as Record<string, unknown>
  const v = findVariant(n.protocol, n.variant)
  const secret = new Set((v?.fields ?? []).filter((f) => f.type === 'password').map((f) => f.key))
  for (const k of Object.keys(params)) if (secret.has(k) && params[k]) params[k] = MASK
  return { ...listNode(n), params }
}

function cleanLabels(raw: unknown): string[] {
  return (Array.isArray(raw) ? raw : []).map(String).map((l) => l.trim().slice(0, 24)).filter(Boolean).slice(0, 10)
}

/** The params a node keeps: those of its form, with masked passwords replaced by the stored ones. */
function keptParams(variantFields: { key: string }[], incoming: Record<string, unknown>, stored: Record<string, unknown> = {}) {
  const params: Record<string, unknown> = {}
  for (const f of variantFields) {
    let v = incoming[f.key]
    if (v === MASK) v = stored[f.key]
    if (v !== undefined && v !== '') params[f.key] = v
  }
  return params
}

// VLESS nodes made before 0.10.2 get the variant they have now
// (currentVariant in shared/protocols.ts): only the panel's record changes.
// It reads their settings, so it runs after the key, once per database, and
// is recorded among the migrations. A node whose settings do not decrypt
// (written under another key) leaves it to be tried again.
const VARIANTS_MIGRATION = 'data:0015_vless_variants'
let variantsReady: Promise<void> | null = null
async function migrateVariants(env: Env) {
  if (await env.DB.prepare('SELECT 1 FROM psm_migrations WHERE name = ?').bind(VARIANTS_MIGRATION).first()) return
  const { results } = await env.DB.prepare(
    `SELECT id, protocol, variant, engine, params_enc FROM nodes WHERE protocol = 'vless' AND variant IN ('vless-tls', 'vless-xhttp')`)
    .all<Pick<NodeRow, 'id' | 'protocol' | 'variant' | 'engine' | 'params_enc'>>()
  const stmts: D1PreparedStatement[] = []
  let unreadable = 0
  for (const n of results) {
    let params: Record<string, unknown>
    try {
      params = JSON.parse(await decrypt(env.TOKEN_KEY, n.params_enc)) as Record<string, unknown>
    } catch {
      unreadable++
      continue
    }
    const v = currentVariant(n.protocol, n.variant, n.engine, params)
    if (v !== n.variant) stmts.push(env.DB.prepare('UPDATE nodes SET variant = ? WHERE id = ?').bind(v, n.id))
  }
  if (!unreadable) stmts.push(env.DB.prepare('INSERT OR IGNORE INTO psm_migrations (name) VALUES (?)').bind(VARIANTS_MIGRATION))
  else console.error(`vless variants: ${unreadable} node(s) not readable, left for the next start`)
  if (stmts.length) await env.DB.batch(stmts)
}

// ── every request the Worker sees: the tables and the key ────────────────────
// Where TOKEN_KEY came from: the secret, or the panel's own copy in D1 (a
// one-click deploy); 系统设置 warns about the second.
let tokenKeySource: 'secret' | 'panel' | null = null
let panelKey: string | null = null
app.use('*', async (c, next) => {
  await ensureSchema(c.env.DB)
  tokenKeySource ??= c.env.TOKEN_KEY ? 'secret' : 'panel'
  if (!c.env.TOKEN_KEY) c.env.TOKEN_KEY = panelKey ??= await storedTokenKey(c.env.DB)
  variantsReady ??= migrateVariants(c.env).catch((e) => { variantsReady = null; throw e })
  await variantsReady
  // after TOKEN_KEY: the session signature is derived from it
  await syncAdminPassword(c.env)
  await next()
})

// Every answer from the API: never sniffed as another type, never framed,
// never cached (it carries links, keys and tokens), no referrer. The pages
// themselves get theirs from web/public/_headers.
app.use('/api/*', async (c, next) => {
  await next()
  c.header('X-Content-Type-Options', 'nosniff')
  c.header('X-Frame-Options', 'DENY')
  c.header('Referrer-Policy', 'no-referrer')
  if (!c.res.headers.has('Cache-Control')) c.header('Cache-Control', 'no-store')
})
app.use('/sub/*', async (c, next) => {
  await next()
  c.header('X-Content-Type-Options', 'nosniff')
  c.header('Referrer-Policy', 'no-referrer')
})

// A change made from a browser must come from the panel's own page. The
// cookie is SameSite=Strict already; this is the second lock. Browsers say
// where a request comes from in Sec-Fetch-Site (a proxy in front cannot make
// that look cross-site, as it could a Host that differs from the Origin);
// one too old for it still sends Origin. Tools without a browser send
// neither and are let through on their session alone.
const CHANGES = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
function crossSite(c: C): boolean {
  if (!CHANGES.has(c.req.method)) return false
  const site = c.req.header('Sec-Fetch-Site')
  if (site) return site !== 'same-origin' && site !== 'none'
  const origin = c.req.header('Origin')
  return !!origin && origin !== new URL(c.req.url).origin
}

// The admin API needs a session. psm-agent's endpoints use its own token, and
// signing in is open (limited per address).
const OPEN = new Set(['/api/session', '/api/login', '/api/logout'])
app.use('/api/*', async (c, next) => {
  const path = new URL(c.req.url).pathname
  if (path.startsWith('/api/agent/')) return next()
  if (crossSite(c)) return c.json(fail('cross_site', 'a change must come from the panel itself'), 403)
  if (OPEN.has(path)) return next()
  if (!adminConfigured(c.env)) return c.json(fail('not_configured', 'set the ADMIN_PASSWORD secret (8+ characters)'), 503)
  if (!(await validSession(c.env, c.req.header('Cookie')))) return c.json(fail('unauthorized', 'sign in first'), 401)
  await next()
})

const isHttps = (url: string) => new URL(url).protocol === 'https:'

app.get('/api/session', async (c) =>
  c.json({ configured: adminConfigured(c.env), authenticated: await validSession(c.env, c.req.header('Cookie')),
    version: PANEL_VERSION, password_ignored: passwordIgnored(c.env) }))

app.post('/api/login', async (c) => {
  if (!adminConfigured(c.env)) return c.json(fail('not_configured', 'set the ADMIN_PASSWORD secret (8+ characters)'), 503)
  const ip = ipKey(c.req.header('CF-Connecting-IP') ?? 'unknown')
  if (await tooManyFailures(c.env.DB, ip)) return c.json(fail('too_many', 'too many failed sign-ins; try again in 15 minutes'), 429)
  const body = await c.req.json<{ password?: unknown }>().catch(() => null)
  if (!(await passwordMatches(c.env, typeof body?.password === 'string' ? body.password : ''))) {
    await recordFailure(c.env.DB, ip)
    await audit(c.env, 'login.failed', ip, '', 'anonymous')
    return c.json(fail('bad_password', 'wrong password'), 401)
  }
  await clearFailures(c.env.DB, ip)
  await audit(c.env, 'login', ip)
  c.header('Set-Cookie', await sessionCookie(c.env, isHttps(c.req.url)))
  return c.json({ ok: true })
})

// Signing out ends every session (see auth.ts) — only for someone signed in:
// anyone may ask for their cookie to be cleared, not end the admin's.
app.post('/api/logout', async (c) => {
  if (await validSession(c.env, c.req.header('Cookie'))) {
    await revokeSessions(c.env.DB)
    await audit(c.env, 'logout', ipKey(c.req.header('CF-Connecting-IP') ?? ''))
  }
  c.header('Set-Cookie', clearedCookie(isHttps(c.req.url)))
  return c.body(null, 204)
})

// ── servers ──────────────────────────────────────────────────────────────────
app.get('/api/servers', async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT s.id, s.name, ${serverStatusSQL(c.env)} AS status, s.hostname, s.agent_version, s.psm_version, s.note,
            s.last_seen, s.created_at, s.status_at, s.leave_error, s.relay_port_min, s.relay_port_max, s.last_ip,
            s.asn, s.country,
            (SELECT COUNT(*) FROM nodes n WHERE n.server_id = s.id) AS node_count,
            (SELECT COUNT(*) FROM relays r WHERE r.server_id = s.id OR (r.mode = 'tunnel' AND r.exit_server_id = s.id)) AS relay_count,
            (SELECT COALESCE(SUM(n.traffic_used), 0) FROM nodes n WHERE n.server_id = s.id) AS traffic_used
       FROM servers s ORDER BY s.id`).all()
  // agent_latest rides along so the page can mark an outdated agent without a
  // second request
  return c.json(results.map((r) => ({ ...r, agent_latest: AGENT_VERSION })))
})

// Add a server; it waits for its install command.
app.post('/api/servers', async (c) => {
  const body = await c.req.json<{ name?: string; note?: string }>().catch(() => null)
  const name = body?.name?.trim().toLowerCase() ?? ''
  if (!SERVER_NAME_RE.test(name)) return c.json(fail('bad_name', 'name: 1-32 lowercase letters, digits and -'), 400)
  let id: number
  try {
    const r = await c.env.DB.prepare('INSERT INTO servers (name, note) VALUES (?, ?)').bind(name, body?.note?.slice(0, 200) ?? '').run()
    id = Number(r.meta.last_row_id)
  } catch (e) {
    if (String(e).includes('UNIQUE')) return c.json(fail('exists', 'a server with this name exists'), 409)
    throw e
  }
  await audit(c.env, 'server.add', name)
  return c.json({ id, install_command: await installCommand(c, await joinToken(c.env, id)) }, 201)
})

// A server's note and its relay port range (where a relay's port is picked
// when none is typed in; both null: 20000-60000).
app.patch('/api/servers/:id', async (c) => {
  const s = await getServer(c.env, c.req.param('id'))
  if (!s) return c.json(fail('not_found', 'no such server'), 404)
  const b = await c.req.json<{ note?: string; relay_port_min?: number | null; relay_port_max?: number | null }>().catch(() => null)
  if (!b || typeof b !== 'object') return c.json(fail('bad_body', 'the body must be a JSON object'), 400)
  const min = b.relay_port_min === undefined ? s.relay_port_min : b.relay_port_min
  const max = b.relay_port_max === undefined ? s.relay_port_max : b.relay_port_max
  if ((min === null) !== (max === null) || (min !== null && (!goodPort(min) || !goodPort(max) || min! > max!))) {
    const msg = '中转端口段：两个 1-65535 的端口，前小后大；都留空用默认的 20000-60000'
    return c.json(fail('invalid', msg, { errors: [msg] }), 400)
  }
  const note = b.note === undefined ? s.note : String(b.note).slice(0, 200)
  await c.env.DB.prepare('UPDATE servers SET note = ?, relay_port_min = ?, relay_port_max = ? WHERE id = ?').bind(note, min, max, s.id).run()
  await audit(c.env, 'server.update', s.name, min === null ? '' : `中转端口 ${min}-${max}`)
  return c.json({ id: s.id, note, relay_port_min: min, relay_port_max: max })
})

// The server's install command: the same one while it is valid, or with
// {"fresh": true} a new one that voids the others (a command shown somewhere
// it should not have been).
app.post('/api/servers/:id/install-command', async (c) => {
  const s = await getServer(c.env, c.req.param('id'))
  if (!s) return c.json(fail('not_found', 'no such server'), 404)
  const fresh = (await c.req.json<{ fresh?: unknown }>().catch(() => null))?.fresh === true
  if (fresh) await audit(c.env, 'server.new-command', s.name)
  return c.json({ install_command: await installCommand(c, await joinToken(c.env, s.id, fresh)) })
})

// Upgrade psm-agent on a server, so that it does not need the install command
// run by hand over SSH. The agent reports this task before doing any of it: the
// upgrade updates PSM first (the psm-agent version to install is named in PSM's
// own lib/agent.sh), then replaces the binary and restarts the service, which
// stops the process that would otherwise report the result.
app.post('/api/servers/:id/upgrade-agent', async (c) => {
  const s = await getServer(c.env, c.req.param('id'))
  if (!s) return c.json(fail('not_found', 'no such server'), 404)
  if (!s.agent_token_hash) return c.json(fail('not_joined', 'the server has not joined yet'), 409)
  await enqueue(c.env, s.id, null, { kind: 'agent.update' })
  await audit(c.env, 'server.upgrade-agent', s.name, s.agent_version === AGENT_VERSION
    ? `更新 PSM（psm-agent 已是 ${AGENT_VERSION}）` : `${s.agent_version ?? '未知'} → ${AGENT_VERSION}`)
  return c.json({ status: 'queued' }, 202)
})

// Remove a server. One that has joined is asked to clean up first: its agent
// deletes the nodes and standalone servers made from the panel (not those made
// on the server's own command line; PSM and the cores stay), reports, and
// uninstalls psm-agent; the server leaves the panel when that report arrives
// (202). ?force=1 removes it from the panel only — for a server that is gone or
// offline (it keeps its nodes; `psm agent remove --yes` there uninstalls the
// agent). One that never joined goes at once (204).
app.delete('/api/servers/:id', async (c) => {
  const s = await getServer(c.env, c.req.param('id'))
  if (!s) return c.json(fail('not_found', 'no such server'), 404)
  const force = new URL(c.req.url).searchParams.get('force') === '1'
  if (!s.agent_token_hash || force) {
    await detachServerRelays(c.env, s.id)
    await c.env.DB.prepare('DELETE FROM servers WHERE id = ?').bind(s.id).run()
    await audit(c.env, s.agent_token_hash ? 'server.forget' : 'server.delete', s.name)
    return c.body(null, 204)
  }
  if (s.leaving) return c.json({ status: 'leaving' }, 202)
  const { results } = await c.env.DB.prepare(`SELECT * FROM nodes WHERE server_id = ? AND status != 'waiting'`).bind(s.id).all<NodeRow>()
  // The relay rows go with the server (they are ON DELETE CASCADE), but the
  // realm rules and their accounting rules would be left behind on the machine
  // unless the agent is told to remove them as well.
  const { results: rels } = await c.env.DB.prepare(
    `SELECT name FROM relays WHERE server_id = ? AND status NOT IN ('waiting', 'pending', 'deleted')
     UNION SELECT name FROM relays WHERE mode = 'tunnel' AND exit_server_id = ? AND exit_status NOT IN ('waiting', 'deleted', '')`)
    .bind(s.id, s.id).all<{ name: string }>()
  const plan = {
    nodes: results.filter((n) => n.engine !== 'standalone').map((n) => ({ core: n.engine, protocol: n.psm_protocol, tag: n.name })),
    standalone: [...new Set(results.filter((n) => n.engine === 'standalone').map((n) => n.psm_protocol))],
    relays: rels.map((r) => r.name),
  }
  await c.env.DB.batch([
    c.env.DB.prepare(`DELETE FROM tasks WHERE server_id = ? AND status = 'queued'`).bind(s.id),
    c.env.DB.prepare(`UPDATE servers SET leaving = 1, leave_error = NULL WHERE id = ?`).bind(s.id),
  ])
  await enqueue(c.env, s.id, null, { kind: 'agent.leave', data: plan })
  await detachServerRelays(c.env, s.id)
  await audit(c.env, 'server.leave', s.name, `${plan.nodes.length} 个节点，${plan.standalone.length} 个独立安装，${plan.relays.length} 条中转`)
  return c.json({ status: 'leaving' }, 202)
})

// Diagnostics: ask the server's agent for a status report (psm doctor, cores,
// nodes, traffic, standalone servers); it arrives with the next sync.
app.post('/api/servers/:id/status', async (c) => {
  const s = await getServer(c.env, c.req.param('id'))
  if (!s) return c.json(fail('not_found', 'no such server'), 404)
  if (!s.agent_token_hash) return c.json(fail('not_joined', 'the server has not joined yet'), 409)
  await enqueue(c.env, s.id, null, { kind: 'status' })
  await audit(c.env, 'server.diagnose', s.name)
  return c.json({ status: 'queued' }, 202)
})

app.get('/api/servers/:id/status', async (c) => {
  const s = await getServer(c.env, c.req.param('id'))
  if (!s) return c.json(fail('not_found', 'no such server'), 404)
  const pending = !!(await c.env.DB.prepare(`SELECT 1 FROM tasks WHERE server_id = ? AND kind = 'status' AND status IN ('queued', 'running') LIMIT 1`)
    .bind(s.id).first())
  const report = s.status_enc ? JSON.parse(await decrypt(c.env.TOKEN_KEY, s.status_enc)) : null
  return c.json({ at: s.status_at, pending, report })
})

// ── the IP quality and unlock check (psm check, jinqians/ipcheck) ────────────
// The server runs it and reports; the last report stays on the server row.
app.post('/api/servers/:id/check', async (c) => {
  const s = await getServer(c.env, c.req.param('id'))
  if (!s) return c.json(fail('not_found', 'no such server'), 404)
  if (!s.agent_token_hash) return c.json(fail('not_joined', '服务器还没有接入面板'), 409)
  if (!versionAtLeast(s.agent_version, CHECK_AGENT))
    return c.json(fail('agent_too_old', `${s.name} 的 psm-agent 是 ${s.agent_version ?? '旧版'}，IP 检测要 ${CHECK_AGENT} 以上：先在 ⋯ 里升级 psm-agent`), 409)
  const body = await c.req.json<{ family?: unknown }>().catch(() => ({} as { family?: unknown }))
  const family = body.family === '4' || body.family === '6' ? body.family : ''
  if (await c.env.DB.prepare(`SELECT 1 FROM tasks WHERE server_id = ? AND kind = 'check.run' AND status IN ('queued', 'running') LIMIT 1`).bind(s.id).first())
    return c.json({ status: 'queued' }, 202)   // one is on its way already
  const keys = await ipcheckKeys(c.env)
  const data = { ...(family ? { family } : {}), ...(Object.keys(keys).length ? { keys } : {}) }
  await enqueue(c.env, s.id, null, { kind: 'check.run', ...(Object.keys(data).length ? { data } : {}) })
  await audit(c.env, 'server.check', s.name, family ? `IPv${family}` : '')
  return c.json({ status: 'queued' }, 202)
})

app.get('/api/servers/:id/check', async (c) => {
  const s = await getServer(c.env, c.req.param('id'))
  if (!s) return c.json(fail('not_found', 'no such server'), 404)
  const pending = !!(await c.env.DB.prepare(`SELECT 1 FROM tasks WHERE server_id = ? AND kind = 'check.run' AND status IN ('queued', 'running') LIMIT 1`)
    .bind(s.id).first())
  const report = s.check_enc ? JSON.parse(await decrypt(c.env.TOKEN_KEY, s.check_enc)) : null
  return c.json({ at: s.check_at, pending, report, error: s.check_error,
    // what the server needs first, if anything
    needs: !s.agent_token_hash ? 'join' : versionAtLeast(s.agent_version, CHECK_AGENT) ? null : CHECK_AGENT })
})

// ── nodes ────────────────────────────────────────────────────────────────────
// The list carries no settings (GET /api/nodes/:id does): decrypting every
// node's for a table that shows none of them was most of the list's cost.
app.get('/api/nodes', async (c) => {
  const sid = idOf(new URL(c.req.url).searchParams.get('server_id'))
  const stmt = sid !== null
    ? c.env.DB.prepare('SELECT * FROM nodes WHERE server_id = ? ORDER BY id').bind(sid)
    : c.env.DB.prepare('SELECT * FROM nodes ORDER BY id')
  const { results } = await stmt.all<NodeRow>()
  return c.json(results.map(listNode))
})

app.get('/api/nodes/:id', async (c) => {
  const n = await getNode(c.env, c.req.param('id'))
  return n ? c.json(await publicNode(c.env, n)) : c.json(fail('not_found', 'no such node'), 404)
})

// Create a node: checked against the protocol table and saved. On a server
// that has joined, tasks for its agent are queued; otherwise the node waits
// for the install command, which is then returned.
app.post('/api/nodes', async (c) => {
  const body = await c.req.json<NodeInput & { server_id?: number; reset_day?: number }>().catch(() => null)
  if (!body) return c.json(fail('bad_body', 'the body must be a JSON object'), 400)
  const server = await getServer(c.env, body.server_id ?? '')
  if (!server) return c.json(fail('bad_server', 'choose a server'), 400)
  const v = validateNode(body)
  if (!v.ok) return c.json(fail('invalid', v.errors.join('；'), { errors: v.errors }), 400)
  const tooOld = psmTooOld(server, v.data)
  if (tooOld) return c.json(fail('psm_too_old', tooOld, { errors: [tooOld] }), 409)
  const resetDay = body.reset_day ?? 1
  if (!Number.isInteger(resetDay) || resetDay < 1 || resetDay > 28) return c.json(fail('invalid', '流量重置日：1-28', { errors: ['流量重置日：1-28'] }), 400)
  // on the shared 443 clients reach 443: another public port would be dropped without a word
  if (body.mount_443 && body.public_port !== undefined && body.public_port !== null && body.public_port !== 443) {
    const msg = '挂到 443 复用的节点，连接端口就是 443'
    return c.json(fail('invalid', msg, { errors: [msg] }), 400)
  }
  // one being removed does not count: its removal runs on the server before this install
  if (v.engine === 'standalone' && await c.env.DB.prepare(
    `SELECT 1 FROM nodes WHERE server_id = ? AND engine = 'standalone' AND psm_protocol = ? AND status != 'deleting'`).bind(server.id, v.psmProtocol).first()) {
    const msg = `${server.name} 已有一个独立安装的 ${v.psmProtocol === 'snell' ? 'Snell' : 'SS2022'}（每台服务器一个），可以改用内核运行`
    return c.json(fail('exists', msg, { errors: [msg] }), 409)
  }

  const variant = findVariant(body.protocol, body.variant)!
  const params = keptParams(activeFields(variant, v.engine, body.params ?? {}), body.params ?? {})
  const joined = !!server.agent_token_hash
  const status = joined ? 'queued' : 'waiting'
  const mount443 = !!body.mount_443

  let id: number
  try {
    const r = await c.env.DB.prepare(
      `INSERT INTO nodes (server_id, protocol, variant, engine, psm_protocol, name, address, port, public_port, traffic_limit_gb, reset_day, labels, params_enc, status, mount_443)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(server.id, body.protocol, body.variant, v.engine, v.psmProtocol, body.name, body.address, body.port,
        // on the shared 443 the node listens on 127.0.0.1 and clients reach 443
        mount443 ? 443 : body.public_port ?? null, body.traffic_limit_gb ?? 0, resetDay, JSON.stringify(cleanLabels(body.labels)),
        await encrypt(c.env.TOKEN_KEY, JSON.stringify(params)), status, mount443 ? 1 : 0)
      .run()
    id = Number(r.meta.last_row_id)
  } catch (e) {
    if (String(e).includes('UNIQUE')) return c.json(fail('exists', `${server.name} already has a node named ${body.name}`), 409)
    throw e
  }
  if (status === 'queued') await queueApply(c.env, (await getNode(c.env, id))!, v.data)
  await audit(c.env, 'node.add', `${server.name}/${body.name}`, `${v.engine} ${v.psmProtocol}`)
  // a server that has not joined needs the install command; one that has gets
  // the node through its agent (to reinstall it, the servers page issues one)
  const install_command = joined ? undefined : await installCommand(c, await joinToken(c.env, server.id))
  return c.json({ id, status, joined, install_command }, 201)
})

// Edit a node: its address, ports, traffic limit, labels and settings (the
// protocol, how it runs, its server and its name stay). A node on its server is
// updated there by the agent; one that failed is tried again.
app.patch('/api/nodes/:id', async (c) => {
  const n = await getNode(c.env, c.req.param('id'))
  if (!n) return c.json(fail('not_found', 'no such node'), 404)
  if (n.status === 'queued' || n.status === 'deleting') return c.json(fail('busy', '节点正在下发或删除，稍后再改'), 409)
  const body = await c.req.json<Partial<NodeInput> & { reset_day?: number }>().catch(() => null)
  if (!body) return c.json(fail('bad_body', 'the body must be a JSON object'), 400)
  // PSM refuses to move a node onto or off the shared 443 as an update: the
  // node's public address changes, so that is a delete and an add.
  if (body.mount_443 !== undefined && !!body.mount_443 !== !!n.mount_443) {
    const msg = '443 端口复用不能改：请删除这个节点后按新的方式重建'
    return c.json(fail('invalid', msg, { errors: [msg] }), 400)
  }
  // null takes a public port away (clients use the port itself); left out keeps it
  const publicPort = body.public_port === undefined ? (n.public_port ?? undefined) : (body.public_port ?? undefined)
  if (n.mount_443 && publicPort !== 443) {
    const msg = '挂到 443 复用的节点，连接端口就是 443'
    return c.json(fail('invalid', msg, { errors: [msg] }), 400)
  }
  const stored = JSON.parse(await decrypt(c.env.TOKEN_KEY, n.params_enc)) as Record<string, unknown>
  const input: NodeInput = {
    protocol: n.protocol, variant: n.variant, engine: n.engine as NodeInput['engine'], name: n.name,
    address: body.address ?? n.address, port: body.port ?? n.port,
    public_port: publicPort,
    traffic_limit_gb: body.traffic_limit_gb ?? n.traffic_limit_gb,
    labels: body.labels ?? JSON.parse(n.labels),
    params: { ...stored, ...(body.params ?? {}) },
  }
  for (const [k, val] of Object.entries(input.params!)) if (val === MASK) input.params![k] = stored[k]
  const v = validateNode(input)
  if (!v.ok) return c.json(fail('invalid', v.errors.join('；'), { errors: v.errors }), 400)
  const tooOld = psmTooOld((await getServer(c.env, n.server_id))!, v.data)
  if (tooOld) return c.json(fail('psm_too_old', tooOld, { errors: [tooOld] }), 409)
  const resetDay = body.reset_day ?? n.reset_day
  if (!Number.isInteger(resetDay) || resetDay < 1 || resetDay > 28) return c.json(fail('invalid', '流量重置日：1-28', { errors: ['流量重置日：1-28'] }), 400)
  const variant = findVariant(n.protocol, n.variant)!
  const params = keptParams(activeFields(variant, v.engine, input.params!), input.params!, stored)
  const server = (await getServer(c.env, n.server_id))!
  const joined = !!server.agent_token_hash
  const onServer = n.status === 'applied'
  const status = joined && (onServer || n.status === 'failed') ? 'queued' : n.status
  await c.env.DB.prepare(
    `UPDATE nodes SET address = ?, port = ?, public_port = ?, traffic_limit_gb = ?, reset_day = ?, labels = ?, params_enc = ?,
            status = ?, last_error = NULL WHERE id = ?`)
    .bind(input.address, input.port, input.public_port ?? null, input.traffic_limit_gb ?? 0, resetDay,
      JSON.stringify(cleanLabels(input.labels)), await encrypt(c.env.TOKEN_KEY, JSON.stringify(params)), status, n.id).run()
  const updated = (await getNode(c.env, n.id))!
  if (status === 'queued') await queueApply(c.env, updated, v.data, onServer ? 'update' : 'add')
  await audit(c.env, 'node.update', `${server.name}/${n.name}`)
  // the relays landing on it go where its clients now go
  if (nodeTarget(updated).host !== nodeTarget(n).host || nodeTarget(updated).port !== nodeTarget(n).port) await retargetNodeRelays(c.env, updated)
  return c.json(await publicNode(c.env, updated))
})

// Delete a node: one on its server is removed by the agent first (202); one
// that never reached its server goes at once (204).
app.delete('/api/nodes/:id', async (c) => {
  const n = await getNode(c.env, c.req.param('id'))
  if (!n) return c.json(fail('not_found', 'no such node'), 404)
  const server = await getServer(c.env, n.server_id)
  // ?force=1 forgets it without waiting for the server, as for a relay or a
  // server itself: a node on a machine that never answers again would sit in
  // "deleting" for ever, and nothing could remove it.
  const force = new URL(c.req.url).searchParams.get('force') === '1'
  if (!force && (n.status === 'applied' || n.status === 'deleting')) {
    if (n.status === 'applied') {
      await enqueue(c.env, n.server_id, n.id, n.engine === 'standalone'
        ? { kind: 'standalone.remove', protocol: n.psm_protocol }
        : { kind: 'node.delete', core: n.engine, protocol: n.psm_protocol, tag: n.name })
      await c.env.DB.prepare(`UPDATE nodes SET status = 'deleting' WHERE id = ?`).bind(n.id).run()
      await audit(c.env, 'node.delete', `${server?.name}/${n.name}`)
    }
    return c.json({ status: 'deleting' }, 202)
  }
  await c.env.DB.batch([
    c.env.DB.prepare(`DELETE FROM tasks WHERE node_id = ? AND status = 'queued'`).bind(n.id),
    c.env.DB.prepare('DELETE FROM nodes WHERE id = ?').bind(n.id),
  ])
  await audit(c.env, 'node.delete', `${server?.name}/${n.name}`)
  return c.body(null, 204)
})

// The client link (or Surge line for Snell), as the agent exported it.
app.get('/api/nodes/:id/link', async (c) => {
  const n = await getNode(c.env, c.req.param('id'))
  if (!n) return c.json(fail('not_found', 'no such node'), 404)
  if (!n.link_enc) return c.json(fail('no_link', 'the node has no link yet'), 409)
  return c.json({ format: linkFormat(n), content: await decrypt(c.env.TOKEN_KEY, n.link_enc) })
})

// ── traffic ──────────────────────────────────────────────────────────────────
// Every node's traffic this month (as its server counts it, reset on its
// reset day) and the bytes per day over the last `days` days.
app.get('/api/traffic', async (c) => {
  const days = Math.min(Math.max(Number(new URL(c.req.url).searchParams.get('days')) || 30, 1), 90)
  const { results: nodes } = await c.env.DB.prepare(
    `SELECT n.id, n.name, n.protocol, n.variant, n.engine, n.status, n.traffic_used, n.traffic_limit_gb, n.traffic_paused,
            n.traffic_at, n.reset_day, s.id AS server_id, s.name AS server
       FROM nodes n JOIN servers s ON s.id = n.server_id ORDER BY n.traffic_used DESC, n.id`).all()
  const { results: daily } = await c.env.DB.prepare(
    `SELECT day, SUM(bytes) AS bytes FROM traffic_daily WHERE day >= date('now', ?) GROUP BY day ORDER BY day`)
    .bind(`-${days - 1} days`).all()
  const { results: perNode } = await c.env.DB.prepare(
    `SELECT node_id, day, bytes FROM traffic_daily WHERE day >= date('now', ?) ORDER BY day`)
    .bind(`-${days - 1} days`).all()
  return c.json({ days, nodes: nodes.map((n) => ({ ...n, traffic_paused: !!n.traffic_paused })), daily, per_node: perNode })
})

// Ask every joined server for its counters now (they arrive within seconds).
app.post('/api/traffic/refresh', async (c) => {
  const { results } = await c.env.DB.prepare('SELECT id FROM servers WHERE agent_token_hash IS NOT NULL').all<{ id: number }>()
  const stmts = await Promise.all(results.map((s) => taskStmt(c.env, s.id, null, { kind: 'traffic.report' })))
  if (stmts.length) await c.env.DB.batch(stmts)
  return c.json({ servers: results.length }, 202)
})

// Start a node's count from zero again (and lift a pause).
app.post('/api/nodes/:id/traffic/reset', async (c) => {
  const n = await getNode(c.env, c.req.param('id'))
  if (!n) return c.json(fail('not_found', 'no such node'), 404)
  if (n.status !== 'applied') return c.json(fail('not_applied', 'the node is not running on its server'), 409)
  await enqueue(c.env, n.server_id, n.id, { kind: 'traffic.reset', tag: trafficTag(n) })
  await audit(c.env, 'traffic.reset', n.name)
  return c.json({ status: 'queued' }, 202)
})

// ── relays ───────────────────────────────────────────────────────────────────
// A relay forwards a port of its entry server to the landing side: one host,
// or several shared by a strategy. Two engines do it on the server (psm
// relay): realm, and gost for what realm cannot do — failover between the
// landing hosts with health checks, a rate limit, and the tunnel.
//
// A tunnel is one relay and two rules with its name: the exit's, on
// exit_server_id, forwarding to the landing hosts, and the entry's, which
// clients connect to and which carries their traffic to the exit in gost's
// relay protocol over TLS / mTLS / WSS / mWSS with a password. The exit goes
// first: its certificate comes back with its result, and the entry, sent
// after it (pending_entry), pins it.
//
// A landing host may be a server in the panel (its server_id only pairs the
// two ends, so both can be named) or any address: the address is always what
// is dialled, because the panel does not know a server's public address — it
// offers the one the server's agent last came from.
// What a relay's settings may be is in shared/relays.ts: the page checks the
// same as it is typed. Anything beyond a plain realm forward to one host needs psm-agent 0.11.0 (and
// the PSM it comes with) on the servers involved.
const RELAY_AGENT = '0.11.0'
// psm check (the IP quality and unlock check) came with psm-agent 0.12.0
const CHECK_AGENT = '0.12.0'

type RelayTarget = { host: string; port: number; server_id: number | null }
type RelayInput = {
  server_id?: number; name?: string; listen_port?: number | null
  mode?: string; engine?: string
  targets?: { host?: unknown; port?: unknown; server_id?: unknown }[]
  // one landing host, the way relays were created before targets
  remote_host?: string; remote_port?: number; remote_server_id?: number | null
  strategy?: string; probe?: boolean; udp?: boolean
  tls?: boolean; tls_sni?: string; tls_insecure?: boolean
  exit_server_id?: number; exit_host?: string; exit_port?: number | null
  transport?: string; ws_host?: string; ws_path?: string
  speed_mbps?: number; limit_gb?: number; reset_day?: number; expires_at?: string | null
  // landing on a node of the panel (null: no longer), published through the relay
  node_id?: number | null; entry_host?: string; in_sub?: boolean
}
/** A relay as it is to be: checked, complete, before it touches D1. */
type RelayPlan = {
  server: ServerRow; name: string; mode: RelayMode; engine: RelayEngine
  listen_port: number | null   // null: picked from the server's range
  targets: RelayTarget[]; strategy: string; probe: boolean; udp: boolean
  tls: boolean; tls_sni: string; tls_insecure: boolean
  exit: ServerRow | null; exit_host: string; exit_port: number | null
  transport: string; ws_host: string; ws_path: string
  speed_mbps: number; limit_gb: number; reset_day: number; expires_at: string | null
  node: NodeRow | null; entry_host: string; in_sub: boolean
}

async function getRelay(env: Env, id: unknown): Promise<RelayRow | null> {
  const n = idOf(id)
  return n === null ? null : env.DB.prepare('SELECT * FROM relays WHERE id = ?').bind(n).first<RelayRow>()
}

/** Its landing hosts: the list, or for a relay made before there were lists, its one host. */
function relayTargets(r: RelayRow): RelayTarget[] {
  try {
    const t = JSON.parse(r.targets || '[]') as RelayTarget[]
    if (Array.isArray(t) && t.length) return t
  } catch { /* the one host below */ }
  return [{ host: r.remote_host, port: r.remote_port, server_id: r.remote_server_id }]
}

const publicRelay = (r: RelayRow) => {
  const { secret_enc: _s, exit_cert: cert, ...rest } = r
  let health: unknown = null
  try { health = r.target_health ? JSON.parse(r.target_health) : null } catch { /* none */ }
  return { ...rest, udp: !!r.udp, tls: !!r.tls, tls_insecure: !!r.tls_insecure, probe: !!r.probe,
    auto_port: !!r.auto_port, exit_auto_port: !!r.exit_auto_port, targets: relayTargets(r), target_health: health,
    exit_pinned: !!cert, in_sub: !!r.in_sub }
}

// PSM learnt Hysteria2's disable_pmtud on 2026-10-07 (proxy-stack #7). An older
// PSM keeps the setting and does nothing with it, so a server that reported an
// older PSM ("2026-10-06 58642cc", psm version) is asked to update first; one
// that has not joined yet gets the current PSM when it does.
const PSM_PMTUD = '2026-10-07'
function psmTooOld(s: ServerRow, data: Record<string, unknown>): string | null {
  if (data.disable_pmtud !== true) return null
  const d = /^(\d{4}-\d{2}-\d{2})\b/.exec(s.psm_version ?? '')?.[1]
  if (!d || d >= PSM_PMTUD) return null
  return `${s.name} 上的 PSM 是 ${d} 的版本，还不认识「关闭 MTU 探测」：先在服务器页的 ⋯ 里点「升级 agent」（会先更新 PSM），再保存`
}

/** "1.2.3" at least "1.2.0"? An unknown version is not. */
function versionAtLeast(v: string | null, want: string): boolean {
  const p = (s: string) => s.replace(/^v/, '').split('.').map((x) => Number.parseInt(x, 10) || 0)
  if (!v || !/^v?\d+\.\d+/.test(v)) return false
  const [a, b] = [p(v), p(want)]
  for (let i = 0; i < 3; i++) if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0)
  return true
}

/** A plain realm forward to one host, as relays were before engines: any psm-agent carries it. */
const relayIsPlain = (p: RelayPlan) => p.mode === 'forward' && p.engine === 'realm' && p.targets.length === 1 &&
  !p.strategy && !p.limit_gb && !p.expires_at && p.listen_port !== null

/** Checks a relay as it will be; `old` supplies whatever a change leaves out, and fixes what cannot change. */
async function planRelay(env: Env, b: RelayInput, old?: RelayRow): Promise<{ plan?: RelayPlan; errors: string[] }> {
  const errors: string[] = []
  const server = await getServer(env, old ? old.server_id : b.server_id)
  if (!server) return { errors: ['选择入口服务器'] }
  if (old && b.mode !== undefined && b.mode !== old.mode) errors.push('转发方式不能改：删除后重新建')
  const mode: RelayMode = old ? (old.mode as RelayMode) : b.mode === 'tunnel' ? 'tunnel' : 'forward'
  // a tunnel is gost's; saying otherwise is reported, not ignored
  const engine = String(mode === 'tunnel' ? (b.engine ?? 'gost') : (b.engine ?? old?.engine ?? 'realm')) as RelayEngine

  // a node of the panel as the landing side: its address and port, not the ones typed
  const nodeId = b.node_id === undefined ? (old?.node_id ?? null) : b.node_id
  const node = nodeId === null ? null : await getNode(env, nodeId)
  if (nodeId !== null && !node) return { errors: ['落地节点不存在'] }

  // the landing hosts: a list, or the one host relays had before there were lists
  let raw: { host?: unknown; port?: unknown; server_id?: unknown }[] | null = null
  if (node) raw = [nodeTarget(node)]
  else if (Array.isArray(b.targets)) raw = b.targets
  else if (b.remote_host !== undefined || b.remote_port !== undefined || b.remote_server_id !== undefined) {
    const first = old ? relayTargets(old)[0] : undefined
    raw = [{ host: b.remote_host ?? first?.host, port: b.remote_port ?? first?.port,
      server_id: b.remote_server_id === undefined ? first?.server_id : b.remote_server_id }]
  }
  const list = raw ?? (old ? relayTargets(old) : [])
  const targets: RelayTarget[] = list.map((t) => ({ host: bareHost(t?.host), port: Number(t?.port), server_id: null }))
  // a landing server only pairs the two ends; it must exist, and a forward cannot land on itself
  for (const [i, t] of list.slice(0, targets.length).entries()) {
    if (t?.server_id === undefined || t?.server_id === null || t?.server_id === '') continue
    const s = await getServer(env, t.server_id)
    const n = list.length > 1 ? `落地 ${i + 1} ` : '落地'
    if (!s) errors.push(`${n}服务器不存在`)
    else if (s.id === server.id && mode === 'forward') errors.push('入口和落地不能是同一台服务器')
    else targets[i].server_id = s.id
  }

  const transport = mode === 'tunnel' ? String(b.transport ?? old?.transport ?? 'tls') || 'tls' : ''
  const ws = transport.includes('ws')
  let expires_at: string | null = b.expires_at === undefined ? (old?.expires_at ?? null) : (b.expires_at || null)
  const f: RelayFields = {
    name: old ? old.name : String(b.name ?? '').trim(),
    mode, engine,
    listen_port: b.listen_port === undefined ? (old ? old.listen_port : null) : b.listen_port,
    targets,
    // one landing host when it is a node: nothing to share out
    strategy: node ? '' : String(b.strategy ?? old?.strategy ?? ''),
    // realm's own TLS hop, asked for (or kept, while it is still a realm forward)
    tls: b.tls ?? (mode === 'forward' && engine === 'realm' ? !!old?.tls : false),
    tls_sni: String(b.tls_sni ?? old?.tls_sni ?? '').trim(),
    exit_host: mode === 'tunnel' ? bareHost(b.exit_host ?? old?.exit_host) : '',
    exit_port: mode === 'tunnel' ? (b.exit_port === undefined ? (old?.exit_port ?? null) : b.exit_port) : null,
    transport,
    ws_host: ws ? String(b.ws_host ?? old?.ws_host ?? '').trim() : '',
    ws_path: ws ? String(b.ws_path ?? old?.ws_path ?? '').trim() : '',
    speed_mbps: Number(b.speed_mbps ?? old?.speed_mbps ?? 0),
    limit_gb: Number(b.limit_gb ?? old?.limit_gb ?? 0),
    reset_day: Number(b.reset_day ?? old?.reset_day ?? 1),
    expires_at,
  }
  errors.push(...relayProblems(f))
  // realm's TLS needs a realm on the far side to take it off; a node is not one
  if (node && f.tls) errors.push('落地是面板节点时不能用 realm TLS（节点不认这一层）；要加密这一跳，用隧道')
  const entry_host = bareHost(b.entry_host ?? old?.entry_host ?? '')
  if (entry_host && !goodHost(entry_host)) errors.push('入口地址：客户端连入口服务器用的域名或 IP')

  // the tunnel's exit server
  let exit: ServerRow | null = null
  if (mode === 'tunnel') {
    if (old && b.exit_server_id !== undefined && b.exit_server_id !== old.exit_server_id) errors.push('出口服务器不能改：删除后重新建')
    exit = await getServer(env, old ? old.exit_server_id : b.exit_server_id)
    if (!exit) errors.push('选择出口服务器')
    else if (exit.id === server.id) errors.push('入口和出口不能是同一台服务器')
  }
  if (errors.length) return { errors }
  // one form everywhere after this: UTC, to the second
  if (expires_at) expires_at = new Date(Date.parse(expires_at)).toISOString().replace(/\.\d{3}Z$/, 'Z')
  const probe = b.probe ?? (old ? !!old.probe : true)
  // a node that speaks UDP alone (QUIC, mKCP, WireGuard) is unreachable without it
  const udp = (node && await nodeOverUdp(env, node)) || (b.udp ?? (old ? !!old.udp : false))
  return { errors, plan: {
    server, name: f.name, mode, engine, listen_port: f.listen_port, targets, strategy: f.strategy, probe, udp,
    tls: f.tls, tls_sni: f.tls && !f.tls_sni ? targets[0].host : f.tls_sni, tls_insecure: f.tls ? (b.tls_insecure ?? !!old?.tls_insecure) : false,
    exit, exit_host: f.exit_host, exit_port: f.exit_port, transport, ws_host: f.ws_host, ws_path: f.ws_path,
    speed_mbps: f.speed_mbps, limit_gb: f.limit_gb, reset_day: f.reset_day, expires_at,
    node, entry_host, in_sub: b.in_sub ?? (old ? !!old.in_sub : true),
  } }
}

/** Where a relay landing on this node forwards to: what its clients dial. */
const nodeTarget = (n: NodeRow): RelayTarget => ({ host: n.address, port: n.public_port ?? n.port, server_id: n.server_id })

/** The node speaks UDP alone: Hysteria2, TUIC, WireGuard, Xray's mKCP. */
async function nodeOverUdp(_env: Env, n: NodeRow): Promise<boolean> {
  return ['hysteria2', 'tuic', 'wireguard'].includes(n.protocol) || n.variant === 'vless-mkcp'
}

/** Another relay rule on this server has the name: its own relays, and the tunnels it is the exit of. */
async function relayNameTaken(env: Env, serverId: number, name: string, exceptId = 0): Promise<boolean> {
  return !!(await env.DB.prepare(
    `SELECT 1 FROM relays WHERE id != ? AND name = ? AND (server_id = ? OR (mode = 'tunnel' AND exit_server_id = ?)) LIMIT 1`)
    .bind(exceptId, name, serverId, serverId).first())
}

/** The ports relays and nodes hold on a server (a relay's own left out). */
async function relayUsedPorts(env: Env, serverId: number, exceptId = 0): Promise<Set<number>> {
  const { results } = await env.DB.prepare(
    `SELECT listen_port AS p FROM relays WHERE server_id = ? AND id != ?
     UNION SELECT exit_port FROM relays WHERE mode = 'tunnel' AND exit_server_id = ? AND id != ? AND exit_port IS NOT NULL
     UNION SELECT port FROM nodes WHERE server_id = ?
     UNION SELECT public_port FROM nodes WHERE server_id = ? AND public_port IS NOT NULL`)
    .bind(serverId, exceptId, serverId, exceptId, serverId, serverId).all<{ p: number }>()
  return new Set(results.map((r) => r.p))
}

const relayRange = (s: ServerRow): [number, number] =>
  s.relay_port_min && s.relay_port_max ? [s.relay_port_min, s.relay_port_max] : [RELAY_PORTS[0], RELAY_PORTS[1]]

/** A port in the server's range that nothing the panel knows of holds (psm checks the machine itself). */
function pickRelayPort(used: Set<number>, [min, max]: [number, number]): number | null {
  const span = max - min + 1
  for (let i = 0; i < 64; i++) {
    const p = min + Math.floor(Math.random() * span)
    if (!used.has(p)) return p
  }
  const start = Math.floor(Math.random() * span)
  for (let i = 0; i < span; i++) {
    const p = min + ((start + i) % span)
    if (!used.has(p)) return p
  }
  return null
}

/** Why a server cannot carry this relay yet: its psm-agent is older than the relay needs. */
function relayAgentProblem(p: RelayPlan): string | null {
  if (relayIsPlain(p)) return null
  for (const s of [p.server, p.exit]) {
    if (s?.agent_token_hash && !versionAtLeast(s.agent_version, RELAY_AGENT))
      return `${s.name} 的 psm-agent 是 ${s.agent_version ?? '旧版'}，这种中转要 ${RELAY_AGENT} 以上：先在服务器页点「升级 agent」`
  }
  return null
}

/** One side of a relay as `psm relay add|update --input -` takes it on stdin. */
async function relayData(env: Env, r: RelayRow, side: 'forward' | 'entry' | 'exit'): Promise<Record<string, unknown>> {
  const targets = relayTargets(r)
  const hosts = targets.map(({ host, port }) => ({ host, port }))
  const range = async (id: number | null) => {
    const s = id === null ? null : await getServer(env, id)
    return s ? relayRange(s).join('-') : RELAY_PORTS.join('-')
  }
  const limits = { speed_mbps: r.speed_mbps, limit_bytes: Math.round(r.limit_gb * GB), reset_day: r.reset_day, expires_at: r.expires_at ?? '' }
  if (side === 'forward') {
    return {
      tag: r.name, engine: r.engine, mode: 'forward', listen_port: r.listen_port,
      remote_host: hosts[0].host, remote_port: hosts[0].port, targets: hosts, strategy: r.strategy, probe: !!r.probe,
      udp: !!r.udp, tls: !!r.tls, tls_sni: r.tls_sni, tls_insecure: !!r.tls_insecure, ...limits,
      ...(r.auto_port ? { listen_port_auto: true, port_range: await range(r.server_id) } : {}),
    }
  }
  const secret = r.secret_enc ? await decrypt(env.TOKEN_KEY, r.secret_enc) : ''
  const wire = { transport: r.transport, tls_sni: r.tls_sni, ws_path: r.ws_path, secret }
  if (side === 'exit') {
    return {
      tag: r.name, engine: 'gost', mode: 'tunnel-exit', listen_port: r.exit_port,
      remote_host: hosts[0].host, remote_port: hosts[0].port, targets: hosts, strategy: r.strategy, probe: !!r.probe,
      udp: !!r.udp, ...wire,
      ...(r.exit_auto_port ? { listen_port_auto: true, port_range: await range(r.exit_server_id) } : {}),
    }
  }
  return {
    tag: r.name, engine: 'gost', mode: 'tunnel-entry', listen_port: r.listen_port,
    remote_host: r.exit_host, remote_port: r.exit_port, udp: !!r.udp, ...wire, ws_host: r.ws_host,
    exit_cert_pem: r.exit_cert ?? '', ...limits,
    ...(r.auto_port ? { listen_port_auto: true, port_range: await range(r.server_id) } : {}),
  }
}

/** Queue one side's task. A tunnel's entry only once its exit's certificate is known. */
async function queueRelaySide(env: Env, r: RelayRow, side: 'forward' | 'entry' | 'exit', kind: 'add' | 'update' | 'delete') {
  const serverId = side === 'exit' ? r.exit_server_id! : r.server_id
  if (kind === 'delete') return enqueue(env, serverId, null, { kind: 'relay.delete', tag: r.name }, r.id)
  return enqueue(env, serverId, null, { kind: `relay.${kind}`, tag: r.name, data: await relayData(env, r, side) }, r.id)
}

/** Send a tunnel's entry now that its exit is there, or leave it to its server's join. */
async function sendPendingEntry(env: Env, r: RelayRow) {
  if (!r.pending_entry || r.status === 'deleting') return
  const entry = await getServer(env, r.server_id)
  if (entry?.agent_token_hash) {
    await env.DB.prepare(`UPDATE relays SET status = 'queued', pending_entry = '' WHERE id = ?`).bind(r.id).run()
    await queueRelaySide(env, (await getRelay(env, r.id))!, 'entry', r.pending_entry === 'update' ? 'update' : 'add')
  } else {
    await env.DB.prepare(`UPDATE relays SET status = 'waiting', pending_entry = '' WHERE id = ?`).bind(r.id).run()
  }
}

/** Make a relay: the row, its ports, and the first task (the exit's, for a tunnel). */
async function createRelay(env: Env, b: RelayInput): Promise<{ id?: number; status?: string; joined?: boolean; errors: string[]; conflict?: boolean }> {
  const { plan: p, errors } = await planRelay(env, b)
  if (!p) return { errors }
  if (await relayNameTaken(env, p.server.id, p.name)) return { errors: [`${p.server.name} 上已有同名中转`], conflict: true }
  if (p.exit && await relayNameTaken(env, p.exit.id, p.name)) return { errors: [`出口 ${p.exit.name} 上已有同名中转`], conflict: true }
  const why = relayAgentProblem(p)
  if (why) return { errors: [why] }
  let listen = p.listen_port
  const used = await relayUsedPorts(env, p.server.id)
  if (listen !== null && used.has(listen)) return { errors: [`${p.server.name} 上的端口 ${listen} 已被节点或另一条中转占用`], conflict: true }
  const auto = listen === null
  if (auto && (listen = pickRelayPort(used, relayRange(p.server))) === null) return { errors: [`${p.server.name} 的中转端口段已经用完`] }
  let exitPort = p.exit_port
  const exitAuto = !!p.exit && exitPort === null
  if (p.exit) {
    const xused = await relayUsedPorts(env, p.exit.id)
    if (exitPort !== null && xused.has(exitPort)) return { errors: [`${p.exit.name} 上的端口 ${exitPort} 已被节点或另一条中转占用`], conflict: true }
    if (exitAuto && (exitPort = pickRelayPort(xused, relayRange(p.exit))) === null) return { errors: [`${p.exit.name} 的中转端口段已经用完`] }
  }
  const joined = !!p.server.agent_token_hash
  const exitJoined = !!p.exit?.agent_token_hash
  const status = p.mode === 'tunnel' ? 'pending' : joined ? 'queued' : 'waiting'
  const exitStatus = p.mode === 'tunnel' ? (exitJoined ? 'queued' : 'waiting') : ''
  const secret = p.mode === 'tunnel' ? await encrypt(env.TOKEN_KEY, randomToken(18)) : null
  let id: number
  try {
    const r = await env.DB.prepare(
      `INSERT INTO relays (server_id, name, listen_port, remote_host, remote_port, remote_server_id, udp, tls, tls_sni, tls_insecure,
         status, engine, mode, targets, strategy, probe, auto_port, exit_server_id, exit_host, exit_port, exit_auto_port,
         transport, ws_host, ws_path, secret_enc, exit_status, pending_entry, speed_mbps, limit_gb, reset_day, expires_at,
         node_id, entry_host, in_sub)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(p.server.id, p.name, listen, p.targets[0].host, p.targets[0].port, p.targets[0].server_id,
        p.udp ? 1 : 0, p.tls ? 1 : 0, p.tls_sni, p.tls_insecure ? 1 : 0,
        status, p.engine, p.mode, JSON.stringify(p.targets), p.strategy, p.probe ? 1 : 0, auto ? 1 : 0,
        p.exit?.id ?? null, p.exit_host, exitPort, exitAuto ? 1 : 0, p.transport, p.ws_host, p.ws_path, secret,
        exitStatus, p.mode === 'tunnel' ? 'add' : '', p.speed_mbps, p.limit_gb, p.reset_day, p.expires_at,
        p.node?.id ?? null, p.entry_host, p.in_sub ? 1 : 0)
      .run()
    id = Number(r.meta.last_row_id)
  } catch (e) {
    if (String(e).includes('UNIQUE')) return { errors: [`${p.server.name} 上已有同名中转，或这个监听端口已被另一条中转占用`], conflict: true }
    throw e
  }
  const row = (await getRelay(env, id))!
  if (p.mode === 'tunnel') {
    if (exitJoined) await queueRelaySide(env, row, 'exit', 'add')
  } else if (joined) {
    await queueRelaySide(env, row, 'forward', 'add')
  }
  const hop = p.mode === 'tunnel' ? `${listen} → ${p.exit!.name}:${exitPort} → ` : `${listen} → `
  const landing = p.node ? `${(await getServer(env, p.node.server_id))?.name}/${p.node.name} ` : ''
  await audit(env, 'relay.add', `${p.server.name}/${p.name}`,
    hop + landing + p.targets.map((t) => `${t.host}:${t.port}`).join(', '))
  return { id, status, joined, errors: [] }
}

app.get('/api/relays', async (c) => {
  const sid = new URL(c.req.url).searchParams.get('server_id')
  const stmt = sid && /^\d+$/.test(sid)
    ? c.env.DB.prepare(`SELECT * FROM relays WHERE server_id = ? OR (mode = 'tunnel' AND exit_server_id = ?) ORDER BY id`).bind(Number(sid), Number(sid))
    : c.env.DB.prepare('SELECT * FROM relays ORDER BY id')
  const { results } = await stmt.all<RelayRow>()
  return c.json(results.map(publicRelay))
})

// A relay's hop over time: round trip, jitter, loss and the traffic of each
// interval, newest last. `hours` covers the seven days that are kept.
app.get('/api/relays/:id/metrics', async (c) => {
  const r = await getRelay(c.env, c.req.param('id'))
  if (!r) return c.json(fail('not_found', 'no such relay'), 404)
  const hours = Math.min(Math.max(Number(new URL(c.req.url).searchParams.get('hours')) || 6, 1), 24 * 7)
  // A reading a minute is 10,080 rows a week: the chart gets at most ~240
  // points whatever the window — the round trip averaged, the worst loss and
  // the bytes summed per bucket (a bucket with no round trip stays a gap).
  // D1 binds a number as REAL, and REAL division would put every reading in
  // a bucket of its own: the CAST keeps it integer division.
  const bucket = Math.max(60, Math.round((hours * 3600) / 240))
  const { results } = await c.env.DB.prepare(
    `SELECT MIN(at) AS at, AVG(rtt_ms) AS rtt_ms, AVG(jitter_ms) AS jitter_ms, MAX(loss_pct) AS loss_pct, SUM(bytes) AS bytes
       FROM relay_samples WHERE relay_id = ? AND at >= datetime('now', ?)
      GROUP BY CAST(strftime('%s', at) AS INTEGER) / CAST(? AS INTEGER) ORDER BY 1`)
    .bind(r.id, `-${hours} hours`, bucket).all()
  return c.json({ hours, bucket_seconds: bucket, relay: publicRelay(r), samples: results })
})

// Create a relay. A server that has joined gets it through its agent (realm or
// gost is installed there on first use); otherwise it waits for the server,
// whose install command comes back with the answer.
app.post('/api/relays', async (c) => {
  const body = await c.req.json<RelayInput>().catch(() => null)
  if (!body || typeof body !== 'object') return c.json(fail('bad_body', 'the body must be a JSON object'), 400)
  const r = await createRelay(c.env, body)
  if (r.errors.length) return c.json(fail(r.conflict ? 'exists' : 'invalid', r.errors.join('；'), { errors: r.errors }), r.conflict ? 409 : 400)
  const relay = (await getRelay(c.env, r.id!))!
  const waiting = [relay.server_id, relay.exit_server_id].filter((x): x is number => x !== null)
  const install: { server: string; command: string }[] = []
  for (const id of waiting) {
    const s = await getServer(c.env, id)
    if (s && !s.agent_token_hash) install.push({ server: s.name, command: await installCommand(c, await joinToken(c.env, s.id)) })
  }
  return c.json({ id: r.id, status: r.status, joined: r.joined, install_command: install[0]?.command, install }, 201)
})

// Many relays at once, one per line: "name port|auto host:port[,host:port…]",
// the rest of the settings shared. Every line is checked before any is made;
// a bad one is named by its number and nothing is created.
app.post('/api/relays/batch', async (c) => {
  const body = await c.req.json<RelayInput & { lines?: string }>().catch(() => null)
  if (!body || typeof body !== 'object') return c.json(fail('bad_body', 'the body must be a JSON object'), 400)
  // a node is one landing host: a batch is lines of landing hosts, not that
  const { lines: text, node_id: _node, ...common } = body
  const rows = String(text ?? '').split('\n').map((l, i) => ({ no: i + 1, line: l.replace(/#.*/, '').trim() })).filter((r) => r.line)
  const errors: string[] = []
  if (!rows.length) errors.push('每行一条：名称 端口(或 auto) 落地地址:端口[,落地地址:端口…]')
  if (rows.length > 100) errors.push('一次最多 100 条')
  const inputs: RelayInput[] = []
  const names = new Set<string>(), ports = new Set<number>()
  for (const { no, line } of rows.slice(0, 100)) {
    const [name, port, list, ...rest] = line.split(/\s+/)
    if (!name || !port || !list || rest.length) { errors.push(`第 ${no} 行：名称 端口 落地地址:端口`); continue }
    const targets: RelayInput['targets'] = []
    for (const hp of list.split(',')) {
      const t = parseHostPort(hp)
      if (!t) { errors.push(`第 ${no} 行：落地要写成 地址:端口（IPv6 写成 [地址]:端口）：${hp}`); continue }
      targets.push(t)
    }
    const listen = port === 'auto' ? null : Number(port)
    if (listen !== null && !goodPort(listen)) { errors.push(`第 ${no} 行：端口 1-65535 或 auto`); continue }
    if (names.has(name)) errors.push(`第 ${no} 行：名称 ${name} 重复`)
    if (listen !== null && ports.has(listen)) errors.push(`第 ${no} 行：端口 ${listen} 重复`)
    names.add(name); if (listen !== null) ports.add(listen)
    const input: RelayInput = { ...common, name, listen_port: listen, targets }
    if (common.mode === 'tunnel') input.exit_port = null   // each tunnel its own port on the exit
    const { errors: e } = await planRelay(c.env, input)
    for (const m of e) errors.push(`第 ${no} 行：${m}`)
    inputs.push(input)
  }
  if (errors.length) return c.json(fail('invalid', errors.slice(0, 20).join('；'), { errors }), 400)
  const created: number[] = []
  for (const [i, input] of inputs.entries()) {
    const r = await createRelay(c.env, input)
    if (r.errors.length) {
      errors.push(...r.errors.map((m) => `第 ${rows[i].no} 行：${m}`))
      continue
    }
    created.push(r.id!)
  }
  return c.json({ created: created.length, ids: created, errors }, errors.length ? 207 : 201)
})

// Edit a relay: ports, landing hosts, strategy, the tunnel's wire, the limits.
// Its name, its entry and exit servers and its mode stay — psm keys a rule by
// its name, so a rename or a move is a different relay.
app.patch('/api/relays/:id', async (c) => {
  const old = await getRelay(c.env, c.req.param('id'))
  if (!old) return c.json(fail('not_found', 'no such relay'), 404)
  const busy = ['queued', 'deleting', 'deleted'].includes(old.status) || ['queued', 'deleting', 'deleted'].includes(old.exit_status)
  if (busy) return c.json(fail('busy', '中转正在下发或删除，稍后再改'), 409)
  const body = await c.req.json<RelayInput>().catch(() => null)
  if (!body || typeof body !== 'object') return c.json(fail('bad_body', 'the body must be a JSON object'), 400)
  const { plan: p, errors } = await planRelay(c.env, body, old)
  if (!p) return c.json(fail('invalid', errors.join('；'), { errors }), 400)
  const why = relayAgentProblem(p)
  if (why) return c.json(fail('invalid', why, { errors: [why] }), 400)
  let listen = p.listen_port, auto = !!old.auto_port
  if (listen === null) {
    // back to picking: keep the port it has unless it never had one
    listen = old.listen_port; auto = true
  } else if (listen !== old.listen_port) {
    if ((await relayUsedPorts(c.env, p.server.id, old.id)).has(listen)) {
      const msg = `${p.server.name} 上的端口 ${listen} 已被节点或另一条中转占用`
      return c.json(fail('exists', msg, { errors: [msg] }), 409)
    }
    auto = false
  } else if (body.listen_port !== undefined) auto = false
  let exitPort = p.exit_port ?? old.exit_port, exitAuto = !!old.exit_auto_port
  if (p.mode === 'tunnel' && body.exit_port !== undefined) {
    if (body.exit_port === null) exitAuto = true
    else if (body.exit_port !== old.exit_port) {
      if ((await relayUsedPorts(c.env, p.exit!.id, old.id)).has(body.exit_port)) {
        const msg = `${p.exit!.name} 上的端口 ${body.exit_port} 已被节点或另一条中转占用`
        return c.json(fail('exists', msg, { errors: [msg] }), 409)
      }
      exitPort = body.exit_port; exitAuto = false
    } else exitAuto = false
  }
  try {
    await c.env.DB.prepare(
      `UPDATE relays SET listen_port = ?, remote_host = ?, remote_port = ?, remote_server_id = ?, udp = ?, tls = ?,
              tls_sni = ?, tls_insecure = ?, engine = ?, targets = ?, strategy = ?, probe = ?, auto_port = ?,
              exit_host = ?, exit_port = ?, exit_auto_port = ?, transport = ?, ws_host = ?, ws_path = ?,
              speed_mbps = ?, limit_gb = ?, reset_day = ?, expires_at = ?, node_id = ?, entry_host = ?, in_sub = ?,
              last_error = NULL, exit_error = NULL WHERE id = ?`)
      .bind(listen, p.targets[0].host, p.targets[0].port, p.targets[0].server_id, p.udp ? 1 : 0, p.tls ? 1 : 0,
        p.tls_sni, p.tls_insecure ? 1 : 0, p.engine, JSON.stringify(p.targets), p.strategy, p.probe ? 1 : 0, auto ? 1 : 0,
        p.exit_host, exitPort, exitAuto ? 1 : 0, p.transport, p.ws_host, p.ws_path,
        p.speed_mbps, p.limit_gb, p.reset_day, p.expires_at, p.node?.id ?? null, p.entry_host, p.in_sub ? 1 : 0, old.id).run()
  } catch (e) {
    if (String(e).includes('UNIQUE')) {
      const msg = `${p.server.name} 上这个监听端口已被另一条中转占用`
      return c.json(fail('exists', msg, { errors: [msg] }), 409)
    }
    throw e
  }
  // a change of what only the panel uses (the node it publishes, the entry
  // address, the subscription) and nothing else is none for the servers;
  // anything else is sent again, unchanged or not (that is how a failed one is retried)
  const now = (await getRelay(c.env, old.id))!
  const rest = (x: RelayRow) => JSON.stringify({ ...x, node_id: null, entry_host: '', in_sub: 0, last_error: null, exit_error: null })
  const panelOnly = (old.node_id !== now.node_id || old.entry_host !== now.entry_host || old.in_sub !== now.in_sub) && rest(old) === rest(now)
  if (!panelOnly) await resendRelay(c.env, old)
  await audit(c.env, 'relay.update', `${p.server.name}/${old.name}`)
  return c.json(publicRelay((await getRelay(c.env, old.id))!))
})

/** A relay's row has changed (`old` is how it was): the change goes to the side(s) on a server. */
async function resendRelay(env: Env, old: RelayRow) {
  let r = (await getRelay(env, old.id))!
  const entryJoined = !!(await getServer(env, r.server_id))?.agent_token_hash
  if (r.mode === 'forward') {
    if (entryJoined && (old.status === 'applied' || old.status === 'failed')) {
      await env.DB.prepare(`UPDATE relays SET status = 'queued' WHERE id = ?`).bind(r.id).run()
      await queueRelaySide(env, r, 'forward', old.status === 'applied' ? 'update' : 'add')
    }
    return
  }
  // what the exit has to change first: its landing hosts, its port, the wire
  const exitKey = (x: RelayRow) => JSON.stringify([relayTargets(x), x.strategy, x.probe, x.exit_port, x.transport, x.tls_sni, x.ws_path])
  const exitChanged = exitKey(old) !== exitKey(r)
  const exitJoined = !!(r.exit_server_id && (await getServer(env, r.exit_server_id))?.agent_token_hash)
  const entryNext = old.status === 'applied' ? 'update' : 'add'
  // a failed exit is sent again even unchanged: that is how it is retried
  if ((exitChanged || old.exit_status === 'failed') && exitJoined && (old.exit_status === 'applied' || old.exit_status === 'failed')) {
    await env.DB.prepare(`UPDATE relays SET exit_status = 'queued', pending_entry = ? WHERE id = ?`).bind(entryNext, r.id).run()
    r = (await getRelay(env, r.id))!
    await queueRelaySide(env, r, 'exit', old.exit_status === 'applied' ? 'update' : 'add')
  } else if (old.exit_status === 'applied' && entryJoined && ['applied', 'failed', 'pending'].includes(old.status)) {
    await env.DB.prepare(`UPDATE relays SET status = 'queued', pending_entry = '' WHERE id = ?`).bind(r.id).run()
    await queueRelaySide(env, r, 'entry', entryNext)
  }
}

/**
 * A node's address or port changed: the relays landing on it follow (each a
 * change of its landing host, sent as an edit would send it). One under way
 * keeps its target until it is edited again.
 */
async function retargetNodeRelays(env: Env, n: NodeRow) {
  const { results } = await env.DB.prepare('SELECT * FROM relays WHERE node_id = ?').bind(n.id).all<RelayRow>()
  const t = nodeTarget(n)
  for (const old of results) {
    const cur = relayTargets(old)
    if (cur.length === 1 && cur[0].host === t.host && cur[0].port === t.port) continue
    if (['queued', 'deleting', 'deleted'].includes(old.status) || ['queued', 'deleting', 'deleted'].includes(old.exit_status)) continue
    await env.DB.prepare(`UPDATE relays SET targets = ?, remote_host = ?, remote_port = ?, remote_server_id = ?, strategy = '',
                                 last_error = NULL, exit_error = NULL WHERE id = ?`)
      .bind(JSON.stringify([t]), t.host, t.port, t.server_id, old.id).run()
    await resendRelay(env, old)
    await audit(env, 'relay.update', `${old.name}`, `跟随节点 ${n.name} → ${t.host}:${t.port}`)
  }
}

/** Remove a relay row once no side of it is left on a server. */
async function relayGoneIfDone(env: Env, id: number) {
  const r = await getRelay(env, id)
  if (!r) return
  const entryGone = ['deleted', 'waiting', 'pending'].includes(r.status)
  const exitGone = r.mode !== 'tunnel' || ['deleted', 'waiting', ''].includes(r.exit_status)
  if (entryGone && exitGone) {
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM tasks WHERE relay_id = ? AND status = 'queued'`).bind(id),
      env.DB.prepare('DELETE FROM relays WHERE id = ?').bind(id),
    ])
  }
}

// Delete a relay: the sides that are on a server are removed there first
// (202); a relay no server has goes at once (204). ?force=1 forgets it without
// waiting, for a server that never answers again.
app.delete('/api/relays/:id', async (c) => {
  const r = await getRelay(c.env, c.req.param('id'))
  if (!r) return c.json(fail('not_found', 'no such relay'), 404)
  const server = await getServer(c.env, r.server_id)
  const force = new URL(c.req.url).searchParams.get('force') === '1'
  const onEntry = ['applied', 'failed', 'queued'].includes(r.status) && !!server?.agent_token_hash
  const exitServer = r.mode === 'tunnel' && r.exit_server_id ? await getServer(c.env, r.exit_server_id) : null
  const onExit = ['applied', 'failed', 'queued'].includes(r.exit_status) && !!exitServer?.agent_token_hash
  const deleting = r.status === 'deleting' || r.exit_status === 'deleting'
  if (!force && (onEntry || onExit || deleting)) {
    if (onEntry) await queueRelaySide(c.env, r, r.mode === 'tunnel' ? 'entry' : 'forward', 'delete')
    if (onExit) await queueRelaySide(c.env, r, 'exit', 'delete')
    if (onEntry || onExit) {
      // a side not on a server counts as gone; one already being removed stays so
      const entryState = onEntry || r.status === 'deleting' ? 'deleting' : 'deleted'
      const exitState = r.mode !== 'tunnel' ? '' : onExit || r.exit_status === 'deleting' ? 'deleting' : 'deleted'
      await c.env.DB.prepare(`UPDATE relays SET status = ?, exit_status = ?, pending_entry = '' WHERE id = ?`)
        .bind(entryState, exitState, r.id).run()
      await c.env.DB.prepare(`DELETE FROM tasks WHERE relay_id = ? AND status = 'queued' AND kind != 'relay.delete'`).bind(r.id).run()
      await audit(c.env, 'relay.delete', `${server?.name}/${r.name}`)
    }
    return c.json({ status: 'deleting' }, 202)
  }
  await c.env.DB.batch([
    c.env.DB.prepare(`DELETE FROM tasks WHERE relay_id = ? AND status = 'queued'`).bind(r.id),
    c.env.DB.prepare('DELETE FROM relays WHERE id = ?').bind(r.id),
  ])
  await audit(c.env, 'relay.delete', `${server?.name}/${r.name}`)
  return c.body(null, 204)
})

/**
 * A server leaving the panel takes its side of every relay with it (the leave
 * plan deletes those rules there); the other side of a tunnel is on another
 * server and has to be removed there, or it would forward into nothing.
 */
async function detachServerRelays(env: Env, serverId: number) {
  // tunnels whose entry leaves: their exits elsewhere go (the rows go with the server)
  const { results: entries } = await env.DB.prepare(
    `SELECT * FROM relays WHERE server_id = ? AND mode = 'tunnel' AND exit_server_id IS NOT NULL AND exit_server_id != ?`)
    .bind(serverId, serverId).all<RelayRow>()
  for (const r of entries) {
    if (['applied', 'failed', 'queued'].includes(r.exit_status)) await queueRelaySide(env, r, 'exit', 'delete')
  }
  // tunnels whose exit leaves: their entries elsewhere go, then the rows
  const { results: exits } = await env.DB.prepare(
    `SELECT * FROM relays WHERE mode = 'tunnel' AND exit_server_id = ? AND server_id != ?`).bind(serverId, serverId).all<RelayRow>()
  for (const r of exits) {
    const onEntry = ['applied', 'failed', 'queued'].includes(r.status)
    if (onEntry) await queueRelaySide(env, r, 'entry', 'delete')
    await env.DB.prepare(`UPDATE relays SET status = ?, exit_status = 'deleted', pending_entry = '' WHERE id = ?`)
      .bind(onEntry ? 'deleting' : 'deleted', r.id).run()
    await relayGoneIfDone(env, r.id)
  }
}

// ── subscriptions ────────────────────────────────────────────────────────────
type SubRow = { id: number; name: string; labels: string; token_hash: string; token_enc: string; last_used: string | null; created_at: string; templates: string }

async function publicSub(c: C, s: SubRow) {
  const token = await decrypt(c.env.TOKEN_KEY, s.token_enc)
  const url = `${await panelUrl(c)}/sub/${token}`
  return { id: s.id, name: s.name, labels: JSON.parse(s.labels), last_used: s.last_used, created_at: s.created_at, url,
    templates: JSON.parse(s.templates || '{}') as Record<string, number> }
}

/** A subscription's template choices, checked: format → one of the user's templates of that format. */
async function cleanTemplateChoices(env: Env, raw: unknown): Promise<Record<string, number> | string> {
  const out: Record<string, number> = {}
  if (!raw || typeof raw !== 'object') return out
  for (const [format, id] of Object.entries(raw as Record<string, unknown>)) {
    if (!(TEMPLATE_FORMATS as string[]).includes(format)) return `没有这种格式：${format}`
    if (id === null || id === '' || id === 'builtin') continue   // the built-in template
    const row = Number.isInteger(id)
      ? await env.DB.prepare('SELECT id FROM templates WHERE id = ? AND format = ?').bind(id, format).first()
      : null
    if (!row) return `${FORMAT_LABELS[format as TemplateFormat]} 模板不存在`
    out[format] = id as number
  }
  return out
}

app.get('/api/subscriptions', async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM subscriptions ORDER BY id').all<SubRow>()
  return c.json(await Promise.all(results.map((s) => publicSub(c, s))))
})

const getSub = (env: Env, id: unknown) => {
  const n = idOf(id)
  return n === null ? Promise.resolve(null) : env.DB.prepare('SELECT * FROM subscriptions WHERE id = ?').bind(n).first<SubRow>()
}

app.post('/api/subscriptions', async (c) => {
  const body = await c.req.json<{ name?: string; labels?: unknown }>().catch(() => null)
  const name = typeof body?.name === 'string' ? body.name.trim().slice(0, 48) : ''
  if (!name) return c.json(fail('bad_name', '订阅名称：必填'), 400)
  // 24 random bytes do not collide; should they ever, the unique hash says so and another is drawn
  for (let attempt = 0; ; attempt++) {
    const token = randomToken(24)
    try {
      const r = await c.env.DB.prepare('INSERT INTO subscriptions (name, labels, token_hash, token_enc) VALUES (?, ?, ?, ?)')
        .bind(name, JSON.stringify(cleanLabels(body?.labels)), await sha256Hex(token), await encrypt(c.env.TOKEN_KEY, token)).run()
      await audit(c.env, 'subscription.add', name)
      const s = (await getSub(c.env, r.meta.last_row_id))!
      return c.json(await publicSub(c, s), 201)
    } catch (e) {
      if (attempt < 2 && String(e).includes('UNIQUE')) continue
      throw e
    }
  }
})

app.patch('/api/subscriptions/:id', async (c) => {
  const s = await getSub(c.env, c.req.param('id'))
  if (!s) return c.json(fail('not_found', 'no such subscription'), 404)
  const body = await c.req.json<{ name?: string; labels?: unknown; templates?: unknown }>().catch(() => null)
  const name = (typeof body?.name === 'string' ? body.name.trim().slice(0, 48) : '') || s.name
  const labels = body?.labels !== undefined ? JSON.stringify(cleanLabels(body.labels)) : s.labels
  let templates = s.templates || '{}'
  if (body?.templates !== undefined) {
    const t = await cleanTemplateChoices(c.env, body.templates)
    if (typeof t === 'string') return c.json(fail('invalid', t, { errors: [t] }), 400)
    templates = JSON.stringify(t)
  }
  await c.env.DB.prepare('UPDATE subscriptions SET name = ?, labels = ?, templates = ? WHERE id = ?').bind(name, labels, templates, s.id).run()
  await audit(c.env, 'subscription.update', name)
  return c.json(await publicSub(c, { ...s, name, labels, templates }))
})

// A new URL; the old one stops working.
app.post('/api/subscriptions/:id/reset', async (c) => {
  const s = await getSub(c.env, c.req.param('id'))
  if (!s) return c.json(fail('not_found', 'no such subscription'), 404)
  const token = randomToken(24)
  const hash = await sha256Hex(token), enc = await encrypt(c.env.TOKEN_KEY, token)
  await c.env.DB.prepare('UPDATE subscriptions SET token_hash = ?, token_enc = ? WHERE id = ?').bind(hash, enc, s.id).run()
  await audit(c.env, 'subscription.reset', s.name)
  return c.json(await publicSub(c, { ...s, token_hash: hash, token_enc: enc }))
})

app.delete('/api/subscriptions/:id', async (c) => {
  const s = await getSub(c.env, c.req.param('id'))
  if (!s) return c.json(fail('not_found', 'no such subscription'), 404)
  await c.env.DB.prepare('DELETE FROM subscriptions WHERE id = ?').bind(s.id).run()
  await audit(c.env, 'subscription.delete', s.name)
  return c.body(null, 204)
})

// The subscription itself (no sign-in: the token in the URL is the key).
app.get('/sub/:token', async (c) => {
  const token = c.req.param('token')
  const s = token.length >= 24
    ? await c.env.DB.prepare('SELECT * FROM subscriptions WHERE token_hash = ?').bind(await sha256Hex(token)).first<SubRow>()
    : null
  if (!s) return c.text('not found', 404)
  const labels = JSON.parse(s.labels) as string[]
  const { results } = await c.env.DB.prepare(
    `SELECT n.id, n.name, n.labels, n.link_enc, n.outbound_enc, n.clash_enc, n.traffic_used, n.traffic_limit_gb, s.name AS server
       FROM nodes n JOIN servers s ON s.id = n.server_id
      WHERE n.status = 'applied' AND n.traffic_paused = 0 ORDER BY s.id, n.id`)
    .all<{ id: number; name: string; labels: string; link_enc: string | null; outbound_enc: string | null; clash_enc: string | null; traffic_used: number; traffic_limit_gb: number; server: string }>()
  const chosen = results.filter((n) => !labels.length || (JSON.parse(n.labels) as string[]).some((l) => labels.includes(l)))
  const own: SubNode[] = await Promise.all(chosen.map(async (n) => ({
    server: n.server, name: n.name,
    link: n.link_enc ? await decrypt(c.env.TOKEN_KEY, n.link_enc) : null,
    outbound: n.outbound_enc ? JSON.parse(await decrypt(c.env.TOKEN_KEY, n.outbound_enc)) : null,
    clash: n.clash_enc ? JSON.parse(await decrypt(c.env.TOKEN_KEY, n.clash_enc)) : null,
  })))
  // each node, then the same node through every relay that publishes it (the
  // node's labels choose both; its traffic is counted once, at the node)
  const relayed = await publishedRelays(c.env)
  const nodes: SubNode[] = []
  const names = new Set(own.map((n) => `${n.server}-${n.name}`))
  for (const [i, n] of own.entries()) {
    nodes.push(n)
    for (const r of relayed.filter((x) => x.node_id === chosen[i].id)) {
      // a relay may share a name with a node on its server: the copy gets a number
      let name = r.name
      for (let k = 2; names.has(`${r.server}-${name}`); k++) name = `${r.name}-${k}`
      names.add(`${r.server}-${name}`)
      nodes.push(nodeVia(n, r.via, r.server, name))
    }
  }
  const url = new URL(c.req.url)
  const format = pickFormat(url.searchParams.get('format'), c.req.header('User-Agent') ?? '')
  // the subscription's own template for this format, or the built-in one
  const chosen_tpl = format === 'uri' ? undefined : (JSON.parse(s.templates || '{}') as Record<string, unknown>)[format]
  const tpl = Number.isInteger(chosen_tpl)
    ? await c.env.DB.prepare('SELECT body FROM templates WHERE id = ? AND format = ?').bind(chosen_tpl, format).first<{ body: string }>()
    : null
  const out = buildSubscription(format, nodes, `${await panelUrl(c)}/sub/${token}`, { name: s.name, template: tpl?.body })
  await c.env.DB.prepare(`UPDATE subscriptions SET last_used = datetime('now') WHERE id = ?`).bind(s.id).run()
  const used = chosen.reduce((a, n) => a + (n.traffic_used || 0), 0)
  const total = chosen.every((n) => n.traffic_limit_gb > 0) ? Math.round(chosen.reduce((a, n) => a + n.traffic_limit_gb * GB, 0)) : 0
  return c.body(out.body, 200, {
    'Content-Type': out.type,
    'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(s.name)}.${out.ext}`,
    'Profile-Update-Interval': '12',
    'Subscription-Userinfo': `upload=0; download=${used}; total=${total}`,
    'Cache-Control': 'no-store',
  })
})

/**
 * The relays that publish their node: running (a tunnel at both ends), not
 * paused, asked to, and with an address for clients — the one set, else the
 * one the entry server's psm-agent last synced from.
 */
async function publishedRelays(env: Env): Promise<{ node_id: number; name: string; server: string; via: Via }[]> {
  const { results } = await env.DB.prepare(
    `SELECT r.node_id, r.name, r.listen_port, r.entry_host, s.name AS server, s.last_ip
       FROM relays r JOIN servers s ON s.id = r.server_id
      WHERE r.node_id IS NOT NULL AND r.in_sub = 1 AND r.paused = '' AND r.status = 'applied'
        AND (r.mode != 'tunnel' OR r.exit_status = 'applied') ORDER BY r.id`)
    .all<{ node_id: number; name: string; listen_port: number; entry_host: string; server: string; last_ip: string | null }>()
  return results.filter((r) => r.entry_host || r.last_ip)
    .map((r) => ({ node_id: r.node_id, name: r.name, server: r.server, via: { host: r.entry_host || r.last_ip!, port: r.listen_port } }))
}

// A relay's node as its clients reach it through the relay: the node's link
// (or Surge line, or wg-quick file) with the entry's address and port.
app.get('/api/relays/:id/link', async (c) => {
  const r = await getRelay(c.env, c.req.param('id'))
  if (!r) return c.json(fail('not_found', 'no such relay'), 404)
  const n = r.node_id === null ? null : await getNode(c.env, r.node_id)
  if (!n) return c.json(fail('no_node', '这条中转没有落到面板节点上'), 409)
  if (!n.link_enc) return c.json(fail('no_link', '节点还没有链接'), 409)
  const host = r.entry_host || (await getServer(c.env, r.server_id))?.last_ip
  if (!host) return c.json(fail('no_host', '入口服务器还没连过面板：在中转里填上入口地址'), 409)
  const link = linkVia(await decrypt(c.env.TOKEN_KEY, n.link_enc), { host, port: r.listen_port })
  if (!link) return c.json(fail('no_link', '这种链接改不了地址'), 409)
  // named as the subscription names it (a Surge line or wg-quick file keeps its own)
  const entry = (await getServer(c.env, r.server_id))?.name ?? ''
  const content = /^[a-z][a-z0-9+.-]*:\/\//i.test(link) ? renameLink(link, `${entry}-${r.name}`) : link
  return c.json({ format: linkFormat(n), content, host, port: r.listen_port })
})

// ── subscription templates ───────────────────────────────────────────────────
// The built-in ones (templates.ts) to start from, and the user's own.
type TemplateRow = { id: number; name: string; format: string; body: string; created_at: string; updated_at: string | null }

function templateProblem(format: string, name: string, body: string): string | null {
  if (!(TEMPLATE_FORMATS as string[]).includes(format)) return '格式：Clash、Stash、sing-box、Surge、Quantumult X 或 Loon'
  if (!name.trim() || name.trim().length > 48) return '模板名称：1-48 个字符'
  if (!body.trim() || body.length > 64 * 1024) return '模板内容：不能为空，最多 64 KB'
  // Clash can take its nodes from the proxy-provider instead, and then there is
  // no {{proxies}} line to fill in — the built-in Clash template works that way.
  if (!/\{\{provider_url\}\}/.test(body) && !/^[ \t]*\{\{proxies\}\}[ \t]*$/m.test(body))
    return '模板里要有单独占一行的 {{proxies}}（节点写在那里），或者用 {{provider_url}} 让 Clash 自己从订阅拉取节点'
  return null
}

app.get('/api/templates', async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM templates ORDER BY format, id').all<TemplateRow>()
  return c.json({
    formats: FORMAT_LABELS,
    builtin: TEMPLATE_FORMATS.map((f) => ({ format: f, name: BUILTIN_TEMPLATES[f].name, body: BUILTIN_TEMPLATES[f].body })),
    custom: results,
  })
})

app.post('/api/templates', async (c) => {
  const b = await c.req.json<{ name?: string; format?: string; body?: string }>().catch(() => null)
  const str = (v: unknown) => (typeof v === 'string' ? v : '')
  const problem = templateProblem(str(b?.format), str(b?.name), str(b?.body))
  if (problem) return c.json(fail('invalid', problem, { errors: [problem] }), 400)
  const r = await c.env.DB.prepare('INSERT INTO templates (name, format, body) VALUES (?, ?, ?)').bind(b!.name!.trim(), b!.format, b!.body).run()
  await audit(c.env, 'template.add', b!.name!.trim(), FORMAT_LABELS[b!.format as TemplateFormat])
  return c.json(await c.env.DB.prepare('SELECT * FROM templates WHERE id = ?').bind(Number(r.meta.last_row_id)).first<TemplateRow>(), 201)
})

const getTemplate = (env: Env, id: unknown) => {
  const n = idOf(id)
  return n === null ? Promise.resolve(null) : env.DB.prepare('SELECT * FROM templates WHERE id = ?').bind(n).first<TemplateRow>()
}

app.put('/api/templates/:id', async (c) => {
  const t = await getTemplate(c.env, c.req.param('id'))
  if (!t) return c.json(fail('not_found', '没有这个模板'), 404)
  const b = await c.req.json<{ name?: string; body?: string }>().catch(() => null)
  const name = typeof b?.name === 'string' ? b.name.trim() : t.name
  const body = typeof b?.body === 'string' ? b.body : t.body
  const problem = templateProblem(t.format, name, body)
  if (problem) return c.json(fail('invalid', problem, { errors: [problem] }), 400)
  await c.env.DB.prepare(`UPDATE templates SET name = ?, body = ?, updated_at = datetime('now') WHERE id = ?`).bind(name, body, t.id).run()
  await audit(c.env, 'template.update', name, FORMAT_LABELS[t.format as TemplateFormat])
  return c.json(await c.env.DB.prepare('SELECT * FROM templates WHERE id = ?').bind(t.id).first<TemplateRow>())
})

// Subscriptions that used it go back to the built-in template.
app.delete('/api/templates/:id', async (c) => {
  const t = await getTemplate(c.env, c.req.param('id'))
  if (!t) return c.json(fail('not_found', '没有这个模板'), 404)
  const { results } = await c.env.DB.prepare('SELECT id, templates FROM subscriptions').all<{ id: number; templates: string }>()
  for (const s of results) {
    const m = JSON.parse(s.templates || '{}') as Record<string, unknown>
    if (m[t.format] !== t.id) continue
    delete m[t.format]
    await c.env.DB.prepare('UPDATE subscriptions SET templates = ? WHERE id = ?').bind(JSON.stringify(m), s.id).run()
  }
  await c.env.DB.prepare('DELETE FROM templates WHERE id = ?').bind(t.id).run()
  await audit(c.env, 'template.delete', t.name, FORMAT_LABELS[t.format as TemplateFormat])
  return c.body(null, 204)
})

// ── settings and the audit log ───────────────────────────────────────────────
/**
 * Where the key that encrypts D1 lives. 'panel': only in D1, next to what it
 * encrypts (a one-click deploy) — a copy of the database is enough to read
 * everything. 'both': the TOKEN_KEY secret holds the same key and D1's copy
 * can go. 'secret': only the secret (as it should be). 'mismatch': the secret
 * is another key than the one D1's data was written with.
 */
async function tokenKeyState(env: Env): Promise<'panel' | 'secret' | 'both' | 'mismatch'> {
  if (tokenKeySource === 'panel') return 'panel'
  const stored = await getSetting(env, 'token_key')
  return !stored ? 'secret' : stored === env.TOKEN_KEY ? 'both' : 'mismatch'
}

app.get('/api/settings', async (c) => c.json({
  version: PANEL_VERSION,
  agent_version: AGENT_VERSION,
  panel_url: (await getSetting(c.env, 'panel_url')) ?? '',
  effective_panel_url: await panelUrl(c),
  sync_interval: syncInterval(c.env),
  token_key: await tokenKeyState(c.env),
  sni_engine: (await getSetting(c.env, 'sni_engine')) ?? 'netlas',
  sni_key_set: !!(await getSetting(c.env, 'sni_key_enc')),
  ipcheck_keys: Object.fromEntries(await Promise.all(IPCHECK_KEYS.map(async (k) => [k, !!(await getSetting(c.env, `ipcheck_key_${k}_enc`))]))),
}))

// The IP check's optional databases, by their free API keys (kept encrypted;
// they go to a server with each check, on psm-agent's stdin, never in argv)
const IPCHECK_KEYS = ['abuseipdb', 'ipqs', 'ip2location'] as const
const IPCHECK_KEY_RE = /^[A-Za-z0-9_-]{8,128}$/
async function ipcheckKeys(env: Env): Promise<Record<string, string>> {
  const out: Record<string, string> = {}
  for (const k of IPCHECK_KEYS) {
    const enc = await getSetting(env, `ipcheck_key_${k}_enc`)
    if (enc) out[k] = await decrypt(env.TOKEN_KEY, enc)
  }
  return out
}

const putSetting = (env: Env, key: string, value: string) =>
  env.DB.prepare(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).bind(key, value).run()

/**
 * The panel's address, as install commands and subscriptions carry it: HTTPS
 * (an agent token and every node's secrets travel over it), plain HTTP only
 * for an address that never leaves the machine or its LAN (a test panel).
 */
function panelUrlProblem(url: string): string | null {
  let u: URL
  try { u = new URL(url) } catch { return '面板地址：形如 https://psm.example.com' }
  if (!/^https?:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$/.test(url) || u.username || u.password) return '面板地址：形如 https://psm.example.com'
  if (u.protocol === 'https:') return null
  const h = u.hostname
  const local = h === 'localhost' || /^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(h) || !h.includes('.')
  return local ? null : '面板地址要用 https://（节点的密钥和 agent 的令牌经它传输）；http:// 只能用于本机或内网地址'
}

// Each setting changes only when it is sent: the panel address, and the
// mapping engine for REALITY camouflage targets with its API key (kept
// encrypted; the panel queries the engine itself, the key never leaves it).
app.put('/api/settings', async (c) => {
  const body = await c.req.json<{ panel_url?: unknown; sni_engine?: unknown; sni_key?: unknown; ipcheck_keys?: unknown }>().catch(() => null)
  if (!body || typeof body !== 'object') return c.json(fail('invalid', 'bad request'), 400)
  const invalid = (m: string) => c.json(fail('invalid', m, { errors: [m] }), 400)
  if (body.sni_engine !== undefined && !SNI_ENGINES.includes(String(body.sni_engine))) return invalid('网络测绘引擎：Netlas、Quake、ZoomEye 或 FOFA')
  const key = body.sni_key === undefined ? undefined : String(body.sni_key).trim()
  if (key !== undefined && (key.length > 512 || /[\r\n]/.test(key))) return invalid('API Key 不正确')
  // the IP check's keys: each one sent is saved ('' clears it)
  const ipKeys: [string, string][] = []
  if (body.ipcheck_keys !== undefined) {
    if (!body.ipcheck_keys || typeof body.ipcheck_keys !== 'object') return invalid('IP 检测的 API Key 不正确')
    for (const [k, v] of Object.entries(body.ipcheck_keys as Record<string, unknown>)) {
      const value = String(v ?? '').trim()
      if (!(IPCHECK_KEYS as readonly string[]).includes(k)) return invalid(`没有这个数据库：${k}`)
      if (value && !IPCHECK_KEY_RE.test(value)) return invalid(`${k} 的 API Key 只含字母、数字、- 和 _（8-128 位）`)
      ipKeys.push([k, value])
    }
  }
  if (body.panel_url !== undefined) {
    const url = String(body.panel_url).trim().replace(/\/+$/, '')
    const problem = url ? panelUrlProblem(url) : null
    if (problem) return invalid(problem)
    if (url) await putSetting(c.env, 'panel_url', url)
    else await c.env.DB.prepare(`DELETE FROM settings WHERE key = 'panel_url'`).run()
    await audit(c.env, 'settings.update', 'panel_url', url)
  }
  if (body.sni_engine !== undefined) {
    await putSetting(c.env, 'sni_engine', String(body.sni_engine))
    await audit(c.env, 'settings.update', 'sni_engine', String(body.sni_engine))
  }
  if (key !== undefined) {
    if (key) await putSetting(c.env, 'sni_key_enc', await encrypt(c.env.TOKEN_KEY, key))
    else await c.env.DB.prepare(`DELETE FROM settings WHERE key = 'sni_key_enc'`).run()
    await audit(c.env, 'settings.update', 'sni_key', key ? '已更新' : '已清除')
  }
  for (const [k, value] of ipKeys) {
    if (value) await putSetting(c.env, `ipcheck_key_${k}_enc`, await encrypt(c.env.TOKEN_KEY, value))
    else await c.env.DB.prepare('DELETE FROM settings WHERE key = ?').bind(`ipcheck_key_${k}_enc`).run()
    await audit(c.env, 'settings.update', `ipcheck_key_${k}`, value ? '已更新' : '已清除')
  }
  return c.json({ panel_url: (await getSetting(c.env, 'panel_url')) ?? '', effective_panel_url: await panelUrl(c) })
})

// The key D1 is encrypted with, shown once more to the admin (the password
// again, and counted as a sign-in attempt): to be set as the TOKEN_KEY secret,
// after which D1's copy can be forgotten.
app.post('/api/settings/token-key/reveal', async (c) => {
  const ip = ipKey(c.req.header('CF-Connecting-IP') ?? 'unknown')
  if (await tooManyFailures(c.env.DB, ip)) return c.json(fail('too_many', 'too many failed attempts; try again in 15 minutes'), 429)
  const body = await c.req.json<{ password?: unknown }>().catch(() => null)
  if (!(await passwordMatches(c.env, typeof body?.password === 'string' ? body.password : ''))) {
    await recordFailure(c.env.DB, ip)
    await audit(c.env, 'settings.reveal-key.failed', ip)
    return c.json(fail('bad_password', '密码不对'), 403)
  }
  const stored = await getSetting(c.env, 'token_key')
  if (!stored) return c.json(fail('not_found', '数据库里没有密钥：它只在 TOKEN_KEY 机密里'), 404)
  await audit(c.env, 'settings.reveal-key', ip)
  return c.json({ token_key: stored })
})

// D1's copy goes once the secret holds the same key (never otherwise: that
// copy would be the only one).
app.post('/api/settings/token-key/forget', async (c) => {
  if ((await tokenKeyState(c.env)) !== 'both') {
    const msg = '先把 TOKEN_KEY 机密设成数据库里的这把密钥，再删除数据库里的副本'
    return c.json(fail('invalid', msg, { errors: [msg] }), 409)
  }
  await c.env.DB.prepare(`DELETE FROM settings WHERE key = 'token_key'`).run()
  panelKey = null
  await audit(c.env, 'settings.forget-key')
  return c.json({ token_key: await tokenKeyState(c.env) })
})

// REALITY camouflage targets in a server's own network. The panel asks the
// mapping engine for hosts with a certificate in the server's ASN (Cloudflare
// names it with every sync) — the engine's key never leaves the panel — and
// the server checks each with one TLS handshake (psm sni check). The page
// asks for the answer with GET /api/tasks/:id.
app.post('/api/servers/:id/sni-find', async (c) => {
  const s = await getServer(c.env, c.req.param('id'))
  if (!s) return c.json(fail('not_found', '没有这台服务器'), 404)
  const invalid = (m: string) => c.json(fail('invalid', m, { errors: [m] }), 400)
  if (!s.agent_token_hash) return invalid('服务器还没有接入面板，接入后才能查询')
  if (!versionAtLeast(s.agent_version, RELAY_AGENT))
    return invalid(`${s.name} 的 psm-agent 是 ${s.agent_version ?? '旧版'}，自动选择伪装目标要 ${RELAY_AGENT} 以上：先在服务器页点「升级 agent」`)
  const keyEnc = await getSetting(c.env, 'sni_key_enc')
  if (!keyEnc) return invalid('先在“系统设置”里填写网络测绘引擎的 API Key')
  if (!s.asn) return invalid(`还不知道 ${s.name} 所在的网络：等它和面板同步一次（半分钟内）再试`)
  const engine = (await getSetting(c.env, 'sni_engine')) ?? 'netlas'
  const found = await findSniCandidates({
    engine, key: await decrypt(c.env.TOKEN_KEY, keyEnc), asn: s.asn, country: s.country ?? '', max: 40,
    netlasBase: c.env.SNI_NETLAS_BASE,
  })
  if (!found.pairs.length) return invalid(found.error ?? `${engine} 在 AS${s.asn} 里没有找到带证书的网站（或者额度用完了）`)
  const id = await enqueue(c.env, s.id, null, { kind: 'sni.check', data: { pairs: found.pairs } })
  // the page shows where the search looked
  await c.env.DB.prepare('UPDATE tasks SET result_enc = ? WHERE id = ?')
    .bind(await encrypt(c.env.TOKEN_KEY, JSON.stringify({ asn: s.asn, country: s.country, engine, found: found.pairs.length })), id).run()
  await audit(c.env, 'server.sni-find', s.name, `${engine} AS${s.asn}：${found.pairs.length} 个候选`)
  return c.json({ task_id: id, asn: s.asn, country: s.country, found: found.pairs.length }, 202)
})

app.get('/api/tasks/:id', async (c) => {
  const id = idOf(c.req.param('id'))
  const t = id === null ? null
    : await c.env.DB.prepare('SELECT id, kind, status, error, result_enc FROM tasks WHERE id = ?').bind(id)
      .first<{ id: number; kind: string; status: string; error: string | null; result_enc: string | null }>()
  if (!t) return c.json(fail('not_found', '没有这个任务'), 404)
  return c.json({ id: t.id, kind: t.kind, status: t.status, error: t.error,
    result: t.result_enc ? JSON.parse(await decrypt(c.env.TOKEN_KEY, t.result_enc)) : null })
})

// Newest first; ?before=<id> for the page after, ?action=<prefix> to narrow it.
app.get('/api/audit', async (c) => {
  const q = new URL(c.req.url).searchParams
  const limit = Math.min(Math.max(Number(q.get('limit')) || 100, 1), 500)
  const before = idOf(q.get('before'))
  const action = (q.get('action') ?? '').replace(/[^a-z0-9.-]/g, '').slice(0, 40)
  const { results } = await c.env.DB.prepare(
    `SELECT * FROM audit WHERE (? IS NULL OR id < ?) AND (? = '' OR action = ? OR action LIKE ? || '.%')
      ORDER BY id DESC LIMIT ?`).bind(before, before, action, action, action, limit).all()
  return c.json(results)
})

// ── psm-agent ────────────────────────────────────────────────────────────────
// Join: a one-time join token becomes this server's agent token. Nodes and
// relays that were waiting for the server get their tasks.
app.post('/api/agent/join', async (c) => {
  const body = await c.req.json<{ join_token?: unknown; hostname?: unknown; agent_version?: unknown }>().catch(() => null)
  const jt = typeof body?.join_token === 'string' ? body.join_token : ''
  if (jt.length < 32 || jt.length > 256) return c.json(fail('bad_token', 'invalid or expired join token'), 403)
  // Claimed in one statement: of two joins racing with the same token, one
  // gets the row and the other nothing (a read, then a write, let both in).
  const claim = await c.env.DB.prepare(
    `UPDATE join_tokens SET used_at = datetime('now')
      WHERE token_hash = ? AND used_at IS NULL AND expires_at > datetime('now') RETURNING server_id`)
    .bind(await sha256Hex(jt)).first<{ server_id: number }>()
  if (!claim) return c.json(fail('bad_token', 'invalid or expired join token'), 403)
  const server = await getServer(c.env, claim.server_id)
  if (!server) return c.json(fail('bad_token', 'invalid or expired join token'), 403)
  const str = (v: unknown, n: number) => (typeof v === 'string' ? v.slice(0, n) : null)
  const hostname = str(body?.hostname, 64)
  const agentToken = randomToken()
  await c.env.DB.batch([
    // the server has joined: any other install command handed out for it stops working
    c.env.DB.prepare(`DELETE FROM join_tokens WHERE server_id = ? AND used_at IS NULL`).bind(server.id),
    c.env.DB.prepare(`UPDATE servers SET agent_token_hash = ?, hostname = ?, agent_version = ?, last_seen = datetime('now') WHERE id = ?`)
      .bind(await sha256Hex(agentToken), hostname, str(body?.agent_version, 16), server.id),
  ])

  // What waited for the server, in one batch. A node that can no longer be
  // sent (its stored settings do not decrypt or validate) is marked failed
  // with the reason — it must not stop the others, nor the join itself: the
  // token is spent, and an error here would leave the server joined with
  // nothing sent.
  const stmts: D1PreparedStatement[] = []
  const { results: waiting } = await c.env.DB.prepare(
    `SELECT * FROM nodes WHERE server_id = ? AND status IN ('waiting', 'failed')`).bind(server.id).all<NodeRow>()
  for (const n of waiting) {
    try {
      stmts.push(...await applyStmts(c.env, n, await nodeData(c.env, n)),
        c.env.DB.prepare(`UPDATE nodes SET status = 'queued', last_error = NULL WHERE id = ?`).bind(n.id))
    } catch (e) {
      console.error(`join ${server.name}: node ${n.id}`, e)
      stmts.push(c.env.DB.prepare(`UPDATE nodes SET status = 'failed', last_error = ? WHERE id = ?`)
        .bind(`无法下发：${(e as Error).message}`.slice(0, 500), n.id))
    }
  }
  if (stmts.length) await c.env.DB.batch(stmts)
  // Relays wait for their server in the same way a node does — a relay can be
  // created before the server has joined, and the panel hands out the install
  // command for it — so they are sent now too. Without this they stayed
  // "waiting" for ever, since nothing else ever queues them.
  const { results: pending } = await c.env.DB.prepare(
    `SELECT * FROM relays WHERE server_id = ? AND status IN ('waiting', 'failed')`).bind(server.id).all<RelayRow>()
  for (const r of pending) {
    try {
      // a tunnel's entry waits for its exit's certificate
      if (r.mode === 'tunnel' && r.exit_status !== 'applied') {
        await c.env.DB.prepare(`UPDATE relays SET status = 'pending', pending_entry = 'add', last_error = NULL WHERE id = ?`).bind(r.id).run()
        continue
      }
      await c.env.DB.prepare(`UPDATE relays SET status = 'queued', last_error = NULL WHERE id = ?`).bind(r.id).run()
      await queueRelaySide(c.env, r, r.mode === 'tunnel' ? 'entry' : 'forward', 'add')
    } catch (e) {
      console.error(`join ${server.name}: relay ${r.id}`, e)
      await c.env.DB.prepare(`UPDATE relays SET status = 'failed', last_error = ? WHERE id = ?`)
        .bind(`无法下发：${(e as Error).message}`.slice(0, 500), r.id).run()
    }
  }
  const { results: exits } = await c.env.DB.prepare(
    `SELECT * FROM relays WHERE mode = 'tunnel' AND exit_server_id = ? AND exit_status IN ('waiting', 'failed')`).bind(server.id).all<RelayRow>()
  for (const r of exits) {
    try {
      await c.env.DB.prepare(`UPDATE relays SET exit_status = 'queued', exit_error = NULL, pending_entry = ? WHERE id = ?`)
        .bind(r.status === 'applied' ? 'update' : 'add', r.id).run()
      await queueRelaySide(c.env, r, 'exit', 'add')
    } catch (e) {
      console.error(`join ${server.name}: relay exit ${r.id}`, e)
      await c.env.DB.prepare(`UPDATE relays SET exit_status = 'failed', exit_error = ? WHERE id = ?`)
        .bind(`无法下发：${(e as Error).message}`.slice(0, 500), r.id).run()
    }
  }
  await enqueue(c.env, server.id, null, { kind: 'status' })
  await audit(c.env, 'server.join', server.name, hostname ?? '', 'agent')
  return c.json({ agent_token: agentToken, server: { id: server.id, name: server.name }, interval: syncInterval(c.env) })
})

/** A task result on its node (and, for status reports, its server). */
async function applyResult(env: Env, server: ServerRow, t: TaskRow, r: AgentResult) {
  const error = r.ok ? null : String(r.error ?? 'failed').slice(0, 500)
  const link = r.ok && typeof r.link === 'string' && r.link ? await encrypt(env.TOKEN_KEY, r.link.slice(0, 8192)) : null
  const outbound = r.ok && r.outbound && typeof r.outbound === 'object' ? await encrypt(env.TOKEN_KEY, JSON.stringify(r.outbound).slice(0, 16384)) : null
  const clash = r.ok && r.clash && typeof r.clash === 'object' ? await encrypt(env.TOKEN_KEY, JSON.stringify(r.clash).slice(0, 16384)) : null
  const db = env.DB
  switch (t.kind) {
    case 'agent.leave': {
      if (!r.ok) {   // e.g. an agent too old for agent.leave: the server stays, with the reason
        await db.prepare('UPDATE servers SET leaving = 0, leave_error = ? WHERE id = ?').bind(error, server.id).run()
        return
      }
      const out = r.output as { failed?: unknown } | undefined
      const failed = Array.isArray(out?.failed) ? out!.failed.map(String) : []
      await db.prepare('DELETE FROM servers WHERE id = ?').bind(server.id).run()
      await audit(env, 'server.left', server.name, failed.length ? `未能删除：${failed.join('；')}`.slice(0, 500) : '节点和 psm-agent 已卸载', 'agent')
      return
    }
    case 'status':
      if (r.ok && r.output) {
        const report = JSON.stringify(r.output)
        const version = (r.output as { psm_version?: unknown }).psm_version
        await db.prepare(`UPDATE servers SET status_enc = ?, status_at = datetime('now'), psm_version = COALESCE(?, psm_version) WHERE id = ?`)
          .bind(await encrypt(env.TOKEN_KEY, report.slice(0, 512 * 1024)), typeof version === 'string' ? version.slice(0, 40) : null, server.id).run()
      }
      return
    case 'check.run':
      if (r.ok && r.output && typeof r.output === 'object') {
        await db.prepare(`UPDATE servers SET check_enc = ?, check_at = datetime('now'), check_error = NULL WHERE id = ?`)
          .bind(await encrypt(env.TOKEN_KEY, JSON.stringify(r.output).slice(0, 64 * 1024)), server.id).run()
      } else {
        await db.prepare(`UPDATE servers SET check_error = ?, check_at = datetime('now') WHERE id = ?`)
          .bind(error ?? '服务器没有返回检测结果', server.id).run()
      }
      return
    case 'node.add': case 'standalone.install':
      if (!t.node_id) return
      await db.prepare(`UPDATE nodes SET status = ?, last_error = ?, link_enc = COALESCE(?, link_enc), outbound_enc = COALESCE(?, outbound_enc), clash_enc = COALESCE(?, clash_enc) WHERE id = ?`)
        .bind(r.ok ? 'applied' : 'failed', error, link, outbound, clash, t.node_id).run()
      return
    case 'node.update':
      if (!t.node_id) return
      // a failed update leaves the node running as before (PSM rolls back)
      if (!r.ok) {
        await db.prepare(`UPDATE nodes SET status = 'applied', last_error = ? WHERE id = ?`).bind(`修改没有生效：${error}`, t.node_id).run()
        return
      }
      // a sing-box outbound or mihomo proxy the node no longer has goes (turning
      // VLESS Encryption on takes it out of sing-box): kept, it would be a dead node
      await db.prepare(`UPDATE nodes SET status = 'applied', last_error = NULL, link_enc = COALESCE(?, link_enc), outbound_enc = ?, clash_enc = ? WHERE id = ?`)
        .bind(link, outbound, clash, t.node_id).run()
      return
    case 'node.delete': case 'standalone.remove':
      if (!t.node_id) return
      if (r.ok) await db.prepare('DELETE FROM nodes WHERE id = ?').bind(t.node_id).run()
      else await db.prepare(`UPDATE nodes SET status = 'applied', last_error = ? WHERE id = ?`).bind(error, t.node_id).run()
      return
    case 'relay.add': case 'relay.update': case 'relay.delete':
      if (t.relay_id) await applyRelayResult(env, t, r, error)
      return
    case 'node.export':
      // as for an update: what the node exports now, nothing it no longer has
      if (t.node_id && r.ok && link) {
        await db.prepare('UPDATE nodes SET link_enc = ?, outbound_enc = ?, clash_enc = ? WHERE id = ?')
          .bind(link, outbound, clash, t.node_id).run()
      }
      return
    case 'traffic.set': case 'traffic.reset': {
      if (!t.node_id) return
      const what = t.kind === 'traffic.reset' ? '流量重置' : '流量限额'
      // A limit or a reset the server did not take is said on the node (it
      // used to vanish: the node looked limited, or reset, and was not) —
      // on a node that runs and has no other error: when the node itself
      // failed, its limit fails with it, and the node's own reason is the one
      // to read.
      if (!r.ok) {
        await db.prepare(`UPDATE nodes SET last_error = ? WHERE id = ? AND status = 'applied' AND last_error IS NULL`)
          .bind(`${what}没有生效：${error}`.slice(0, 500), t.node_id).run()
        return
      }
      const o = r.output as { used_bytes?: unknown; paused?: unknown } | undefined
      const clear = `last_error = CASE WHEN last_error LIKE '流量%没有生效：%' THEN NULL ELSE last_error END`
      if (o && typeof o.used_bytes === 'number' && Number.isFinite(o.used_bytes)) {
        await db.prepare(`UPDATE nodes SET traffic_used = ?, traffic_paused = ?, traffic_at = datetime('now'), ${clear} WHERE id = ?`)
          .bind(Math.max(0, Math.floor(o.used_bytes)), o.paused === true ? 1 : 0, t.node_id).run()
      } else if (t.kind === 'traffic.reset') {
        // a reset that succeeded without counts is still a reset: zero, running
        await db.prepare(`UPDATE nodes SET traffic_used = 0, traffic_paused = 0, traffic_at = datetime('now'), ${clear} WHERE id = ?`)
          .bind(t.node_id).run()
      } else {
        await db.prepare(`UPDATE nodes SET ${clear} WHERE id = ?`).bind(t.node_id).run()
      }
      return
    }
  }
}

/**
 * The traffic counters a server sent: this month's totals, and today's
 * increase. `skip`: nodes whose limit or reset was reported in the same sync —
 * the counters were read before that ran, and would put back what the reset
 * just cleared.
 */
async function applyTraffic(env: Env, server: ServerRow, entries: TrafficEntry[], skip: Set<number>) {
  const { results: nodes } = await env.DB.prepare('SELECT * FROM nodes WHERE server_id = ?').bind(server.id).all<NodeRow>()
  const byTag = new Map(nodes.map((n) => [trafficTag(n), n]))
  const stmts: D1PreparedStatement[] = []
  for (const e of entries.slice(0, 500)) {
    const n = typeof e.tag === 'string' ? byTag.get(e.tag) : undefined
    if (!n || skip.has(n.id) || typeof e.used_bytes !== 'number' || !Number.isFinite(e.used_bytes)) continue
    const used = Math.max(0, Math.floor(e.used_bytes)), paused = e.paused === true ? 1 : 0
    if (used === n.traffic_used && paused === n.traffic_paused) continue
    // a smaller count means it was reset (monthly, or by hand): all of it is new
    const delta = used >= n.traffic_used ? used - n.traffic_used : used
    stmts.push(env.DB.prepare(`UPDATE nodes SET traffic_used = ?, traffic_paused = ?, traffic_at = datetime('now') WHERE id = ?`).bind(used, paused, n.id))
    if (delta > 0) {
      stmts.push(env.DB.prepare(`INSERT INTO traffic_daily (node_id, day, bytes) VALUES (?, date('now'), ?)
        ON CONFLICT(node_id, day) DO UPDATE SET bytes = bytes + excluded.bytes`).bind(n.id, delta))
    }
  }
  if (stmts.length) await env.DB.batch(stmts)
}

/**
 * The relay measurements a server sent. The byte counter on the server only
 * grows (and starts again when the accounting rules are rebuilt), so what is
 * stored per sample is the difference since the last reading; the newest
 * reading is also kept on the relay itself, so the list needs no samples.
 * Seven days of samples are kept — what the charts draw (housekeeping() drops
 * older ones). A tunnel's exit measures the hop behind it (to the landing
 * side), kept beside the entry's.
 */
async function applyRelaySamples(env: Env, server: ServerRow, entries: RelaySample[]) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM relays WHERE server_id = ? OR (mode = 'tunnel' AND exit_server_id = ?)`).bind(server.id, server.id).all<RelayRow>()
  const own = new Map(results.filter((r) => r.server_id === server.id).map((r) => [r.name, r]))
  const exits = new Map(results.filter((r) => r.mode === 'tunnel' && r.exit_server_id === server.id).map((r) => [r.name, r]))
  const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : null)
  // each landing host: where it is and whether it answered
  const health = (v: unknown) => {
    if (!Array.isArray(v)) return null
    return JSON.stringify(v.slice(0, 16).map((t: { host?: unknown; port?: unknown; rtt_ms?: unknown; loss_pct?: unknown }) =>
      ({ host: String(t?.host ?? '').slice(0, 253), port: num(t?.port), rtt_ms: num(t?.rtt_ms), loss_pct: num(t?.loss_pct) })))
  }
  const stmts: D1PreparedStatement[] = []
  for (const e of entries.slice(0, 200)) {
    if (typeof e.tag !== 'string') continue
    const rtt = num(e.rtt_ms), jitter = num(e.jitter_ms), loss = num(e.loss_pct) ?? 0
    const x = exits.get(e.tag)
    if (x && !own.has(e.tag)) {
      stmts.push(env.DB.prepare(`UPDATE relays SET exit_rtt_ms = ?, exit_loss_pct = ?, target_health = COALESCE(?, target_health) WHERE id = ?`)
        .bind(rtt, loss, health(e.targets), x.id))
      continue
    }
    const r = own.get(e.tag)
    if (!r) continue
    const total = Math.max(0, Math.floor(num(e.bytes) ?? 0))
    const delta = total >= r.meter_bytes ? total - r.meter_bytes : total
    const used = num(e.used_bytes)
    const paused = e.paused === true ? (e.pause_reason === 'expired' ? 'expired' : 'quota') : ''
    stmts.push(env.DB.prepare(
      'INSERT INTO relay_samples (relay_id, rtt_ms, jitter_ms, loss_pct, bytes) VALUES (?, ?, ?, ?, ?)')
      .bind(r.id, rtt, jitter, loss, delta))
    stmts.push(env.DB.prepare(
      `UPDATE relays SET meter_bytes = ?, traffic_bytes = traffic_bytes + ?, last_rtt_ms = ?, last_jitter_ms = ?,
              last_loss_pct = ?, last_sample_at = datetime('now'), quota_used = ?, paused = ?,
              target_health = CASE WHEN mode = 'tunnel' THEN target_health ELSE ? END WHERE id = ?`)
      .bind(total, delta, rtt, jitter, loss, used === null ? null : Math.floor(used), paused, health(e.targets), r.id))
  }
  if (stmts.length) await env.DB.batch(stmts)
}

/**
 * A relay task's result, on the side it was for. A tunnel's exit answering
 * brings its certificate (and its port, when psm picked one), and the entry
 * waiting for it is sent. A relay leaves the panel once no side of it is on a
 * server any more.
 */
async function applyRelayResult(env: Env, t: TaskRow, res: AgentResult, error: string | null) {
  const rel = await getRelay(env, t.relay_id!)
  if (!rel) return
  const db = env.DB
  const exitSide = rel.mode === 'tunnel' && t.server_id === rel.exit_server_id && t.server_id !== rel.server_id
  const item = (res.output as { item?: { listen_port?: unknown; cert_pem?: unknown } } | undefined)?.item
  const port = typeof item?.listen_port === 'number' && goodPort(item.listen_port) ? item.listen_port : null
  if (t.kind === 'relay.delete') {
    if (exitSide) {
      await db.prepare('UPDATE relays SET exit_status = ?, exit_error = ? WHERE id = ?')
        .bind(res.ok ? 'deleted' : 'applied', res.ok ? null : error, rel.id).run()
    } else {
      await db.prepare('UPDATE relays SET status = ?, last_error = ? WHERE id = ?')
        .bind(res.ok ? 'deleted' : 'applied', res.ok ? null : error, rel.id).run()
    }
    await relayGoneIfDone(env, rel.id)
    return
  }
  // a psm-picked port that another row holds: keep ours, say why
  const setPort = async (col: 'listen_port' | 'exit_port') => {
    if (port === null) return
    try { await db.prepare(`UPDATE relays SET ${col} = ? WHERE id = ?`).bind(port, rel.id).run() } catch { /* the unique index */ }
  }
  if (exitSide) {
    if (res.ok) {
      const pem = typeof item?.cert_pem === 'string' && item.cert_pem.startsWith('-----BEGIN CERTIFICATE-----') && item.cert_pem.length < 8192
        ? item.cert_pem : rel.exit_cert
      await db.prepare(`UPDATE relays SET exit_status = 'applied', exit_error = NULL, exit_cert = ? WHERE id = ?`).bind(pem, rel.id).run()
      await setPort('exit_port')
      await sendPendingEntry(env, (await getRelay(env, rel.id))!)
    } else if (t.kind === 'relay.add') {
      await db.prepare(`UPDATE relays SET exit_status = 'failed', exit_error = ? WHERE id = ?`).bind(error, rel.id).run()
    } else {
      // psm rolled the exit back: the tunnel runs on as it was
      await db.prepare(`UPDATE relays SET exit_status = 'applied', exit_error = ?, pending_entry = '' WHERE id = ?`)
        .bind(`修改没有生效：${error}`, rel.id).run()
    }
    return
  }
  if (t.kind === 'relay.add') {
    await db.prepare('UPDATE relays SET status = ?, last_error = ? WHERE id = ?').bind(res.ok ? 'applied' : 'failed', error, rel.id).run()
  } else {
    // a rule the engine would not take is rolled back by PSM: the old hop runs on
    await db.prepare(`UPDATE relays SET status = 'applied', last_error = ? WHERE id = ?`)
      .bind(error ? `修改没有生效：${error}` : null, rel.id).run()
  }
  if (res.ok) await setPort('listen_port')
}

/**
 * What grows without end, trimmed: the audit log and finished tasks after 7
 * days, relay samples after the 7 the charts show, daily traffic after 60
 * (the 流量 page shows 30), sign-in failures and spent or expired join tokens
 * after a day. Once a day by the cron trigger (wrangler.jsonc), whether or
 * not any server syncs; and at most once an hour after a sync, as before (a
 * panel whose trigger was taken away). After the answer is sent (waitUntil):
 * no request waits for it.
 */
let lastHousekeeping = 0
async function housekeeping(env: Env, scheduled = false) {
  if (!scheduled) {
    if (Date.now() - lastHousekeeping < 3600_000) return
    lastHousekeeping = Date.now()
    const due = await env.DB.prepare(`INSERT INTO settings (key, value) VALUES ('housekeeping_at', datetime('now'))
        ON CONFLICT(key) DO UPDATE SET value = excluded.value WHERE value < datetime('now', '-1 hour') RETURNING value`).first()
    if (!due) return   // another isolate did it within the hour
  }
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM audit WHERE at < datetime('now', '-7 days')`),
    env.DB.prepare(`DELETE FROM tasks WHERE status IN ('done', 'failed') AND finished_at < datetime('now', '-7 days')`),
    env.DB.prepare(`DELETE FROM relay_samples WHERE at < datetime('now', '-7 days')`),
    env.DB.prepare(`DELETE FROM traffic_daily WHERE day < date('now', '-60 days')`),
    env.DB.prepare(`DELETE FROM login_failures WHERE at < datetime('now', '-1 day')`),
    env.DB.prepare(`DELETE FROM join_tokens WHERE expires_at < datetime('now', '-1 day') OR used_at < datetime('now', '-1 day')`),
  ])
}

// Sync: the agent reports the results of its tasks (and its traffic
// counters) and takes new ones.
app.post('/api/agent/sync', async (c) => {
  const token = c.req.header('Authorization')?.replace(/^Bearer /, '') ?? ''
  const server = token.length >= 32 && token.length <= 256
    ? await c.env.DB.prepare('SELECT * FROM servers WHERE agent_token_hash = ?').bind(await sha256Hex(token)).first<ServerRow>()
    : null
  if (!server) return c.json(fail('unauthorized', 'unknown agent token'), 401)
  type SyncBody = { hostname?: string; agent_version?: string; psm_version?: string; results?: AgentResult[]; traffic?: TrafficEntry[]; relays?: { items?: RelaySample[] } | RelaySample[] }
  const body = await c.req.json<SyncBody>().catch((): SyncBody => ({}))
  const psmBefore = server.psm_version
  const ip = c.req.header('CF-Connecting-IP') ?? null
  // where the server is: Cloudflare knows the network the agent connects from
  const cf = (c.req.raw as { cf?: { asn?: unknown; country?: unknown } }).cf
  const asn = typeof cf?.asn === 'number' && cf.asn > 0 ? cf.asn : null
  const country = typeof cf?.country === 'string' && /^[A-Z]{2}$/.test(cf.country) ? cf.country : null
  const str = (v: unknown, n: number) => (typeof v === 'string' ? v.slice(0, n) : null)
  // the syncs of this minute counted in the same write (no extra round trip)
  const seen = await c.env.DB.prepare(`UPDATE servers SET last_seen = datetime('now'), hostname = COALESCE(?, hostname),
      agent_version = COALESCE(?, agent_version), psm_version = COALESCE(?, psm_version), last_ip = COALESCE(?, last_ip),
      asn = COALESCE(?, asn), country = COALESCE(?, country),
      sync_count = CASE WHEN sync_window IS NULL OR sync_window < datetime('now', '-60 seconds') THEN 1 ELSE sync_count + 1 END,
      sync_window = CASE WHEN sync_window IS NULL OR sync_window < datetime('now', '-60 seconds') THEN datetime('now') ELSE sync_window END
      WHERE id = ? RETURNING sync_count`)
    .bind(str(body.hostname, 64), str(body.agent_version, 16), str(body.psm_version, 40),
      ip && /^[0-9a-fA-F:.]{2,45}$/.test(ip) ? ip : null, asn, country, server.id).first<{ sync_count: number }>()
  // psm-agent keeps its results when told this, and comes back later
  if ((seen?.sync_count ?? 0) > SYNCS_PER_MINUTE) return c.json(fail('too_many', 'too many syncs; slow down'), 429)

  const trafficTouched = new Set<number>()
  for (const r of (Array.isArray(body.results) ? body.results : []).slice(0, 100)) {
    const id = r && typeof r === 'object' ? idOf(r.task_id) : null
    if (id === null) continue
    const t = await c.env.DB.prepare(`SELECT * FROM tasks WHERE id = ? AND server_id = ? AND status = 'running'`)
      .bind(id, server.id).first<TaskRow>()
    if (!t) continue
    const ok = r.ok === true
    await c.env.DB.prepare(`UPDATE tasks SET status = ?, error = ?, finished_at = datetime('now') WHERE id = ?`)
      .bind(ok ? 'done' : 'failed', ok ? null : String(r.error ?? 'failed').slice(0, 500), t.id).run()
    if (t.kind === 'traffic.set' || t.kind === 'traffic.reset') { if (t.node_id) trafficTouched.add(t.node_id) }
    // One result the panel cannot take (a relay whose stored secret no longer
    // decrypts, say) must not fail the sync: the agent would send the same
    // results again and again, and nothing after them would ever arrive.
    try {
      if (t.kind === 'sni.find' || t.kind === 'sni.check') await storeSniResult(c.env, t, r)
      await applyResult(c.env, server, t, { ...r, ok })
    } catch (e) {
      console.error(`sync ${server.name}: result of task ${t.id} (${t.kind})`, e)
    }
  }
  if (Array.isArray(body.traffic)) await applyTraffic(c.env, server, body.traffic, trafficTouched)
  // PSM on the server changed (updated by hand, or by 更新 PSM / 升级 agent):
  // its nodes' exports may have changed with it (a status result above reads
  // the version afresh, so compare after the results)
  const psmNow = (await c.env.DB.prepare('SELECT psm_version FROM servers WHERE id = ?').bind(server.id).first<{ psm_version: string | null }>())?.psm_version
  if (psmBefore && psmNow && psmNow !== psmBefore) await queueExports(c.env, server.id)
  // `psm relay probe --json` wraps its rows in {api_version, count, items}
  const samples = Array.isArray(body.relays) ? body.relays : body.relays?.items
  if (Array.isArray(samples)) await applyRelaySamples(c.env, server, samples)

  // Claimed in one statement: a second sync of the same server racing this
  // one (a retry, a second agent with a copied token) cannot be handed the
  // same tasks. A task claimed but not reported for a while goes out again.
  const due = `(status = 'queued' OR (status = 'running' AND claimed_at < datetime('now', '-${TASK_RETRY_MINUTES} minutes')))`
  const { results: claimed } = await c.env.DB.prepare(
    `UPDATE tasks SET status = 'running', claimed_at = datetime('now')
      WHERE id IN (SELECT id FROM tasks WHERE server_id = ? AND ${due} ORDER BY id LIMIT 20) AND ${due}
      RETURNING *`).bind(server.id).all<TaskRow>()
  const tasks = []
  for (const t of claimed.sort((a, b) => a.id - b.id)) {
    // a task that cannot be read (written with another TOKEN_KEY) fails with
    // the reason, on its node or relay too — rather than failing every sync
    try {
      tasks.push({ id: t.id, ...JSON.parse(await decrypt(c.env.TOKEN_KEY, t.payload_enc)) })
    } catch (e) {
      const error = `面板读不出这个任务（TOKEN_KEY 换过？）：${(e as Error).message}`.slice(0, 500)
      await c.env.DB.prepare(`UPDATE tasks SET status = 'failed', error = ?, finished_at = datetime('now') WHERE id = ?`).bind(error, t.id).run()
      await applyResult(c.env, server, t, { task_id: t.id, ok: false, error }).catch((err) => console.error(err))
    }
  }
  try { c.executionCtx.waitUntil(housekeeping(c.env).catch((e) => console.error('housekeeping', e))) } catch { /* no context (tests) */ }
  // more queued behind these, or results just came in: come back soon
  const busy = tasks.length > 0 || (body.results?.length ?? 0) > 0 ||
    !!(await c.env.DB.prepare(`SELECT 1 FROM tasks WHERE server_id = ? AND status = 'queued' LIMIT 1`).bind(server.id).first())
  return c.json({ interval: busy ? FAST_INTERVAL : syncInterval(c.env), tasks })
})

/**
 * A REALITY target search's answer, for the page that asked. sni.check keeps
 * where the panel searched (written when it was queued) beside the
 * candidates the server's TLS checks passed; the old sni.find carried the
 * engine's key, which leaves the task here.
 */
async function storeSniResult(env: Env, t: TaskRow & { result_enc?: string | null }, r: AgentResult) {
  let meta: Record<string, unknown> = {}
  if (t.kind === 'sni.check' && t.result_enc) {
    try { meta = JSON.parse(await decrypt(env.TOKEN_KEY, t.result_enc)) } catch { /* only the candidates, then */ }
  }
  const out = r.ok && r.output && typeof r.output === 'object' ? { ...meta, ...(r.output as Record<string, unknown>) } : null
  await env.DB.prepare('UPDATE tasks SET result_enc = ?, payload_enc = ? WHERE id = ?')
    .bind(out ? await encrypt(env.TOKEN_KEY, JSON.stringify(out).slice(0, 65536)) : null,
      await encrypt(env.TOKEN_KEY, JSON.stringify({ kind: t.kind })), t.id).run()
}

// The dashboard in one request: counts and sums, nothing decrypted.
app.get('/api/overview', async (c) => {
  const db = c.env.DB
  const [servers, nodes, relays, today, failing, resetDays] = await db.batch([
    db.prepare(`SELECT ${serverStatusSQL(c.env)} AS status, COUNT(*) AS n FROM servers s GROUP BY 1`),
    db.prepare(`SELECT status, COUNT(*) AS n, SUM(traffic_used) AS used, SUM(traffic_paused) AS paused FROM nodes GROUP BY status`),
    db.prepare(`SELECT status, COUNT(*) AS n, SUM(traffic_bytes) AS bytes,
                  SUM(CASE WHEN paused != '' THEN 1 ELSE 0 END) AS paused,
                  SUM(CASE WHEN last_loss_pct > 0 THEN 1 ELSE 0 END) AS lossy FROM relays GROUP BY status`),
    db.prepare(`SELECT day, SUM(bytes) AS bytes FROM traffic_daily WHERE day >= date('now', '-13 days') GROUP BY day ORDER BY day`),
    db.prepare(`SELECT 'node' AS type, n.id, n.name, s.name AS server, n.last_error AS error FROM nodes n JOIN servers s ON s.id = n.server_id
                 WHERE n.status = 'failed' OR (n.last_error IS NOT NULL AND n.status = 'applied')
                UNION ALL
                SELECT 'relay', r.id, r.name, s.name, COALESCE(r.last_error, r.exit_error) FROM relays r JOIN servers s ON s.id = r.server_id
                 WHERE r.status = 'failed' OR r.exit_status = 'failed'
                LIMIT 20`),
    // the days of the month the nodes' counts start over on (本月 counts from there)
    db.prepare('SELECT DISTINCT reset_day FROM nodes'),
  ])
  return c.json({
    version: PANEL_VERSION,
    servers: servers.results, nodes: nodes.results, relays: relays.results,
    daily: today.results, problems: failing.results,
    reset_days: (resetDays.results as { reset_day: number }[]).map((r) => r.reset_day),
  })
})

app.all('/api/*', (c) => c.json(fail('not_found', 'no such endpoint'), 404))

export default {
  fetch: app.fetch,
  // the cron trigger (wrangler.jsonc): the daily housekeeping
  scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(ensureSchema(env.DB).then(() => housekeeping(env, true)).catch((e) => console.error('housekeeping', e)))
  },
} satisfies ExportedHandler<Env>
