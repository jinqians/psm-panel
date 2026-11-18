// Calls the panel's own API (/api/*), same origin, and the types it answers with.
import type { RelayEngine, RelayMode } from '@shared/relays'

export class ApiError extends Error {
  constructor(message: string, public errors: string[] = [], public status = 0) {
    super(message)
  }
}

export async function api<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const r = await fetch(path, {
    ...init,
    headers: { 'content-type': 'application/json', ...(init.headers as Record<string, string> | undefined) },
  })
  if (r.status === 204) return undefined as T
  // the session ended (expired, signed out elsewhere, the password changed): back to the sign-in page
  if (r.status === 401 && path !== '/api/login') window.dispatchEvent(new Event('psm:signed-out'))
  const body = await r.json().catch(() => ({}))
  if (!r.ok) throw new ApiError(body?.error?.message ?? `HTTP ${r.status}`, body?.error?.errors ?? [], r.status)
  return body as T
}

/** The message to show for a failed call: the list of problems, or the one message. */
export const errorText = (e: unknown) =>
  e instanceof ApiError && e.errors.length ? e.errors.join('；') : e instanceof Error ? e.message : String(e)

export type ServerStatus = 'pending' | 'online' | 'offline' | 'leaving'
export type Server = {
  id: number; name: string; status: ServerStatus
  hostname: string | null; agent_version: string | null; psm_version: string | null; leave_error: string | null
  /** the psm-agent release the panel expects; a server reporting another can be upgraded */
  agent_latest?: string
  note: string; last_seen: string | null; created_at: string; status_at: string | null
  node_count: number; relay_count: number; traffic_used: number
  /** where a relay's port is picked when none is typed in (both null: 20000-60000) */
  relay_port_min: number | null; relay_port_max: number | null
  /** where the agent last synced from, and that network (Cloudflare's view) */
  last_ip: string | null; asn: number | null; country: string | null
}

export type NodeStatus = 'waiting' | 'queued' | 'applied' | 'failed' | 'deleting'

/** A node as the list has it (no settings: GET /api/nodes/:id has those). */
export type PanelNode = {
  id: number; server_id: number; protocol: string; variant: string; engine: string; psm_protocol: string
  name: string; address: string; port: number; public_port: number | null; traffic_limit_gb: number
  labels: string[]; status: NodeStatus
  last_error: string | null; created_at: string; has_link: boolean
  /** shares the public 443 by SNI; fixed when the node is created */
  mount_443: boolean
  /** the name in clients; '' = the server's flag and "<server>-<name>" */
  display_name: string
  traffic_used: number; traffic_paused: boolean; traffic_at: string | null; reset_day: number
  params?: Record<string, unknown>
}

export type RelayStatus = NodeStatus | 'pending' | 'deleted'
export type RelayTarget = { host: string; port: number; server_id: number | null }
export type TargetHealth = { host: string; port: number | null; rtt_ms: number | null; loss_pct: number | null }

/**
 * A relay: a forward (one rule on the entry server, realm or gost) or a
 * tunnel (the entry's rule, carrying clients to the exit server over gost's
 * relay protocol, and the exit's, forwarding to the landing hosts).
 */
export type Relay = {
  id: number; server_id: number; name: string; listen_port: number; auto_port: boolean
  mode: RelayMode; engine: RelayEngine
  targets: RelayTarget[]; strategy: string; probe: boolean; udp: boolean
  remote_host: string; remote_port: number; remote_server_id: number | null
  tls: boolean; tls_sni: string; tls_insecure: boolean
  exit_server_id: number | null; exit_host: string; exit_port: number | null; exit_auto_port: boolean
  transport: string; ws_host: string; ws_path: string; exit_pinned: boolean
  status: RelayStatus; last_error: string | null; exit_status: RelayStatus | ''; exit_error: string | null
  pending_entry: string; created_at: string
  speed_mbps: number; limit_gb: number; reset_day: number; expires_at: string | null
  quota_used: number | null; paused: '' | 'quota' | 'expired'
  /** the newest measurement of the hop; null until the first one arrives */
  last_rtt_ms: number | null; last_jitter_ms: number | null; last_loss_pct: number | null
  last_sample_at: string | null; traffic_bytes: number
  exit_rtt_ms: number | null; exit_loss_pct: number | null
  target_health: TargetHealth[] | null
  /** the node of the panel it lands on (its parent), published through it when in_sub */
  node_id: number | null; in_sub: boolean
  /** the address clients reach the entry at; '' is the entry server's last_ip */
  entry_host: string
}

/** One point of a relay's chart; `bytes` is that interval's traffic. */
export type RelaySample = {
  at: string; rtt_ms: number | null; jitter_ms: number | null; loss_pct: number; bytes: number
}

export type Subscription = {
  id: number; name: string; labels: string[]; url: string; last_used: string | null; created_at: string
  /** format → one of the user's templates (absent: the built-in one) */
  templates: Record<string, number>
}

export type Template = { id: number; name: string; format: string; body: string; created_at: string; updated_at: string | null }
export type Templates = {
  formats: Record<string, string>
  builtin: { format: string; name: string; body: string }[]
  custom: Template[]
}

export type AuditEntry = { id: number; at: string; actor: string; action: string; target: string; detail: string }

export const GB = 1024 ** 3

/** 1536 → "1.5 KB" */
export function formatBytes(n: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let v = Math.max(0, n || 0), i = 0
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${i ? v.toFixed(v < 10 ? 2 : 1) : v} ${units[i]}`
}

/**
 * The UTC day this month's counts started on ("2026-10-01"), when every node
 * resets on the same day of the month; null when they differ or there are no
 * nodes. (Each server resets at midnight in its own time zone, so the day can
 * be a few hours off.) The days before it in a chart are last month's.
 */
export function cycleStart(resetDays: number[], now = new Date()): string | null {
  const days = [...new Set(resetDays)]
  if (days.length !== 1) return null
  const y = now.getUTCFullYear(), m = now.getUTCMonth()
  return new Date(Date.UTC(y, now.getUTCDate() >= days[0] ? m : m - 1, days[0])).toISOString().slice(0, 10)
}

/** D1's "2026-09-15 08:00:00" (UTC) or an ISO time → a Date */
export function parseTime(t: string | null | undefined): Date | null {
  if (!t) return null
  const d = new Date(/[TZ]/.test(t) ? t : t.replace(' ', 'T') + 'Z')
  return Number.isNaN(d.getTime()) ? null : d
}

/** → local time */
export function localTime(t: string | null | undefined): string {
  const d = parseTime(t)
  return d ? d.toLocaleString('zh-CN', { hour12: false }) : t ? String(t) : '—'
}

/** → "3 分钟前", "2 天后" */
export function ago(t: string | null | undefined): string {
  const d = parseTime(t)
  if (!d) return '—'
  const s = Math.round((Date.now() - d.getTime()) / 1000)
  const a = Math.abs(s), suffix = s >= 0 ? '前' : '后'
  if (a < 45) return s >= 0 ? '刚刚' : '马上'
  if (a < 3600) return `${Math.round(a / 60)} 分钟${suffix}`
  if (a < 86400) return `${Math.round(a / 3600)} 小时${suffix}`
  return `${Math.round(a / 86400)} 天${suffix}`
}

export const NODE_STATUS: Record<string, string> = {
  waiting: '待安装', queued: '下发中', applied: '运行中', failed: '失败', deleting: '删除中', pending: '等待出口', deleted: '已删除',
}
