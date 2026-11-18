// A node published through a relay (the relay's parent node): the same
// settings, but clients dial the relay's entry address and port, which carry
// them to the node unchanged. Everything else stays as the node exported it.
//
// What a client sent the node's own address for has to be kept, now that it
// dials another one: a node whose TLS name or WebSocket Host was left to
// default to its address gets that address written in, or the handshake
// would carry the entry's. Port hopping (Hysteria2) goes: a relay forwards
// one port.

import type { SubNode } from './subscription'

export type Via = { host: string; port: number }

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Obj = Record<string, any>

/** a name, not an IP address: what a certificate and a Host header carry */
const isDomain = (h: string) => /[a-z]/i.test(h) && !h.includes(':')
/** an address as it goes after "host" in a URL or "host:port" */
const hostPort = (host: string, port: number) => `${host.includes(':') ? `[${host}]` : host}:${port}`

function b64(s: string): string {
  let bin = ''
  for (const byte of new TextEncoder().encode(s)) bin += String.fromCharCode(byte)
  return btoa(bin)
}
function unb64(s: string): string {
  const std = s.replace(/-/g, '+').replace(/_/g, '/')
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4)
  return new TextDecoder().decode(Uint8Array.from(atob(padded), (ch) => ch.charCodeAt(0)))
}

/** vmess://: base64 of v2rayN's JSON (add, port, host, sni …) */
function vmessVia(link: string, via: Via): string | null {
  try {
    const j = JSON.parse(unb64(link.slice('vmess://'.length))) as Obj
    const orig = String(j.add ?? '')
    if (isDomain(orig)) {
      if (!j.sni && j.tls === 'tls') j.sni = orig
      if (!j.host) j.host = orig
    }
    j.add = via.host
    j.port = String(via.port)
    return 'vmess://' + b64(JSON.stringify(j))
  } catch {
    return null
  }
}

// the schemes whose TLS name is ?sni= (vless and trojan: when security=tls)
const SNI_SCHEMES = new Set(['vless', 'trojan', 'hysteria2', 'hy2', 'tuic', 'anytls'])

/**
 * scheme://[userinfo@]host:port[,hop ports][/][?query][#name]. The query is
 * kept as written (re-encoding it could change what a client reads); a
 * parameter is only added, or the hop ports dropped.
 */
function uriVia(link: string, via: Via): string | null {
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/i.exec(link)
  if (!m) return null
  const [, scheme, authority, path, rawQuery = '', frag = ''] = m
  const at = authority.lastIndexOf('@')
  const userinfo = at >= 0 ? authority.slice(0, at + 1) : ''
  const hp = authority.slice(at + 1)
  // [v6]:port or host:port, with Hysteria2's ",20000-30000" after the port
  const h = /^\[([^\]]+)\]:(\d+)(?:,[\d,:-]+)?$/.exec(hp) ?? /^([^:]+):(\d+)(?:,[\d,:-]+)?$/.exec(hp)
  if (!h) return null
  const orig = h[1]
  let query = rawQuery.replace(/^\?/, '').split('&').filter((kv) => kv && !/^mport=/i.test(kv)).join('&')
  const q = new URLSearchParams(query)
  const add = (k: string, v: string) => { query += `${query ? '&' : ''}${k}=${encodeURIComponent(v)}` }
  const s = scheme.toLowerCase()
  if (isDomain(orig) && SNI_SCHEMES.has(s)) {
    const security = q.get('security')
    const tls = (s !== 'vless' && s !== 'trojan') || security === 'tls' || (s === 'trojan' && !security)
    if (tls && !q.get('sni') && !q.get('peer')) add('sni', orig)
    const type = q.get('type') ?? ''
    if (s === 'vless' && ['ws', 'httpupgrade', 'h2', 'http', 'xhttp'].includes(type) && !q.get('host')) add('host', orig)
  }
  return `${scheme}://${userinfo}${hostPort(via.host, via.port)}${path}${query ? `?${query}` : ''}${frag}`
}

/** A Surge line (standalone Snell and SS2022): "name = type, server, port, …" */
function surgeVia(line: string, via: Via): string | null {
  const m = /^(.*? = [a-z0-9-]+, )([^,]+), (\d+)(.*)$/is.exec(line)
  return m ? `${m[1]}${via.host}, ${via.port}${m[4]}` : null
}

/** A WireGuard node's wg-quick file(s): each "Endpoint = host:port" */
function wgVia(conf: string, via: Via): string | null {
  return /^Endpoint\s*=/m.test(conf) ? conf.replace(/^(Endpoint\s*=\s*).*$/gm, `$1${hostPort(via.host, via.port)}`) : null
}

/** The node's share link (or Surge line, or wg-quick file) through the relay. */
export function linkVia(link: string, via: Via): string | null {
  const t = link.trim()
  if (t.startsWith('vmess://')) return vmessVia(t, via)
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return uriVia(t, via)
  if (/^\[Interface\]/m.test(t)) return wgVia(t, via)
  if (/ = [a-z0-9-]+, /i.test(t)) return surgeVia(t, via)
  return null
}

/** A mihomo proxy through the relay. */
export function clashVia(p: Obj, via: Via): Obj {
  const out: Obj = structuredClone(p)
  const orig = String(p.server ?? '')
  out.server = via.host
  out.port = via.port
  delete out.ports   // Hysteria2's port hopping
  if (isDomain(orig) && !p['reality-opts']) {
    const key = p.type === 'vless' || p.type === 'vmess' ? 'servername' : 'sni'
    const tls = ['trojan', 'hysteria2', 'tuic', 'anytls'].includes(p.type) || ((p.type === 'vless' || p.type === 'vmess') && p.tls)
    if (tls && !p.sni && !p.servername) out[key] = orig
    const name = String(out[key] || orig)
    if (out['ws-opts'] && !out['ws-opts'].headers?.Host) out['ws-opts'].headers = { ...(out['ws-opts'].headers ?? {}), Host: name }
    if (out['h2-opts'] && !out['h2-opts'].host?.length) out['h2-opts'].host = [name]
    if (out['xhttp-opts'] && !out['xhttp-opts'].host) out['xhttp-opts'].host = name
  }
  return out
}

/** A sing-box outbound through the relay. */
export function singboxVia(o: Obj, via: Via): Obj {
  const out: Obj = structuredClone(o)
  const orig = String(o.server ?? '')
  out.server = via.host
  out.server_port = via.port
  delete out.server_ports   // Hysteria2's port hopping
  delete out.hop_interval
  if (isDomain(orig) && !o.tls?.reality?.enabled) {
    if (out.tls?.enabled && !out.tls.server_name) out.tls.server_name = orig
    const name = String(out.tls?.server_name || orig)
    const tr = out.transport
    if (tr?.type === 'ws' && !tr.headers?.Host) tr.headers = { ...(tr.headers ?? {}), Host: name }
    if (tr?.type === 'httpupgrade' && !tr.host) tr.host = name
    if (tr?.type === 'http' && !tr.host?.length) tr.host = [name]
  }
  return out
}

/** The whole node through the relay, named for the subscription (the entry server's flag, server-name). */
export function nodeVia(n: SubNode, via: Via, server: string, name: string, country?: string | null): SubNode {
  return {
    server, name, country,
    link: n.link ? linkVia(n.link, via) : null,
    outbound: n.outbound ? singboxVia(n.outbound, via) : null,
    clash: n.clash && typeof n.clash === 'object' ? clashVia(n.clash, via) : null,
  }
}
