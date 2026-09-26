// Subscription templates. What a client downloads is a template with the
// nodes filled in: the built-in ones give each client a basic rule-based setup
// (ads blocked, AI and streaming groups, China direct, the rest through PSM);
// users copy one and edit it, or write their own (系统 → 订阅模板).
//
// The nodes come as psm-agent exports them: a mihomo proxy for the protocols
// mihomo can dial (psm node export --format clash), a sing-box outbound, and
// the share link or Surge line. Surge, Quantumult X and Loon lines are written
// from the mihomo proxy; each client gets the protocols it supports and no
// others (a line it cannot parse would break its whole profile).

import type { SubNode } from './subscription'

export type TemplateFormat = 'clash' | 'stash' | 'singbox' | 'surge' | 'quanx' | 'loon'
export const TEMPLATE_FORMATS: TemplateFormat[] = ['clash', 'stash', 'singbox', 'surge', 'quanx', 'loon']
export const FORMAT_LABELS: Record<TemplateFormat, string> = {
  clash: 'Clash / mihomo', stash: 'Stash', singbox: 'sing-box', surge: 'Surge', quanx: 'Quantumult X', loon: 'Loon',
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Proxy = Record<string, any>

const str = (v: unknown) => (v === undefined || v === null ? '' : String(v))
const q = (v: unknown) => `"${str(v).replace(/"/g, '')}"`   // Loon quotes passwords; a quote cannot be escaped there
const insecure = (p: Proxy) => p['skip-cert-verify'] === true
// A self-signed node's certificate SHA-256 (PSM's export: fingerprint). Where a
// client can pin it, it is pinned and verified instead of trusted blindly.
const pin = (p: Proxy) => (typeof p.fingerprint === 'string' && /^[0-9a-f]{64}$/i.test(p.fingerprint) ? p.fingerprint.toLowerCase() : '')
const tlsName = (p: Proxy) => str(p.servername || p.sni || p.server)
const wsHost = (p: Proxy) => str(p['ws-opts']?.headers?.Host || tlsName(p))
const wsPath = (p: Proxy) => str(p['ws-opts']?.path || '/')
const isUpgrade = (p: Proxy) => p['ws-opts']?.['v2ray-http-upgrade'] === true
const shadowTls = (p: Proxy) => (p.plugin === 'shadow-tls' ? p['plugin-opts'] ?? {} : null)

// ── Surge ────────────────────────────────────────────────────────────────────
// manual.nssurge.com/policies: ss, vmess, trojan, hysteria2, tuic-v5, anytls,
// snell, socks5. No VLESS, no WireGuard server of ours.
export function surgeLine(name: string, p: Proxy): string | null {
  const tls = pin(p)
    ? `, sni=${tlsName(p)}, skip-cert-verify=false, server-cert-fingerprint-sha256=${pin(p)}`
    : `, sni=${tlsName(p)}, skip-cert-verify=${insecure(p)}`
  switch (p.type) {
    case 'ss': {
      const st = shadowTls(p)
      return `${name} = ss, ${p.server}, ${p.port}, encrypt-method=${p.cipher}, password=${p.password}, udp-relay=true`
        + (st ? `, shadow-tls-password=${str(st.password)}, shadow-tls-sni=${str(st.host)}, shadow-tls-version=3` : '')
    }
    case 'vmess':
      if (p.network !== 'ws' || isUpgrade(p)) return null
      return `${name} = vmess, ${p.server}, ${p.port}, username=${p.uuid}, ws=true, ws-path=${wsPath(p)}, ws-headers=Host:${wsHost(p)}, vmess-aead=true`
        + (p.tls ? `, tls=true${tls}` : '')
    case 'trojan':
      if (p.network && p.network !== 'tcp') return null
      return `${name} = trojan, ${p.server}, ${p.port}, password=${p.password}${tls}`
    case 'hysteria2':
      if (p.obfs || p.ports) return null   // Salamander and port hopping: not in Surge's documented parameters
      return `${name} = hysteria2, ${p.server}, ${p.port}, password=${p.password}${tls}`
    case 'tuic':
      return `${name} = tuic-v5, ${p.server}, ${p.port}, uuid=${p.uuid}, password=${p.password}, alpn=h3${tls}`
    case 'anytls':
      return `${name} = anytls, ${p.server}, ${p.port}, password=${p.password}${tls}`
    case 'socks5':
      return p.username ? `${name} = socks5, ${p.server}, ${p.port}, ${p.username}, ${p.password}` : `${name} = socks5, ${p.server}, ${p.port}`
    default:
      return null
  }
}

// ── Quantumult X ─────────────────────────────────────────────────────────────
// crossutility/Quantumult-X sample.conf: shadowsocks, vmess, vless, trojan,
// anytls, socks5. No Hysteria2, TUIC or Snell.
export function quanxLine(name: string, p: Proxy): string | null {
  const verify = pin(p) ? `tls-verification=true, tls-cert-sha256=${pin(p)}` : `tls-verification=${!insecure(p)}`
  const reality = (x: Proxy) => x['reality-opts']
    ? `, reality-base64-pubkey=${str(x['reality-opts']['public-key'])}, reality-hex-shortid=${str(x['reality-opts']['short-id'])}` : ''
  switch (p.type) {
    case 'ss':
      if (shadowTls(p)) return null
      return `shadowsocks=${p.server}:${p.port}, method=${p.cipher}, password=${p.password}, udp-relay=true, tag=${name}`
    case 'vmess':
      if (p.network !== 'ws' || isUpgrade(p)) return null
      return `vmess=${p.server}:${p.port}, method=chacha20-poly1305, password=${p.uuid}, obfs=${p.tls ? 'wss' : 'ws'}, obfs-host=${wsHost(p)}, obfs-uri=${wsPath(p)}`
        + (p.tls ? `, ${verify}` : '') + `, udp-relay=false, tag=${name}`
    case 'vless': {
      if (p.encryption && p.encryption !== 'none') return null   // VLESS Encryption: not in Quantumult X
      const net = p.network ?? 'tcp'
      const flow = p.flow ? `, vless-flow=${p.flow}` : ''
      if (net === 'tcp') return `vless=${p.server}:${p.port}, method=none, password=${p.uuid}, obfs=over-tls, obfs-host=${tlsName(p)}${reality(p)}${flow}, ${verify}, udp-relay=true, tag=${name}`
      if (net === 'ws' && !isUpgrade(p)) return `vless=${p.server}:${p.port}, method=none, password=${p.uuid}, obfs=wss, obfs-host=${wsHost(p)}, obfs-uri=${wsPath(p)}, ${verify}, udp-relay=true, tag=${name}`
      return null
    }
    case 'trojan':
      if (p.network && p.network !== 'tcp') return null
      return `trojan=${p.server}:${p.port}, password=${p.password}, over-tls=true, tls-host=${tlsName(p)}, ${verify}, udp-relay=true, tag=${name}`
    case 'anytls':
      return `anytls=${p.server}:${p.port}, password=${p.password}, over-tls=true, tls-host=${tlsName(p)}, ${verify}, udp-relay=true, tag=${name}`
    case 'socks5':
      return `socks5=${p.server}:${p.port}` + (p.username ? `, username=${p.username}, password=${p.password}` : '') + `, udp-relay=true, tag=${name}`
    default:
      return null
  }
}

// ── Loon ─────────────────────────────────────────────────────────────────────
// nsloon.app/docs/Node: Shadowsocks, vmess, VLESS, trojan, Hysteria2, AnyTLS,
// socks5. No TUIC or Snell.
export function loonLine(name: string, p: Proxy): string | null {
  const tls = pin(p)
    ? `,sni=${tlsName(p)},skip-cert-verify=false,tls-cert-sha256=${pin(p)}`
    : `,sni=${tlsName(p)},skip-cert-verify=${insecure(p)}`
  switch (p.type) {
    case 'ss': {
      const st = shadowTls(p)
      return `${name} = Shadowsocks,${p.server},${p.port},${p.cipher},${q(p.password)}`
        + (st ? `,shadow-tls-password=${q(st.password)},shadow-tls-sni=${str(st.host)},shadow-tls-version=3` : '') + ',udp=true'
    }
    case 'vmess':
      if (p.network !== 'ws' || isUpgrade(p)) return null
      return `${name} = vmess,${p.server},${p.port},auto,${q(p.uuid)},transport=ws,alterId=0,path=${wsPath(p)},host=${wsHost(p)},over-tls=${!!p.tls}`
        + (p.tls ? tls : '') + ',udp=true'
    case 'vless': {
      if (p.encryption && p.encryption !== 'none') return null
      const net = p.network ?? 'tcp'
      const r = p['reality-opts']
      const extra = (p.flow ? `,flow=${p.flow}` : '') + (r ? `,public-key=${q(r['public-key'])},short-id=${str(r['short-id'])}` : '')
      if (net === 'tcp') return `${name} = VLESS,${p.server},${p.port},${q(p.uuid)},transport=tcp${extra},over-tls=true${tls},udp=true`
      if (net === 'ws' && !isUpgrade(p)) return `${name} = VLESS,${p.server},${p.port},${q(p.uuid)},transport=ws,path=${wsPath(p)},host=${wsHost(p)},over-tls=true${tls},udp=true`
      return null
    }
    case 'trojan':
      if (p.network && p.network !== 'tcp') return null
      return `${name} = trojan,${p.server},${p.port},${q(p.password)}${tls},udp=true`
    case 'hysteria2':
      if (p.ports || (p.obfs && p.obfs !== 'salamander')) return null
      return `${name} = Hysteria2,${p.server},${p.port},${q(p.password)}${tls}` + (p.obfs ? `,salamander-password=${q(p['obfs-password'])}` : '') + ',udp=true'
    case 'anytls':
      return `${name} = AnyTLS,${p.server},${p.port},${q(p.password)}${tls},udp=true`
    case 'socks5':
      return p.username ? `${name} = socks5,${p.server},${p.port},${p.username},${q(p.password)},udp=true` : `${name} = socks5,${p.server},${p.port},udp=true`
    default:
      return null
  }
}

// Nodes exported without a mihomo proxy (the standalone ss-rust, or a node an
// older PSM exported, such as Xray's XHTTP ones): their share link is read
// instead, for the kinds that carry everything — ss:// and vless://.
function unb64url(s: string): string {
  const std = s.replace(/-/g, '+').replace(/_/g, '/')
  return new TextDecoder().decode(Uint8Array.from(atob(std + '='.repeat((4 - (std.length % 4)) % 4)), (c) => c.charCodeAt(0)))
}
export function linkProxy(link: string | null): Proxy | null {
  if (!link) return null
  try {
    const u = new URL(link)
    const server = u.hostname.replace(/^\[|\]$/g, ''), port = Number(u.port)
    if (!server || !port) return null
    if (u.protocol === 'ss:') {
      const info = decodeURIComponent(u.username)
      const dec = info.includes(':') ? info : unb64url(info)
      const i = dec.indexOf(':')
      if (i < 1 || u.searchParams.get('plugin')) return null
      return { type: 'ss', server, port, cipher: dec.slice(0, i), password: dec.slice(i + 1), udp: true }
    }
    if (u.protocol === 'vless:') {
      const q = u.searchParams
      const enc = q.get('encryption')
      const net = q.get('type') ?? 'tcp'
      const base: Proxy = {
        type: 'vless', server, port, uuid: decodeURIComponent(u.username), udp: true, tls: true,
        servername: q.get('sni') ?? '', 'client-fingerprint': q.get('fp') || 'chrome',
        ...(q.get('flow') ? { flow: q.get('flow') } : {}), ...(enc && enc !== 'none' ? { encryption: enc } : {}),
      }
      const path = q.get('path') || '/', svc = q.get('serviceName') ?? ''
      if (q.get('security') === 'reality') {
        const r = { 'reality-opts': { 'public-key': q.get('pbk') ?? '', 'short-id': q.get('sid') ?? '' } }
        if (net === 'tcp') return { ...base, ...r, network: 'tcp' }
        if (net === 'grpc') return { ...base, ...r, network: 'grpc', 'grpc-opts': { 'grpc-service-name': svc } }
        if (net === 'xhttp') return { ...base, ...r, network: 'xhttp', 'xhttp-opts': { path, mode: q.get('mode') || 'auto' } }
        return null
      }
      if (q.get('security') !== 'tls') return null
      const host = q.get('host') || q.get('sni') || server
      // a self-signed certificate: skipped as the link says, and pinned (pcs)
      const cert: Proxy = {
        ...(['1', 'true'].includes(q.get('allowInsecure') ?? q.get('insecure') ?? '') ? { 'skip-cert-verify': true } : {}),
        ...(/^[0-9a-f]{64}$/i.test(q.get('pcs') ?? '') ? { fingerprint: q.get('pcs')!.toLowerCase() } : {}),
      }
      // HTTPUpgrade: mihomo reads "type=httpupgrade" as a network its VLESS
      // client does not have, so such a link never upgrades. It is mihomo's
      // ws with v2ray-http-upgrade instead (PSM's own mihomo export agrees).
      if (net === 'httpupgrade') return { ...base, ...cert, network: 'ws', 'ws-opts': { path, headers: { Host: host }, 'v2ray-http-upgrade': true } }
      if (net === 'ws') return { ...base, ...cert, network: 'ws', 'ws-opts': { path, headers: { Host: host } } }
      if (net === 'grpc') return { ...base, ...cert, network: 'grpc', 'grpc-opts': { 'grpc-service-name': svc } }
      if (net === 'xhttp') return {
        ...base, ...cert, network: 'xhttp', ...(q.get('alpn') ? { alpn: q.get('alpn')!.split(',') } : {}),
        'xhttp-opts': { path, host, mode: q.get('mode') || 'auto' },
      }
      if (net === 'tcp') return { ...base, ...cert, network: 'tcp' }
      return null
    }
  } catch {
    return null
  }
  return null
}

// Stash: Clash's format; no AnyTLS, no XHTTP. It pins a certificate with
// server-cert-fingerprint (stash.wiki: skip-cert-verify is not needed then).
const stashOk = (p: Proxy) => p.type !== 'anytls' && p.network !== 'xhttp'
function stashProxy(p: Proxy): Proxy {
  if (!pin(p)) return p
  const out: Proxy = { ...p, 'skip-cert-verify': false, 'server-cert-fingerprint': pin(p) }
  delete out.fingerprint
  return out
}

// ── rendering ────────────────────────────────────────────────────────────────
export type RenderInput = {
  name: string          // the subscription's name
  selfUrl: string       // this subscription's URL (without ?format)
  nodes: SubNode[]
  displayName: (n: SubNode) => string
  surgeLineOf: (n: SubNode) => string | null   // a node's own Surge line (Snell, SS2022), else null
}

type Entry = { name: string; line: string }

function entries(format: TemplateFormat, r: RenderInput): Entry[] {
  const out: Entry[] = []
  for (const n of r.nodes) {
    const name = r.displayName(n)
    const own = n.clash && typeof n.clash === 'object' ? n.clash : linkProxy(n.link)
    const p = own ? { ...own, name } : null
    let line: string | null = null
    switch (format) {
      case 'clash': line = p ? `- ${JSON.stringify(p)}` : null; break
      case 'stash': line = p && stashOk(p) ? `- ${JSON.stringify(stashProxy(p))}` : null; break
      case 'singbox': line = n.outbound ? JSON.stringify({ ...n.outbound, tag: name }) : null; break
      case 'surge': line = (p && surgeLine(name, p)) || r.surgeLineOf(n); break
      case 'quanx': line = p ? quanxLine(name, p) : null; break
      case 'loon': line = p ? loonLine(name, p) : null; break
    }
    if (line) out.push({ name, line })
  }
  return out
}

/**
 * Fills a template in. Placeholders:
 * - {{proxies}}   on a line of its own: the node definitions, one per line,
 *                 indented like the placeholder (sing-box: outbound objects,
 *                 each followed by a comma)
 * - {{names}}     the node names, each followed by ", " (YAML / JSON: quoted),
 *                 to put in a group before its fixed members
 * - {{names_list}} the same names, joined by ", " with nothing after the last
 *                 (for a group of the nodes alone, such as url-test)
 * - {{provider_url}}, {{provider_exclude}} (Clash): this subscription's nodes
 *                 as mihomo proxies (format=provider), and a filter leaving out
 *                 the nodes written out above
 * - {{sub_url}}   this subscription in this format; {{name}} its name
 */
export function renderTemplate(format: TemplateFormat, body: string, r: RenderInput): string {
  const list = entries(format, r)
  const quoted = format === 'clash' || format === 'stash' || format === 'singbox'
  const each = list.map((e) => (quoted ? JSON.stringify(e.name) : e.name))
  const names = each.map((n) => n + ', ').join('')
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const exclude = list.length ? `^(${list.map((e) => esc(e.name)).join('|')})$` : '^$'
  const join = r.selfUrl.includes('?') ? '&' : '?'
  // every replacement is a function: in a replacement string "$'" means
  // "everything after the match", and the exclude filter ends in exactly that
  // ( …)$' ), which silently cut the line short and broke the whole profile
  return body
    .replace(/^([ \t]*)\{\{proxies\}\}[ \t]*$/gm, (_m, indent: string) =>
      list.map((e) => indent + e.line + (format === 'singbox' ? ',' : '')).join('\n'))
    .replace(/\{\{names_list\}\}/g, () => each.join(', '))
    .replace(/\{\{names\}\}/g, () => names)
    .replace(/\{\{provider_url\}\}/g, () => JSON.stringify(`${r.selfUrl}${join}format=provider`))
    .replace(/\{\{provider_exclude\}\}/g, () => `'${exclude.replace(/'/g, "''")}'`)
    .replace(/\{\{sub_url\}\}/g, () => `${r.selfUrl}${join}format=${format}`)
    .replace(/\{\{name\}\}/g, () => r.name.replace(/[\r\n]/g, ' '))
}

// ── the built-in templates ───────────────────────────────────────────────────
const BM = 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule'

const CLASH = `# PSM Panel subscription for mihomo / Clash Meta ({{name}})
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info

# the nodes come from the provider alone, so a node added or removed in the
# panel reaches this profile by itself, within the hour
proxy-providers:
  psm:
    type: http
    url: {{provider_url}}
    interval: 3600
    path: ./psm-panel.yaml
    health-check:
      enable: true
      url: http://www.gstatic.com/generate_204
      interval: 300

proxy-groups:
  - name: PSM
    type: select
    proxies: [自动选择, DIRECT]
    use: [psm]
  - name: 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    use: [psm]
  - name: AI
    type: select
    proxies: [PSM, DIRECT]
    use: [psm]
  - name: 流媒体
    type: select
    proxies: [PSM, DIRECT]
    use: [psm]

rules:
  - GEOSITE,category-ads-all,REJECT
  - GEOSITE,openai,AI
  - GEOSITE,anthropic,AI
  - GEOSITE,google-gemini,AI
  - GEOSITE,netflix,流媒体
  - GEOSITE,disney,流媒体
  - GEOSITE,youtube,流媒体
  - GEOSITE,private,DIRECT
  - GEOSITE,cn,DIRECT
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,PSM
`

const STASH = `# PSM Panel subscription for Stash ({{name}})
mixed-port: 7890
mode: rule
log-level: info

proxies:
  {{proxies}}

proxy-groups:
  - name: PSM
    type: select
    proxies: [自动选择, {{names}}DIRECT]
  - name: 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies: [{{names_list}}]
  - name: AI
    type: select
    proxies: [PSM, {{names}}DIRECT]
  - name: 流媒体
    type: select
    proxies: [PSM, {{names}}DIRECT]

rule-providers:
  ads: {type: http, behavior: classical, format: yaml, interval: 86400, url: "${BM}/Clash/Advertising/Advertising.yaml"}
  openai: {type: http, behavior: classical, format: yaml, interval: 86400, url: "${BM}/Clash/OpenAI/OpenAI.yaml"}
  claude: {type: http, behavior: classical, format: yaml, interval: 86400, url: "${BM}/Clash/Claude/Claude.yaml"}
  gemini: {type: http, behavior: classical, format: yaml, interval: 86400, url: "${BM}/Clash/Gemini/Gemini.yaml"}
  netflix: {type: http, behavior: classical, format: yaml, interval: 86400, url: "${BM}/Clash/Netflix/Netflix.yaml"}
  disney: {type: http, behavior: classical, format: yaml, interval: 86400, url: "${BM}/Clash/Disney/Disney.yaml"}
  youtube: {type: http, behavior: classical, format: yaml, interval: 86400, url: "${BM}/Clash/YouTube/YouTube.yaml"}
  china: {type: http, behavior: classical, format: yaml, interval: 86400, url: "${BM}/Clash/China/China.yaml"}

rules:
  - RULE-SET,ads,REJECT
  - RULE-SET,openai,AI
  - RULE-SET,claude,AI
  - RULE-SET,gemini,AI
  - RULE-SET,netflix,流媒体
  - RULE-SET,disney,流媒体
  - RULE-SET,youtube,流媒体
  - RULE-SET,china,DIRECT
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,PSM
`

const SINGBOX = `{
  "log": { "level": "info" },
  "dns": {
    "servers": [
      { "type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "PSM" },
      { "type": "udp", "tag": "local", "server": "223.5.5.5" }
    ],
    "rules": [ { "rule_set": ["geosite-cn"], "server": "local" } ],
    "final": "remote"
  },
  "inbounds": [ { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890 } ],
  "outbounds": [
    { "type": "selector", "tag": "PSM", "outbounds": ["自动选择", {{names}}"direct"] },
    { "type": "urltest", "tag": "自动选择", "outbounds": [{{names_list}}], "url": "https://www.gstatic.com/generate_204", "interval": "5m" },
    { "type": "selector", "tag": "AI", "outbounds": ["PSM", {{names}}"direct"] },
    { "type": "selector", "tag": "流媒体", "outbounds": ["PSM", {{names}}"direct"] },
    {{proxies}}
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "action": "sniff" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "rule_set": ["geosite-category-ads-all"], "action": "reject" },
      { "rule_set": ["geosite-openai", "geosite-anthropic", "geosite-google-gemini"], "outbound": "AI" },
      { "rule_set": ["geosite-netflix", "geosite-disney", "geosite-youtube"], "outbound": "流媒体" },
      { "ip_is_private": true, "outbound": "direct" },
      { "rule_set": ["geosite-cn", "geoip-cn"], "outbound": "direct" }
    ],
    "rule_set": [
${['category-ads-all', 'openai', 'anthropic', 'google-gemini', 'netflix', 'disney', 'youtube', 'cn'].map((s) =>
  `      { "type": "remote", "tag": "geosite-${s}", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-${s}.srs", "http_client": { "detour": "PSM" } }`).join(',\n')},
      { "type": "remote", "tag": "geoip-cn", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs", "http_client": { "detour": "PSM" } }
    ],
    "final": "PSM",
    "default_domain_resolver": "local",
    "auto_detect_interface": true
  },
  "experimental": { "cache_file": { "enabled": true } }
}
`

const SURGE = `#!MANAGED-CONFIG {{sub_url}} interval=43200 strict=false
# PSM Panel subscription for Surge ({{name}})

[General]
loglevel = notify
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local
dns-server = system, 223.5.5.5, 1.1.1.1

[Proxy]
{{proxies}}

[Proxy Group]
PSM = select, 自动选择, {{names}}DIRECT
自动选择 = url-test, {{names_list}}, url=http://www.gstatic.com/generate_204, interval=300
AI = select, PSM, {{names}}DIRECT
流媒体 = select, PSM, {{names}}DIRECT

[Rule]
RULE-SET,${BM}/Surge/Advertising/Advertising.list,REJECT
RULE-SET,${BM}/Surge/OpenAI/OpenAI.list,AI
RULE-SET,${BM}/Surge/Claude/Claude.list,AI
RULE-SET,${BM}/Surge/Gemini/Gemini.list,AI
RULE-SET,${BM}/Surge/Netflix/Netflix.list,流媒体
RULE-SET,${BM}/Surge/Disney/Disney.list,流媒体
RULE-SET,${BM}/Surge/YouTube/YouTube.list,流媒体
RULE-SET,${BM}/Surge/China/China.list,DIRECT
GEOIP,CN,DIRECT
FINAL,PSM,dns-failed
`

const QUANX = `# PSM Panel subscription for Quantumult X ({{name}})
[general]
server_check_url = http://www.gstatic.com/generate_204

[dns]
server = 223.5.5.5
server = 119.29.29.29

[policy]
static = PSM, 自动选择, {{names}}direct
url-latency-benchmark = 自动选择, server-tag-regex=.*, check-interval=300, tolerance=50
static = AI, PSM, {{names}}direct
static = 流媒体, PSM, {{names}}direct

[server_local]
{{proxies}}

[filter_remote]
${BM}/QuantumultX/Advertising/Advertising.list, tag=广告, force-policy=reject, enabled=true
${BM}/QuantumultX/OpenAI/OpenAI.list, tag=OpenAI, force-policy=AI, enabled=true
${BM}/QuantumultX/Claude/Claude.list, tag=Claude, force-policy=AI, enabled=true
${BM}/QuantumultX/Gemini/Gemini.list, tag=Gemini, force-policy=AI, enabled=true
${BM}/QuantumultX/Netflix/Netflix.list, tag=Netflix, force-policy=流媒体, enabled=true
${BM}/QuantumultX/Disney/Disney.list, tag=Disney, force-policy=流媒体, enabled=true
${BM}/QuantumultX/YouTube/YouTube.list, tag=YouTube, force-policy=流媒体, enabled=true
${BM}/QuantumultX/China/China.list, tag=国内, force-policy=direct, enabled=true

[filter_local]
ip-cidr, 10.0.0.0/8, direct
ip-cidr, 172.16.0.0/12, direct
ip-cidr, 192.168.0.0/16, direct
ip-cidr, 127.0.0.0/8, direct
geoip, cn, direct
final, PSM
`

const LOON = `# PSM Panel subscription for Loon ({{name}})
[General]
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local
dns-server = system, 223.5.5.5

[Proxy]
{{proxies}}

[Proxy Group]
PSM = select, 自动选择, {{names}}DIRECT
自动选择 = url-test, {{names_list}}, url=http://www.gstatic.com/generate_204, interval=300
AI = select, PSM, {{names}}DIRECT
流媒体 = select, PSM, {{names}}DIRECT

[Remote Rule]
${BM}/Loon/Advertising/Advertising.list, policy=REJECT, tag=广告, enabled=true
${BM}/Loon/OpenAI/OpenAI.list, policy=AI, tag=OpenAI, enabled=true
${BM}/Loon/Claude/Claude.list, policy=AI, tag=Claude, enabled=true
${BM}/Loon/Gemini/Gemini.list, policy=AI, tag=Gemini, enabled=true
${BM}/Loon/Netflix/Netflix.list, policy=流媒体, tag=Netflix, enabled=true
${BM}/Loon/Disney/Disney.list, policy=流媒体, tag=Disney, enabled=true
${BM}/Loon/YouTube/YouTube.list, policy=流媒体, tag=YouTube, enabled=true
${BM}/Loon/China/China.list, policy=DIRECT, tag=国内, enabled=true

[Rule]
GEOIP,CN,DIRECT
FINAL,PSM
`

export const BUILTIN_TEMPLATES: Record<TemplateFormat, { name: string; body: string }> = {
  clash: { name: '内置 · Clash / mihomo 基础分流', body: CLASH },
  stash: { name: '内置 · Stash 基础分流', body: STASH },
  singbox: { name: '内置 · sing-box 基础分流', body: SINGBOX },
  surge: { name: '内置 · Surge 基础分流', body: SURGE },
  quanx: { name: '内置 · Quantumult X 基础分流', body: QUANX },
  loon: { name: '内置 · Loon 基础分流', body: LOON },
}

/** Every rule-list URL the built-in templates use (checked by the tests). */
export const BUILTIN_URLS: string[] = [...new Set(Object.values(BUILTIN_TEMPLATES)
  .flatMap((t) => [...t.body.matchAll(/https:\/\/raw\.githubusercontent\.com\/[^\s",]+/g)].map((m) => m[0])))]
