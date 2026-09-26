// Subscriptions: the running nodes of every server behind one URL, in the
// format the client wants — a base64 list of share links (v2rayN, Shadowrocket,
// Hiddify …), or a whole client profile made from a template: Clash / mihomo,
// Stash, sing-box, Surge, Quantumult X or Loon (templates.ts). Node names
// become "<server>-<node>" so nodes of the same name on different servers
// stay apart.

import { BUILTIN_TEMPLATES, linkProxy, renderTemplate, TEMPLATE_FORMATS, type TemplateFormat } from './templates'

export type SubNode = {
  server: string
  name: string
  link: string | null
  outbound: Record<string, unknown> | null
  /** the node as a ready mihomo proxy (psm node export --format clash) */
  clash?: Record<string, unknown> | null
}

/**
 * provider: the nodes as mihomo proxies (YAML), for a Clash profile's
 * proxy-provider ({{provider_url}}). Share links would lose what mihomo's link
 * importer does not read — a self-signed VMess or TUIC node's certificate, an
 * HTTPUpgrade transport — so the provider serves PSM's own mihomo proxies.
 */
export type Format = 'uri' | 'provider' | TemplateFormat
export const FORMATS: Format[] = ['uri', 'provider', ...TEMPLATE_FORMATS]

/** ?format= first, then the client's User-Agent; share links by default. */
export function pickFormat(query: string | null | undefined, userAgent: string): Format {
  if (query && (FORMATS as string[]).includes(query)) return query as Format
  if (/sing-box|\bSF[AIMT]\//i.test(userAgent)) return 'singbox'
  if (/stash/i.test(userAgent)) return 'stash'
  if (/clash|mihomo|verge|nyanpasu/i.test(userAgent)) return 'clash'
  if (/surge/i.test(userAgent)) return 'surge'
  if (/quantumult/i.test(userAgent)) return 'quanx'
  if (/loon/i.test(userAgent)) return 'loon'
  return 'uri'
}

export const displayName = (n: SubNode) => `${n.server}-${n.name}`

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

const isShareLink = (link: string) => /^[a-z][a-z0-9+.-]*:\/\//i.test(link)
const isSurgeLine = (link: string) => / = [a-z0-9-]+, /i.test(link) && !isShareLink(link)

/** A share link with its display name set (vmess carries it inside its JSON). */
export function renameLink(link: string, name: string): string {
  if (link.startsWith('vmess://')) {
    try {
      const j = JSON.parse(unb64(link.slice('vmess://'.length)))
      j.ps = name
      return 'vmess://' + b64(JSON.stringify(j))
    } catch {
      return link
    }
  }
  const hash = link.indexOf('#')
  return (hash < 0 ? link : link.slice(0, hash)) + '#' + encodeURIComponent(name)
}

function uriList(nodes: SubNode[]): string[] {
  return nodes.filter((n) => n.link && isShareLink(n.link)).map((n) => renameLink(n.link!, displayName(n)))
}

/** A node's own Surge line (standalone Snell and SS2022 export one), renamed. */
const surgeLineOf = (n: SubNode) =>
  n.link && isSurgeLine(n.link) ? `${displayName(n)} = ${n.link.slice(n.link.indexOf(' = ') + 3)}` : null

const CONTENT: Record<TemplateFormat, { type: string; ext: string }> = {
  clash: { type: 'text/yaml; charset=utf-8', ext: 'yaml' },
  stash: { type: 'text/yaml; charset=utf-8', ext: 'yaml' },
  singbox: { type: 'application/json; charset=utf-8', ext: 'json' },
  surge: { type: 'text/plain; charset=utf-8', ext: 'conf' },
  quanx: { type: 'text/plain; charset=utf-8', ext: 'conf' },
  loon: { type: 'text/plain; charset=utf-8', ext: 'conf' },
}

/**
 * The provider body: every node that has a mihomo proxy (PSM's export, or one
 * read from its share link), as YAML flow mappings — JSON is valid YAML.
 */
export function providerYaml(nodes: SubNode[]): string {
  const lines: string[] = []
  for (const n of nodes) {
    const p = n.clash && typeof n.clash === 'object' ? n.clash : linkProxy(n.link)
    if (p) lines.push(`  - ${JSON.stringify({ ...p, name: displayName(n) })}`)
  }
  return `proxies:\n${lines.join('\n')}\n`
}

/**
 * The subscription body and its content type. selfUrl: this subscription's
 * URL; template: the body of the subscription's own template for this format
 * (the built-in one when absent).
 */
export function buildSubscription(format: Format, nodes: SubNode[], selfUrl: string,
  opts: { name?: string; template?: string | null } = {}): { body: string; type: string; ext: string } {
  if (format === 'uri') return { body: b64(uriList(nodes).join('\n')), type: 'text/plain; charset=utf-8', ext: 'txt' }
  if (format === 'provider') return { body: providerYaml(nodes), type: 'text/yaml; charset=utf-8', ext: 'yaml' }
  const body = renderTemplate(format, opts.template ?? BUILTIN_TEMPLATES[format].body,
    { name: opts.name ?? 'PSM', selfUrl, nodes, displayName, surgeLineOf })
  return { body, ...CONTENT[format] }
}
