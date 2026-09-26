// The protocols the panel offers, which engines run each, and the fields the
// "新建节点" dialog asks for. The Worker validates against this and the page
// renders its form from it, so both always agree. Field keys are the keys of
// PSM's node store (the same names as `psm node add --foo-bar` → foo_bar).

export type Core = 'xray' | 'sing-box' | 'mihomo'
/** A core, or the standalone program (snell-server for Snell, ss-rust for SS2022). */
export type Engine = Core | 'standalone'

export type FieldType = 'text' | 'password' | 'number' | 'select' | 'bool'

export interface Field {
  key: string
  label: string
  type: FieldType
  required?: boolean
  /** only for these engines (all when absent) */
  engines?: Engine[]
  /** only when another field has one of these values, e.g. { mode: ['xhttp', 'ws'] } */
  when?: Record<string, string[]>
  options?: { value: string; label: string }[]
  /** a select whose value PSM wants as a number (its schema checks the type) */
  numeric?: boolean
  default?: string | number | boolean
  placeholder?: string
  help?: string
  min?: number
  max?: number
  pattern?: string
}

export interface Variant {
  id: string
  label: string
  /** PSM's protocol name for `psm node add CORE <protocol>` */
  psm: string
  engines: Engine[]
  defaultEngine: Engine
  fields: Field[]
}

export interface Protocol {
  id: string
  label: string
  /** the dot colour in the protocol menu */
  color: string
  variants: Variant[]
}

export const ENGINE_LABELS: Record<Engine, string> = {
  standalone: '独立安装',
  xray: 'Xray',
  'sing-box': 'sing-box',
  mihomo: 'mihomo',
}

// ── shared field groups ──────────────────────────────────────────────────────
const cert = (engines: Engine[]): Field[] => [
  { key: 'sni', label: '证书域名（SNI）', type: 'text', engines, placeholder: '留空：自签证书，SNI 用 www.bing.com',
    help: '服务器上已有这个域名的证书（/etc/nginx/ssl/<域名>/）就直接用；没有就由 PSM 自动签一张自签证书，客户端自动跳过校验' },
  { key: 'cert_path', label: '证书文件', type: 'text', engines, placeholder: '留空自动（见上）', help: '自己的证书放在别处时才填，私钥文件也要填' },
  { key: 'key_path', label: '私钥文件', type: 'text', engines, placeholder: '留空自动（见上）' },
  { key: 'insecure', label: '证书不受信任（客户端跳过校验）', type: 'bool', default: false, engines,
    help: '只在自己填的证书是自签证书时勾选；自动签的自签证书总是跳过校验' },
]
const xrayDomain: Field = {
  key: 'domain', label: '域名', type: 'text', required: true, engines: ['xray'],
  placeholder: 'hk.example.com', help: '证书由主菜单 10. SSL 证书管理签发，存放在 /etc/nginx/ssl/<域名>/',
}
const password: Field = { key: 'password', label: '密码', type: 'password', placeholder: '留空自动生成' }
// VLESS Encryption (post-quantum; psm node … --vless-enc). sing-box's VLESS has
// none, so such a node is left out of the sing-box subscription.
const VENC_HELP = '客户端需要 Xray v25.9+ 或 mihomo 1.19.13+；sing-box、Surge、Quantumult X、Loon 用不了开启后的节点（sing-box 订阅里不会出现它）。X25519 链接短；ML-KEM-768 全程抗量子，但链接约 1.6 KB。'
const vlessEnc = (engines?: Engine[]): Field => ({
  key: 'vless_enc', label: 'VLESS Encryption（后量子加密）', type: 'select', default: '', engines, help: VENC_HELP,
  options: [{ value: '', label: '不开启' }, { value: 'x25519', label: 'X25519' }, { value: 'mlkem768', label: 'ML-KEM-768' }],
})
const uuid: Field = { key: 'uuid', label: 'UUID', type: 'text', placeholder: '留空自动生成' }

const ALL_CORES: Engine[] = ['xray', 'sing-box', 'mihomo']
const SB_MH: Engine[] = ['sing-box', 'mihomo']

export const PROTOCOLS: Protocol[] = [
  {
    id: 'ss2022', label: 'Shadowsocks 2022', color: '#5b9a5b',
    variants: [{
      id: 'ss2022', label: 'Shadowsocks 2022', psm: 'ss2022',
      engines: ['standalone', ...ALL_CORES], defaultEngine: 'standalone',
      fields: [
        { key: 'method', label: '加密方式', type: 'select', default: '2022-blake3-aes-128-gcm', options: [
          { value: '2022-blake3-aes-128-gcm', label: '2022-blake3-aes-128-gcm（推荐）' },
          { value: '2022-blake3-aes-256-gcm', label: '2022-blake3-aes-256-gcm' },
          { value: '2022-blake3-chacha20-poly1305', label: '2022-blake3-chacha20-poly1305' },
        ] },
        { ...password, placeholder: '留空自动生成符合长度的密钥' },
      ],
    }],
  },
  {
    id: 'vmess', label: 'VMess', color: '#c0407d',
    variants: [{
      id: 'vmess', label: 'VMess（WS + TLS）', psm: 'vmess', engines: ALL_CORES, defaultEngine: 'xray',
      fields: [xrayDomain, ...cert(SB_MH), uuid, { key: 'path', label: 'WebSocket 路径', type: 'text', placeholder: '留空自动生成' }],
    }],
  },
  {
    id: 'trojan', label: 'Trojan', color: '#e0b04a',
    variants: [{
      id: 'trojan', label: 'Trojan', psm: 'trojan', engines: ALL_CORES, defaultEngine: 'xray',
      fields: [xrayDomain, ...cert(SB_MH), password],
    }],
  },
  {
    id: 'hysteria2', label: 'Hysteria2', color: '#5b7fe0',
    variants: [{
      id: 'hysteria2', label: 'Hysteria2', psm: 'hysteria2', engines: ALL_CORES, defaultEngine: 'sing-box',
      fields: [
        ...cert(ALL_CORES), password,
        { key: 'obfs_pass', label: '混淆密码', type: 'password', placeholder: '留空不混淆' },
        { key: 'obfs_type', label: '混淆类型', type: 'select', default: 'salamander', options: [
          { value: 'salamander', label: 'Salamander' }, { value: 'gecko', label: 'Gecko' }] },
        { key: 'hop_ports', label: '端口跳跃范围', type: 'text', placeholder: '20000-20999（留空不开启）', pattern: '^$|^\\d{1,5}-\\d{1,5}$' },
        // Xray has it from v26.4.13, but the panel installs Xray's stable release (v26.3.27)
        { key: 'bbr_profile', label: 'BBR 拥塞配置档', type: 'select', default: '', engines: SB_MH, options: [
          { value: '', label: '默认（standard）' },
          { value: 'conservative', label: 'conservative：温和，带宽多人共享或线路拥堵时' },
          { value: 'aggressive', label: 'aggressive：激进，丢包较高的跨境线路' }],
          help: '服务器向客户端发数据时 BBR 的激进程度（不限速时生效）。需要 sing-box 1.14+ 或 mihomo 1.19.24+，服务器上的内核太旧时节点会创建失败并说明原因。' },
      ],
    }],
  },
  {
    id: 'vless', label: 'VLESS', color: '#1a1a1a',
    variants: [
      {
        id: 'vless-reality', label: 'REALITY', psm: 'reality', engines: ALL_CORES, defaultEngine: 'xray',
        fields: [
          { key: 'server_name', label: '伪装域名（SNI）', type: 'text', required: true, placeholder: 'learn.microsoft.com',
            help: '选支持 TLS 1.3、不在 CDN 后面的真实网站' },
          { key: 'dest', label: '伪装目标', type: 'text', required: true, placeholder: 'learn.microsoft.com:443', pattern: '^[^\\s:]+:\\d{1,5}$' },
          uuid, vlessEnc(['xray']),
        ],
      },
      { id: 'vless-vision', label: 'Vision（TCP + TLS）', psm: 'vision', engines: ['xray'], defaultEngine: 'xray', fields: [xrayDomain, uuid, vlessEnc()] },
      {
        id: 'vless-xhttp', label: 'XHTTP', psm: 'xhttp', engines: ['xray'], defaultEngine: 'xray',
        fields: [
          { key: 'mode', label: '传输模式', type: 'select', default: 'xhttp', options: [
            { value: 'xhttp', label: 'XHTTP / SplitHTTP' }, { value: 'ws', label: 'WebSocket' }, { value: 'grpc', label: 'gRPC' },
            { value: 'httpupgrade', label: 'HTTPUpgrade' }, { value: 'h2', label: 'HTTP/2' },
            { value: 'reality-layer', label: 'REALITY 层（无需域名）' }, { value: 'mkcp', label: 'mKCP（UDP）' }] },
          { ...xrayDomain, when: { mode: ['xhttp', 'ws', 'grpc', 'httpupgrade', 'h2'] } },
          { key: 'server_name', label: '伪装域名', type: 'text', required: true, when: { mode: ['reality-layer'] }, placeholder: 'learn.microsoft.com' },
          { key: 'reality_transport', label: 'REALITY 层传输', type: 'select', default: 'xhttp', when: { mode: ['reality-layer'] },
            options: [{ value: 'xhttp', label: 'XHTTP' }, { value: 'grpc', label: 'gRPC' }] },
          { key: 'kcp_seed', label: 'mKCP 混淆种子', type: 'text', when: { mode: ['mkcp'] }, placeholder: '留空自动生成' },
          uuid,
          { ...vlessEnc(), when: { mode: ['xhttp', 'ws', 'grpc', 'httpupgrade', 'h2', 'reality-layer'] } },
          { key: 'vless_enc', label: 'VLESS Encryption（后量子加密）', type: 'select', default: '', when: { mode: ['mkcp'] },
            help: 'mKCP 不套 TLS，而 Xray v26.7.7 起的客户端拒绝向公网地址发送未加密的 VLESS，所以默认开启（X25519）。选「不开启」只有旧版客户端能连。',
            options: [{ value: '', label: 'X25519（默认）' }, { value: 'mlkem768', label: 'ML-KEM-768' }, { value: 'none', label: '不开启（仅旧版客户端）' }] },
        ],
      },
      {
        id: 'vless-tls', label: 'TLS', psm: 'vless', engines: SB_MH, defaultEngine: 'sing-box',
        fields: [
          ...cert(SB_MH),
          { key: 'transport', label: '传输方式', type: 'select', default: 'tcp', options: [
            { value: 'tcp', label: 'TCP' }, { value: 'ws', label: 'WebSocket' }, { value: 'grpc', label: 'gRPC' },
            { value: 'httpupgrade', label: 'HTTPUpgrade（sing-box）' }, { value: 'xhttp', label: 'XHTTP（mihomo）' }] },
          { key: 'path', label: '路径', type: 'text', when: { transport: ['ws', 'httpupgrade', 'xhttp'] }, placeholder: '留空自动生成' },
          uuid, vlessEnc(['mihomo']),
        ],
      },
    ],
  },
  {
    id: 'tuic', label: 'TUIC', color: '#4cbb5e',
    variants: [{
      id: 'tuic', label: 'TUIC v5', psm: 'tuic', engines: SB_MH, defaultEngine: 'sing-box',
      fields: [...cert(SB_MH), uuid, password,
        { key: 'congestion_control', label: '拥塞控制', type: 'select', default: 'bbr',
          options: [{ value: 'bbr', label: 'BBR' }, { value: 'cubic', label: 'CUBIC' }, { value: 'new_reno', label: 'NewReno' }] }],
    }],
  },
  {
    id: 'socks', label: 'SOCKS', color: '#3f8fe6',
    variants: [{
      id: 'socks', label: 'SOCKS5', psm: 'socks', engines: ALL_CORES, defaultEngine: 'xray',
      fields: [
        { key: 'listen_addr', label: '监听范围', type: 'select', default: '127.0.0.1', options: [
          { value: '127.0.0.1', label: '仅本机（推荐）' }, { value: '0.0.0.0', label: '公网（必须设置用户名和密码）' }] },
        { key: 'username', label: '用户名', type: 'text', when: { listen_addr: ['0.0.0.0'] }, required: true },
        { key: 'password', label: '密码', type: 'password', when: { listen_addr: ['0.0.0.0'] }, required: true },
      ],
    }],
  },
  {
    id: 'anytls', label: 'AnyTLS', color: '#7b5cc2',
    variants: [{ id: 'anytls', label: 'AnyTLS', psm: 'anytls', engines: SB_MH, defaultEngine: 'sing-box', fields: [...cert(SB_MH), password] }],
  },
  {
    id: 'snell', label: 'Snell', color: '#e3643a',
    variants: [{
      id: 'snell', label: 'Snell', psm: 'snell', engines: ['standalone', ...SB_MH], defaultEngine: 'standalone',
      fields: [
        { key: 'version', label: 'Snell 版本', type: 'select', numeric: true, default: '5', options: [
          { value: '4', label: 'v4（独立安装、mihomo）' }, { value: '5', label: 'v5' }, { value: '6', label: 'v6（独立安装、sing-box；上游仍是测试版）' }] },
        { key: 'psk', label: 'PSK', type: 'password', placeholder: '留空自动生成' },
      ],
    }],
  },
  {
    id: 'wireguard', label: 'WireGuard', color: '#8a2be2',
    variants: [{
      id: 'wireguard', label: 'WireGuard', psm: 'wireguard', engines: ['sing-box'], defaultEngine: 'sing-box',
      fields: [{ key: 'peer_count', label: '客户端数量', type: 'number', default: 1, min: 1, max: 50 }],
    }],
  },
]

// ── the exit: what of a core node's traffic leaves through WARP or the free
// residential line (psm node … --exit, lib/exit_cli.sh); everything else goes
// out directly. Standalone servers have no routing.
const EXIT_COUNTRIES: [string, string][] = [
  ['JP', '日本'], ['KR', '韩国'], ['US', '美国'], ['TH', '泰国'], ['VN', '越南'], ['ID', '印度尼西亚'],
  ['RU', '俄罗斯'], ['DE', '德国'], ['GB', '英国'], ['FR', '法国'], ['CA', '加拿大'], ['AU', '澳大利亚'],
]
const EXIT_ON = ['warp', 'vpngate']
export const EXIT_FIELDS: Field[] = [
  { key: 'exit', label: '出口分流', type: 'select', default: 'none', engines: ALL_CORES, options: [
    { value: 'none', label: '不分流（全部从服务器直连）' }, { value: 'warp', label: 'Cloudflare WARP' }, { value: 'vpngate', label: '免费家宽（VPNGate）' }],
    help: '选中的流量从 WARP 或家宽 IP 出去，给看 IP 的服务（ChatGPT、Netflix 等）用；其余流量照常直连。WARP 第一次用时自动注册，任何服务器都能用。家宽线路由志愿者提供，速度和稳定性不保证，断线时服务器会自动换一条；它走 OpenVPN，需要服务器有 /dev/net/tun——LXC / OpenVZ 的小鸡常常没有（服务器页的诊断里会写明），这类机器请改用 WARP。' },
  { key: 'exit_sites', label: '分流范围', type: 'select', default: 'ai', engines: ALL_CORES, when: { exit: EXIT_ON }, options: [
    { value: 'ai', label: 'AI（ChatGPT、Claude、Gemini）' },
    { value: 'streaming', label: '流媒体（Netflix、Disney+、HBO、Prime Video、Spotify）' },
    { value: 'ai,streaming', label: 'AI + 流媒体' },
    { value: 'all', label: '这个节点的全部流量' },
    { value: 'custom', label: '自定义 geosite 列表' }] },
  { key: 'exit_geosite', label: 'geosite 列表', type: 'text', required: true, engines: ALL_CORES, when: { exit: EXIT_ON, exit_sites: ['custom'] },
    placeholder: 'openai,netflix,youtube', pattern: '^[a-z0-9!@._-]+(,[a-z0-9!@._-]+)*$', help: '逗号分隔的 geosite 名称（v2fly domain-list-community 里的名字）' },
  { key: 'exit_country', label: '家宽国家', type: 'select', default: 'JP', engines: ALL_CORES, when: { exit: ['vpngate'] },
    options: EXIT_COUNTRIES.map(([value, label]) => ({ value, label: `${label}（${value}）` })),
    help: '服务器第一次建家宽出口时找这个国家的家宽线路；已经有家宽线路时继续用它。' },
]
for (const p of PROTOCOLS) for (const v of p.variants) if (v.engines.some((e) => e !== 'standalone')) v.fields.push(...EXIT_FIELDS)

/** Snell versions each engine can run. */
export const SNELL_VERSIONS: Partial<Record<Engine, string[]>> = {
  standalone: ['4', '5', '6'], 'sing-box': ['5', '6'], mihomo: ['4', '5'],
}

/**
 * The name PSM's traffic metering knows a node by: its own name, or snell /
 * ss2022 for the standalone servers (one of each per server). Those two are
 * therefore not allowed as node names.
 */
export const RESERVED_NAMES = ['snell', 'ss2022']
export function trafficTag(n: { engine: string; psm_protocol: string; name: string }): string {
  return n.engine === 'standalone' ? n.psm_protocol : n.name
}

export function findVariant(protocolId: string, variantId: string): Variant | undefined {
  return PROTOCOLS.find((p) => p.id === protocolId)?.variants.find((v) => v.id === variantId)
}

/** The fields shown for this variant, engine and the values entered so far. */
export function activeFields(v: Variant, engine: Engine, values: Record<string, unknown>): Field[] {
  return v.fields.filter((f) =>
    (!f.engines || f.engines.includes(engine)) &&
    (!f.when || Object.entries(f.when).every(([k, allowed]) => allowed.includes(String(values[k] ?? v.fields.find((x) => x.key === k)?.default ?? '')))))
}

export interface NodeInput {
  protocol: string
  variant: string
  engine: Engine
  name: string
  address: string
  port: number
  public_port?: number
  traffic_limit_gb?: number
  labels?: string[]
  params?: Record<string, unknown>
  /**
   * Share the public 443: the node listens on 127.0.0.1 and Nginx routes the
   * connection to it by the name in the TLS handshake. This is not a node
   * setting — it is how the node is created (`psm node add … --mount-443`),
   * and PSM refuses to move a node onto or off the shared 443 as an update.
   */
  mount_443?: boolean
}

/**
 * Which nodes can share the public 443. Nginx routes by the name in the TLS
 * handshake, so only a protocol that starts with a TLS ClientHello can be told
 * apart there — the same list PSM checks (_node_cli_fronted_pair).
 */
const FRONTED: Partial<Record<Engine, string[]>> = {
  xray: ['reality', 'vision', 'xhttp', 'trojan', 'vmess'],
  'sing-box': ['reality', 'anytls', 'trojan', 'vmess', 'vless'],
  mihomo: ['reality', 'anytls', 'trojan', 'vmess', 'vless'],
}
export function canMount443(engine: Engine, psmProtocol: string): boolean {
  return (FRONTED[engine] ?? []).includes(psmProtocol)
}

// never starting with "-": on the server the name is an argument to psm, and
// "--show-secrets" would be read as an option
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$/
const HOST_RE = /^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$|^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]+$/

/**
 * Checks a new node against the protocol table and returns the problems, or
 * the PSM request (core or standalone, protocol and node store fields).
 */
export function validateNode(n: NodeInput):
  | { ok: false; errors: string[] }
  | { ok: true; engine: Engine; psmProtocol: string; data: Record<string, unknown> } {
  const errors: string[] = []
  const v = findVariant(n.protocol, n.variant)
  if (!v) return { ok: false, errors: ['未知的协议'] }
  if (!v.engines.includes(n.engine)) errors.push(`${v.label} 不能用 ${ENGINE_LABELS[n.engine] ?? n.engine} 运行`)
  if (!NAME_RE.test(n.name ?? '')) errors.push('节点名称：1-48 位字母、数字、. _ -，以字母或数字开头')
  else if (RESERVED_NAMES.includes(n.name.toLowerCase())) errors.push(`节点名称：${n.name} 是保留名称（独立安装的流量统计用它），请换一个`)
  if (!HOST_RE.test(n.address ?? '')) errors.push('节点地址：填写域名或 IP')
  const portOk = (p: unknown) => Number.isInteger(p) && (p as number) >= 1 && (p as number) <= 65535
  if (!portOk(n.port)) errors.push('服务端口：1-65535')
  if (n.public_port !== undefined && !portOk(n.public_port)) errors.push('连接端口：1-65535')
  if (n.traffic_limit_gb !== undefined && !(Number.isFinite(n.traffic_limit_gb) && n.traffic_limit_gb >= 0))
    errors.push('流量限制：不小于 0 的数字')
  if (n.mount_443 && !canMount443(n.engine, v.psm))
    errors.push(`${v.label} 用 ${ENGINE_LABELS[n.engine] ?? n.engine} 运行时不能挂到 443 复用`)

  const params = n.params ?? {}
  const data: Record<string, unknown> = { tag: n.name, port: n.port }
  if (n.public_port && n.public_port !== n.port) data.public_port = n.public_port
  for (const f of activeFields(v, n.engine, params)) {
    let val = params[f.key]
    if (val === undefined || val === '') val = f.default
    if (val === undefined || val === '') {
      if (f.required) errors.push(`${f.label}：必填`)
      continue
    }
    if (f.type === 'number' && !(Number.isFinite(Number(val)) && (f.min === undefined || Number(val) >= f.min) && (f.max === undefined || Number(val) <= f.max)))
      errors.push(`${f.label}：${f.min}-${f.max}`)
    if (f.type === 'select' && !f.options?.some((o) => o.value === String(val))) errors.push(`${f.label}：无效的选项`)
    if (f.pattern && !new RegExp(f.pattern).test(String(val))) errors.push(`${f.label}：格式不正确`)
    data[f.key] = f.type === 'number' || f.numeric ? Number(val) : f.type === 'bool' ? (val === true || val === 'true' ? 1 : 0) : val
  }
  // a custom exit scope is the geosite list itself (PSM's exit_sites takes names)
  if (data.exit_sites === 'custom') data.exit_sites = data.exit_geosite
  delete data.exit_geosite
  if (v.psm === 'snell' && !(SNELL_VERSIONS[n.engine] ?? []).includes(String(data.version)))
    errors.push(`Snell v${data.version} 不能用 ${ENGINE_LABELS[n.engine]} 运行`)
  if (v.id === 'vless-tls') {
    const t = String(data.transport)
    if (t === 'httpupgrade' && n.engine !== 'sing-box') errors.push('HTTPUpgrade 只有 sing-box 支持')
    if (t === 'xhttp' && n.engine !== 'mihomo') errors.push('XHTTP 只有 mihomo 支持')
  }
  return errors.length ? { ok: false, errors } : { ok: true, engine: n.engine, psmProtocol: v.psm, data }
}
