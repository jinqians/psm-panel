<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { PROTOCOLS, ENGINE_LABELS, findVariant, type Engine } from '@shared/protocols'
import { api, errorText, formatBytes, NODE_STATUS, type PanelNode, type Relay, type Server } from '../api'
import { confirmAction, toast, usePoll } from '../ui'
import NodeDialog from '../components/NodeDialog.vue'
import RelayDialog from '../components/RelayDialog.vue'
import RelayLink from '../components/RelayLink.vue'
import SecretText from '../components/SecretText.vue'
import Modal from '../components/Modal.vue'
import RowMenu from '../components/RowMenu.vue'
import Icon from '../components/Icon.vue'

const nodes = ref<PanelNode[]>([])
const servers = ref<Server[]>([])
const relays = ref<Relay[]>([])
const loaded = ref(false)
const dialog = ref(false)
const editing = ref<PanelNode | null>(null)
// a relay landing on a node (经中转发布, or editing one), and a relayed link
const relayDialog = ref<null | { node: PanelNode | null; relay: Relay | null }>(null)
const relayLink = ref<Relay | null>(null)

async function load() {
  try {
    ;[nodes.value, servers.value, relays.value] = await Promise.all([
      api<PanelNode[]>('/api/nodes'), api<Server[]>('/api/servers'), api<Relay[]>('/api/relays')])
  } catch (e) {
    toast(errorText(e), 'err')
  } finally {
    loaded.value = true
  }
}
onMounted(load)
// every few seconds while a change is on its way to a server, else every half minute
usePoll(load, 30000, () => nodes.value.some((n) => n.status === 'queued' || n.status === 'deleting') ||
  relays.value.some((r) => r.node_id !== null && (['queued', 'deleting', 'pending'].includes(r.status) || ['queued', 'deleting'].includes(r.exit_status))))

const proto = (id: string) => PROTOCOLS.find((p) => p.id === id)
const serverName = (id: number) => servers.value.find((s) => s.id === id)?.name ?? '?'
/** the relays that land on a node: the node, published again through each */
const relaysOf = (n: PanelNode) => relays.value.filter((r) => r.node_id === n.id)
const entryHost = (r: Relay) => r.entry_host || servers.value.find((s) => s.id === r.server_id)?.last_ip || '?'
/** a relay's state as one: a tunnel waits for its exit first */
const relayState = (r: Relay) => (r.mode === 'tunnel' && r.exit_status !== 'applied' && r.status !== 'failed' ? r.exit_status || r.status : r.status)

// ── search and filters ───────────────────────────────────────────────────────
const q = ref('')
const fServer = ref<number | ''>('')
const fStatus = ref('')
const fProto = ref('')
const PAGE = 50
const page = ref(1)
const shown = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return nodes.value.filter((n) =>
    (!needle || n.name.toLowerCase().includes(needle) || n.display_name.toLowerCase().includes(needle) || n.address.toLowerCase().includes(needle) ||
      n.labels.some((l) => l.toLowerCase().includes(needle)) || String(n.public_port ?? n.port) === needle) &&
    (fServer.value === '' || n.server_id === fServer.value) &&
    (!fStatus.value || (fStatus.value === 'paused' ? n.traffic_paused : n.status === fStatus.value)) &&
    (!fProto.value || n.protocol === fProto.value))
})
const pages = computed(() => Math.max(1, Math.ceil(shown.value.length / PAGE)))
const rows = computed(() => shown.value.slice((page.value - 1) * PAGE, page.value * PAGE))
watch([q, fServer, fStatus, fProto], () => { page.value = 1 })
const filtered = computed(() => !!(q.value || fServer.value !== '' || fStatus.value || fProto.value))
const usedProtocols = computed(() => PROTOCOLS.filter((p) => nodes.value.some((n) => n.protocol === p.id)))

// ── the share link (masked until asked for) ──────────────────────────────────
const link = ref<{ node: PanelNode; content: string; format: string } | null>(null)
async function showLink(n: PanelNode) {
  try {
    const r = await api<{ content: string; format: string }>(`/api/nodes/${n.id}/link`)
    link.value = { node: n, ...r }
  } catch (e) {
    toast(errorText(e), 'err')
  }
}

async function remove(n: PanelNode) {
  // A node whose server never answers again stays in 删除中 for ever, so that
  // state must still offer a way out: forget it here, as a server can be.
  const stuck = n.status === 'deleting'
  const ok = await confirmAction(stuck
    ? { title: `只从面板移除 ${n.name}？`, danger: true, ok: '只从面板移除',
        body: `它一直停在删除中，服务器没有回应。\n服务器上的节点不会被删掉；那台机器如果还在，请在它上面执行 psm node delete 清理。` }
    : { title: `删除节点 ${n.name}？`, danger: true, ok: '删除', body: '服务器上的节点也会一起删除，订阅里随之消失。' +
        (relaysOf(n).length ? `\n落到它上面的 ${relaysOf(n).length} 条中转会留下（转发到原来的地址），不再进订阅。` : '') })
  if (!ok) return
  try {
    await api(`/api/nodes/${n.id}${stuck ? '?force=1' : ''}`, { method: 'DELETE' })
    toast(stuck ? `${n.name} 已从面板移除` : `正在删除 ${n.name}`)
    await load()
  } catch (e) {
    toast(errorText(e), 'err')
  }
}
async function resetTraffic(n: PanelNode) {
  if (!(await confirmAction({ title: `重置 ${n.name} 的流量？`, body: '从 0 重新计算；超额暂停的节点会恢复。', ok: '重置' }))) return
  try {
    await api(`/api/nodes/${n.id}/traffic/reset`, { method: 'POST' })
    toast(`已通知 ${serverName(n.server_id)}，几秒后生效`)
  } catch (e) {
    toast(errorText(e), 'err')
  }
}
function openNew() {
  editing.value = null
  dialog.value = true
}
function openEdit(n: PanelNode) {
  editing.value = n
  dialog.value = true
}
const busy = (n: PanelNode) => n.status === 'queued' || n.status === 'deleting'
const pct = (n: PanelNode) => (n.traffic_limit_gb > 0 ? Math.min(100, (n.traffic_used / (n.traffic_limit_gb * 1024 ** 3)) * 100) : 0)
</script>

<template>
  <div class="page-head">
    <div><h1>节点管理</h1><p>节点由各服务器上的 psm-agent 建好；这里的修改几秒内生效。</p></div>
    <div class="page-actions">
      <button class="btn primary" data-test="new-node" @click="openNew"><Icon name="plus" />新建节点</button>
    </div>
  </div>
  <div class="card">
    <div class="toolbar">
      <input v-model="q" class="input search" type="search" placeholder="搜索名称、地址、端口、标签" data-test="node-search">
      <select v-model="fServer" class="select" data-test="node-filter-server">
        <option value="">全部服务器</option>
        <option v-for="s in servers" :key="s.id" :value="s.id">{{ s.name }}</option>
      </select>
      <select v-model="fProto" class="select">
        <option value="">全部协议</option>
        <option v-for="p in usedProtocols" :key="p.id" :value="p.id">{{ p.label }}</option>
      </select>
      <select v-model="fStatus" class="select">
        <option value="">全部状态</option>
        <option v-for="(label, s) in { applied: '运行中', queued: '下发中', waiting: '待安装', failed: '失败', deleting: '删除中' }" :key="s" :value="s">{{ label }}</option>
        <option value="paused">超额暂停</option>
      </select>
      <span class="grow" />
      <span class="muted">{{ filtered ? `${shown.length} / ` : '' }}{{ nodes.length }} 个节点</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>节点</th><th>状态</th><th>协议</th><th>运行方式</th><th>服务器</th><th>地址</th><th>本月流量</th><th>标签</th><th class="actions">操作</th></tr>
        </thead>
        <tbody>
          <template v-for="n in rows" :key="n.id">
          <tr :data-test="`node-${n.name}`" :data-status="n.status">
            <td><b>{{ n.name }}</b><span class="sub">{{ n.display_name ? `${n.display_name} · ` : '' }}#{{ n.id }}</span></td>
            <td>
              <span class="status" :class="n.status" :title="n.last_error ?? ''"><span class="dot" />{{ NODE_STATUS[n.status] }}</span>
              <span v-if="n.traffic_paused" class="badge warn" title="超出流量上限，已暂停">超额暂停</span>
              <span v-if="n.last_error && n.status !== 'failed'" class="badge err" :title="n.last_error">!</span>
              <span v-if="n.status === 'failed' && n.last_error" class="sub ellipsis" :title="n.last_error">{{ n.last_error }}</span>
            </td>
            <td>
              <span class="proto-tag"><span class="dot" :style="{ background: proto(n.protocol)?.color }" />
                {{ proto(n.protocol)?.label }}<template v-if="(proto(n.protocol)?.variants.length ?? 0) > 1"> · {{ findVariant(n.protocol, n.variant)?.label }}</template>
              </span>
            </td>
            <td>{{ ENGINE_LABELS[n.engine as Engine] ?? n.engine }}</td>
            <td>{{ serverName(n.server_id) }}</td>
            <td class="mono">{{ n.address }}:{{ n.public_port ?? n.port }}<span v-if="n.mount_443" class="badge info">443 复用</span></td>
            <td>
              <div class="small">{{ formatBytes(n.traffic_used) }} / {{ n.traffic_limit_gb ? `${n.traffic_limit_gb} GB` : '不限' }}</div>
              <div v-if="n.traffic_limit_gb" class="meter" style="margin-top: 3px"><span :class="{ over: pct(n) >= 80, full: pct(n) >= 100 }" :style="{ width: `${pct(n)}%` }" /></div>
            </td>
            <td><span v-for="l in n.labels" :key="l" class="label-chip">{{ l }}</span></td>
            <td class="actions">
              <span class="row-actions">
                <button class="btn small ghost" :disabled="!n.has_link" :data-test="`link-${n.name}`" @click="showLink(n)"><Icon name="link" />链接</button>
                <button class="btn small ghost" :disabled="busy(n)" :data-test="`edit-${n.name}`" @click="openEdit(n)"><Icon name="edit" />编辑</button>
                <RowMenu :test="`more-${n.name}`">
                  <button type="button" :disabled="n.status === 'deleting'" :data-test="`via-relay-${n.name}`"
                          @click="relayDialog = { node: n, relay: null }"><Icon name="relays" />经中转发布…</button>
                  <button type="button" :disabled="n.status !== 'applied'" @click="resetTraffic(n)"><Icon name="refresh" />重置流量</button>
                  <hr>
                  <button type="button" class="danger" :data-test="`delete-${n.name}`" @click="remove(n)">
                    <Icon name="trash" />{{ n.status === 'deleting' ? '强制移除' : '删除' }}
                  </button>
                </RowMenu>
              </span>
            </td>
          </tr>
          <!-- the node again, through each relay landing on it -->
          <tr v-for="r in relaysOf(n)" :key="`r${r.id}`" class="relayed" :data-test="`relayed-${r.name}`" :data-status="relayState(r)">
            <td><span class="branch">↳</span><b>{{ r.name }}</b><span class="sub">经 {{ serverName(r.server_id) }} {{ r.mode === 'tunnel' ? '隧道' : '中转' }}</span></td>
            <td>
              <span class="status" :class="relayState(r)" :title="r.last_error ?? r.exit_error ?? ''"><span class="dot" />{{ NODE_STATUS[relayState(r)] ?? relayState(r) }}</span>
              <span v-if="r.paused" class="badge warn">{{ r.paused === 'expired' ? '已到期' : '超额暂停' }}</span>
            </td>
            <td class="faint">同节点</td>
            <td>{{ r.engine }}</td>
            <td>{{ serverName(r.server_id) }}</td>
            <td class="mono">{{ entryHost(r) }}:{{ r.listen_port }}</td>
            <td class="faint small">计入节点</td>
            <td>
              <span v-if="r.in_sub" class="label-chip" title="跟着节点的标签进订阅">进订阅</span>
              <span v-else class="faint small">不进订阅</span>
            </td>
            <td class="actions">
              <span class="row-actions">
                <button class="btn small ghost" :disabled="!n.has_link" :data-test="`relayed-link-${r.name}`" @click="relayLink = r"><Icon name="link" />链接</button>
                <button class="btn small ghost" :data-test="`edit-relay-${r.name}`"
                        :disabled="['queued', 'deleting', 'deleted'].includes(r.status) || ['queued', 'deleting', 'deleted'].includes(r.exit_status)"
                        @click="relayDialog = { node: null, relay: r }"><Icon name="edit" />编辑</button>
                <!-- where a node's ⋯ is: the buttons line up with the node's -->
                <span class="btn icon small ghost" style="visibility: hidden" aria-hidden="true"><Icon name="more" /></span>
              </span>
            </td>
          </tr>
          </template>
        </tbody>
      </table>
      <div v-if="!loaded" class="skeleton-rows"><div v-for="i in 4" :key="i" class="skeleton" style="height: 22px" /></div>
      <div v-else-if="!nodes.length" class="empty">
        <div class="big">◉</div>
        <p>还没有节点。新建一个，面板会给出服务器上要执行的一键命令。</p>
        <button class="btn primary" @click="openNew"><Icon name="plus" />新建节点</button>
      </div>
      <div v-else-if="!shown.length" class="empty">没有符合条件的节点。</div>
    </div>
    <div v-if="pages > 1" class="pager">
      <button class="btn small" :disabled="page === 1" @click="page--">上一页</button>
      <span>{{ page }} / {{ pages }}</span>
      <button class="btn small" :disabled="page === pages" @click="page++">下一页</button>
    </div>
  </div>

  <NodeDialog v-if="dialog" :servers="servers" :node="editing" @close="dialog = false; load()" @created="load" />
  <RelayDialog v-if="relayDialog" :servers="servers" :nodes="nodes" :node="relayDialog.node" :relay="relayDialog.relay"
               @close="relayDialog = null; load()" @created="load" />
  <RelayLink v-if="relayLink" :relay="relayLink" :entry="serverName(relayLink.server_id)" @close="relayLink = null" />
  <Modal v-if="link" :title="`${link.node.name} 的${link.format === 'surge' ? ' Surge 配置行' : '链接'}`" @close="link = null">
    <div class="dialog-body">
      <SecretText :value="link.content" test="node-link" copied="已复制链接" />
      <p class="help">链接里有节点的密码，只发给要用它的人。订阅页可以按标签把多个节点一起给出去。</p>
    </div>
    <template #foot><button class="btn primary" type="button" @click="link = null">完成</button></template>
  </Modal>
</template>

<style scoped>
tr.relayed > td { background: var(--surface-2) }
tr.relayed .branch { display: inline-block; width: 1.3em; color: var(--faint) }
</style>
