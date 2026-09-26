<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { api, ApiError, formatBytes, localTime, type Server } from '../api'
import InstallCommand from '../components/InstallCommand.vue'

const servers = ref<Server[]>([])
const name = ref('')
const error = ref('')
const command = ref<{ server: string; text: string } | null>(null)

type Check = { id?: string; status?: string; message?: string }
type Report = {
  psm_version?: string; agent_version?: string
  cores?: { core: string; installed: boolean; version: string; active: boolean }[] | null
  doctor?: { checks?: Check[]; results?: Check[] } | null
  nodes?: { items?: unknown[] } | null
  traffic?: { tag: string; used_bytes: number; paused: boolean }[] | null
  snell?: { installed: boolean; active: boolean; port: number | null; version: string } | null
  ss2022?: { installed: boolean; active: boolean; port: number | null; method: string } | null
}
const diag = ref<{ server: Server; at: string | null; pending: boolean; report: Report | null } | null>(null)
let poll: ReturnType<typeof setInterval> | undefined

async function load() {
  servers.value = await api<Server[]>('/api/servers')
}
onMounted(load)
onUnmounted(() => clearInterval(poll))

async function add() {
  error.value = ''
  try {
    const r = await api<{ id: number; install_command: string }>('/api/servers', { method: 'POST', body: JSON.stringify({ name: name.value.trim() }) })
    command.value = { server: name.value.trim().toLowerCase(), text: r.install_command }
    name.value = ''
    await load()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : String(e)
  }
}
async function newCommand(s: Server) {
  const r = await api<{ install_command: string }>(`/api/servers/${s.id}/install-command`, { method: 'POST' })
  command.value = { server: s.name, text: r.install_command }
}
// Removing a joined, online server uninstalls on it what the panel made (its
// nodes, standalone Snell / ss-rust, psm-agent); an offline one (or one stuck
// leaving) can only be removed from the panel.
const notice = ref('')
async function remove(s: Server) {
  const onServer = s.status === 'online'
  const msg = s.status === 'pending'
    ? `移除服务器 ${s.name}？它还没有接入，节点记录会一起删除。`
    : onServer
      ? `移除服务器 ${s.name}？\n\n服务器上由面板建的节点、独立安装的 Snell / ss-rust 和 psm-agent 会被卸载。PSM 本身、内核和在服务器命令行里建的节点会保留。`
      : `${s.name} 现在${s.status === 'leaving' ? '还没有完成卸载' : '离线'}，无法在服务器上卸载。只从面板移除吗？\n\n服务器上的节点和 psm-agent 会保留；之后可以在服务器上执行 psm agent remove --yes 卸载 psm-agent。`
  if (!confirm(msg)) return
  error.value = ''
  try {
    await api(`/api/servers/${s.id}${onServer || s.status === 'pending' ? '' : '?force=1'}`, { method: 'DELETE' })
    notice.value = onServer ? `正在卸载 ${s.name} 上由面板建的节点和 psm-agent，完成后它会从列表里消失。` : ''
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : String(e)
  }
  await load()
}
// An agent older than the one the panel expects can be upgraded from here: the
// server updates PSM, installs the psm-agent it names and restarts it. Only for
// a server that is online — an offline one would only queue the task.
const outdated = (s: Server) => s.status === 'online' && !!s.agent_version && !!s.agent_latest && s.agent_version !== s.agent_latest
async function upgradeAgent(s: Server) {
  if (!confirm(`把 ${s.name} 上的 psm-agent 从 ${s.agent_version} 升级到 ${s.agent_latest}？\n\n服务器上会先更新 PSM，再替换 psm-agent 并重启它。节点和中转不受影响。`)) return
  error.value = ''
  try {
    await api(`/api/servers/${s.id}/upgrade-agent`, { method: 'POST' })
    notice.value = `已通知 ${s.name} 升级 psm-agent，完成后 Agent 列会变成 ${s.agent_latest}。`
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : String(e)
  }
}
// PSM itself, when the agent is current: the same task — PSM is updated first,
// and psm-agent stays as it is. The panel asks for the nodes' links again once
// the server reports the new version (at its next version check, within the
// hour, or right away when 诊断 is run).
async function updatePsm(s: Server) {
  if (!confirm(`把 ${s.name} 上的 PSM 更新到最新版？\n\n节点和中转不受影响。更新后面板会重新取一次节点的链接和订阅（服务器下次报告版本时，最多一小时；点「诊断」立即生效）。`)) return
  error.value = ''
  try {
    await api(`/api/servers/${s.id}/upgrade-agent`, { method: 'POST' })
    notice.value = `已通知 ${s.name} 更新 PSM，完成后 PSM 列会显示新版本。`
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : String(e)
  }
}
// while a server is leaving, look again every few seconds
let leavingPoll: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  leavingPoll = setInterval(() => { if (servers.value.some((s) => s.status === 'leaving')) load() }, 4000)
})
onUnmounted(() => clearInterval(leavingPoll))

async function readStatus(s: Server) {
  const r = await api<{ at: string | null; pending: boolean; report: Report | null }>(`/api/servers/${s.id}/status`)
  diag.value = { server: s, ...r }
  if (!r.pending) clearInterval(poll)
}
async function diagnose(s: Server) {
  error.value = ''
  try {
    await api(`/api/servers/${s.id}/status`, { method: 'POST' })
    await readStatus(s)
    clearInterval(poll)
    poll = setInterval(() => readStatus(s), 3000)
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : String(e)
  }
}
const checks = (r: Report) => r.doctor?.checks ?? r.doctor?.results ?? []
const problems = (r: Report) => checks(r).filter((c) => c.status && c.status !== 'ok' && c.status !== 'pass')
const statusText = { online: '在线', pending: '待接入', offline: '离线', leaving: '卸载中' } as const
</script>

<template>
  <div class="page-head">
    <div><h1>服务器</h1></div>
    <form class="cmd" style="min-width: 360px" @submit.prevent="add">
      <input v-model="name" class="input" placeholder="新服务器名称，例如 hk1" data-test="server-name">
      <button class="btn primary" type="submit" data-test="add-server">添加服务器</button>
    </form>
  </div>
  <div v-if="error" class="notice err">{{ error }}</div>
  <div v-if="notice" class="notice ok" data-test="server-notice">{{ notice }}</div>
  <div v-if="command" class="card" style="padding: 16px; margin-bottom: 16px" data-test="server-command">
    <div class="field-label">在 {{ command.server }} 上以 root 执行：</div>
    <InstallCommand :command="command.text" />
    <div class="help" style="color: var(--muted); margin-top: 6px">24 小时内有效，只能用一次。</div>
  </div>
  <div class="card table-wrap">
    <table>
      <thead><tr><th>ID</th><th>名称</th><th>状态</th><th>主机名</th><th>PSM</th><th>Agent</th><th>本月流量</th><th>最近同步</th><th>节点数</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="s in servers" :key="s.id" :data-test="`server-${s.name}`" :data-status="s.status">
          <td>{{ s.id }}</td>
          <td>{{ s.name }}</td>
          <td>
            <span class="status" :class="s.status"><span class="dot" />{{ statusText[s.status] }}</span>
            <span v-if="s.leave_error" class="badge err" :title="s.leave_error">卸载失败</span>
          </td>
          <td>{{ s.hostname ?? '—' }}</td>
          <td>{{ s.psm_version ?? '—' }}</td>
          <td>{{ s.agent_version ?? '—' }}<span v-if="outdated(s)" class="badge" :title="`可升级到 ${s.agent_latest}`">可升级</span></td>
          <td>{{ formatBytes(s.traffic_used) }}</td>
          <td>{{ localTime(s.last_seen) }}</td>
          <td>{{ s.node_count }}</td>
          <td>
            <button class="btn small ghost" :disabled="s.status === 'pending'" :data-test="`diagnose-${s.name}`" @click="diagnose(s)">诊断</button>
            <button class="btn small ghost" @click="newCommand(s)">安装命令</button>
            <button v-if="outdated(s)" class="btn small ghost" :data-test="`upgrade-agent-${s.name}`" @click="upgradeAgent(s)">升级 agent</button>
            <button v-else-if="s.status === 'online'" class="btn small ghost" :data-test="`update-psm-${s.name}`" @click="updatePsm(s)">更新 PSM</button>
            <button class="btn small ghost danger" :data-test="`remove-${s.name}`" @click="remove(s)">{{ s.status === 'leaving' ? '只从面板移除' : '移除' }}</button>
          </td>
        </tr>
      </tbody>
    </table>
    <div v-if="!servers.length" class="empty">还没有服务器。</div>
  </div>

  <div v-if="diag" class="card" style="padding: 18px; margin-top: 16px" data-test="diagnostics">
    <div class="sub-head">
      <strong>{{ diag.server.name }} 的诊断</strong>
      <span class="muted">{{ diag.pending ? '正在收集…' : `收集于 ${localTime(diag.at)}` }}</span>
    </div>
    <template v-if="diag.report">
      <dl class="facts">
        <dt>PSM 版本</dt><dd>{{ diag.report.psm_version || '—' }}</dd>
        <dt>psm-agent</dt><dd>{{ diag.report.agent_version || '—' }}</dd>
        <dt>内核</dt>
        <dd data-test="diag-cores">
          <span v-for="c in diag.report.cores ?? []" :key="c.core" class="label-chip">
            {{ c.core }}：{{ c.installed ? `${c.version}${c.active ? '（运行中）' : '（未运行）'}` : '未安装' }}
          </span>
        </dd>
        <dt>独立 Snell</dt><dd>{{ diag.report.snell?.installed ? `v${diag.report.snell.version}，端口 ${diag.report.snell.port}，${diag.report.snell.active ? '运行中' : '未运行'}` : '未安装' }}</dd>
        <dt>独立 SS2022</dt><dd>{{ diag.report.ss2022?.installed ? `${diag.report.ss2022.method}，端口 ${diag.report.ss2022.port}，${diag.report.ss2022.active ? '运行中' : '未运行'}` : '未安装' }}</dd>
        <dt>节点</dt><dd>{{ diag.report.nodes?.items?.length ?? 0 }} 个（PSM 里）</dd>
        <dt>psm doctor</dt>
        <dd data-test="diag-doctor">
          {{ checks(diag.report).length }} 项检查，{{ problems(diag.report).length }} 项需要注意
          <ul v-if="problems(diag.report).length" class="problems">
            <li v-for="p in problems(diag.report)" :key="p.id">[{{ p.status }}] {{ p.message }}</li>
          </ul>
        </dd>
      </dl>
    </template>
    <div v-else-if="!diag.pending" class="muted">还没有诊断结果。</div>
  </div>
</template>
