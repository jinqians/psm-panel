<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { api, ApiError, localTime, type Subscription, type Template, type Templates } from '../api'

const subs = ref<Subscription[]>([])
const tpl = ref<Templates | null>(null)
const name = ref('')
const labels = ref<string[]>([])
const labelDraft = ref('')
const error = ref('')
const copied = ref('')

const formats = [
  { id: '', label: '通用（自动识别）', help: 'v2rayN、Shadowrocket、Hiddify、NekoBox 等；下面几种客户端用这个地址也会自动拿到各自的格式' },
  { id: 'clash', label: 'Clash / mihomo', help: 'Clash Verge、Mihomo Party、ClashX Meta' },
  { id: 'stash', label: 'Stash', help: 'Stash（iOS / macOS）' },
  { id: 'singbox', label: 'sing-box', help: 'sing-box 官方客户端（SFA / SFI / SFM），1.14 及以上' },
  { id: 'surge', label: 'Surge', help: 'Surge（iOS / macOS）；没有 VLESS' },
  { id: 'quanx', label: 'Quantumult X', help: 'Quantumult X；没有 Hysteria2、TUIC、Snell' },
  { id: 'loon', label: 'Loon', help: 'Loon；没有 TUIC、Snell' },
]
const urlFor = (s: Subscription, f: string) => (f ? `${s.url}?format=${f}` : s.url)
const customOf = (format: string) => (tpl.value?.custom ?? []).filter((t) => t.format === format)

async function load() {
  subs.value = await api<Subscription[]>('/api/subscriptions')
  tpl.value = await api<Templates>('/api/templates')
}
onMounted(load)

function addLabel() {
  const l = labelDraft.value.trim()
  if (l && !labels.value.includes(l)) labels.value.push(l)
  labelDraft.value = ''
}
async function create() {
  error.value = ''
  try {
    await api('/api/subscriptions', { method: 'POST', body: JSON.stringify({ name: name.value, labels: labels.value }) })
    name.value = ''
    labels.value = []
    await load()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : String(e)
  }
}
async function copy(text: string) {
  await navigator.clipboard.writeText(text).catch(() => undefined)
  copied.value = text
  setTimeout(() => (copied.value = ''), 1500)
}
async function reset(s: Subscription) {
  if (!confirm(`重置 ${s.name} 的地址？旧地址立即失效，客户端要换成新地址。`)) return
  await api(`/api/subscriptions/${s.id}/reset`, { method: 'POST' })
  await load()
}
async function remove(s: Subscription) {
  if (!confirm(`删除订阅 ${s.name}？`)) return
  await api(`/api/subscriptions/${s.id}`, { method: 'DELETE' })
  await load()
}
async function chooseTemplate(s: Subscription, format: string, value: string) {
  const templates = { ...s.templates }
  if (value) templates[format] = Number(value)
  else delete templates[format]
  try {
    await api(`/api/subscriptions/${s.id}`, { method: 'PATCH', body: JSON.stringify({ templates }) })
    await load()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : String(e)
  }
}

// ── the template editor ──────────────────────────────────────────────────────
const editor = reactive({ open: false, id: 0, format: 'clash', name: '', body: '', error: '', busy: false })
const editing = computed(() => editor.id > 0)
function startNew(format = 'clash') {
  const b = tpl.value?.builtin.find((x) => x.format === format)
  Object.assign(editor, { open: true, id: 0, format, name: '', body: b?.body ?? '', error: '' })
}
function newFromBuiltin() {
  const b = tpl.value?.builtin.find((x) => x.format === editor.format)
  editor.body = b?.body ?? ''
}
function startEdit(t: Template) {
  Object.assign(editor, { open: true, id: t.id, format: t.format, name: t.name, body: t.body, error: '' })
}
async function saveTemplate() {
  editor.error = ''
  editor.busy = true
  try {
    if (editing.value) await api(`/api/templates/${editor.id}`, { method: 'PUT', body: JSON.stringify({ name: editor.name, body: editor.body }) })
    else await api('/api/templates', { method: 'POST', body: JSON.stringify({ name: editor.name, format: editor.format, body: editor.body }) })
    editor.open = false
    await load()
  } catch (e) {
    editor.error = e instanceof ApiError && e.errors.length ? e.errors.join('；') : String((e as Error).message)
  } finally {
    editor.busy = false
  }
}
async function removeTemplate(t: Template) {
  if (!confirm(`删除模板 ${t.name}？用它的订阅改回内置模板。`)) return
  await api(`/api/templates/${t.id}`, { method: 'DELETE' })
  await load()
}
</script>

<template>
  <div class="page-head">
    <div><h1>订阅</h1></div>
  </div>
  <form class="card" style="padding: 16px; margin-bottom: 16px" @submit.prevent="create">
    <div class="row2">
      <div class="field">
        <label>订阅名称</label>
        <input v-model="name" class="input" placeholder="例如 我的手机" data-test="sub-name">
      </div>
      <div class="field">
        <label>只包含带这些标签的节点（留空为全部）</label>
        <div class="chips">
          <span v-for="l in labels" :key="l" class="chip">{{ l }}<button type="button" @click="labels = labels.filter((x) => x !== l)">×</button></span>
          <input v-model="labelDraft" placeholder="输入后回车添加" @keydown.enter.prevent="addLabel">
        </div>
      </div>
    </div>
    <div v-if="error" class="notice err">{{ error }}</div>
    <button class="btn primary" type="submit" data-test="sub-create">新建订阅</button>
  </form>

  <div v-for="s in subs" :key="s.id" class="card sub" :data-test="`sub-${s.name}`">
    <div class="sub-head">
      <div>
        <strong>{{ s.name }}</strong>
        <span v-for="l in s.labels" :key="l" class="label-chip" style="margin-left: 8px">{{ l }}</span>
        <span v-if="!s.labels.length" class="muted" style="margin-left: 8px">全部节点</span>
      </div>
      <div class="muted">最近更新：{{ localTime(s.last_used) }}</div>
    </div>
    <div v-for="f in formats" :key="f.id" class="sub-row">
      <div class="sub-format">
        <div>{{ f.label }}</div><div class="muted small">{{ f.help }}</div>
        <select v-if="f.id" class="select small" style="margin-top: 4px; max-width: 220px" :value="s.templates[f.id] ?? ''"
          :data-test="`sub-tpl-${s.name}-${f.id}`" @change="chooseTemplate(s, f.id, ($event.target as HTMLSelectElement).value)">
          <option value="">内置模板（基础分流）</option>
          <option v-for="t in customOf(f.id)" :key="t.id" :value="t.id">{{ t.name }}</option>
        </select>
      </div>
      <div class="cmd">
        <code :data-test="`sub-url-${f.id || 'auto'}`">{{ urlFor(s, f.id) }}</code>
        <button class="btn" type="button" @click="copy(urlFor(s, f.id))">{{ copied === urlFor(s, f.id) ? '已复制' : '复制' }}</button>
      </div>
    </div>
    <div class="sub-actions">
      <button class="btn small ghost" @click="reset(s)">重置地址</button>
      <button class="btn small ghost danger" @click="remove(s)">删除</button>
    </div>
  </div>
  <div v-if="!subs.length" class="card empty">还没有订阅。</div>

  <div class="page-head" style="margin-top: 28px">
    <div><h1>订阅模板</h1><p>客户端拿到的配置 = 模板 + 节点。内置模板带基础分流（广告拦截、AI、流媒体、国内直连）；复制一份改成自己的规则，再在订阅里选用。</p></div>
    <button class="btn primary" type="button" data-test="tpl-new" @click="startNew()">＋ 新建模板</button>
  </div>
  <div class="card table-wrap">
    <table>
      <thead><tr><th>名称</th><th>格式</th><th>更新时间</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="t in tpl?.custom ?? []" :key="t.id" :data-test="`tpl-${t.name}`">
          <td>{{ t.name }}</td><td>{{ tpl?.formats[t.format] ?? t.format }}</td><td>{{ localTime(t.updated_at ?? t.created_at) }}</td>
          <td><button class="btn small ghost" @click="startEdit(t)">编辑</button> <button class="btn small ghost danger" @click="removeTemplate(t)">删除</button></td>
        </tr>
      </tbody>
    </table>
    <div v-if="!(tpl?.custom ?? []).length" class="empty">还没有自己的模板，订阅都用内置模板。</div>
  </div>

  <div v-if="editor.open" class="overlay" @click.self="editor.open = false">
    <div class="dialog" role="dialog" aria-label="订阅模板" style="max-width: 860px">
      <div class="dialog-head"><div><h2>{{ editing ? `编辑模板 ${editor.name}` : '新建订阅模板' }}</h2>
        <p>节点写在单独一行的 <code v-pre>{{proxies}}</code> 处；<code v-pre>{{names}}</code> 是节点名列表（每个后面带逗号，放在策略组固定成员前面），<code v-pre>{{names_list}}</code> 是不带尾逗号的节点名列表，<code v-pre>{{sub_url}}</code> 是这个订阅的地址，<code v-pre>{{name}}</code> 是订阅名称。Clash 还可以用 <code v-pre>{{provider_url}}</code> 让客户端自己从订阅拉取节点——内置的 Clash 模板就是这样，不写 <code v-pre>{{proxies}}</code>；两者都用时，可以用 <code v-pre>{{provider_exclude}}</code> 排掉已内联的节点以免重复。</p></div></div>
      <div class="dialog-body">
        <ul v-if="editor.error" class="errors" data-test="tpl-errors"><li>{{ editor.error }}</li></ul>
        <div class="row2">
          <div class="field"><label>模板名称</label><input v-model="editor.name" class="input" placeholder="例如 我的 Surge 规则" data-test="tpl-name"></div>
          <div class="field"><label>格式</label>
            <select v-model="editor.format" class="select" :disabled="editing" data-test="tpl-format" @change="newFromBuiltin">
              <option v-for="(label, f) in tpl?.formats ?? {}" :key="f" :value="f">{{ label }}</option>
            </select>
          </div>
        </div>
        <div class="field">
          <label>模板内容 <button v-if="!editing" class="btn small ghost" type="button" @click="newFromBuiltin">换成内置模板</button></label>
          <textarea v-model="editor.body" class="input" spellcheck="false" data-test="tpl-body"
            style="min-height: 420px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; white-space: pre"></textarea>
        </div>
      </div>
      <div class="dialog-foot">
        <button class="btn ghost" type="button" @click="editor.open = false">取消</button>
        <button class="btn primary" type="button" :disabled="editor.busy" data-test="tpl-save" @click="saveTemplate">{{ editor.busy ? '保存中…' : '保存' }}</button>
      </div>
    </div>
  </div>
</template>
