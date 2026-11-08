<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { api, ApiError, ago, errorText, localTime, type Subscription, type Template, type Templates } from '../api'
import { confirmAction, toast } from '../ui'
import SecretText from '../components/SecretText.vue'
import Modal from '../components/Modal.vue'
import Icon from '../components/Icon.vue'

const subs = ref<Subscription[]>([])
const tpl = ref<Templates | null>(null)
const name = ref('')
const labels = ref<string[]>([])
const labelDraft = ref('')
const error = ref('')

const formats = [
  { id: '', label: '通用（自动识别）', help: 'v2rayN、Shadowrocket、Hiddify、NekoBox 等；下面几种客户端用这个地址也会自动拿到各自的格式' },
  { id: 'clash', label: 'Clash / mihomo', help: 'Clash Verge、Mihomo Party、ClashX Meta' },
  { id: 'stash', label: 'Stash', help: 'Stash（iOS / macOS）' },
  { id: 'singbox', label: 'sing-box', help: 'sing-box 官方客户端（SFA / SFI / SFM），1.14 及以上' },
  { id: 'surge', label: 'Surge', help: 'Surge（iOS / macOS）；没有 VLESS。Snell 节点只在这个格式里' },
  { id: 'quanx', label: 'Quantumult X', help: 'Quantumult X；没有 Hysteria2、TUIC、Snell' },
  { id: 'loon', label: 'Loon', help: 'Loon；没有 TUIC、Snell' },
]
const urlFor = (s: Subscription, f: string) => (f ? `${s.url}?format=${f}` : s.url)
const otherFormats = formats.filter((f) => f.id).map((f) => f.label.split(' / ')[0]).join('、')
// One address is all most clients need (the 通用 one picks their format), so a
// subscription shows that and opens the others on demand: seven rows each
// filled the page once there were a few subscriptions (proxy-stack #10).
const open = ref(new Set<number>())
function toggleFormats(id: number) {
  const next = new Set(open.value)
  if (!next.delete(id)) next.add(id)
  open.value = next
}
const customCount = (s: Subscription) => Object.keys(s.templates).length
/** the token in a subscription's URL: what is masked on the page */
const tokenOf = (s: Subscription) => s.url.split('/sub/')[1] ?? ''
const loaded = ref(false)
const customOf = (format: string) => (tpl.value?.custom ?? []).filter((t) => t.format === format)

async function load() {
  try {
    ;[subs.value, tpl.value] = await Promise.all([api<Subscription[]>('/api/subscriptions'), api<Templates>('/api/templates')])
  } catch (e) {
    toast(errorText(e), 'err')
  } finally {
    loaded.value = true
  }
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
    toast(`已新建订阅 ${name.value.trim()}`)
    name.value = ''
    labels.value = []
    await load()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : String(e)
  }
}
async function reset(s: Subscription) {
  if (!(await confirmAction({ title: `重置 ${s.name} 的地址？`, body: '旧地址立即失效，用它的客户端要换成新地址。地址泄露了就该重置。', ok: '重置地址', danger: true }))) return
  try {
    await api(`/api/subscriptions/${s.id}/reset`, { method: 'POST' })
    toast(`${s.name} 的地址已重置`)
    await load()
  } catch (e) {
    toast(errorText(e), 'err')
  }
}
async function remove(s: Subscription) {
  if (!(await confirmAction({ title: `删除订阅 ${s.name}？`, body: '用它的客户端将拿不到节点。', ok: '删除', danger: true }))) return
  try {
    await api(`/api/subscriptions/${s.id}`, { method: 'DELETE' })
    toast(`已删除 ${s.name}`)
    await load()
  } catch (e) {
    toast(errorText(e), 'err')
  }
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
  if (!(await confirmAction({ title: `删除模板 ${t.name}？`, body: '用它的订阅改回内置模板。', ok: '删除', danger: true }))) return
  try {
    await api(`/api/templates/${t.id}`, { method: 'DELETE' })
    await load()
  } catch (e) {
    toast(errorText(e), 'err')
  }
}
</script>

<template>
  <div class="page-head">
    <div><h1>订阅</h1><p>一个订阅地址给出选中的节点，按客户端自动选格式。地址本身就是密钥：只发给要用的人，泄露了就重置。</p></div>
  </div>
  <form class="card card-pad section" @submit.prevent="create">
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
    <button class="btn primary" type="submit" :disabled="!name.trim()" data-test="sub-create"><Icon name="plus" />新建订阅</button>
  </form>

  <div v-for="s in subs" :key="s.id" class="card sub-card" :data-test="`sub-${s.name}`">
    <div class="sub-head">
      <div class="hstack">
        <strong>{{ s.name }}</strong>
        <span v-for="l in s.labels" :key="l" class="label-chip">{{ l }}</span>
        <span v-if="!s.labels.length" class="muted small">全部节点</span>
      </div>
      <div class="hstack">
        <span class="muted small" :title="localTime(s.last_used)">{{ s.last_used ? `客户端 ${ago(s.last_used)}更新过` : '还没有客户端用过' }}</span>
        <button class="btn small ghost" @click="reset(s)"><Icon name="refresh" />重置地址</button>
        <button class="btn small ghost danger" @click="remove(s)"><Icon name="trash" />删除</button>
      </div>
    </div>
    <div v-for="f in formats.filter((x) => !x.id || open.has(s.id))" :key="f.id" class="sub-row">
      <div class="sub-format">
        <div><b>{{ f.label }}</b></div><div class="muted small">{{ f.help }}</div>
        <select v-if="f.id" class="select small" style="margin-top: 4px; max-width: 220px; padding: 4px 8px" :value="s.templates[f.id] ?? ''"
          :data-test="`sub-tpl-${s.name}-${f.id}`" @change="chooseTemplate(s, f.id, ($event.target as HTMLSelectElement).value)">
          <option value="">内置模板（基础分流）</option>
          <option v-for="t in customOf(f.id)" :key="t.id" :value="t.id">{{ t.name }}</option>
        </select>
      </div>
      <SecretText :value="urlFor(s, f.id)" :secret="tokenOf(s)" :test="`sub-url-${f.id || 'auto'}`" copied="已复制订阅地址" />
    </div>
    <button class="btn small ghost sub-more" type="button" :aria-expanded="open.has(s.id)" :data-test="`sub-more-${s.name}`" @click="toggleFormats(s.id)">
      <span class="caret">{{ open.has(s.id) ? '▾' : '▸' }}</span>{{ open.has(s.id) ? '收起其他客户端格式' : `其他客户端格式：${otherFormats}` }}
      <span v-if="customCount(s)" class="muted small">（{{ customCount(s) }} 种用了自己的模板）</span>
    </button>
  </div>
  <div v-if="loaded && !subs.length" class="card empty">还没有订阅。</div>

  <div class="page-head" style="margin-top: 28px">
    <div><h1>订阅模板</h1><p>客户端拿到的配置 = 模板 + 节点。内置模板带基础分流（广告拦截、AI、流媒体、国内直连）；复制一份改成自己的规则，再在订阅里选用。</p></div>
    <button class="btn primary" type="button" data-test="tpl-new" @click="startNew()"><Icon name="plus" />新建模板</button>
  </div>
  <div class="card table-wrap">
    <table>
      <thead><tr><th>名称</th><th>格式</th><th>更新时间</th><th class="actions">操作</th></tr></thead>
      <tbody>
        <tr v-for="t in tpl?.custom ?? []" :key="t.id" :data-test="`tpl-${t.name}`">
          <td><b>{{ t.name }}</b></td><td>{{ tpl?.formats[t.format] ?? t.format }}</td><td>{{ localTime(t.updated_at ?? t.created_at) }}</td>
          <td class="actions"><button class="btn small ghost" @click="startEdit(t)"><Icon name="edit" />编辑</button> <button class="btn small ghost danger" @click="removeTemplate(t)"><Icon name="trash" />删除</button></td>
        </tr>
      </tbody>
    </table>
    <div v-if="!(tpl?.custom ?? []).length" class="empty">还没有自己的模板，订阅都用内置模板。</div>
  </div>

  <Modal v-if="editor.open" :title="editing ? `编辑模板 ${editor.name}` : '新建订阅模板'" size="wide" sticky @close="editor.open = false">
    <template #subtitle>
      <p>节点写在单独一行的 <code v-pre>{{proxies}}</code> 处；<code v-pre>{{names}}</code> 是节点名列表（每个后面带逗号，放在策略组固定成员前面），<code v-pre>{{names_list}}</code> 是不带尾逗号的节点名列表，<code v-pre>{{sub_url}}</code> 是这个订阅的地址，<code v-pre>{{name}}</code> 是订阅名称。Clash 还可以用 <code v-pre>{{provider_url}}</code> 让客户端自己从订阅拉取节点——内置的 Clash 模板就是这样，不写 <code v-pre>{{proxies}}</code>；两者都用时，可以用 <code v-pre>{{provider_exclude}}</code> 排掉已内联的节点以免重复。</p>
    </template>
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
        <textarea v-model="editor.body" class="input mono" spellcheck="false" data-test="tpl-body" style="min-height: 420px; white-space: pre"></textarea>
      </div>
    </div>
    <template #foot>
      <button class="btn ghost" type="button" @click="editor.open = false">取消</button>
      <button class="btn primary" type="button" :disabled="editor.busy" data-test="tpl-save" @click="saveTemplate">{{ editor.busy ? '保存中…' : '保存' }}</button>
    </template>
  </Modal>
</template>
