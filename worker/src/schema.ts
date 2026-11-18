// The Worker creates and upgrades its own tables, so a one-click deploy needs
// no migration step: on the first request of each isolate it applies whatever
// file in migrations/ is not applied yet (each in one batch, so all or
// nothing). Files applied earlier with `wrangler d1 migrations apply` count as
// applied.
import m0001 from '../../migrations/0001_init.sql'
import m0002 from '../../migrations/0002_auth.sql'
import m0003 from '../../migrations/0003_panel.sql'
import m0004 from '../../migrations/0004_leave.sql'
import m0005 from '../../migrations/0005_clash.sql'
import m0006 from '../../migrations/0006_task_result.sql'
import m0007 from '../../migrations/0007_templates.sql'
import m0008 from '../../migrations/0008_relays.sql'
import m0009 from '../../migrations/0009_relay_samples.sql'
import m0010 from '../../migrations/0010_mount_443.sql'
import m0011 from '../../migrations/0011_relays_gost.sql'
import m0012 from '../../migrations/0012_audit.sql'
import m0013 from '../../migrations/0013_ipcheck.sql'
import m0014 from '../../migrations/0014_relay_node.sql'
import m0015 from '../../migrations/0015_display_name.sql'

const MIGRATIONS: [name: string, sql: string][] = [
  ['0001_init.sql', m0001],
  ['0002_auth.sql', m0002],
  ['0003_panel.sql', m0003],
  ['0004_leave.sql', m0004],
  ['0005_clash.sql', m0005],
  ['0006_task_result.sql', m0006],
  ['0007_templates.sql', m0007],
  ['0008_relays.sql', m0008],
  ['0009_relay_samples.sql', m0009],
  ['0010_mount_443.sql', m0010],
  ['0011_relays_gost.sql', m0011],
  ['0012_audit.sql', m0012],
  ['0013_ipcheck.sql', m0013],
  ['0014_relay_node.sql', m0014],
  ['0015_display_name.sql', m0015],
]

let ready: Promise<void> | null = null

export function ensureSchema(db: D1Database): Promise<void> {
  // a failed attempt (say, two isolates racing on a fresh database) is retried by the next request
  ready ??= migrate(db).catch((e) => { ready = null; throw e })
  return ready
}

async function migrate(db: D1Database) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS psm_migrations (
    name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))`).run()
  const done = new Set((await db.prepare('SELECT name FROM psm_migrations').all<{ name: string }>()).results.map((r) => r.name))
  if (await db.prepare(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'd1_migrations'`).first())
    for (const r of (await db.prepare('SELECT name FROM d1_migrations').all<{ name: string }>()).results) done.add(r.name)
  for (const [name, sql] of MIGRATIONS) {
    if (done.has(name)) continue
    await db.batch([
      ...statements(sql).map((s) => db.prepare(s)),
      db.prepare('INSERT OR IGNORE INTO psm_migrations (name) VALUES (?)').bind(name),
    ])
  }
}

/** The statements of a migration file (comments dropped; they hold no ';' or '--' inside strings). */
function statements(sql: string): string[] {
  return sql.replace(/--[^\n]*/g, '').split(';').map((s) => s.trim()).filter(Boolean)
}

/**
 * The key that encrypts node settings in D1: the TOKEN_KEY secret when there
 * is one, otherwise one the panel makes on first use and keeps in `settings`
 * (a one-click deploy asks for nothing but the admin password).
 */
export async function storedTokenKey(db: D1Database): Promise<string> {
  const fresh = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
  await db.prepare(`INSERT OR IGNORE INTO settings (key, value) VALUES ('token_key', ?)`).bind(fresh).run()
  const row = await db.prepare(`SELECT value FROM settings WHERE key = 'token_key'`).first<{ value: string }>()
  return row!.value
}
