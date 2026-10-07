import { useEffect, useState } from 'react'
import { finops, ApiError, type Finding } from './api'

const sev = {
  critical: { cls: 'critical', icon: '✕', text: 'Critical' },
  high: { cls: 'serious', icon: '!', text: 'High' },
  medium: { cls: 'warning', icon: '!', text: 'Medium' },
  low: { cls: 'good', icon: 'i', text: 'Low' },
} as const

export function FindingsView({ tenantId }: { tenantId: string }) {
  const [items, setItems] = useState<Finding[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    let stale = false
    finops
      .findings(tenantId)
      .then((f) => !stale && (setItems(f), setError(null)))
      .catch((e: Error) => !stale && setError(e.message))
    return () => {
      stale = true
    }
  }, [tenantId, reload])

  const resolve = async (f: Finding) => {
    const reason = window.prompt('How was this resolved?')
    if (!reason) return
    try {
      await finops.resolve(tenantId, f.id, reason)
      setReload((n) => n + 1)
    } catch (e) {
      setError(e instanceof ApiError && e.status === 403 ? 'You are not allowed to resolve findings here.' : (e as Error).message)
    }
  }

  if (error) return <p className="notice error">{error}</p>
  if (!items) return <p className="muted">Loading findings…</p>
  if (items.length === 0) return <p className="muted">No open findings.</p>
  return (
    <section>
      {items.map((f) => {
        const s = sev[f.severity]
        const top = (f.detail.top_resources as { resource_id: string; delta: string }[] | undefined) ?? []
        return (
          <article key={f.id} className="card finding">
            <span className={`status ${s.cls}`}>
              <span aria-hidden>{s.icon}</span> {s.text} · {f.kind.replace('_', ' ')}
            </span>
            <strong>{f.title}</strong>
            {top.length > 0 && <span className="meta">Top contributors: {top.map((t) => `${t.resource_id} (+${t.delta})`).join(', ')}</span>}
            <span className="meta">First seen {new Date(f.first_seen_at).toLocaleString()}</span>
            <div>
              <button className="secondary" onClick={() => resolve(f)}>
                Resolve…
              </button>
            </div>
          </article>
        )
      })}
    </section>
  )
}
