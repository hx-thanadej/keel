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

  const [recs, setRecs] = useState<Record<string, { id: string; pr_url: string | null }>>({})
  useEffect(() => {
    finops
      .recommendations(tenantId)
      .then((rs) => setRecs(Object.fromEntries(rs.map((r) => [r.finding_id, { id: r.id, pr_url: r.pr_url }]))))
      .catch(() => setRecs({}))
  }, [tenantId, reload])

  const openPR = async (f: Finding) => {
    const r = recs[f.id]
    if (!r) return
    try {
      const { pr_url } = await finops.applyRecommendation(tenantId, r.id)
      window.open(pr_url, '_blank', 'noopener')
      setReload((n) => n + 1)
    } catch (e) {
      setError((e as Error).message)
    }
  }

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
        const cur = f.detail.current as Record<string, string> | undefined
        const rec = f.detail.recommended as Record<string, string> | undefined
        const ev = f.detail.evidence as Record<string, unknown> | undefined
        return (
          <article key={f.id} className="card finding">
            <span className={`status ${s.cls}`}>
              <span aria-hidden>{s.icon}</span> {s.text} · {f.kind.replace('_', ' ')}
            </span>
            <strong>{f.title}</strong>
            {f.due_at && (
              <span className={f.overdue_at ? 'status critical' : 'meta'}>
                {f.overdue_at ? '✕ Overdue since ' : 'Due '}
                {new Date(f.due_at).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}
              </span>
            )}
            {top.length > 0 && <span className="meta">Top contributors: {top.map((t) => `${t.resource_id} (+${t.delta})`).join(', ')}</span>}
            {cur && rec && (
              <span className="meta">
                {Object.keys(rec)
                  .filter((k) => k in cur)
                  .map((k) => `${k}: ${cur[k] ?? '—'} → ${rec[k]}`)
                  .join(' · ')}
                {ev?.lookback_days !== undefined && ` · based on ${String(ev.lookback_days)} days`}
                {ev?.replicas !== undefined && `, ${String(ev.replicas)} replica(s)`}
              </span>
            )}
            <span className="meta">First seen {new Date(f.first_seen_at).toLocaleString()}</span>
            <div className="toolbar">
              {f.kind === 'rightsizing' && recs[f.id]?.pr_url && (
                <a href={recs[f.id].pr_url ?? '#'} target="_blank" rel="noopener noreferrer">
                  View pull request
                </a>
              )}
              {f.kind === 'rightsizing' && recs[f.id] && !recs[f.id].pr_url && (
                <button className="primary" onClick={() => openPR(f)}>
                  Open pull request
                </button>
              )}
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
