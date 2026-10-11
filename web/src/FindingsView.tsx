import { useEffect, useRef, useState } from 'react'
import { api, finops, ApiError, type CloudAccount, type Finding, type Recommendation } from './api'
import { manualSteps, opensPullRequest, ownershipOf, readOnlyReason, recommendationAccounts } from './ownership'

const sev = {
  critical: { cls: 'critical', icon: '✕', text: 'Critical' },
  high: { cls: 'serious', icon: '!', text: 'High' },
  medium: { cls: 'warning', icon: '!', text: 'Medium' },
  low: { cls: 'good', icon: 'i', text: 'Low' },
} as const

export function FindingsView({ tenantId, focus }: { tenantId: string; focus?: string }) {
  const [items, setItems] = useState<Finding[] | null>(null)
  // A Finding linked from elsewhere that the inbox's first 200 do not include, fetched on its own.
  const [fetched, setFetched] = useState<{ id: string; finding: Finding | 'missing' }>()
  const outside = focus !== undefined && items !== null && !items.some((f) => f.id === focus)
  const linked = outside && fetched?.id === focus ? fetched.finding : null
  const focused = useRef<HTMLElement>(null)
  const consumed = useRef<string | undefined>(undefined)
  useEffect(() => {
    if (!focused.current || consumed.current === focus) return
    consumed.current = focus
    focused.current.scrollIntoView?.({ block: 'center' })
    focused.current.focus()
  }, [items, linked, focus])
  useEffect(() => {
    if (!outside) return
    let stale = false
    finops
      .finding(tenantId, focus)
      .then((f) => !stale && setFetched({ id: focus, finding: f }))
      .catch(() => !stale && setFetched({ id: focus, finding: 'missing' }))
    return () => {
      stale = true
    }
  }, [tenantId, focus, outside])
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

  const [recs, setRecs] = useState<Record<string, Recommendation>>({})
  const [accounts, setAccounts] = useState<CloudAccount[]>([])
  useEffect(() => {
    finops
      .recommendations(tenantId)
      .then((rs) => setRecs(Object.fromEntries(rs.map((r) => [r.finding_id, r]))))
      .catch(() => setRecs({}))
    api
      .cloudAccounts(tenantId)
      .then(setAccounts)
      .catch(() => setAccounts([]))
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
  const shown = linked && linked !== 'missing' ? [linked, ...items] : items
  if (shown.length === 0 && linked !== 'missing') return <p className="muted">No open findings.</p>
  return (
    <section>
      {linked === 'missing' && (
        <p className="notice error" role="alert">
          The linked Finding could not be loaded. It may have been removed.
        </p>
      )}
      {linked && linked !== 'missing' && (
        <p className="notice" role="status">
          The linked Finding is not among the {items.length} Findings listed below, so it is shown first.
        </p>
      )}
      {shown.map((f) => {
        const s = sev[f.severity]
        const top = (f.detail.top_resources as { resource_id: string; delta: string }[] | undefined) ?? []
        const cur = f.detail.current as Record<string, string> | undefined
        const rec = f.detail.recommended as Record<string, string> | undefined
        const ev = f.detail.evidence as Record<string, unknown> | undefined
        const r = recs[f.id]
        const readOnly = r ? readOnlyReason(ownershipOf(recommendationAccounts(r, accounts))) : null
        return (
          <article key={f.id} id={`finding-${f.id}`} className="card finding" tabIndex={-1} ref={f.id === focus ? focused : undefined}>
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
            {r && !opensPullRequest(r) && (
              <span className="meta">
                Manual steps: {manualSteps(r)} {readOnly ?? 'Keel opens pull requests only for Kubernetes request changes and off-hours schedules.'}
              </span>
            )}
            {r && opensPullRequest(r) && readOnly && <span className="meta">The pull request goes to your Git repository; Keel does not change the client-owned account.</span>}
            <div className="toolbar">
              {r && opensPullRequest(r) && r.pr_url && (
                <a href={r.pr_url} target="_blank" rel="noopener noreferrer">
                  View pull request
                </a>
              )}
              {r && opensPullRequest(r) && !r.pr_url && (
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
