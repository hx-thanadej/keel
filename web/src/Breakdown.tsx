import { useEffect, useState } from 'react'
import { finops, fmtMoney, type BreakdownRow } from './api'

/** Where the money went: top services or resources, ranked, single hue. */
export function Breakdown({ tenantId, from, to, project, environment }: { tenantId: string; from: string; to: string; project?: string; environment?: string }) {
  const [by, setBy] = useState<'service' | 'resource'>('service')
  const [rows, setRows] = useState<BreakdownRow[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let stale = false
    finops
      .breakdown(tenantId, { from, to, by, project, environment })
      .then((r) => !stale && (setRows(r), setError(null)))
      .catch((e: Error) => !stale && setError(e.message))
    return () => {
      stale = true
    }
  }, [tenantId, from, to, by, project, environment])

  const max = Math.max(1, ...(rows ?? []).map((r) => Number(r.effective || 0)))
  return (
    <section className="card">
      <div className="toolbar">
        <h2 style={{ marginRight: 'auto' }}>Top {by === 'service' ? 'services' : 'resources'}</h2>
        <div className="segmented" role="group" aria-label="Break down by">
          {(['service', 'resource'] as const).map((b) => (
            <button key={b} aria-pressed={by === b} onClick={() => setBy(b)}>
              {b === 'service' ? 'Service' : 'Resource'}
            </button>
          ))}
        </div>
      </div>
      {error && <p className="notice error">{error}</p>}
      {rows && rows.length === 0 && <p className="muted">No spend in this window.</p>}
      <ol className="rank">
        {rows?.map((r) => (
          <li key={r.key}>
            <span className="name">
              {r.key}
              {by === 'resource' && <span className="muted"> · {r.service}</span>}
            </span>
            <span className="amt">{fmtMoney(r.effective, r.currency)}</span>
            <span className="bar" style={{ width: `${(Number(r.effective || 0) / max) * 100}%` }} aria-hidden />
          </li>
        ))}
      </ol>
    </section>
  )
}
