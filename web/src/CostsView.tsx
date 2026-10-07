import { useEffect, useMemo, useState } from 'react'
import { finops, fmtMoney, type DailyCost } from './api'
import { Breakdown } from './Breakdown'

const thisMonth = () => new Date().toISOString().slice(0, 7)

/** Read-only cost view: daily spend by Project × Environment, with CSV export. */
export function CostsView({ tenantId }: { tenantId: string }) {
  const [month, setMonth] = useState(thisMonth)
  const [rows, setRows] = useState<DailyCost[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const from = `${month}-01`
  const to = useMemo(() => {
    const [y, m] = month.split('-').map(Number)
    return new Date(Date.UTC(y, m, 1)).toISOString().slice(0, 10)
  }, [month])

  useEffect(() => {
    let stale = false
    finops
      .daily(tenantId, from, to)
      .then((r) => !stale && (setRows(r), setError(null)))
      .catch((e: Error) => !stale && setError(e.message))
    return () => {
      stale = true
    }
  }, [tenantId, from, to])

  const totals = useMemo(() => {
    const m = new Map<string, { scope: string; currency: string; billed: number; effective: number }>()
    for (const r of rows ?? []) {
      const k = `${r.project_slug ?? '(unallocated)'} · ${r.environment_name || '—'} · ${r.provider}`
      const cur = m.get(k + r.currency) ?? { scope: k, currency: r.currency, billed: 0, effective: 0 }
      cur.billed += Number(r.billed)
      cur.effective += Number(r.effective ?? r.billed)
      m.set(k + r.currency, cur)
    }
    return [...m.values()].sort((a, b) => b.effective - a.effective)
  }, [rows])

  return (
    <section>
      <div className="toolbar">
        <input type="month" aria-label="Month" value={month} onChange={(e) => e.target.value && setMonth(e.target.value)} />
        <a className="secondary" style={{ padding: '6px 12px', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', textDecoration: 'none' }} href={finops.dailyCsvUrl(tenantId, from, to)} download>
          Download CSV
        </a>
      </div>
      {error && <p className="notice error">{error}</p>}
      {rows && rows.length === 0 && <p className="muted">No cost data for this month yet.</p>}
      {totals.length > 0 && (
        <div className="card table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Project · Environment · Provider</th>
                <th>Billed</th>
                <th>Effective</th>
              </tr>
            </thead>
            <tbody>
              {totals.map((t) => (
                <tr key={t.scope + t.currency}>
                  <td>{t.scope}</td>
                  <td>{fmtMoney(t.billed, t.currency)}</td>
                  <td>{fmtMoney(t.effective, t.currency)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted" style={{ fontSize: '0.85em' }}>
            Billed is what the invoice shows; effective spreads prepaid purchases over their term. Amounts are in the provider’s billing currency.
          </p>
        </div>
      )}
      <Breakdown tenantId={tenantId} from={from} to={to} />
    </section>
  )
}
