import { useEffect, useState } from 'react'
import { api, finops, fmtMoney, type Project, type Savings } from './api'

/** Savings recommended → accepted → applied → realised, for the Tenant or one Project (#75). */
export function SavingsView({ tenantId }: { tenantId: string }) {
  const [projects, setProjects] = useState<Project[]>([])
  const [project, setProject] = useState('')
  const [data, setData] = useState<Savings | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .projects(tenantId)
      .then(setProjects)
      .catch(() => setProjects([]))
  }, [tenantId])

  useEffect(() => {
    let stale = false
    finops
      .savings(tenantId, project || undefined)
      .then((s) => !stale && (setData(s), setError(null)))
      .catch((e: Error) => !stale && setError(e.message))
    return () => {
      stale = true
    }
  }, [tenantId, project])

  if (error) return <p className="notice error">{error}</p>
  if (!data) return <p className="muted">Loading savings…</p>
  const c = data.currency
  return (
    <section>
      <div className="toolbar">
        <label>
          Project{' '}
          <select value={project} onChange={(e) => setProject(e.target.value)}>
            <option value="">All projects</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="tiles">
        <div className="tile">
          <div className="label">Open advice</div>
          <div className="value">{fmtMoney(data.open, c)}</div>
          <div className="sub">per month, not yet decided</div>
        </div>
        <div className="tile">
          <div className="label">Accepted</div>
          <div className="value">{fmtMoney(data.accepted, c)}</div>
          <div className="sub">per month, awaiting change</div>
        </div>
        <div className="tile">
          <div className="label">Applied</div>
          <div className="value">{fmtMoney(data.applied, c)}</div>
          <div className="sub">per month, as recommended</div>
        </div>
        <div className="tile">
          <div className="label">Realised</div>
          <div className="value">{fmtMoney(data.realised, c)}</div>
          <div className={`status ${data.regressions > 0 ? 'serious' : 'good'}`}>
            <span aria-hidden>{data.regressions > 0 ? '!' : '✓'}</span>{' '}
            {data.regressions > 0 ? `${data.regressions} regression${data.regressions > 1 ? 's' : ''}` : 'No regressions'}
          </div>
        </div>
      </div>
      {data.items.length === 0 && <p className="muted">Nothing applied yet.</p>}
      {data.items.map((i) => (
        <article key={i.id} className="card finding">
          <strong>{i.resource_id}</strong>
          <span className="meta">
            Applied {i.applied_at.slice(0, 10)} · recommended {fmtMoney(i.recommended, c)}/month ·{' '}
            {i.realised === null ? 'waiting for 7 days of data' : `realised ${fmtMoney(i.realised, c)}/month (${i.method})`}
          </span>
          {i.regression && (
            <span className="status serious">
              <span aria-hidden>!</span> Regression: {i.regression}
            </span>
          )}
        </article>
      ))}
    </section>
  )
}
