import { useEffect, useState } from 'react'
import {
  insights,
  monthStarts,
  ApiError,
  fetchBlob,
  type DecisionEntry,
  type DoraReport,
  type MaturityAnswer,
  type MaturityView,
  type ReportSummary,
  type ScorecardReport,
} from './api'

const message = (e: unknown) => (e instanceof ApiError && e.status === 403 ? 'You are not allowed to do that here.' : (e as Error).message)
const loadMessage = (e: unknown) => (e instanceof ApiError && e.status === 403 ? 'You are not allowed to see this here.' : (e as Error).message)
const pct = (v: number | null | undefined) => (v == null ? '—' : `${Math.round(v * 100)}%`)
const hours = (v: number | null | undefined) => (v == null ? '—' : v < 48 ? `${v.toFixed(1)} h` : `${(v / 24).toFixed(1)} d`)
const monthName = (iso: string) => new Date(iso).toLocaleString('en-GB', { month: 'short', year: '2-digit', timeZone: 'UTC' })

/** Insights: DORA trend, scorecards, decisions, monthly reports, evidence and maturity (#155). */
type Section = 'dora' | 'cards' | 'reports' | 'maturity'
type Errors = Partial<Record<Section, string>>

async function save(url: string, filename: string) {
  const href = URL.createObjectURL(await fetchBlob(url))
  const a = document.createElement('a')
  a.href = href
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(href), 1000)
}

const SectionError = ({ text }: { text?: string }) => (text ? <p className="notice error" role="alert">{text}</p> : null)

export function InsightsView({ tenantId, canSubmit, canGenerate }: { tenantId: string; canSubmit: boolean; canGenerate: boolean }) {
  const [months, setMonths] = useState<DoraReport[]>([])
  const [cards, setCards] = useState<ScorecardReport | null>(null)
  const [reports, setReports] = useState<ReportSummary[]>([])
  const [maturity, setMaturity] = useState<MaturityView | null>(null)
  const [actionErrors, setActionErrors] = useState<Record<string, string>>({})
  const [errors, setErrors] = useState<Errors>({})
  const [reload, setReload] = useState(0)

  useEffect(() => {
    let stale = false
    const starts = monthStarts(6)
    Promise.allSettled([
      Promise.allSettled(starts.slice(0, -1).map((from, i) => insights.dora(tenantId, from, starts[i + 1]))),
      insights.scorecards(tenantId),
      insights.reports(tenantId),
      insights.maturity(tenantId),
    ]).then(([ds, sc, rs, mt]) => {
      if (stale) return
      const errs: Errors = {}
      const fail = (k: Section, r: PromiseSettledResult<unknown>) => {
        if (r.status === 'rejected') errs[k] = loadMessage(r.reason)
      }
      const doraOk = ds.status === 'fulfilled' ? ds.value.filter((d): d is PromiseFulfilledResult<DoraReport> => d.status === 'fulfilled') : []
      const doraFail = ds.status === 'fulfilled' ? ds.value.find((d) => d.status === 'rejected') : undefined
      setMonths(doraOk.map((d) => d.value))
      if (doraOk.length === 0 && doraFail) fail('dora', doraFail)
      setCards(sc.status === 'fulfilled' ? sc.value : null)
      fail('cards', sc)
      setReports(rs.status === 'fulfilled' ? rs.value : [])
      fail('reports', rs)
      setMaturity(mt.status === 'fulfilled' ? mt.value : null)
      fail('maturity', mt)
      setErrors(errs)
    })
    return () => {
      stale = true
    }
  }, [tenantId, reload])

  const setActionError = (key: string, text?: string) =>
    setActionErrors((prev) => {
      const { [key]: _, ...rest } = prev
      return text ? { ...rest, [key]: text } : rest
    })

  const download = (key: string, url: string, filename: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    setActionError(key)
    save(url, filename).catch((err) => setActionError(key, message(err)))
  }

  const regenerate = async (period: string) => {
    const key = `regenerate:${period}`
    setActionError(key)
    try {
      await insights.regenerateReport(tenantId, period)
      setReload((n) => n + 1)
    } catch (e) {
      setActionError(key, message(e))
    }
  }

  const latest = months[months.length - 1]
  return (
    <section className="delivery">
      <h2>Delivery performance (production)</h2>
      <SectionError text={errors.dora} />
      {latest && (
        <div className="tiles">
          <Tile label="Deployments this month" value={String(latest.tenant.deployments)} sub={`${latest.tenant.deployments_per_day.toFixed(2)} per day`} />
          <Tile label="Lead time" value={hours(latest.tenant.lead_time_hours)} sub="median, release → prod" />
          <Tile label="Change failure rate" value={pct(latest.tenant.change_fail_rate)} sub={`${latest.tenant.failed} failed`} />
          <Tile label="Recovery time" value={hours(latest.tenant.recovery_hours)} sub={`rework ${pct(latest.tenant.rework_rate)}`} />
        </div>
      )}
      {months.length > 0 && <DoraChart months={months} />}

      <h2>Service scorecards</h2>
      <SectionError text={errors.cards} />
      {!errors.cards && <Scorecards report={cards} />}

      <h2>Decisions</h2>
      <Decisions tenantId={tenantId} />

      <h2>Monthly reports</h2>
      <SectionError text={errors.reports} />
      {!errors.reports && reports.length === 0 && <p className="muted">The first report appears on the first of next month.</p>}
      {reports.map((r) => (
        <article key={r.period} className="card finding">
          <strong>
            {monthName(r.period + '-01T00:00:00Z')}
            {!r.final && <span className="meta"> provisional</span>}
          </strong>
          <a href={insights.reportURL(tenantId, r.period)} download={`keel-report-${r.period}.html`} onClick={download(`report:${r.period}`, insights.reportURL(tenantId, r.period), `keel-report-${r.period}.html`)}>
            Download report {r.period}
          </a>
          {canGenerate && (
            <button type="button" onClick={() => regenerate(r.period)}>
              Regenerate {r.period}
            </button>
          )}
          <SectionError text={actionErrors[`report:${r.period}`] ?? actionErrors[`regenerate:${r.period}`]} />
        </article>
      ))}

      <h2>Evidence export</h2>
      <Evidence tenantId={tenantId} download={download} error={actionErrors.evidence} />

      <h2>Platform maturity</h2>
      <SectionError text={errors.maturity} />
      {maturity ? (
        <Maturity view={maturity} canSubmit={canSubmit} onSubmit={async (q, a) => {
          try {
            await insights.submitMaturity(tenantId, q, a)
            setActionError('maturity')
            setReload((n) => n + 1)
          } catch (e) {
            setActionError('maturity', message(e))
          }
        }} />
      ) : (
        !errors.maturity && <p className="muted">No maturity data.</p>
      )}
      <SectionError text={actionErrors.maturity} />
    </section>
  )
}

function Tile({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <div className="tile">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      <div className="sub">{sub}</div>
    </div>
  )
}

/** Deployments per month as bars, with lead time labelled under each. */
function DoraChart({ months }: { months: DoraReport[] }) {
  const max = Math.max(1, ...months.map((m) => m.tenant.deployments))
  const w = 56
  const h = 120
  return (
    <figure className="card" aria-label="Deployments per month">
      <svg viewBox={`0 0 ${months.length * w} ${h + 34}`} width="100%" role="img" aria-label="Production deployments per month">
        {months.map((m, i) => {
          const bh = Math.round((m.tenant.deployments / max) * h)
          return (
            <g key={m.from}>
              <title>{`${monthName(m.from)}: ${m.tenant.deployments} deployments, lead time ${hours(m.tenant.lead_time_hours)}, CFR ${pct(m.tenant.change_fail_rate)}`}</title>
              <rect x={i * w + 12} y={h - bh} width={w - 24} height={bh} rx={3} fill="var(--accent)" />
              <text x={i * w + w / 2} y={h - bh - 4} textAnchor="middle" fontSize="11" fill="var(--text)">{m.tenant.deployments}</text>
              <text x={i * w + w / 2} y={h + 14} textAnchor="middle" fontSize="11" fill="var(--muted)">{monthName(m.from)}</text>
              <text x={i * w + w / 2} y={h + 28} textAnchor="middle" fontSize="10" fill="var(--muted)">{hours(m.tenant.lead_time_hours)}</text>
            </g>
          )
        })}
      </svg>
      <figcaption className="muted">Production deployments per month; lead time below.</figcaption>
    </figure>
  )
}

function Scorecards({ report }: { report: ScorecardReport | null }) {
  const services = report?.services ?? []
  if (!report || services.length === 0) return <p className="muted">No Services yet.</p>
  return (
    <div className="table-wrap">
      <p className="muted">
        Tenant score {report.score}/100 ({report.version})
      </p>
      <table className="data-table controls">
        <thead>
          <tr>
            <th>Service</th>
            <th>Score</th>
            <th>Failing checks</th>
          </tr>
        </thead>
        <tbody>
          {[...services]
            .sort((a, b) => a.score - b.score)
            .map((c) => {
              const failing = c.checks.filter((x) => !x.pass)
              const trend = c.previous_score == null ? '' : c.score > c.previous_score ? ' ↑' : c.score < c.previous_score ? ' ↓' : ''
              return (
                <tr key={c.service_id}>
                  <td>{c.service}</td>
                  <td>
                    {c.score}
                    {trend}
                  </td>
                  <td>{failing.length === 0 ? 'all pass' : failing.map((x) => `${x.name} (${x.why ?? x.control})`).join('; ')}</td>
                </tr>
              )
            })}
        </tbody>
      </table>
    </div>
  )
}

function Decisions({ tenantId }: { tenantId: string }) {
  const [q, setQ] = useState('')
  const [hits, setHits] = useState<DecisionEntry[] | null>(null)
  const [err, setErr] = useState<string>()
  const search = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      setHits(await insights.decisions(tenantId, q))
      setErr(undefined)
    } catch (x) {
      setHits(null)
      setErr(loadMessage(x))
    }
  }
  return (
    <>
      <form className="toolbar" onSubmit={search}>
        <label>
          Search decisions <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="e.g. queue" />
        </label>
        <button className="primary" type="submit">
          Search
        </button>
      </form>
      <SectionError text={err} />
      {hits?.length === 0 && <p className="muted">No matching decisions.</p>}
      {hits?.map((d) => (
        <article key={d.service_id + d.path} className="card finding">
          <strong>
            {d.service}: {d.number != null ? `ADR-${String(d.number).padStart(4, '0')} ` : ''}
            {d.title}
          </strong>
          <span className="meta">
            {d.status}
            {d.date ? ` · ${d.date}` : ''}
            {d.superseded_by ? ` · superseded by ${d.superseded_by}` : ''}
          </span>
          <a href={d.url} target="_blank" rel="noreferrer">
            Open record
          </a>
        </article>
      ))}
    </>
  )
}

function Evidence({ tenantId, download, error }: { tenantId: string; download: (key: string, url: string, filename: string) => (e: React.MouseEvent) => void; error?: string }) {
  const [from, setFrom] = useState(monthStarts(3)[0])
  const [to, setTo] = useState(monthStarts(1)[1])
  return (
    <>
      <div className="toolbar">
        <label>
          From <input type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
        </label>
        <label>
          To <input type="date" value={to} onChange={(e) => setTo(e.target.value)} />
        </label>
        <a className="button primary" href={insights.evidenceURL(tenantId, from, to)} download={`keel-evidence-${from}-${to}.json`} onClick={download('evidence', insights.evidenceURL(tenantId, from, to), `keel-evidence-${from}-${to}.json`)}>
          Export evidence
        </a>
      </div>
      <SectionError text={error} />
    </>
  )
}

function Maturity({ view, canSubmit, onSubmit }: { view: MaturityView; canSubmit: boolean; onSubmit: (quarter: string, a: Record<string, MaturityAnswer>) => void }) {
  const q = view.questionnaire
  const done = view.assessments.find((a) => a.quarter === view.quarter)
  const suggested = view.indicators.suggested_levels ?? {}
  const [levels, setLevels] = useState<Record<string, number>>(() =>
    Object.fromEntries(q.aspects.map((a) => [a.id, done?.answers[a.id]?.level ?? suggested[a.id] ?? 1])),
  )
  return (
    <>
      <p className="muted">
        {view.quarter}: {done ? `assessed by ${done.submitted_by.replace(/^user:/, '')}` : 'not assessed yet'} · template adoption {pct(view.indicators.template_adoption)} · self-service
        environments {pct(view.indicators.self_service_environments)}
      </p>
      {view.assessments.length > 0 && (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Aspect</th>
                {view.assessments.map((a) => (
                  <th key={a.quarter}>{a.quarter}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {q.aspects.map((asp) => (
                <tr key={asp.id}>
                  <td>{asp.title}</td>
                  {view.assessments.map((a) => (
                    <td key={a.quarter}>{a.answers[asp.id] ? q.levels[a.answers[asp.id].level - 1] : '—'}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault()
          onSubmit(view.quarter, Object.fromEntries(Object.entries(levels).map(([k, v]) => [k, { level: v }])))
        }}
      >
        {q.aspects.map((a) => (
          <article key={a.id} className="card finding">
            <label>
              <strong>{a.title}</strong>: {a.question}
              <select value={levels[a.id]} onChange={(e) => setLevels({ ...levels, [a.id]: Number(e.target.value) })}>
                {a.levels.map((text, i) => (
                  <option key={i} value={i + 1}>
                    {q.levels[i]}: {text}
                  </option>
                ))}
              </select>
            </label>
            {suggested[a.id] && <span className="meta">Keel measures {q.levels[suggested[a.id] - 1]}</span>}
          </article>
        ))}
        {canSubmit && (
          <button className="primary" type="submit">
            Save {view.quarter} assessment
          </button>
        )}
      </form>
    </>
  )
}
