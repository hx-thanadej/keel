import { useEffect, useState } from 'react'
import { api, finops, fmtMoney, windowFor, ApiError, type Budget, type BudgetStatus, type Environment, type Period, type Project } from './api'
import { BudgetChart } from './BudgetChart'
import { Breakdown } from './Breakdown'

const today = () => new Date().toISOString().slice(0, 10)

export function BudgetsView({ tenantId }: { tenantId: string }) {
  const [budgets, setBudgets] = useState<Budget[] | null>(null)
  const [projects, setProjects] = useState<Project[]>([])
  const [envs, setEnvs] = useState<Record<string, Environment[]>>({})
  const [selected, setSelected] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    let stale = false
    ;(async () => {
      try {
        const [bs, ps] = await Promise.all([finops.budgets(tenantId), api.projects(tenantId)])
        const es = Object.fromEntries(await Promise.all(ps.map(async (p) => [p.id, await api.environments(tenantId, p.id)] as const)))
        if (stale) return
        setBudgets(bs)
        setProjects(ps)
        setEnvs(es)
        setSelected((s) => s ?? bs[0]?.id ?? null)
      } catch (e) {
        if (!stale) setError((e as Error).message)
      }
    })()
    return () => {
      stale = true
    }
  }, [tenantId, reload])

  const scope = (b: Budget) => {
    const p = projects.find((x) => x.id === b.project_id)
    const e = b.environment_id ? envs[b.project_id]?.find((x) => x.id === b.environment_id) : null
    return [p?.name ?? 'Project', e ? e.name : 'all environments', b.provider].filter(Boolean).join(' · ')
  }

  if (error) return <p className="notice error">{error}</p>
  if (!budgets) return <p className="muted">Loading budgets…</p>
  const current = budgets.find((b) => b.id === selected)
  return (
    <section>
      {budgets.length > 0 && (
        <div className="toolbar">
          <label className="muted" htmlFor="budget-pick">
            Budget
          </label>
          <select id="budget-pick" value={selected ?? ''} onChange={(e) => setSelected(e.target.value)}>
            {budgets.map((b) => (
              <option key={b.id} value={b.id}>
                {b.name} — {scope(b)} ({b.year})
              </option>
            ))}
          </select>
        </div>
      )}
      {budgets.length === 0 && <p className="muted">No budgets yet.</p>}
      {current && <BudgetDetail key={current.id} tenantId={tenantId} budget={current} scope={scope(current)} />}
      <NewBudget tenantId={tenantId} projects={projects} envs={envs} onCreated={() => setReload((n) => n + 1)} />
    </section>
  )
}

function varianceStatus(st: BudgetStatus) {
  const v = Number(st.variance)
  const toDate = Number(st.budget_to_date) || 1
  const r = v / toDate
  if (r <= 0) return { cls: 'good', icon: '✓', text: 'Under budget' }
  if (r < 0.1) return { cls: 'warning', icon: '!', text: 'Slightly over' }
  if (r < 0.25) return { cls: 'serious', icon: '!', text: 'Over budget' }
  return { cls: 'critical', icon: '✕', text: 'Well over budget' }
}

function BudgetDetail({ tenantId, budget, scope }: { tenantId: string; budget: Budget; scope: string }) {
  const [period, setPeriod] = useState<Period>('month')
  const [date, setDate] = useState(() => {
    const t = today()
    return t.startsWith(String(budget.year)) ? t : `${budget.year}-12-31`
  })
  const [st, setSt] = useState<BudgetStatus | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let stale = false
    finops
      .status(tenantId, budget.id, period, date)
      .then((s) => !stale && (setSt(s), setError(null)))
      .catch((e: Error) => !stale && setError(e.message))
    return () => {
      stale = true
    }
  }, [tenantId, budget.id, period, date])

  // Breakdown covers the same days as "Actual to date": window start through the as-of date.
  const full = windowFor(period, date)
  const dayAfter = new Date(new Date(date + 'T00:00:00Z').getTime() + 86400000).toISOString().slice(0, 10)
  const w = { from: full.from, to: dayAfter < full.to ? dayAfter : full.to }
  const vs = st && varianceStatus(st)
  const windowName = period === 'day' ? 'Today' : period === 'month' ? 'Month' : 'Year'
  return (
    <>
      <div className="toolbar">
        <div className="segmented" role="group" aria-label="Period">
          {(['day', 'month', 'year'] as const).map((p) => (
            <button key={p} aria-pressed={period === p} onClick={() => setPeriod(p)}>
              {p[0].toUpperCase() + p.slice(1)}
            </button>
          ))}
        </div>
        <input type="date" aria-label="As of" value={date} min={`${budget.year}-01-01`} max={`${budget.year}-12-31`} onChange={(e) => e.target.value && setDate(e.target.value)} />
        <span className="muted">{scope} · {budget.cost_basis} cost</span>
      </div>
      {error && <p className="notice error">{error}</p>}
      {st && vs && (
        <>
          <div className="badges">
            {st.providers.map((p) => (
              <span key={p.provider} className={`status ${p.final ? 'good' : 'warning'}`}>
                <span className="dot" aria-hidden />
                {p.provider}: {p.final ? 'data final' : 'data not final'}
              </span>
            ))}
            {st.missing_fx && (
              <span className="status serious">
                <span className="dot" aria-hidden />
                Some spend has no exchange rate yet
              </span>
            )}
          </div>
          <div className="tiles">
            <div className="tile">
              <div className="label">{windowName} budget</div>
              <div className="value">{fmtMoney(st.budget, st.currency)}</div>
              <div className="sub">{fmtMoney(st.budget_to_date)} to date</div>
            </div>
            <div className="tile">
              <div className="label">Actual to date</div>
              <div className="value">{fmtMoney(st.actual, st.currency)}</div>
              <div className={`status ${vs.cls}`}>
                <span aria-hidden>{vs.icon}</span> {vs.text} ({Number(st.variance) > 0 ? '+' : ''}
                {fmtMoney(st.variance)})
              </div>
            </div>
            <div className="tile">
              <div className="label">Forecast at {period === 'year' ? 'year' : 'month'} end</div>
              {period === 'day' ? (
                <div className="sub">Switch to Month or Year</div>
              ) : st.forecast ? (
                <>
                  <div className="value">{fmtMoney(st.forecast, st.currency)}</div>
                  <div className="sub">
                    likely {fmtMoney(st.forecast_p10)} – {fmtMoney(st.forecast_p90)}
                  </div>
                </>
              ) : (
                <div className="sub">Needs 28 days of history ({st.history_days} so far)</div>
              )}
            </div>
            <div className="tile">
              <div className="label">Forecast vs budget</div>
              {st.forecast && period !== 'day' ? (
                <>
                  <div className="value">{Math.round((Number(st.forecast) / Number(st.budget)) * 100)}%</div>
                  <div className="sub">{st.backtest_mape !== undefined ? `backtest error ${(st.backtest_mape * 100).toFixed(1)}%` : 'no backtest yet'}</div>
                </>
              ) : (
                <div className="value">—</div>
              )}
            </div>
          </div>
          {st.series && st.series.length > 0 && <BudgetChart series={st.series} currency={st.currency} unit={period === 'year' ? 'month' : 'day'} />}
          <Breakdown tenantId={tenantId} from={w.from} to={w.to} project={budget.project_id} environment={budget.environment_id ?? undefined} />
        </>
      )}
    </>
  )
}

function NewBudget({ tenantId, projects, envs, onCreated }: { tenantId: string; projects: Project[]; envs: Record<string, Environment[]>; onCreated: () => void }) {
  const [open, setOpen] = useState(false)
  const [project, setProject] = useState('')
  const [env, setEnv] = useState('')
  const [amount, setAmount] = useState('')
  const [year, setYear] = useState(() => new Date().getUTCFullYear())
  const [error, setError] = useState<string | null>(null)
  if (projects.length === 0) return null
  if (!open)
    return (
      <button className="secondary" onClick={() => setOpen(true)}>
        New budget
      </button>
    )
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const p = projects.find((x) => x.id === project)
    const en = envs[project]?.find((x) => x.id === env)
    try {
      await finops.createBudget(tenantId, { project_id: project, ...(env ? { environment_id: env } : {}), name: `${p?.slug}${en ? '-' + en.name : ''} ${year}`, year, amount })
      setOpen(false)
      onCreated()
    } catch (err) {
      setError(err instanceof ApiError && err.status === 403 ? 'You are not allowed to create budgets for this project.' : (err as Error).message)
    }
  }
  return (
    <form className="card inline" onSubmit={submit}>
      <label>
        Project
        <select required value={project} onChange={(e) => (setProject(e.target.value), setEnv(''))}>
          <option value="">Choose…</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </label>
      <label>
        Environment
        <select value={env} onChange={(e) => setEnv(e.target.value)} disabled={!project}>
          <option value="">All environments</option>
          {(envs[project] ?? []).map((e) => (
            <option key={e.id} value={e.id}>
              {e.name}
            </option>
          ))}
        </select>
      </label>
      <label>
        Year
        <input type="number" value={year} min={2000} max={2100} onChange={(e) => setYear(Number(e.target.value))} />
      </label>
      <label>
        Yearly amount
        <input required inputMode="decimal" pattern="\d+(\.\d+)?" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="365000" />
      </label>
      <button className="primary" type="submit">
        Create
      </button>
      {error && <p className="notice error">{error}</p>}
    </form>
  )
}
