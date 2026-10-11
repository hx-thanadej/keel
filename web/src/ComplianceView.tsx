import { useEffect, useState } from 'react'
import {
  compliance,
  frameworks,
  insights,
  monthStarts,
  saveDownload,
  ApiError,
  type Breach,
  type ControlReport,
  type ControlView,
  type FrameworkId,
  type PdpaChange,
  type PdpaOverview,
  type RetentionMode,
} from './api'

/** A section's data: loading, failed with a message, or loaded. Only a loaded section may show an empty state. */
type Loaded<T> = { state: 'loading' } | { state: 'error'; message: string } | { state: 'ok'; data: T }

const loadMessage = (e: unknown) => (e instanceof ApiError && e.status === 403 ? 'You are not allowed to see this here.' : (e as Error).message)
const actionMessage = (e: unknown) => (e instanceof ApiError && e.status === 403 ? 'You are not allowed to do that here.' : (e as Error).message)
const day = (iso: string) => new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) + ' UTC'

function load<T>(p: Promise<T>, set: (l: Loaded<T>) => void, stale: () => boolean) {
  set({ state: 'loading' })
  p.then(
    (data) => !stale() && set({ state: 'ok', data }),
    (e) => !stale() && set({ state: 'error', message: loadMessage(e) }),
  )
}

const SectionError = ({ text }: { text?: string }) => (text ? <p className="notice error" role="alert">{text}</p> : null)

/** Compliance: per-framework Control coverage with gaps, evidence export, and PDPA state (#192). */
export function ComplianceView({ tenantId, canConfigure, onOpenFinding }: { tenantId: string; canConfigure: boolean; onOpenFinding: (id: string) => void }) {
  const [framework, setFramework] = useState<FrameworkId>('iso27001')
  const [report, setReport] = useState<Loaded<ControlReport>>({ state: 'loading' })

  useEffect(() => {
    let stale = false
    load(compliance.controls(tenantId), setReport, () => stale)
    return () => {
      stale = true
    }
  }, [tenantId])

  return (
    <section className="delivery">
      <div className="toolbar">
        <label>
          Framework{' '}
          <select value={framework} onChange={(e) => setFramework(e.target.value as FrameworkId)}>
            {frameworks.map(([id, name]) => (
              <option key={id} value={id}>
                {name}
              </option>
            ))}
          </select>
        </label>
      </div>

      <h2>Controls</h2>
      {report.state === 'loading' && <p className="muted">Loading controls…</p>}
      <SectionError text={report.state === 'error' ? report.message : undefined} />
      {report.state === 'ok' && <Controls report={report.data} framework={framework} onOpenFinding={onOpenFinding} />}

      <h2>Evidence export</h2>
      <Evidence key={framework} tenantId={tenantId} framework={framework} />

      {framework === 'pdpa' && <Pdpa tenantId={tenantId} canConfigure={canConfigure} />}
    </section>
  )
}

const statusOf = (c: ControlView) => (c.gap ? { cls: 'critical', text: '✕ Gap' } : { cls: 'good', text: '✓ Covered' })
const gapReason = (c: ControlView) => c.gap_reason ?? (c.gap ? 'Mapped to a Keel policy that has not covered any Service yet' : '')

function OpenFindings({ open, onOpen }: { open: ControlView['open_findings']; onOpen: (id: string) => void }) {
  if (open.count === 0) return <>None open</>
  const more = open.count - open.items.length
  return (
    <>
      <span>{open.count} open</span>
      <ul className="plain">
        {open.items.map((f) => (
          <li key={f.id}>
            <a
              href={`#finding-${f.id}`}
              onClick={(e) => {
                e.preventDefault()
                onOpen(f.id)
              }}
            >
              {f.severity[0].toUpperCase() + f.severity.slice(1)}: {f.title}
            </a>
          </li>
        ))}
      </ul>
      {more > 0 && <span className="meta">and {more} more</span>}
    </>
  )
}

function Controls({ report, framework, onOpenFinding }: { report: ControlReport; framework: FrameworkId; onOpenFinding: (id: string) => void }) {
  const [gapsOnly, setGapsOnly] = useState(false)
  const summary = report.frameworks.find((f) => f.id.toLowerCase() === framework)
  if (!summary) return <p className="muted">Keel maps no Controls to this framework yet.</p>
  const all = report.controls.filter((c) => c.framework === summary.id)
  const shown = gapsOnly ? all.filter((c) => c.gap) : all
  return (
    <>
      <p className="meta" role="status">
        {summary.name}: {summary.covered} of {summary.controls} controls covered, {summary.gaps} {summary.gaps === 1 ? 'gap' : 'gaps'}. {summary.mapped} mapped to a Keel policy,
        across {report.services} {report.services === 1 ? 'service' : 'services'}.
      </p>
      <label>
        <input type="checkbox" checked={gapsOnly} onChange={(e) => setGapsOnly(e.target.checked)} /> Show gaps only
      </label>
      {shown.length === 0 ? (
        <p className="muted">{gapsOnly ? 'No gaps in this framework.' : 'No Controls in this framework.'}</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table controls">
            <caption className="muted">{summary.name} Controls</caption>
            <thead>
              <tr>
                <th scope="col">Control</th>
                <th scope="col">Status</th>
                <th scope="col">Keel policies (services covered)</th>
                <th scope="col">Open findings</th>
                <th scope="col">Gap reason</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((c) => {
                const st = statusOf(c)
                return (
                  <tr key={c.id}>
                    <th scope="row">
                      {c.id} {c.title}
                    </th>
                    <td>
                      <span className={`status ${st.cls}`}>{st.text}</span>
                    </td>
                    <td>{c.coverage.length === 0 ? 'None' : c.coverage.map((p) => `${p.name} @${p.point} (${p.covered_services})`).join(', ')}</td>
                    <td>
                      <OpenFindings open={c.open_findings} onOpen={onOpenFinding} />
                    </td>
                    <td>{gapReason(c)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

function Evidence({ tenantId, framework }: { tenantId: string; framework: FrameworkId }) {
  const [from, setFrom] = useState(monthStarts(3)[0])
  const [to, setTo] = useState(monthStarts(1)[1])
  const [error, setError] = useState<string>()
  const url = insights.evidenceURL(tenantId, from, to, framework)
  const name = frameworks.find(([id]) => id === framework)?.[1]
  const exportEvidence = () => {
    setError(undefined)
    saveDownload(url, `keel-evidence-${framework}-${from}-${to}.json`).catch((e) => setError(actionMessage(e)))
  }
  return (
    <>
      <div className="toolbar">
        <label>
          From <input type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
        </label>
        <label>
          To <input type="date" value={to} onChange={(e) => setTo(e.target.value)} />
        </label>
        <button type="button" className="primary" onClick={exportEvidence}>
          Export {name} evidence
        </button>
      </div>
      <SectionError text={error} />
    </>
  )
}

const openStates = new Set(['declared', 'warning', 'deadline'])
const clockText: Record<string, string> = {
  declared: 'Clock running',
  warning: 'Warning: over 48 hours since aware',
  deadline: 'Deadline passed',
}

function timeLeft(b: Breach, now: number) {
  const h = Math.round((Date.parse(b.notify_by) - now) / 3600000)
  return h >= 0 ? `${h} h left to notify the PDPC` : `${-h} h overdue`
}

const modeText: Record<RetentionMode, string> = {
  dry_run: 'Dry run, nothing deleted',
  deleted: 'Deleted expired data',
  held: 'Held, nothing deleted',
}

function Pdpa({ tenantId, canConfigure }: { tenantId: string; canConfigure: boolean }) {
  const [overview, setOverview] = useState<Loaded<PdpaOverview & { fetchedAt: number }>>({ state: 'loading' })
  const [reload, setReload] = useState(0)
  const [actionError, setActionError] = useState<string>()

  useEffect(() => {
    let stale = false
    load(compliance.pdpa(tenantId).then((o) => ({ ...o, fetchedAt: Date.now() })), setOverview, () => stale)
    return () => {
      stale = true
    }
  }, [tenantId, reload])

  const change = async (c: PdpaChange) => {
    setActionError(undefined)
    try {
      await compliance.configurePdpa(tenantId, c)
      setReload((n) => n + 1)
      return true
    } catch (e) {
      setActionError(actionMessage(e))
      return false
    }
  }

  if (overview.state !== 'ok') {
    return (
      <>
        <h2>PDPA</h2>
        {overview.state === 'loading' && <p className="muted">Loading PDPA state…</p>}
        <SectionError text={overview.state === 'error' ? overview.message : undefined} />
      </>
    )
  }
  const { settings, last_retention_run: run } = overview.data
  const open = (overview.data.breaches ?? []).filter((b) => openStates.has(b.state))
  return (
    <>
      <h2>PDPA data residency and retention</h2>
      <dl className="meta">
        <dt>Data region</dt>
        <dd>{settings.data_regions.join(', ')}</dd>
        <dt>Legal hold</dt>
        <dd>{settings.legal_hold ? `In place: ${settings.legal_hold}` : 'None'}</dd>
        <dt>Deletion</dt>
        <dd>{settings.deletion_enabled ? 'Enabled: retention deletes expired data' : 'Off: retention runs are dry runs'}</dd>
      </dl>
      {canConfigure && <PdpaSettingsForm key={reload} settings={settings} onChange={change} />}
      <SectionError text={actionError} />

      <h3>Open breaches</h3>
      {open.length === 0 && <p className="muted">No open personal data breaches.</p>}
      {open.map((b) => (
        <article key={b.id} className="card finding">
          <strong>{b.title}</strong>
          <span className={`status ${b.state === 'declared' ? 'warning' : 'critical'}`}>{clockText[b.state]}</span>
          <span className="meta">
            Notify by {day(b.notify_by)} · {timeLeft(b, overview.data.fetchedAt)}
          </span>
        </article>
      ))}

      <h3>Last retention run</h3>
      {run ? (
        <p className="meta">
          {day(run.ran_at)}: {modeText[run.mode] ?? run.mode}. {run.detail}
        </p>
      ) : (
        <p className="muted">Retention has not run yet.</p>
      )}
    </>
  )
}

function PdpaSettingsForm({ settings, onChange }: { settings: PdpaOverview['settings']; onChange: (c: PdpaChange) => Promise<boolean> }) {
  const [regions, setRegions] = useState(settings.data_regions.join(', '))
  const [deletion, setDeletion] = useState(settings.deletion_enabled)
  const [holdReason, setHoldReason] = useState('')
  const [liftReason, setLiftReason] = useState('')

  const saveSettings = (e: React.FormEvent) => {
    e.preventDefault()
    void onChange({ data_regions: regions.split(',').map((r) => r.trim()).filter(Boolean), deletion_enabled: deletion })
  }
  const hold = (e: React.FormEvent) => {
    e.preventDefault()
    const reason = (settings.legal_hold ? liftReason : holdReason).trim()
    void onChange(settings.legal_hold ? { legal_hold: '', lift_reason: reason } : { legal_hold: reason })
  }
  return (
    <>
      <form className="card toolbar" onSubmit={saveSettings}>
        <label>
          Data regions <input value={regions} onChange={(e) => setRegions(e.target.value)} required />
        </label>
        <label>
          <input type="checkbox" checked={deletion} onChange={(e) => setDeletion(e.target.checked)} /> Allow retention to delete expired data
        </label>
        <button className="primary" type="submit">
          Save PDPA settings
        </button>
      </form>
      <form className="card toolbar" onSubmit={hold}>
        {settings.legal_hold ? (
          <>
            <label>
              Reason for lifting the hold <input value={liftReason} onChange={(e) => setLiftReason(e.target.value)} required pattern=".*\S.*" maxLength={500} />
            </label>
            <button type="submit">Lift legal hold</button>
          </>
        ) : (
          <>
            <label>
              Legal hold reason <input value={holdReason} onChange={(e) => setHoldReason(e.target.value)} required pattern=".*\S.*" maxLength={500} />
            </label>
            <button type="submit">Place legal hold</button>
          </>
        )}
      </form>
    </>
  )
}
