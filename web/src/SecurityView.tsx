import { useEffect, useState } from 'react'
import { delivery, security, ApiError, type Attestation, type ControlReport, type Exception, type Release, type ServiceEntry, type VexStatement } from './api'

const justifications = [
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
]

const message = (e: unknown) => (e instanceof ApiError && e.status === 403 ? 'You are not allowed to do that here.' : (e as Error).message)

/** Security: Controls coverage, Exceptions, VEX and release provenance (#117). */
export function SecurityView({ tenantId }: { tenantId: string }) {
  const [controls, setControls] = useState<ControlReport | null>(null)
  const [exceptions, setExceptions] = useState<Exception[]>([])
  const [vex, setVex] = useState<VexStatement[]>([])
  const [services, setServices] = useState<ServiceEntry[]>([])
  const [releases, setReleases] = useState<Release[]>([])
  const [attestations, setAttestations] = useState<Record<string, Attestation[]>>({})
  const [error, setError] = useState<string | null>(null)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    let stale = false
    const ok = <T,>(p: Promise<T>, fallback: T) => p.catch(() => fallback)
    Promise.all([ok(security.controls(tenantId), null), ok(security.exceptions(tenantId), []), ok(security.vex(tenantId), []), ok(delivery.services(tenantId), []), ok(delivery.releases(tenantId), [])])
      .then(async ([c, ex, vx, ss, rs]) => {
        const recent = rs.slice(0, 8)
        const att = await Promise.all(recent.map((r) => ok(security.attestations(tenantId, r.id), [])))
        if (stale) return
        setControls(c)
        setExceptions(ex)
        setVex(vx)
        setServices(ss)
        setReleases(recent)
        setAttestations(Object.fromEntries(recent.map((r, i) => [r.id, att[i]])))
      })
      .catch((e: Error) => !stale && setError(e.message))
    return () => {
      stale = true
    }
  }, [tenantId, reload])

  const again = () => setReload((n) => n + 1)
  const fail = (e: unknown) => setError(message(e))
  const svc = (id: string) => services.find((s) => s.id === id)

  const decide = async (e: Exception, d: 'approve' | 'reject') => {
    const note = window.prompt(d === 'approve' ? 'Approval note (why the risk is accepted)' : 'Why is this rejected?') ?? ''
    if (d === 'reject' && !note) return
    try {
      await security.decideException(tenantId, e.id, d, note)
      again()
    } catch (err) {
      fail(err)
    }
  }

  const gaps = controls?.controls.filter((c) => c.gap).length ?? 0
  return (
    <section className="delivery">
      {error && <p className="notice error">{error}</p>}

      <h2>Releases: provenance</h2>
      {releases.length === 0 && <p className="muted">No releases yet.</p>}
      {releases.map((r) => {
        const latest = attestations[r.id]?.[0]
        return (
          <article key={r.id} className="card finding">
            <strong>
              {svc(r.service_id)?.name ?? 'Service'} {r.version}
            </strong>
            {!latest && <span className="status warning">! No provenance submitted; promotion is blocked</span>}
            {latest && (
              <span className={`status ${latest.passed ? 'good' : 'critical'}`}>
                {latest.passed ? '✓ VSA passed' : '✕ VSA failed: ' + latest.checks.filter((c) => !c.pass).map((c) => c.name).join(', ')}
              </span>
            )}
            {latest && !latest.passed && (
              <span className="meta">
                {latest.checks
                  .filter((c) => !c.pass)
                  .map((c) => c.detail)
                  .join(' · ')}
              </span>
            )}
          </article>
        )
      })}

      <h2>Exceptions</h2>
      {exceptions.length === 0 && <p className="muted">No Exceptions.</p>}
      {exceptions.map((e) => (
        <article key={e.id} className="card finding">
          <span className={`status ${e.state === 'approved' ? 'warning' : e.state === 'requested' ? 'serious' : 'good'}`}>{e.state}</span>
          <strong>{e.fingerprint || `${e.finding_ids.length} Finding(s)`}</strong>
          <span className="meta">
            {e.reason} · requested by {e.requested_by.replace(/^user:/, '')} · until {new Date(e.expires_at).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}
          </span>
          {e.state === 'requested' && (
            <div className="toolbar">
              <button className="primary" onClick={() => decide(e, 'approve')}>
                Approve exception
              </button>
              <button className="link" onClick={() => decide(e, 'reject')}>
                Reject
              </button>
            </div>
          )}
        </article>
      ))}
      <ExceptionForm tenantId={tenantId} onDone={again} onError={fail} />

      <h2>VEX</h2>
      {vex.map((v) => (
        <article key={v.id} className="card finding">
          <strong>
            {v.vulnerability} · {svc(v.service_id)?.slug ?? 'service'}: {v.status.replaceAll('_', ' ')}
          </strong>
          <span className="meta">{v.justification?.replaceAll('_', ' ') ?? v.impact_statement ?? v.action_statement}</span>
        </article>
      ))}
      {services.length > 0 && <VexForm tenantId={tenantId} services={services} onDone={again} onError={fail} />}

      <h2>
        Controls {controls && <span className="badge">{controls.version}</span>}
      </h2>
      {controls && (
        <p className="meta">
          {controls.controls.length} controls, {gaps} without coverage, across {controls.services} services.
        </p>
      )}
      {controls && (
        <ul className="meta">
          {controls.frameworks.map((f) => (
            <li key={f.id}>
              {f.name}: {f.covered} of {f.controls} covered, {f.mapped} mapped to a Keel policy
            </li>
          ))}
        </ul>
      )}
      {controls && (
        <div className="table-wrap">
          <table className="data-table controls">
            <thead>
              <tr>
                <th>Control</th>
                <th>Policies (services covered)</th>
              </tr>
            </thead>
            <tbody>
              {controls.controls.map((c) => (
                <tr key={c.framework + c.id}>
                  <td>
                    <span className={`status ${c.gap ? 'critical' : 'good'}`}>{c.gap ? '✕' : '✓'}</span> {c.framework} {c.id} — {c.title}
                  </td>
                  <td>{c.coverage.length === 0 ? `no Keel policy: ${c.gap_reason ?? 'not yet mapped'}` : c.coverage.map((p) => `${p.name} @${p.point} (${p.covered_services})`).join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function ExceptionForm({ tenantId, onDone, onError }: { tenantId: string; onDone: () => void; onError: (e: unknown) => void }) {
  const [fingerprint, setFingerprint] = useState('')
  const [reason, setReason] = useState('')
  const [days, setDays] = useState(30)
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await security.requestException(tenantId, { fingerprint, reason, expires_at: new Date(Date.now() + days * 86400000).toISOString() })
      setFingerprint('')
      setReason('')
      onDone()
    } catch (err) {
      onError(err)
    }
  }
  return (
    <form className="card toolbar" onSubmit={submit}>
      <label>
        Findings{' '}
        <input value={fingerprint} onChange={(e) => setFingerprint(e.target.value)} placeholder="vuln:CVE-2026-1234:" required />
      </label>
      <label>
        Reason <input value={reason} onChange={(e) => setReason(e.target.value)} minLength={10} required />
      </label>
      <label>
        Days{' '}
        <input type="number" min={1} max={90} value={days} onChange={(e) => setDays(Number(e.target.value))} />
      </label>
      <button className="primary" type="submit">
        Request exception
      </button>
    </form>
  )
}

function VexForm({ tenantId, services, onDone, onError }: { tenantId: string; services: ServiceEntry[]; onDone: () => void; onError: (e: unknown) => void }) {
  const [vulnerability, setVulnerability] = useState('')
  const [service, setService] = useState(services[0]?.id ?? '')
  const [status, setStatus] = useState('not_affected')
  const [justification, setJustification] = useState('')
  const [statement, setStatement] = useState('')
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await security.recordVex(tenantId, {
        vulnerability,
        service_id: service,
        status,
        justification: justification || undefined,
        impact_statement: status === 'not_affected' && statement ? statement : undefined,
        action_statement: status === 'affected' ? statement : undefined,
      })
      setVulnerability('')
      setStatement('')
      onDone()
    } catch (err) {
      onError(err)
    }
  }
  return (
    <form className="card toolbar" onSubmit={submit}>
      <label>
        Vulnerability <input value={vulnerability} onChange={(e) => setVulnerability(e.target.value)} placeholder="CVE-2026-1234" required />
      </label>
      <label>
        Service{' '}
        <select value={service} onChange={(e) => setService(e.target.value)}>
          {services.map((s) => (
            <option key={s.id} value={s.id}>
              {s.slug}
            </option>
          ))}
        </select>
      </label>
      <label>
        Status{' '}
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="not_affected">not affected</option>
          <option value="affected">affected</option>
          <option value="fixed">fixed</option>
          <option value="under_investigation">under investigation</option>
        </select>
      </label>
      {status === 'not_affected' && (
        <label>
          Justification{' '}
          <select value={justification} onChange={(e) => setJustification(e.target.value)} required={!statement}>
            <option value="">Choose…</option>
            {justifications.map((j) => (
              <option key={j} value={j}>
                {j.replaceAll('_', ' ')}
              </option>
            ))}
          </select>
        </label>
      )}
      {(status === 'not_affected' || status === 'affected') && (
        <label>
          {status === 'affected' ? 'Action' : 'Impact'}{' '}
          <input value={statement} onChange={(e) => setStatement(e.target.value)} required={status === 'affected'} />
        </label>
      )}
      <button className="primary" type="submit">
        Record VEX statement
      </button>
    </form>
  )
}
