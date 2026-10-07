import { useEffect, useState } from 'react'
import { api, delivery, ApiError, type Decision, type Environment, type Flow, type Project, type Promotion, type Release, type ServiceEntry, type Template } from './api'

const stateLabel: Record<string, { cls: string; icon: string }> = {
  succeeded: { cls: 'good', icon: '✓' },
  deployed: { cls: 'good', icon: '✓' },
  running: { cls: 'warning', icon: '…' },
  pr_open: { cls: 'warning', icon: '…' },
  merged: { cls: 'warning', icon: '…' },
  pending_approval: { cls: 'warning', icon: '!' },
  failed: { cls: 'critical', icon: '✕' },
  denied: { cls: 'critical', icon: '✕' },
  closed: { cls: 'serious', icon: '–' },
  cancelled: { cls: 'serious', icon: '–' },
  cancelling: { cls: 'serious', icon: '…' },
}

function State({ s }: { s: string }) {
  const l = stateLabel[s] ?? { cls: 'warning', icon: '?' }
  return (
    <span className={`status ${l.cls}`}>
      <span aria-hidden>{l.icon}</span> {s.replace('_', ' ')}
    </span>
  )
}

const message = (e: unknown) => (e instanceof ApiError && e.status === 403 ? 'You are not allowed to do that here.' : (e as Error).message)

/** Delivery: services from templates, releases and promotions, and the durable flows behind them (#95). */
export function DeliveryView({ tenantId }: { tenantId: string }) {
  const [projects, setProjects] = useState<Project[]>([])
  const [envs, setEnvs] = useState<Environment[]>([])
  const [services, setServices] = useState<ServiceEntry[]>([])
  const [templates, setTemplates] = useState<Template[]>([])
  const [releases, setReleases] = useState<Release[]>([])
  const [promotions, setPromotions] = useState<Promotion[]>([])
  const [flows, setFlows] = useState<Flow[]>([])
  const [error, setError] = useState<string | null>(null)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    let stale = false
    const ok = <T,>(p: Promise<T>, fallback: T) => p.catch(() => fallback)
    Promise.all([
      api.projects(tenantId),
      ok(delivery.services(tenantId), []),
      ok(delivery.templates(tenantId), []),
      ok(delivery.releases(tenantId), []),
      ok(delivery.promotions(tenantId), []),
      ok(delivery.flows(tenantId), []),
    ])
      .then(async ([ps, ss, ts, rs, prs, fs]) => {
        const es = (await Promise.all(ps.map((p) => ok(api.environments(tenantId, p.id), [])))).flat()
        const full = await Promise.all(fs.slice(0, 10).map((f) => ok(delivery.flow(tenantId, f.id), f)))
        if (stale) return
        setProjects(ps)
        setEnvs(es)
        setServices(ss)
        setTemplates(ts)
        setReleases(rs)
        setPromotions(prs)
        setFlows(full)
        setError(null)
      })
      .catch((e: Error) => !stale && setError(e.message))
    return () => {
      stale = true
    }
  }, [tenantId, reload])

  const again = () => setReload((n) => n + 1)
  const svc = (id: string) => services.find((s) => s.id === id)
  const env = (id: string) => envs.find((e) => e.id === id)
  const release = (id: string) => releases.find((r) => r.id === id)

  const approve = async (p: Promotion) => {
    try {
      await delivery.approve(tenantId, p.id)
      again()
    } catch (e) {
      setError(message(e))
    }
  }
  const retry = async (f: Flow) => {
    try {
      await delivery.retryFlow(tenantId, f.id)
      again()
    } catch (e) {
      setError(message(e))
    }
  }

  const pending = promotions.filter((p) => p.state === 'pending_approval')
  return (
    <section className="delivery">
      {error && <p className="notice error">{error}</p>}
      {pending.length > 0 && (
        <>
          <h2>Awaiting approval</h2>
          {pending.map((p) => {
            const r = release(p.release_id)
            return (
              <article key={p.id} className="card finding">
                <strong>
                  {svc(r?.service_id ?? '')?.name ?? 'Release'} {r?.version} → {env(p.environment_id)?.name ?? 'environment'}
                </strong>
                <span className="meta">Requested by {p.requested_by.replace(/^user:/, '')} · policy {p.decision.policy}: allowed</span>
                <button className="primary" onClick={() => approve(p)}>
                  Approve promotion
                </button>
              </article>
            )
          })}
        </>
      )}

      <h2>Releases</h2>
      {releases.length === 0 && <p className="muted">No releases yet. CI creates them after a signed build.</p>}
      {releases.map((r) => (
        <ReleaseCard key={r.id} tenantId={tenantId} release={r} service={svc(r.service_id)} envs={envs.filter((e) => e.project_id === svc(r.service_id)?.project_id)} onDone={again} onError={(m) => setError(m)} />
      ))}

      {promotions.length > 0 && (
        <>
          <h2>Promotions</h2>
          {promotions.map((p) => {
            const r = release(p.release_id)
            return (
              <article key={p.id} className="card finding">
                <State s={p.state} />
                <strong>
                  {svc(r?.service_id ?? '')?.slug ?? 'release'} {r?.version} → {env(p.environment_id)?.name ?? 'environment'}
                </strong>
                {p.decision.reasons.length > 0 && <span className="meta">Denied: {p.decision.reasons.join('; ')}</span>}
                {p.error && <span className="meta">{p.error}</span>}
                {p.pr_url && (
                  <a href={p.pr_url} target="_blank" rel="noopener noreferrer">
                    Pull request
                  </a>
                )}
              </article>
            )
          })}
        </>
      )}

      <h2>Runs</h2>
      {flows.length === 0 && <p className="muted">No vending or service-creation runs.</p>}
      {flows.map((f) => (
        <article key={f.id} className="card finding">
          <State s={f.state} />
          <strong>
            {f.kind.replaceAll('_', ' ')} · {f.subject}
          </strong>
          {f.steps && (
            <span className="meta">
              {f.steps.map((s) => `${s.name} ${s.state === 'succeeded' ? '✓' : s.state === 'failed' ? '✕' : s.state === 'running' ? '…' : '·'}`).join('  ')}
            </span>
          )}
          {f.error && <span className="meta">Stopped at {f.error}</span>}
          {f.state === 'failed' && (
            <button className="link" onClick={() => retry(f)}>
              Retry from the failed step
            </button>
          )}
        </article>
      ))}

      {templates.length > 0 && projects.length > 0 && <NewService tenantId={tenantId} projects={projects} templates={templates} onDone={again} onError={(m) => setError(m)} />}
    </section>
  )
}

function ReleaseCard({ tenantId, release, service, envs, onDone, onError }: {
  tenantId: string
  release: Release
  service?: ServiceEntry
  envs: Environment[]
  onDone: () => void
  onError: (m: string) => void
}) {
  const [target, setTarget] = useState('')
  const [decision, setDecision] = useState<Decision | null>(null)

  const check = async (env: string) => {
    setTarget(env)
    setDecision(null)
    if (!env) return
    try {
      setDecision(await delivery.preview(tenantId, release.id, env))
    } catch (e) {
      onError(message(e))
    }
  }
  const promote = async () => {
    try {
      await delivery.promote(tenantId, release.id, target)
      setDecision(null)
      setTarget('')
      onDone()
    } catch (e) {
      onError(message(e))
    }
  }
  return (
    <article className="card finding">
      <strong>
        {service?.name ?? 'Service'} {release.version}
      </strong>
      <span className="meta">{release.images.map((i) => `${i.name}@${i.digest.slice(0, 19)}…`).join(', ')}</span>
      <div className="toolbar">
        <label>
          Promote to{' '}
          <select value={target} onChange={(e) => check(e.target.value)}>
            <option value="">Choose an environment</option>
            {envs.map((e) => (
              <option key={e.id} value={e.id}>
                {e.name}
              </option>
            ))}
          </select>
        </label>
        {decision && (
          <button className="primary" disabled={!decision.allow} onClick={promote}>
            {decision.needs_approval ? 'Request promotion' : 'Promote'}
          </button>
        )}
      </div>
      {decision && !decision.allow && <span className="status critical">✕ Blocked by {decision.policy}: {decision.reasons.join('; ')}</span>}
      {decision?.allow && decision.needs_approval && <span className="status warning">! Allowed; a Tenant Approver must approve before the pull request opens</span>}
      {decision?.allow && !decision.needs_approval && <span className="status good">✓ Allowed by {decision.policy}; promoting opens a pull request</span>}
    </article>
  )
}

function NewService({ tenantId, projects, templates, onDone, onError }: { tenantId: string; projects: Project[]; templates: Template[]; onDone: () => void; onError: (m: string) => void }) {
  const [project, setProject] = useState(projects[0]?.id ?? '')
  const [template, setTemplate] = useState(templates[0]?.name ?? '')
  const [slug, setSlug] = useState('')
  const [tier, setTier] = useState('nonprod')
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await delivery.createService(tenantId, project, { slug, title: slug, template, tier })
      setSlug('')
      onDone()
    } catch (err) {
      onError(message(err))
    }
  }
  return (
    <form className="card" onSubmit={submit}>
      <h2>New service</h2>
      <div className="toolbar">
        <label>
          Project{' '}
          <select value={project} onChange={(e) => setProject(e.target.value)}>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Template{' '}
          <select value={template} onChange={(e) => setTemplate(e.target.value)}>
            {templates.map((t) => (
              <option key={t.name} value={t.name}>
                {t.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Name{' '}
          <input value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="crm-api" pattern="[a-z0-9][a-z0-9-]*" required />
        </label>
        <label>
          Tier{' '}
          <select value={tier} onChange={(e) => setTier(e.target.value)}>
            <option value="nonprod">nonprod</option>
            <option value="prod">prod</option>
            <option value="sandbox">sandbox</option>
          </select>
        </label>
        <button className="primary" type="submit">
          Create repository and service
        </button>
      </div>
    </form>
  )
}
