import { useEffect, useState } from 'react'
import { accessApi, api, finops, ApiError, type AccessGrant, type AccessRole, type AccessTemplate, type Environment, type Finding, type Team } from './api'

const message = (e: unknown) => (e instanceof ApiError && e.status === 403 ? 'You are not allowed to do that here.' : (e as Error).message)
const time = (iso: string) => new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })

/** Access: eligible roles, time-boxed Access Grants, approvals and standing access (#138). */
export function AccessView({ tenantId }: { tenantId: string }) {
  const [templates, setTemplates] = useState<AccessTemplate[]>([])
  const [roles, setRoles] = useState<AccessRole[]>([])
  const [grants, setGrants] = useState<AccessGrant[]>([])
  const [envs, setEnvs] = useState<Environment[]>([])
  const [teams, setTeams] = useState<Team[]>([])
  const [standing, setStanding] = useState<Finding[]>([])
  const [error, setError] = useState<string | null>(null)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    let stale = false
    const ok = <T,>(p: Promise<T>, fallback: T) => p.catch(() => fallback)
    Promise.all([ok(accessApi.templates(tenantId), []), ok(accessApi.roles(tenantId), []), ok(accessApi.grants(tenantId), []), ok(accessApi.teams(tenantId), []), ok(api.projects(tenantId), []), ok(finops.findings(tenantId), [])])
      .then(async ([ts, rs, gs, tm, ps, fs]) => {
        const es = (await Promise.all(ps.map((p) => ok(api.environments(tenantId, p.id), [])))).flat()
        if (stale) return
        setTemplates(ts)
        setRoles(rs)
        setGrants(gs)
        setTeams(tm)
        setEnvs(es)
        setStanding(fs.filter((f) => f.kind === 'standing_access'))
      })
      .catch((e: Error) => !stale && setError(e.message))
    return () => {
      stale = true
    }
  }, [tenantId, reload])

  const again = () => setReload((n) => n + 1)
  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn()
      again()
    } catch (e) {
      setError(message(e))
    }
  }
  const env = (id: string) => envs.find((e) => e.id === id)?.name ?? 'environment'
  const team = (id: string) => teams.find((t) => t.id === id)?.name ?? 'team'
  const role = (id: string) => roles.find((r) => r.id === id)
  const label = (r?: AccessRole) => (r ? `${r.template} in ${env(r.environment_id)}` : 'role')

  const pending = grants.filter((g) => g.state === 'requested')
  const active = grants.filter((g) => g.state === 'active')
  return (
    <section className="delivery">
      {error && <p className="notice error">{error}</p>}

      {standing.length > 0 && (
        <>
          <h2>Standing production access</h2>
          {standing.map((f) => (
            <article key={f.id} className="card finding">
              <span className="status critical">✕ Critical</span>
              <strong>{f.title}</strong>
            </article>
          ))}
        </>
      )}

      <h2>Request access</h2>
      <GrantForm roles={roles.filter((r) => r.state === 'active')} label={label} templates={templates} onSubmit={(b) => act(() => accessApi.requestGrant(tenantId, b))} />

      {pending.length > 0 && <h2>Waiting for approval</h2>}
      {pending.map((g) => (
        <article key={g.id} className="card finding">
          <strong>
            {g.requester.replace(/^user:/, '')}: {label(role(g.role_id))} for {g.hours}h
          </strong>
          <span className="meta">
            {g.reason} · needs {g.decision.approvals.join(' + ')} · approved by {g.approvals.length ? g.approvals.map((a) => `${a.by.replace(/^user:/, '')} (${a.role})`).join(', ') : 'nobody yet'}
          </span>
          <div className="toolbar">
            <button className="primary" onClick={() => act(() => accessApi.approve(tenantId, g.id))}>
              Approve access
            </button>
            <button
              className="link"
              onClick={() => {
                const why = window.prompt('Why is this rejected?')
                if (why) void act(() => accessApi.reject(tenantId, g.id, why))
              }}
            >
              Reject
            </button>
          </div>
        </article>
      ))}

      <h2>Active grants</h2>
      {active.length === 0 && <p className="muted">Nobody holds access right now.</p>}
      {active.map((g) => (
        <article key={g.id} className="card finding">
          <span className="status warning">! active</span>
          <strong>
            {g.requester.replace(/^user:/, '')}: {label(role(g.role_id))}
          </strong>
          <span className="meta">
            until {g.expires_at ? time(g.expires_at) : '—'} · {g.reason}
          </span>
          <button
            className="link"
            onClick={() => {
              const why = window.prompt('Why end this early?')
              if (why) void act(() => accessApi.revoke(tenantId, g.id, why))
            }}
          >
            Revoke now
          </button>
        </article>
      ))}

      <h2>Eligible roles</h2>
      {roles.map((r) => (
        <article key={r.id} className="card finding">
          <span className={`status ${r.state === 'active' ? 'good' : r.state === 'requested' ? 'warning' : 'serious'}`}>{r.state}</span>
          <strong>
            {team(r.team_id)} · {label(r)}
          </strong>
          {r.state === 'requested' && (
            <div className="toolbar">
              <button className="primary" onClick={() => act(() => accessApi.decideRole(tenantId, r.id, true))}>
                Approve eligibility
              </button>
              <button className="link" onClick={() => act(() => accessApi.decideRole(tenantId, r.id, false))}>
                Deny
              </button>
            </div>
          )}
        </article>
      ))}
      {teams.length > 0 && envs.length > 0 && templates.length > 0 && (
        <RoleForm teams={teams} envs={envs} templates={templates} onSubmit={(b) => act(() => accessApi.requestRole(tenantId, b))} />
      )}
    </section>
  )
}

function GrantForm({ roles, label, templates, onSubmit }: { roles: AccessRole[]; label: (r?: AccessRole) => string; templates: AccessTemplate[]; onSubmit: (b: { role_id: string; hours: number; reason: string }) => void }) {
  const [roleId, setRoleId] = useState(roles[0]?.id ?? '')
  const [hours, setHours] = useState(1)
  const [reason, setReason] = useState('')
  const selected = roles.find((r) => r.id === (roleId || roles[0]?.id))
  const max = templates.find((t) => t.name === selected?.template)?.max_hours ?? 8
  if (roles.length === 0) return <p className="muted">No eligible roles yet. A Team Lead requests them below.</p>
  return (
    <form
      className="card toolbar"
      onSubmit={(e) => {
        e.preventDefault()
        onSubmit({ role_id: roleId || roles[0].id, hours, reason })
        setReason('')
      }}
    >
      <label>
        Role{' '}
        <select value={roleId || roles[0].id} onChange={(e) => setRoleId(e.target.value)}>
          {roles.map((r) => (
            <option key={r.id} value={r.id}>
              {label(r)}
            </option>
          ))}
        </select>
      </label>
      <label>
        Hours <input type="number" min={1} max={max} value={hours} onChange={(e) => setHours(Number(e.target.value))} />
      </label>
      <label>
        Reason <input value={reason} onChange={(e) => setReason(e.target.value)} minLength={10} placeholder="incident or ticket" required />
      </label>
      <button className="primary" type="submit">
        Request access
      </button>
    </form>
  )
}

function RoleForm({ teams, envs, templates, onSubmit }: { teams: Team[]; envs: Environment[]; templates: AccessTemplate[]; onSubmit: (b: { environment_id: string; team_id: string; template: string }) => void }) {
  const [teamId, setTeamId] = useState(teams[0].id)
  const [envId, setEnvId] = useState(envs[0].id)
  const [template, setTemplate] = useState(templates[0].name)
  return (
    <form
      className="card toolbar"
      onSubmit={(e) => {
        e.preventDefault()
        onSubmit({ environment_id: envId, team_id: teamId, template })
      }}
    >
      <label>
        Team{' '}
        <select value={teamId} onChange={(e) => setTeamId(e.target.value)}>
          {teams.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </select>
      </label>
      <label>
        Environment{' '}
        <select value={envId} onChange={(e) => setEnvId(e.target.value)}>
          {envs.map((e) => (
            <option key={e.id} value={e.id}>
              {e.name}
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
              {t.write ? ' (write)' : ''}
            </option>
          ))}
        </select>
      </label>
      <button className="primary" type="submit">
        Make eligible
      </button>
    </form>
  )
}
