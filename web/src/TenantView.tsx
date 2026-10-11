import { useEffect, useId, useState } from 'react'
import { api, ApiError, type CloudAccount, type Environment, type Project, type ReadOnlyRole, type RoleHealth, type Tenant } from './api'
import { accountsIn, grantsBlocking, ownershipOf, readOnlyReason } from './ownership'
import { GuardedButton, OwnershipBadge } from './OwnershipBadge'

type Row = { project: Project; envs: Environment[] }
/** What the signed-in principal may change in this Tenant; a Tenant Member (viewer) gets none of it. */
export type CatalogRights = { vend: boolean; wasteCleanup: boolean; ownership: boolean }

const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : null)

export function TenantView({ tenant, rights }: { tenant: Tenant; rights: CatalogRights }) {
  const [rows, setRows] = useState<Row[] | null>(null)
  const [accounts, setAccounts] = useState<CloudAccount[]>([])
  const [health, setHealth] = useState<RoleHealth[]>([])
  const [error, setError] = useState<string | null>(null)
  const [reload, setReload] = useState(0)

  // Shell keys this component by Tenant, so state starts fresh per Tenant.
  useEffect(() => {
    ;(async () => {
      try {
        const projects = await api.projects(tenant.id)
        const withEnvs = await Promise.all(projects.map(async (p) => ({ project: p, envs: await api.environments(tenant.id, p.id) })))
        setRows(withEnvs)
        setAccounts(await api.cloudAccounts(tenant.id).catch(() => []))
        setHealth(await api.roleHealth(tenant.id).catch(() => []))
      } catch (e) {
        setError((e as Error).message)
      }
    })()
  }, [tenant.id, reload])

  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn()
      setError(null)
      setReload((n) => n + 1)
    } catch (e) {
      setError((e as Error).message)
    }
  }

  if (!rows) return error ? <p className="notice error">{error}</p> : <p className="muted">Loading projects…</p>
  if (rows.length === 0) return <p className="muted">No projects yet.</p>

  const platform = accounts.filter((a) => a.environment_id === null)
  const account = (a: CloudAccount) => (
    <AccountItem key={a.id} tenantId={tenant.id} account={a} health={health.find((h) => h.cloud_account_id === a.id)} canSwitch={rights.ownership} onChanged={() => setReload((n) => n + 1)} />
  )
  return (
    <section>
      {error && (
        <p className="notice error" role="alert">
          {error}
        </p>
      )}
      {rows.map(({ project, envs }) => (
        <article key={project.id} className="card">
          <h2>
            {project.name} <OwnershipBadge ownership={ownershipOf(accountsIn(accounts, envs.map((e) => e.id)))} />
          </h2>
          <p className="muted mono">{project.slug}</p>
          {envs.length === 0 ? (
            <p className="muted">No environments.</p>
          ) : (
            <ul className="envs">
              {envs.map((e) => {
                const accs = accountsIn(accounts, [e.id])
                const owned = ownershipOf(accs)
                const reason = readOnlyReason(owned)
                return (
                  <li key={e.id}>
                    <span className="env">{e.name}</span>
                    <OwnershipBadge ownership={owned} />
                    {accs.length === 0 ? <span className="muted">no cloud account</span> : <ul className="accounts">{accs.map(account)}</ul>}
                    {(rights.vend || rights.wasteCleanup) && (
                      <div className="toolbar">
                        {rights.vend && !accs.some((a) => a.provider === 'tencent' && a.ownership === 'platform') && (
                          <GuardedButton className="secondary" reason={reason} onClick={() => act(() => api.vend(tenant.id, project.id, e.id, 'tencent'))}>
                            Vend Tencent account
                          </GuardedButton>
                        )}
                        {rights.wasteCleanup && (
                          <WasteCleanup env={e} reason={reason} onChange={(on, why) => act(() => api.setWasteCleanup(tenant.id, project.id, e.id, on, why))} />
                        )}
                      </div>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
        </article>
      ))}
      {platform.length > 0 && (
        <article className="card">
          <h2>Platform accounts</h2>
          <ul className="envs accounts">{platform.map(account)}</ul>
        </article>
      )}
    </section>
  )
}

/** Turning cleanup off is always allowed; turning it on in a client-owned scope is refused with the reason. */
function WasteCleanup({ env, reason, onChange }: { env: Environment; reason: string | null; onChange: (on: boolean, why: string) => void }) {
  const id = useId()
  const on = env.waste_cleanup ?? false
  const refused = !on && reason !== null
  return (
    <label>
      <input
        type="checkbox"
        checked={on}
        disabled={refused}
        aria-describedby={refused ? id : undefined}
        onChange={(ev) => {
          const why = window.prompt(ev.target.checked ? 'Why turn on automatic waste cleanup here?' : 'Why turn off automatic waste cleanup here?')
          if (why) onChange(ev.target.checked, why)
        }}
      />{' '}
      Automatic waste cleanup
      {refused && (
        <span id={id} className="reason">
          {' '}
          {reason}
        </span>
      )}
    </label>
  )
}

function roleText(r: ReadOnlyRole): string {
  if ('role_arn' in r) return r.role_arn
  if ('client_id' in r) return `${r.tenant_id} / ${r.client_id}`
  return `${r.workload_identity_provider} as ${r.service_account}`
}

function AccountItem({ tenantId, account: a, health, canSwitch, onChanged }: { tenantId: string; account: CloudAccount; health?: RoleHealth; canSwitch: boolean; onChanged: () => void }) {
  return (
    <li className="account">
      <span>
        {a.provider} · {a.name} <span className="muted mono">{a.external_id}</span> <OwnershipBadge ownership={a.ownership} />
      </span>
      {a.ownership === 'client' && <RoleHealthPanel role={a.read_only_role} health={health} />}
      {canSwitch && <OwnershipSwitch tenantId={tenantId} account={a} onChanged={onChanged} />}
    </li>
  )
}

const sevText = { critical: '✕ Critical', high: '! High', medium: '! Medium', low: 'i Low' } as const

function RoleHealthPanel({ role, health }: { role: ReadOnlyRole; health?: RoleHealth }) {
  const findings = health?.findings ?? []
  return (
    <dl className="role-health" aria-label="Read-only role health">
      <dt>Read-only role</dt>
      <dd className="mono">{roleText(role)}</dd>
      <dt>Last successful assume</dt>
      <dd>{when(health?.last_assume_at ?? null) ?? (health?.client_payer ? 'never' : 'not used: Keel assumes this role only to read a client payer’s bills')}</dd>
      <dt>Last ingest</dt>
      <dd>{when(health?.last_ingest_at ?? null) ?? 'no cost data yet'}</dd>
      <dt>Open role and delivery Findings</dt>
      <dd>
        {findings.length === 0 ? (
          'none'
        ) : (
          <ul>
            {findings.map((f) => (
              <li key={f.id}>
                <span className={`status ${f.severity === 'critical' ? 'critical' : f.severity === 'low' ? 'good' : 'serious'}`}>{sevText[f.severity]}</span> {f.title}
              </li>
            ))}
          </ul>
        )}
      </dd>
    </dl>
  )
}

/** Fields of the read-only role each provider's client grants (catalog.checkOwnership). */
const roleFields: Record<string, [string, string][]> = {
  tencent: [['role_arn', 'Role ARN']],
  aws: [['role_arn', 'Role ARN']],
  alibaba: [['role_arn', 'Role ARN']],
  azure: [
    ['tenant_id', 'Entra tenant ID'],
    ['client_id', 'Client ID'],
  ],
  gcp: [
    ['workload_identity_provider', 'Workload identity provider'],
    ['service_account', 'Service account'],
  ],
}

function OwnershipSwitch({ tenantId, account: a, onChanged }: { tenantId: string; account: CloudAccount; onChanged: () => void }) {
  const [open, setOpen] = useState(false)
  const [role, setRole] = useState<Record<string, string>>({})
  const [why, setWhy] = useState('')
  const [refusal, setRefusal] = useState<{ message: string; grants: string[] } | null>(null)
  const to = a.ownership === 'client' ? 'platform' : 'client'
  if (!open)
    return (
      <button className="link" onClick={() => setOpen(true)}>
        {to === 'client' ? 'Make client-owned…' : 'Make platform-owned…'}
      </button>
    )
  const submit = async () => {
    try {
      await api.setOwnership(tenantId, a.id, to === 'client' ? { ownership: 'client', read_only_role: role as ReadOnlyRole, why } : { ownership: 'platform', why })
      setOpen(false)
      setRefusal(null)
      onChanged()
    } catch (e) {
      const message = (e as Error).message
      setRefusal({ message, grants: e instanceof ApiError && e.status === 409 ? grantsBlocking(message) : [] })
    }
  }
  return (
    <form
      className="toolbar"
      aria-label={`Change ownership of ${a.name}`}
      onSubmit={(ev) => {
        ev.preventDefault()
        void submit()
      }}
    >
      {to === 'client' &&
        (roleFields[a.provider] ?? []).map(([k, label]) => (
          <label key={k}>
            {label} <input value={role[k] ?? ''} onChange={(ev) => setRole({ ...role, [k]: ev.target.value })} required />
          </label>
        ))}
      <label>
        Why <input value={why} onChange={(ev) => setWhy(ev.target.value)} required />
      </label>
      <button className="primary" type="submit">
        {to === 'client' ? 'Make client-owned' : 'Make platform-owned'}
      </button>
      <button className="link" type="button" onClick={() => (setOpen(false), setRefusal(null))}>
        Cancel
      </button>
      {refusal && (
        <div className="notice error" role="alert">
          {refusal.grants.length > 0 ? (
            <>
              <p>Keel cannot make {a.name} client-owned while these Access Grants are open in it, because it could no longer remove their assignments afterwards. Reject or revoke them on the Access tab, then try again.</p>
              <ul>
                {refusal.grants.map((g) => (
                  <li key={g} className="mono">
                    {g}
                  </li>
                ))}
              </ul>
            </>
          ) : (
            refusal.message
          )}
        </div>
      )}
    </form>
  )
}
