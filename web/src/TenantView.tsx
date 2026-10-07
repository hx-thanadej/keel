import { useEffect, useState } from 'react'
import { api, type CloudAccount, type Environment, type Project, type Tenant } from './api'

type Row = { project: Project; envs: Environment[] }

export function TenantView({ tenant }: { tenant: Tenant }) {
  const [rows, setRows] = useState<Row[] | null>(null)
  const [accounts, setAccounts] = useState<CloudAccount[]>([])
  const [error, setError] = useState<string | null>(null)

  // Shell keys this component by Tenant, so state starts fresh per Tenant.
  useEffect(() => {
    ;(async () => {
      try {
        const projects = await api.projects(tenant.id)
        const withEnvs = await Promise.all(projects.map(async (p) => ({ project: p, envs: await api.environments(tenant.id, p.id) })))
        setRows(withEnvs)
        setAccounts(await api.cloudAccounts(tenant.id).catch(() => []))
      } catch (e) {
        setError((e as Error).message)
      }
    })()
  }, [tenant.id])

  if (error) return <p className="notice error">{error}</p>
  if (!rows) return <p className="muted">Loading projects…</p>
  if (rows.length === 0) return <p className="muted">No projects yet.</p>

  const platform = accounts.filter((a) => a.environment_id === null)
  return (
    <section>
      {rows.map(({ project, envs }) => (
        <article key={project.id} className="card">
          <h2>{project.name}</h2>
          <p className="muted mono">{project.slug}</p>
          {envs.length === 0 ? (
            <p className="muted">No environments.</p>
          ) : (
            <ul className="envs">
              {envs.map((e) => {
                const accs = accounts.filter((a) => a.environment_id === e.id)
                return (
                  <li key={e.id}>
                    <span className="env">{e.name}</span>
                    {accs.length === 0 ? (
                      <span className="muted">no cloud account</span>
                    ) : (
                      accs.map((a) => (
                        <span key={a.id} className="account">
                          {a.provider} · {a.name} <span className="muted mono">{a.external_id}</span>
                        </span>
                      ))
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
          <ul className="envs">
            {platform.map((a) => (
              <li key={a.id}>
                <span className="account">
                  {a.provider} · {a.name} <span className="muted mono">{a.external_id}</span>
                </span>
              </li>
            ))}
          </ul>
        </article>
      )}
    </section>
  )
}
