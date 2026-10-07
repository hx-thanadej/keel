import { useEffect, useState } from 'react'
import { api, visibleTenantIds, type Principal, type Tenant } from './api'
import { TenantView } from './TenantView'
import { ActivityFeed } from './ActivityFeed'
import { BudgetsView } from './BudgetsView'
import { CostsView } from './CostsView'
import { FindingsView } from './FindingsView'
import { SavingsView } from './SavingsView'

type Tab = 'budgets' | 'costs' | 'findings' | 'savings' | 'catalog' | 'activity'
const tabs: [Tab, string][] = [
  ['budgets', 'Budgets'],
  ['costs', 'Costs'],
  ['findings', 'Findings'],
  ['savings', 'Savings'],
  ['catalog', 'Projects'],
  ['activity', 'Activity'],
]

export function Shell({ me, onSignedOut }: { me: Principal; onSignedOut: () => void }) {
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('budgets')

  useEffect(() => {
    // A binding the policy rejects (e.g. outside a Tenant Member's own Tenant) simply fails to load.
    Promise.allSettled(visibleTenantIds(me).map((id) => api.tenant(id))).then((rs) => {
      const ok = rs.flatMap((r) => (r.status === 'fulfilled' ? [r.value] : []))
      ok.sort((a, b) => Number(b.is_home) - Number(a.is_home) || a.name.localeCompare(b.name))
      setTenants(ok)
      setSelected((s) => s ?? ok[0]?.id ?? null)
    })
  }, [me])

  const signOut = async () => {
    await api.logout()
    onSignedOut()
  }
  const current = tenants.find((t) => t.id === selected)

  return (
    <div className="shell">
      <header>
        <strong>Keel</strong>
        <span className="who" title={me.subject}>
          {me.subject.replace(/^user:/, '')}
          {me.mfa ? ' · MFA' : ''}
        </span>
        <button className="link" onClick={signOut}>
          Sign out
        </button>
      </header>
      <nav aria-label="Tenants">
        {tenants.length === 0 && <p className="muted">No organisations available.</p>}
        <ul>
          {tenants.map((t) => (
            <li key={t.id}>
              <button aria-current={t.id === selected} onClick={() => setSelected(t.id)}>
                {t.name}
                {t.is_home && <span className="badge">home</span>}
              </button>
            </li>
          ))}
        </ul>
      </nav>
      <main>
        {current && (
          <>
            <h1>{current.name}</h1>
            <div role="tablist">
              {tabs.map(([id, name]) => (
                <button key={id} role="tab" aria-selected={tab === id} onClick={() => setTab(id)}>
                  {name}
                </button>
              ))}
            </div>
            {tab === 'budgets' && <BudgetsView key={current.id} tenantId={current.id} />}
            {tab === 'costs' && <CostsView key={current.id} tenantId={current.id} />}
            {tab === 'findings' && <FindingsView key={current.id} tenantId={current.id} />}
            {tab === 'savings' && <SavingsView key={current.id} tenantId={current.id} />}
            {tab === 'catalog' && <TenantView key={current.id} tenant={current} />}
            {tab === 'activity' && <ActivityFeed key={current.id} tenantId={current.id} />}
          </>
        )}
      </main>
    </div>
  )
}
