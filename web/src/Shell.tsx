import { useEffect, useState } from 'react'
import { api, visibleTenantIds, type Principal, type Tenant } from './api'
import { TenantView } from './TenantView'
import { ActivityFeed } from './ActivityFeed'
import { BudgetsView } from './BudgetsView'
import { CostsView } from './CostsView'
import { FindingsView } from './FindingsView'
import { SavingsView } from './SavingsView'
import { DeliveryView } from './DeliveryView'
import { SecurityView } from './SecurityView'
import { AccessView } from './AccessView'
import { InsightsView } from './InsightsView'
import { ComplianceView } from './ComplianceView'
import { ConnectionsView } from './ConnectionsView'

type Tab = 'budgets' | 'costs' | 'findings' | 'savings' | 'delivery' | 'security' | 'compliance' | 'access' | 'insights' | 'catalog' | 'activity' | 'connections'
const tabs: [Tab, string][] = [
  ['budgets', 'Budgets'],
  ['costs', 'Costs'],
  ['findings', 'Findings'],
  ['savings', 'Savings'],
  ['delivery', 'Delivery'],
  ['security', 'Security'],
  ['compliance', 'Compliance'],
  ['access', 'Access'],
  ['insights', 'Insights'],
  ['catalog', 'Projects'],
  ['activity', 'Activity'],
]

export function Shell({ me, onSignedOut }: { me: Principal; onSignedOut: () => void }) {
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('budgets')
  const [focusFinding, setFocusFinding] = useState<string>()
  const openFinding = (id: string) => {
    setFocusFinding(id)
    setTab('findings')
  }

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
  // Cloud connections are platform data in the home Tenant, managed by its platform admins (ADR-0022).
  const isAdmin = (tenantId: string) => me.bindings.some((b) => b.tenant_id === tenantId && b.role === 'platform_admin')
  const shown: [Tab, string][] = current?.is_home && isAdmin(current.id) ? [...tabs, ['connections', 'Connections']] : tabs
  const active = shown.some(([id]) => id === tab) ? tab : 'budgets'

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
              <button
                aria-current={t.id === selected}
                onClick={() => {
                  setFocusFinding(undefined)
                  setSelected(t.id)
                }}
              >
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
              {shown.map(([id, name]) => (
                <button
                  key={id}
                  role="tab"
                  aria-selected={active === id}
                  onClick={() => {
                    setFocusFinding(undefined)
                    setTab(id)
                  }}
                >
                  {name}
                </button>
              ))}
            </div>
            {active === 'budgets' && <BudgetsView key={current.id} tenantId={current.id} />}
            {active === 'costs' && <CostsView key={current.id} tenantId={current.id} />}
            {active === 'findings' && <FindingsView key={current.id} tenantId={current.id} focus={focusFinding} />}
            {active === 'savings' && <SavingsView key={current.id} tenantId={current.id} />}
            {active === 'delivery' && <DeliveryView key={current.id} tenantId={current.id} />}
            {active === 'security' && <SecurityView key={current.id} tenantId={current.id} />}
            {active === 'compliance' && <ComplianceView key={current.id} tenantId={current.id} onOpenFinding={openFinding} canConfigure={me.bindings.some((b) => b.tenant_id === current.id && b.role === 'platform_admin')} />}
            {active === 'access' && <AccessView key={current.id} tenantId={current.id} />}
            {active === 'insights' && <InsightsView key={current.id} tenantId={current.id} canSubmit={me.bindings.some((b) => b.tenant_id === current.id && (b.role === 'platform_admin' || b.role === 'tenant_approver'))} canGenerate={me.bindings.some((b) => b.tenant_id === current.id && (b.role === 'platform_admin' || b.role === 'finops_lead'))} />}
            {active === 'catalog' && (
              <TenantView
                key={current.id}
                tenant={current}
                rights={{
                  vend: me.bindings.some((b) => b.tenant_id === current.id && b.role === 'platform_admin'),
                  wasteCleanup: me.bindings.some((b) => b.tenant_id === current.id && (b.role === 'platform_admin' || b.role === 'team_lead')),
                  ownership: me.bindings.some((b) => b.tenant_id === current.id && b.role === 'platform_admin'),
                }}
              />
            )}
            {active === 'activity' && <ActivityFeed key={current.id} tenantId={current.id} />}
            {active === 'connections' && <ConnectionsView />}
          </>
        )}
      </main>
    </div>
  )
}
