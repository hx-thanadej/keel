import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../App'
import { visibleTenantIds, type Principal } from '../api'

const home = 'h-1'
const tat = 't-1'

type Routes = Record<string, unknown | ((url: URL) => unknown)>

function mockFetch(routes: Routes) {
  const calls: string[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string) => {
      const url = new URL(input, 'http://keel.test')
      calls.push(url.pathname + url.search)
      const key = Object.keys(routes).find((k) => url.pathname === k)
      if (!key) return new Response(JSON.stringify({ error: 'forbidden' }), { status: 403 })
      const v = routes[key]
      const body = typeof v === 'function' ? (v as (u: URL) => unknown)(url) : v
      if (body instanceof Response) return body
      return new Response(JSON.stringify(body), { status: 200 })
    }),
  )
  return calls
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const operator: Principal = {
  subject: 'user:admin@harmonyx.co',
  kind: 'human',
  tenant_id: home,
  home: true,
  mfa: true,
  bindings: [
    { role: 'platform_admin', tenant_id: home },
    { role: 'platform_admin', tenant_id: tat },
  ],
}
const member: Principal = { subject: 'user:somchai@tat.or.th', kind: 'human', tenant_id: tat, home: false, bindings: [{ role: 'tenant_viewer', tenant_id: tat }] }

const tenantRoutes: Routes = {
  [`/v1/tenants/${home}`]: { id: home, slug: 'harmonyx', name: 'HarmonyX', is_home: true },
  [`/v1/tenants/${tat}`]: { id: tat, slug: 'tat', name: 'TAT', is_home: false },
  [`/v1/tenants/${home}/projects`]: { items: [] },
  [`/v1/tenants/${home}/cloud-accounts`]: { items: [] },
  [`/v1/tenants/${tat}/projects`]: { items: [{ id: 'p1', tenant_id: tat, team_id: 'x', slug: 'tat-crm', name: 'TAT CRM' }] },
  [`/v1/tenants/${tat}/projects/p1/environments`]: { items: [{ id: 'e1', project_id: 'p1', name: 'prod' }, { id: 'e2', project_id: 'p1', name: 'dev' }] },
  [`/v1/tenants/${tat}/cloud-accounts`]: { items: [{ id: 'a1', environment_id: 'e1', provider: 'tencent', external_id: '200048351622', name: 'tat-crm-prod' }] },
}

describe('portal', () => {
  it('shows sign-in when unauthenticated and sends the user to their tenant IdP', async () => {
    mockFetch({ '/auth/me': new Response('{"error":"unauthenticated"}', { status: 401 }) })
    const assign = vi.fn()
    vi.stubGlobal('location', { ...window.location, assign })
    render(<App />)
    await userEvent.type(await screen.findByLabelText('Organisation'), 'TAT')
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect(assign).toHaveBeenCalledWith('/auth/login?tenant=tat&return_to=/')
  })

  it('operator sees home and client tenants; client tree shows envs and accounts', async () => {
    mockFetch({ '/auth/me': operator, ...tenantRoutes })
    render(<App />)
    expect(await screen.findByRole('button', { name: /HarmonyX/ })).toBeTruthy()
    await userEvent.click(screen.getByRole('button', { name: 'TAT' }))
    await userEvent.click(await screen.findByRole('tab', { name: 'Projects' }))
    expect(await screen.findByText('TAT CRM')).toBeTruthy()
    expect(screen.getByText(/tat-crm-prod/)).toBeTruthy()
    expect(screen.getByText('no cloud account')).toBeTruthy() // dev has none
    expect(screen.getByText(/· MFA/)).toBeTruthy()
  })

  it('tenant member sees only their own tenant', async () => {
    const calls = mockFetch({ '/auth/me': member, ...tenantRoutes })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Projects' }))
    expect(await screen.findByText('TAT CRM')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /HarmonyX/ })).toBeNull()
    expect(calls.some((c) => c.startsWith(`/v1/tenants/${home}`))).toBe(false)
  })

  it('activity feed filters by actor and pages older entries', async () => {
    const page = (n: number, start: number) =>
      Array.from({ length: n }, (_, i) => ({
        id: `a${start - i}`,
        seq: start - i,
        occurred_at: '2026-10-07T03:00:00Z',
        type: 'keel.project.created',
        actor_uid: 'user:admin@harmonyx.co',
        operation: 'CreateProject',
        event: { data: { status_id: start - i === 100 ? 2 : 1, status_detail: 'keel-authz@1: deny', why: { reason: 'onboarding' } } },
      }))
    const calls = mockFetch({
      '/auth/me': member,
      ...tenantRoutes,
      [`/v1/tenants/${tat}/activities`]: (u: URL) => ({ items: u.searchParams.get('before') ? page(3, 50) : page(50, 100) }),
    })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Activity' }))
    expect((await screen.findAllByText('keel.project.created')).length).toBe(50)
    expect(screen.getByText('keel-authz@1: deny')).toBeTruthy() // failed entry shows the policy detail
    await userEvent.click(screen.getByRole('button', { name: 'Load older' }))
    await waitFor(() => expect(screen.getAllByText('keel.project.created').length).toBe(53))
    expect(calls.some((c) => c.includes('before=51'))).toBe(true)

    await userEvent.type(screen.getByLabelText('Actor'), 'user:x')
    await waitFor(() => expect(calls.some((c) => c.includes('actor=user%3Ax'))).toBe(true))
  })
})

describe('finops screens', () => {
  const budget = { id: 'b1', project_id: 'p1', environment_id: 'e1', provider: null, name: 'tat-crm-prod 2026', year: 2026, amount: '365000', currency: 'THB', cost_basis: 'effective', thresholds: [] }
  const monthStatus = {
    period: 'month', start: '2026-09-01T00:00:00Z', as_of: '2026-09-02T00:00:00Z', currency: 'THB', cost_basis: 'effective',
    budget: '30000.00', budget_to_date: '2000.00', actual: '2600.00', forecast: '39000.00', forecast_p10: '35000.00', forecast_p90: '43000.00',
    forecast_method: 'seasonal_trend', history_days: 90, backtest_mape: 0.031, variance: '600.00', final: false,
    providers: [{ provider: 'tencent', final: false }], missing_fx: false,
    series: Array.from({ length: 30 }, (_, i) => ({ start: `2026-09-${String(i + 1).padStart(2, '0')}T00:00:00Z`, budget: '1000.00', actual: i < 2 ? '1300.00' : '' })),
  }
  const routes = (statusCalls: string[]) => ({
    '/auth/me': member,
    ...tenantRoutes,
    [`/v1/tenants/${tat}/budgets`]: { items: [budget] },
    [`/v1/tenants/${tat}/budgets/b1/status`]: (u: URL) => {
      statusCalls.push(u.searchParams.get('period') ?? '')
      if (u.searchParams.get('period') === 'day') return { ...monthStatus, period: 'day', budget: '1000.00', actual: '1300.00', forecast: '', series: null }
      if (u.searchParams.get('period') === 'year') return { ...monthStatus, period: 'year', budget: '365000.00', forecast: '', forecast_method: 'insufficient_history', history_days: 12, series: [] }
      return monthStatus
    },
    [`/v1/tenants/${tat}/costs/breakdown`]: { items: [{ key: 'Cloud Virtual Machine', service: 'Cloud Virtual Machine', billed: '2000.00', effective: '2000.00', currency: 'THB' }] },
  })

  it('budget screen shows tiles, finality, chart and switches Day/Month/Year', async () => {
    const statusCalls: string[] = []
    mockFetch(routes(statusCalls))
    render(<App />)
    expect(await screen.findByText('30,000.00 THB')).toBeTruthy()
    expect(screen.getByText(/Slightly over|Over budget|Well over/)).toBeTruthy() // variance carries a label, not colour alone
    expect(screen.getByText('tencent: data not final')).toBeTruthy()
    expect(screen.getByText('39,000.00 THB')).toBeTruthy()
    expect(screen.getByText(/35,000.00 – 43,000.00/)).toBeTruthy()
    expect(screen.getByRole('img')).toBeTruthy() // the chart
    expect(await screen.findByText('Cloud Virtual Machine')).toBeTruthy()

    await userEvent.click(screen.getByRole('button', { name: 'Show table' }))
    expect(screen.getAllByRole('row').length).toBe(31)

    await userEvent.click(screen.getByRole('button', { name: 'Day' }))
    expect(await screen.findByText('Switch to Month or Year')).toBeTruthy()
    await userEvent.click(screen.getByRole('button', { name: 'Year' }))
    expect(await screen.findByText(/Needs 28 days of history \(12 so far\)/)).toBeTruthy()
    expect(statusCalls).toEqual(expect.arrayContaining(['month', 'day', 'year']))
  })

  it('costs tab offers a CSV of the tenant\'s own daily costs', async () => {
    mockFetch({ ...routes([]), [`/v1/tenants/${tat}/costs/daily`]: { items: [{ day: '2026-09-01T00:00:00Z', project_slug: 'tat-crm', environment_name: 'prod', provider: 'tencent', currency: 'USD', billed: '35.20', effective: '6.20' }] } })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Costs' }))
    const link = (await screen.findByRole('link', { name: 'Download CSV' })) as HTMLAnchorElement
    expect(link.getAttribute('href')).toMatch(new RegExp(`^/v1/tenants/${tat}/costs/daily\\?from=\\d{4}-\\d{2}-01&to=.*&format=csv$`))
    expect(await screen.findByText('tat-crm · prod · tencent')).toBeTruthy()
  })

  it('findings tab shows rightsizing current → recommended with evidence', async () => {
    mockFetch({ ...routes([]), [`/v1/tenants/${tat}/findings`]: { items: [{ id: 'f2', kind: 'rightsizing', severity: 'high', status: 'open',
      title: 'Right-size requests of prod-tke/tat-crm-prod/api/app: save about 21516.00 THB/month',
      detail: { current: { cpu: '2000m', memory: '4096Mi' }, recommended: { cpu: '410m', memory: '1531Mi' }, evidence: { lookback_days: 21, replicas: 2 } },
      first_seen_at: '2026-09-30T03:00:00Z', resolution: null }] },
      [`/v1/tenants/${tat}/recommendations`]: { items: [{ id: 'r2', finding_id: 'f2', pr_url: null, state: 'open' }] } })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Findings' }))
    expect(await screen.findByText(/cpu: 2000m → 410m · memory: 4096Mi → 1531Mi · based on 21 days, 2 replica/)).toBeTruthy()
    expect(await screen.findByRole('button', { name: 'Open pull request' })).toBeTruthy()
  })

  it('savings tab compares recommended with realised and flags regressions, per project', async () => {
    const calls = mockFetch({ ...routes([]), [`/v1/tenants/${tat}/savings`]: (u: URL) => ({ currency: 'THB', open: '9000.00', accepted: '0.00', applied: u.searchParams.get('project') ? '3150.00' : '24666.00',
      realised: '3150.00', regressions: 1,
      items: [{ id: 'r1', resource_id: 'ins-big', action: 'resize', project_id: 'p1', recommended: '3150.00', realised: '3150.00', method: 'measured', regression: null, applied_at: '2026-09-15T00:00:00Z' },
        { id: 'r2', resource_id: 'tke/ns/api/app', action: 'resize_requests', project_id: 'p1', recommended: '21516.00', realised: null, method: null, regression: 'cpu_cores p95 at 98% of request on 2026-09-20', applied_at: '2026-09-10T00:00:00Z' }] }) })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Savings' }))
    expect(await screen.findByText('24,666.00 THB')).toBeTruthy()
    expect(screen.getByText(/measured/)).toBeTruthy()
    expect(screen.getByText(/waiting for 7 days of data/)).toBeTruthy()
    expect(screen.getByText(/Regression: cpu_cores p95 at 98%/)).toBeTruthy()
    await userEvent.selectOptions(screen.getByLabelText('Project'), 'p1')
    expect(await screen.findAllByText('3,150.00 THB')).not.toHaveLength(0)
    expect(calls).toContain(`/v1/tenants/${tat}/savings?project=p1`)
  })

  it('findings tab lists anomalies with severity label and contributors', async () => {
    mockFetch({ ...routes([]), [`/v1/tenants/${tat}/findings`]: { items: [{ id: 'f1', kind: 'cost_anomaly', severity: 'critical', status: 'open', title: 'NAT Gateway spend 310.00 USD on 10 Sep', detail: { top_resources: [{ resource_id: 'nat-2', delta: '300.00' }] }, first_seen_at: '2026-09-11T03:00:00Z', resolution: null }] } })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Findings' }))
    expect(await screen.findByText(/Critical · cost anomaly/)).toBeTruthy()
    expect(screen.getByText(/nat-2 \(\+300.00\)/)).toBeTruthy()
  })
})

describe('visibleTenantIds', () => {
  it('dedupes own tenant and bindings', () => {
    expect(visibleTenantIds(operator)).toEqual([home, tat])
    expect(visibleTenantIds(member)).toEqual([tat])
  })
})
