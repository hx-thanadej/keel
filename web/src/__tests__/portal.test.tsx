import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../App'
import { visibleTenantIds, type Principal } from '../api'

const home = 'h-1'
const tat = 't-1'

type Routes = Record<string, unknown | ((url: URL) => unknown)>

function mockFetch(routes: Routes, bodies: Record<string, unknown> = {}) {
  const calls: string[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = new URL(input, 'http://keel.test')
      calls.push(url.pathname + url.search)
      if (typeof init?.body === 'string') bodies[url.pathname] = JSON.parse(init.body)
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

const approver: Principal = { ...member, bindings: [{ role: 'tenant_approver', tenant_id: tat }] }

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
      [`/v1/tenants/${tat}/recommendations`]: { items: [{ id: 'r2', finding_id: 'f2', pr_url: null, state: 'open', provider: 'k8s', account_id: '', environment_id: 'e1',
        resource_id: 'prod-tke/tat-crm-prod/api/app', resource_type: 'k8s_workload', action: 'resize_requests', current: {}, recommended: {} }] } })
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

  it('findings tab shows an off-hours schedule without its machine fields', async () => {
    mockFetch({ ...routes([]), [`/v1/tenants/${tat}/findings`]: { items: [{ id: 'f3', kind: 'rightsizing', severity: 'high', status: 'open',
      title: 'Schedule off-hours stop for ins-dev: save about 1770.00 THB/month',
      detail: { current: { schedule: 'always on' }, recommended: { schedule: 'Mon–Fri 08:00–18:00 Asia/Bangkok, off at weekends', start: '08:00', stop: '18:00' }, evidence: { lookback_days: 14 } },
      first_seen_at: '2026-09-30T03:00:00Z', resolution: null }] } })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Findings' }))
    const line = await screen.findByText(/schedule: always on → Mon–Fri 08:00–18:00 Asia\/Bangkok, off at weekends/)
    expect(line.textContent).not.toMatch(/start:/)
  })

  it('delivery tab previews the policy before promoting, approves, and retries runs', async () => {
    const d = 'sha256:' + 'a'.repeat(64)
    const calls = mockFetch({
      ...routes([]),
      [`/v1/tenants/${tat}/services`]: { items: [{ id: 's1', project_id: 'p1', slug: 'crm-api', name: 'CRM API', repository: '', template: 'go' }] },
      [`/v1/tenants/${tat}/templates`]: { items: [{ name: 'go-service', repo: 'acme/tmpl', ref: 'abc', description: '' }] },
      [`/v1/tenants/${tat}/releases`]: { items: [{ id: 'r1', service_id: 's1', version: '1.5.0', images: [{ name: 'ccr/tat/crm-api', digest: d }], created_at: '2026-10-01T00:00:00Z' }] },
      [`/v1/tenants/${tat}/promotions`]: { items: [{ id: 'pr1', release_id: 'r1', environment_id: 'e1', state: 'pending_approval', decision: { allow: true, reasons: [], needs_approval: true, policy: 'keel-promotion@1' }, pr_url: null, error: null, requested_by: 'user:eng@harmonyx.co', requested_at: '2026-10-02T00:00:00Z' }] },
      [`/v1/tenants/${tat}/flows`]: { items: [{ id: 'f1', kind: 'vend_environment_tencent', subject: 'environment/e1/tencent', state: 'failed', error: 'account: quota', created_by: 'u', created_at: '2026-10-01T00:00:00Z' }] },
      [`/v1/tenants/${tat}/flows/f1`]: { id: 'f1', kind: 'vend_environment_tencent', subject: 'environment/e1/tencent', state: 'failed', error: 'account: quota', created_by: 'u', created_at: '2026-10-01T00:00:00Z', steps: [{ seq: 0, name: 'unit', state: 'succeeded', attempts: 1, error: null }, { seq: 1, name: 'account', state: 'failed', attempts: 8, error: 'quota' }] },
      [`/v1/tenants/${tat}/flows/f1/retry`]: { id: 'f1', state: 'running' },
      [`/v1/tenants/${tat}/releases/r1/preview`]: { allow: false, reasons: ['release is not deployed to dev yet'], needs_approval: false, policy: 'keel-promotion@1' },
      [`/v1/tenants/${tat}/promotions/pr1/approve`]: { id: 'pr1', state: 'pr_open' },
    })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Delivery' }))
    expect(await screen.findByText('CRM API 1.5.0')).toBeTruthy()
    await userEvent.selectOptions(screen.getByLabelText('Promote to'), 'e1')
    expect(await screen.findByText(/Blocked by keel-promotion@1: release is not deployed to dev yet/)).toBeTruthy()
    expect((screen.getByRole('button', { name: 'Promote' }) as HTMLButtonElement).disabled).toBe(true)
    await userEvent.click(screen.getByRole('button', { name: 'Approve promotion' }))
    expect(calls).toContain(`/v1/tenants/${tat}/promotions/pr1/approve`)
    expect(await screen.findByText(/unit ✓ account ✕/)).toBeTruthy()
    await userEvent.click(screen.getByRole('button', { name: 'Retry from the failed step' }))
    expect(calls).toContain(`/v1/tenants/${tat}/flows/f1/retry`)
    expect(screen.getByRole('button', { name: 'Create repository and service' })).toBeTruthy()
  })

  it('security tab shows VSA results, approves exceptions, requires VEX justification', async () => {
    const calls = mockFetch({
      ...routes([]),
      [`/v1/tenants/${tat}/services`]: { items: [{ id: 's1', project_id: 'p1', slug: 'crm-api', name: 'CRM API', repository: '', template: '' }] },
      [`/v1/tenants/${tat}/releases`]: { items: [{ id: 'r1', service_id: 's1', version: '1.5.0', images: [], created_at: '2026-10-01T00:00:00Z' }] },
      [`/v1/tenants/${tat}/releases/r1/attestations`]: { items: [{ id: 'a1', image_digest: 'sha256:aa', passed: false, created_at: '2026-10-01T00:00:00Z',
        checks: [{ name: 'signature', pass: true, detail: 'ok' }, { name: 'trigger', pass: false, detail: 'triggered by pull_request_target' }] }] },
      [`/v1/tenants/${tat}/exceptions`]: { items: [{ id: 'x1', fingerprint: 'vuln:CVE-2026-1:', finding_ids: [], reason: 'patch next sprint', state: 'requested', requested_by: 'user:eng@harmonyx.co', decided_by: null, expires_at: '2026-11-01T00:00:00Z' }] },
      [`/v1/tenants/${tat}/exceptions/x1/approve`]: { id: 'x1', state: 'approved' },
      [`/v1/tenants/${tat}/vex`]: { items: [] },
    })
    vi.stubGlobal('prompt', () => 'internal only')
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Security' }))
    expect(await screen.findByText(/VSA failed: trigger/)).toBeTruthy()
    expect(screen.getByText(/triggered by pull_request_target/)).toBeTruthy()
    await userEvent.click(screen.getByRole('button', { name: 'Approve exception' }))
    expect(calls).toContain(`/v1/tenants/${tat}/exceptions/x1/approve`)
    expect((screen.getByLabelText('Justification') as HTMLSelectElement).required).toBe(true)
  })

  it('access tab requests a grant, shows approvals needed and active grants, and lists standing access', async () => {
    const calls = mockFetch({
      ...routes([]),
      [`/v1/tenants/${tat}/teams`]: { items: [{ id: 't1', slug: 'crm', name: 'CRM' }] },
      [`/v1/tenants/${tat}/access/templates`]: { items: [{ name: 'read-only', description: '', write: false, max_hours: 8 }, { name: 'operator', description: '', write: true, max_hours: 2 }] },
      [`/v1/tenants/${tat}/access/roles`]: { items: [{ id: 'r1', environment_id: 'e1', team_id: 't1', template: 'operator', state: 'active', requested_by: 'u' }] },
      [`/v1/tenants/${tat}/access/grants`]: (u: URL) => u.pathname && { items: [
        { id: 'g1', role_id: 'r1', requester: 'user:eng@harmonyx.co', reason: 'incident 4711', hours: 2, state: 'requested', decision: { allow: true, reasons: [], approvals: ['team_lead', 'security_lead'], policy: 'keel-access@1' }, approvals: [{ role: 'team_lead', by: 'user:lead@harmonyx.co', at: '2026-10-07T10:00:00Z' }], error: null, expires_at: null },
        { id: 'g2', role_id: 'r1', requester: 'user:ops@harmonyx.co', reason: 'disk full', hours: 1, state: 'active', decision: { allow: true, reasons: [], approvals: [], policy: 'keel-access@1' }, approvals: [], error: null, expires_at: '2026-10-07T12:00:00Z' }] },
      [`/v1/tenants/${tat}/access/grants/g1/approve`]: { id: 'g1', state: 'active' },
      [`/v1/tenants/${tat}/findings`]: { items: [{ id: 'f9', kind: 'standing_access', severity: 'critical', status: 'open', title: 'Standing production access in 100002: CAM user alice (standing credentials)', detail: {}, first_seen_at: '2026-10-07T00:00:00Z', resolution: null }] },
    })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Access' }))
    expect(await screen.findByText(/CAM user alice/)).toBeTruthy()
    expect(screen.getByText(/needs team_lead \+ security_lead · approved by lead@harmonyx.co \(team_lead\)/)).toBeTruthy()
    expect(screen.getByText(/ops@harmonyx.co: operator in prod/)).toBeTruthy()
    await userEvent.click(screen.getByRole('button', { name: 'Approve access' }))
    expect(calls).toContain(`/v1/tenants/${tat}/access/grants/g1/approve`)
    expect((screen.getByLabelText('Hours') as HTMLInputElement).max).toBe('2')
  })

  it('insights tab shows DORA per month, failing scorecard checks, reports, evidence and maturity', async () => {
    const dora = (n: number) => ({ from: '2026-10-01T00:00:00Z', to: '2026-11-01T00:00:00Z', tenant: { scope: 'tenant', deployments: n, deployments_per_day: n / 30, lead_time_hours: 5, change_fail_rate: 0.1, recovery_hours: 2, rework_rate: 0, failed: 1, rework: 0 }, services: [] })
    const bodies: Record<string, unknown> = {}
    const calls = mockFetch({
      ...routes([]),
      '/auth/me': approver,
      [`/v1/tenants/${tat}/dora`]: () => dora(12),
      [`/v1/tenants/${tat}/scorecards`]: { version: 'keel-scorecard@1', score: 60, teams: [], services: [
        { service_id: 's1', service: 'crm-api', team_id: 't', score: 60, previous_score: 40, checks: [{ name: 'owner', control: 'PO.2.1', pass: true }, { name: 'scanned', control: 'PW.7.2', pass: false, why: 'no full scanner upload in the last 30 days' }] }] },
      [`/v1/tenants/${tat}/reports`]: [{ period: '2026-09', generated_at: '2026-10-01T01:00:00Z', final: true }],
      [`/v1/tenants/${tat}/decisions`]: { items: [{ service_id: 's1', service: 'crm-api', path: 'docs/decisions/0003-queue.md', number: 3, title: 'Use River for jobs', status: 'accepted', date: '2026-05-01', superseded_by: '', url: 'https://github.com/acme/crm-api/blob/main/docs/decisions/0003-queue.md' }] },
      [`/v1/tenants/${tat}/maturity`]: {
        quarter: '2026-Q4',
        questionnaire: { version: 'keel-maturity@1', levels: ['Provisional', 'Operational', 'Scalable', 'Optimizing'], aspects: [
          { id: 'adoption', title: 'Adoption', question: 'How do teams come to use the platform?', measured: 'template_adoption', levels: ['a1', 'a2', 'a3', 'a4'] }] },
        indicators: { services: 4, template_adoption: 0.75, environments: 2, self_service_environments: 0.5, dora: dora(12).tenant, suggested_levels: { adoption: 3 } },
        assessments: [{ quarter: '2026-Q3', version: 'keel-maturity@1', answers: { adoption: { level: 2 } }, indicators: {}, submitted_by: 'user:lead@tat.or.th', submitted_at: '2026-09-20T00:00:00Z' }],
      },
      [`/v1/tenants/${tat}/maturity/2026-Q4`]: { quarter: '2026-Q4' },
    }, bodies)
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Insights' }))
    expect(await screen.findByText('Deployments this month')).toBeTruthy()
    expect(screen.getByRole('img', { name: 'Production deployments per month' })).toBeTruthy()
    expect(calls.filter((c) => c.startsWith(`/v1/tenants/${tat}/dora?`)).length).toBe(6)
    expect(screen.getByText(/scanned \(no full scanner upload in the last 30 days\)/)).toBeTruthy()
    expect(screen.getByText(/60 ↑/)).toBeTruthy()
    expect((screen.getByRole('link', { name: 'Download report 2026-09' }) as HTMLAnchorElement).getAttribute('href')).toBe(`/v1/tenants/${tat}/reports/2026-09?format=html`)
    expect((screen.getByRole('link', { name: 'Export evidence' }) as HTMLAnchorElement).getAttribute('href')).toMatch(new RegExp(`^/v1/tenants/${tat}/evidence\\?from=\\d{4}-\\d{2}-01&to=`))
    await userEvent.selectOptions(screen.getByLabelText('Framework'), 'pdpa')
    const evidence = screen.getByRole('link', { name: 'Export evidence' }) as HTMLAnchorElement
    expect(evidence.getAttribute('href')).toMatch(new RegExp(`^/v1/tenants/${tat}/evidence\\?from=\\d{4}-\\d{2}-01&to=\\d{4}-\\d{2}-01&framework=pdpa$`))
    expect(evidence.getAttribute('download')).toMatch(/^keel-evidence-pdpa-/)
    expect(screen.getByText('Operational')).toBeTruthy() // Q3 trend cell
    expect(screen.getByText('Keel measures Scalable')).toBeTruthy()
    expect((screen.getByLabelText(/How do teams come to use the platform/) as HTMLSelectElement).value).toBe('3') // pre-filled from the measure
    await userEvent.type(screen.getByLabelText(/Search decisions/), 'queue')
    await userEvent.click(screen.getByRole('button', { name: 'Search' }))
    expect(await screen.findByText(/crm-api: ADR-0003 Use River for jobs/)).toBeTruthy()
    await userEvent.click(screen.getByRole('button', { name: 'Save 2026-Q4 assessment' }))
    await waitFor(() => expect(calls).toContain(`/v1/tenants/${tat}/maturity/2026-Q4`))
    expect(bodies[`/v1/tenants/${tat}/maturity/2026-Q4`]).toEqual({ answers: { adoption: { level: 3 } } })
  })

  it('insights shows a load error instead of the empty state', async () => {
    mockFetch({ ...routes([]), [`/v1/tenants/${tat}/scorecards`]: new Response('{"error":"forbidden"}', { status: 403 }), [`/v1/tenants/${tat}/reports`]: [] })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Insights' }))
    expect(await screen.findAllByText('You are not allowed to see this here.')).not.toHaveLength(0)
    expect(screen.queryByText('No Services yet.')).toBeNull()
  })

  it('insights report download that fails shows the error and saves nothing', async () => {
    const create = vi.fn(() => 'blob:x')
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() }))
    mockFetch({
      ...routes([]),
      [`/v1/tenants/${tat}/reports`]: [{ period: '2026-09', generated_at: '2026-10-01T01:00:00Z' }],
      [`/v1/tenants/${tat}/reports/2026-09`]: new Response('{"error":"report store down"}', { status: 500 }),
    })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Insights' }))
    await userEvent.click(await screen.findByRole('link', { name: 'Download report 2026-09' }))
    const row = (await screen.findByText('report store down')).closest('article') as HTMLElement
    expect(within(row).getByRole('link', { name: 'Download report 2026-09' })).toBeTruthy()
    expect(create).not.toHaveBeenCalled()
  })

  it('insights revokes the download URL only after the click', async () => {
    const events: string[] = []
    const blobURL = vi.fn(() => (events.push('create'), 'blob:x'))
    const revoke = vi.fn(() => void events.push('revoke'))
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => void events.push('click'))
    Object.assign(URL, { createObjectURL: blobURL, revokeObjectURL: revoke })
    try {
      mockFetch({
        ...routes([]),
        [`/v1/tenants/${tat}/reports`]: [{ period: '2026-09', generated_at: '2026-10-01T01:00:00Z', final: true }],
        [`/v1/tenants/${tat}/reports/2026-09`]: new Response('<html></html>', { status: 200 }),
      })
      render(<App />)
      await userEvent.click(await screen.findByRole('tab', { name: 'Insights' }))
      await userEvent.click(await screen.findByRole('link', { name: 'Download report 2026-09' }))
      await waitFor(() => expect(click).toHaveBeenCalled())
      expect(revoke).not.toHaveBeenCalled()
      await waitFor(() => expect(revoke).toHaveBeenCalledWith('blob:x'), { timeout: 3000 })
      expect(events).toEqual(['create', 'click', 'revoke'])
    } finally {
      click.mockRestore()
      Reflect.deleteProperty(URL, 'createObjectURL')
      Reflect.deleteProperty(URL, 'revokeObjectURL')
    }
  })

  it('insights marks provisional reports and lets a finops_lead regenerate one', async () => {
    let list = [{ period: '2026-09', generated_at: '2026-10-01T01:00:00Z', final: false }]
    const calls = mockFetch({
      ...routes([]),
      '/auth/me': { ...member, bindings: [{ role: 'finops_lead', tenant_id: tat }] },
      [`/v1/tenants/${tat}/reports`]: () => list,
      [`/v1/tenants/${tat}/reports/2026-09/regenerate`]: () => {
        list = [{ ...list[0], final: true }]
        return {}
      },
    })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Insights' }))
    expect(await screen.findByText('provisional')).toBeTruthy()
    await userEvent.click(screen.getByRole('button', { name: 'Regenerate 2026-09' }))
    await waitFor(() => expect(screen.queryByText('provisional')).toBeNull())
    expect(calls).toContain(`/v1/tenants/${tat}/reports/2026-09/regenerate`)
    expect(calls.filter((c) => c === `/v1/tenants/${tat}/reports`).length).toBe(2)
  })

  it('insights shows a regenerate failure next to its report', async () => {
    mockFetch({
      ...routes([]),
      '/auth/me': { ...member, bindings: [{ role: 'platform_admin', tenant_id: tat }] },
      [`/v1/tenants/${tat}/reports`]: [{ period: '2026-09', generated_at: '2026-10-01T01:00:00Z', final: false }],
      [`/v1/tenants/${tat}/reports/2026-09/regenerate`]: new Response('{"error":"cost data unavailable"}', { status: 500 }),
    })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Insights' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Regenerate 2026-09' }))
    const row = (await screen.findByText('cost data unavailable')).closest('article') as HTMLElement
    expect(within(row).getByRole('button', { name: 'Regenerate 2026-09' })).toBeTruthy()
  })

  it('insights hides Regenerate from principals without report.generate', async () => {
    mockFetch({
      ...routes([]),
      '/auth/me': approver,
      [`/v1/tenants/${tat}/reports`]: [{ period: '2026-09', generated_at: '2026-10-01T01:00:00Z', final: false }],
    })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Insights' }))
    expect(await screen.findByText('provisional')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Regenerate/ })).toBeNull()
  })

  it('insights hides Save for a tenant_viewer but still shows the trend', async () => {
    mockFetch({
      ...routes([]),
      [`/v1/tenants/${tat}/maturity`]: {
        quarter: '2026-Q4',
        questionnaire: { version: 'keel-maturity@1', levels: ['Provisional', 'Operational', 'Scalable', 'Optimizing'], aspects: [{ id: 'adoption', title: 'Adoption', question: 'q?', measured: 'template_adoption', levels: ['a1', 'a2', 'a3', 'a4'] }] },
        indicators: { services: 4, template_adoption: 0.75, environments: 2, self_service_environments: 0.5, suggested_levels: {} },
        assessments: [{ quarter: '2026-Q3', version: 'keel-maturity@1', answers: { adoption: { level: 2 } }, indicators: {}, submitted_by: 'user:lead@tat.or.th', submitted_at: '2026-09-20T00:00:00Z' }],
      },
    })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Insights' }))
    expect(await screen.findByText('Operational')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Save .* assessment/ })).toBeNull()
  })

  const controlReport = {
    version: 'keel-controls@2',
    services: 3,
    frameworks: [
      { id: 'ISO27001', name: 'ISO/IEC 27001:2022 Annex A', controls: 3, mapped: 2, covered: 1, gaps: 2 },
      { id: 'PDPA', name: 'Thailand Personal Data Protection Act B.E. 2562 (2019)', controls: 2, mapped: 2, covered: 2, gaps: 0 },
    ],
    controls: [
      { id: '8.8', framework: 'ISO27001', title: 'Management of technical vulnerabilities', covered_by: ['keel-scans@1'], coverage: [{ name: 'keel-scans@1', point: 'pipeline', covered_services: 3 }], gap: false },
      { id: '6.1', framework: 'ISO27001', title: 'Screening', covered_by: [], gap_reason: 'People: HR process outside Keel', coverage: [], gap: true },
      { id: '8.32', framework: 'ISO27001', title: 'Change management', covered_by: ['keel-promotion@1'], coverage: [{ name: 'keel-promotion@1', point: 'promotion', covered_services: 0 }], gap: true },
      { id: 's.37(4)', framework: 'PDPA', title: 'Notify the PDPC of a breach within 72 hours', covered_by: ['keel-pdpa-breach@1'], coverage: [{ name: 'keel-pdpa-breach@1', point: 'platform', covered_services: 3 }], gap: false },
      { id: 's.37(3)', framework: 'PDPA', title: 'Erase personal data past its retention period', covered_by: ['keel-pdpa-retention@1'], coverage: [{ name: 'keel-pdpa-retention@1', point: 'platform', covered_services: 3 }], gap: false },
    ],
  }
  const hours = (h: number) => new Date(Date.now() + h * 3600000).toISOString()
  const pdpaOverview = (legalHold = '') => ({
    settings: { data_regions: ['ap-bangkok', 'ap-southeast-7'], deletion_enabled: false, legal_hold: legalHold },
    retention_schedule: [],
    breaches: [
      { id: 'b1', title: 'CRM export emailed to the wrong partner', description: '', state: 'warning', aware_at: hours(-50), notify_by: hours(22), declared_at: hours(-50), declared_by: 'user:sec@tat.or.th' },
      { id: 'b2', title: 'Old laptop lost', description: '', state: 'notified', aware_at: hours(-200), notify_by: hours(-128), declared_at: hours(-200), declared_by: 'user:sec@tat.or.th', notified_at: hours(-190), pdpc_reference: 'PDPC-1' },
    ],
    last_retention_run: { ran_at: '2026-10-10T02:00:00Z', mode: 'dry_run', detail: 'would delete (deletion is off for this Tenant): findings 4, sessions 12' },
  })
  const compliancePage = async () => {
    await userEvent.click(await screen.findByRole('tab', { name: 'Compliance' }))
    await screen.findByRole('status')
  }

  it('compliance picker switches frameworks and their counts, and filters to gaps with reasons', async () => {
    mockFetch({ ...routes([]), [`/v1/tenants/${tat}/controls`]: controlReport, [`/v1/tenants/${tat}/pdpa`]: pdpaOverview() })
    render(<App />)
    await compliancePage()
    expect(screen.getByRole('status').textContent).toMatch(/ISO\/IEC 27001:2022 Annex A: 1 of 3 controls covered, 2 gaps\. 2 mapped to a Keel policy, across 3 services\./)
    const table = screen.getByRole('table')
    expect(within(table).getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Control', 'Status', 'Keel policies (services covered)', 'Gap reason'])
    expect(within(table).getByRole('rowheader', { name: '8.8 Management of technical vulnerabilities' })).toBeTruthy()
    expect(within(table).getByText('keel-scans@1 @pipeline (3)')).toBeTruthy()
    expect(within(table).getAllByText('✕ Gap')).toHaveLength(2)

    await userEvent.click(screen.getByLabelText('Show gaps only'))
    expect(within(table).queryByText(/Management of technical vulnerabilities/)).toBeNull()
    const screening = within(table).getByRole('rowheader', { name: '6.1 Screening' }).closest('tr') as HTMLElement
    expect(within(screening).getByText('People: HR process outside Keel')).toBeTruthy()
    const change = within(table).getByRole('rowheader', { name: '8.32 Change management' }).closest('tr') as HTMLElement
    expect(within(change).getByText('Mapped to a Keel policy that has not covered any Service yet')).toBeTruthy()

    await userEvent.selectOptions(screen.getByLabelText('Framework'), 'PDPA')
    expect(screen.getByRole('status').textContent).toMatch(/Thailand Personal Data Protection Act B\.E\. 2562 \(2019\): 2 of 2 controls covered, 0 gaps\./)
    expect(screen.getByText('No gaps in this framework.')).toBeTruthy()
    await userEvent.click(screen.getByLabelText('Show gaps only'))
    expect(screen.getByRole('rowheader', { name: 's.37(4) Notify the PDPC of a breach within 72 hours' })).toBeTruthy()
    expect(screen.queryByText(/Screening/)).toBeNull()
  })

  it('compliance exports the chosen framework\'s evidence and shows a server error next to the button', async () => {
    const create = vi.fn(() => 'blob:x')
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() }))
    const calls = mockFetch({
      ...routes([]),
      [`/v1/tenants/${tat}/controls`]: controlReport,
      [`/v1/tenants/${tat}/pdpa`]: pdpaOverview(),
      [`/v1/tenants/${tat}/evidence`]: (u: URL) =>
        u.searchParams.get('framework') === 'soc2' ? new Response('{"error":"signing key unavailable"}', { status: 500 }) : new Response('{"version":"keel-evidence@2"}', { status: 200 }),
    })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    try {
      render(<App />)
      await compliancePage()
      await userEvent.selectOptions(screen.getByLabelText('Framework'), 'PDPA')
      await userEvent.click(screen.getByRole('button', { name: 'Export PDPA evidence' }))
      await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
      expect(calls.filter((c) => c.includes('/evidence'))).toEqual([expect.stringMatching(new RegExp(`^/v1/tenants/${tat}/evidence\\?from=\\d{4}-\\d{2}-01&to=\\d{4}-\\d{2}-01&framework=pdpa$`))])

      await userEvent.selectOptions(screen.getByLabelText('Framework'), 'SOC 2')
      await userEvent.click(screen.getByRole('button', { name: 'Export SOC 2 evidence' }))
      expect((await screen.findByRole('alert')).textContent).toBe('signing key unavailable')
      expect(calls.at(-1)).toMatch(/framework=soc2$/)
      expect(create).toHaveBeenCalledTimes(1)
    } finally {
      click.mockRestore()
    }
  })

  it('compliance PDPA panel falls back to the raw mode for an unknown retention mode', async () => {
    mockFetch({ ...routes([]), [`/v1/tenants/${tat}/controls`]: controlReport, [`/v1/tenants/${tat}/pdpa`]: { ...pdpaOverview(), last_retention_run: { ran_at: '2026-10-10T02:00:00Z', mode: 'archived', detail: 'moved 3 rows' } } })
    render(<App />)
    await compliancePage()
    await userEvent.selectOptions(screen.getByLabelText('Framework'), 'PDPA')
    expect(await screen.findByText(/10 Oct 2026.*archived\. moved 3 rows/)).toBeTruthy()
    expect(screen.queryByText(/undefined/)).toBeNull()
  })

  it('compliance PDPA panel shows region, hold, open breaches with time left and the last retention run, read-only for a viewer', async () => {
    mockFetch({ ...routes([]), [`/v1/tenants/${tat}/controls`]: controlReport, [`/v1/tenants/${tat}/pdpa`]: pdpaOverview('Litigation TAT-2026-14') })
    render(<App />)
    await compliancePage()
    await userEvent.selectOptions(screen.getByLabelText('Framework'), 'PDPA')
    expect(await screen.findByText('ap-bangkok, ap-southeast-7')).toBeTruthy()
    expect(screen.getByText('In place: Litigation TAT-2026-14')).toBeTruthy()
    expect(screen.getByText('Off: retention runs are dry runs')).toBeTruthy()
    const breach = screen.getByText('CRM export emailed to the wrong partner').closest('article') as HTMLElement
    expect(within(breach).getByText('Warning: over 48 hours since aware')).toBeTruthy()
    expect(within(breach).getByText(/22 h left to notify the PDPC/)).toBeTruthy()
    expect(screen.queryByText('Old laptop lost')).toBeNull()
    expect(screen.getByText(/10 Oct 2026.*Dry run, nothing deleted\. would delete \(deletion is off for this Tenant\): findings 4, sessions 12/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /legal hold|Save PDPA settings/ })).toBeNull()
    expect(screen.queryByRole('textbox')).toBeNull()
  })

  it('compliance lets a platform admin lift a legal hold only with a reason', async () => {
    const bodies: Record<string, unknown> = {}
    const calls = mockFetch(
      { '/auth/me': operator, ...tenantRoutes, [`/v1/tenants/${tat}/controls`]: controlReport, [`/v1/tenants/${tat}/pdpa`]: pdpaOverview('Litigation TAT-2026-14'), [`/v1/tenants/${tat}/pdpa/settings`]: { data_regions: ['ap-bangkok'], deletion_enabled: false, legal_hold: '' } },
      bodies,
    )
    render(<App />)
    await userEvent.click(await screen.findByRole('button', { name: 'TAT' }))
    await compliancePage()
    await userEvent.selectOptions(screen.getByLabelText('Framework'), 'PDPA')
    await userEvent.click(await screen.findByRole('button', { name: 'Lift legal hold' }))
    expect(calls.filter((c) => c.endsWith('/pdpa/settings'))).toEqual([])
    await userEvent.type(screen.getByLabelText('Reason for lifting the hold'), '   ')
    await userEvent.click(screen.getByRole('button', { name: 'Lift legal hold' }))
    expect(calls.filter((c) => c.endsWith('/pdpa/settings'))).toEqual([])

    await userEvent.type(screen.getByLabelText('Reason for lifting the hold'), 'Case TAT-2026-14 settled')
    await userEvent.click(screen.getByRole('button', { name: 'Lift legal hold' }))
    await waitFor(() => expect(bodies[`/v1/tenants/${tat}/pdpa/settings`]).toEqual({ legal_hold: '', lift_reason: 'Case TAT-2026-14 settled' }))
  })

  it('compliance shows the not-allowed message per section on a 403', async () => {
    mockFetch({ ...routes([]), [`/v1/tenants/${tat}/controls`]: new Response('{"error":"forbidden"}', { status: 403 }) })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Compliance' }))
    expect((await screen.findByRole('alert')).textContent).toBe('You are not allowed to see this here.')
    expect(screen.queryByText('No gaps in this framework.')).toBeNull()
    await userEvent.selectOptions(screen.getByLabelText('Framework'), 'PDPA')
    await waitFor(() => expect(screen.getAllByRole('alert').map((a) => a.textContent)).toEqual(['You are not allowed to see this here.', 'You are not allowed to see this here.']))
    expect(screen.queryByText('No open personal data breaches.')).toBeNull()
    expect(screen.queryByText('Retention has not run yet.')).toBeNull()
    expect(screen.getByRole('button', { name: 'Export PDPA evidence' })).toBeTruthy()
  })

  it('findings tab lists anomalies with severity label and contributors', async () => {
    mockFetch({ ...routes([]), [`/v1/tenants/${tat}/findings`]: { items: [{ id: 'f1', kind: 'cost_anomaly', severity: 'critical', status: 'open', title: 'NAT Gateway spend 310.00 USD on 10 Sep', detail: { top_resources: [{ resource_id: 'nat-2', delta: '300.00' }] }, first_seen_at: '2026-09-11T03:00:00Z', resolution: null, due_at: '2026-09-18T03:00:00Z', overdue_at: '2026-09-19T00:00:00Z' }] } })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Findings' }))
    expect(await screen.findByText(/Critical · cost anomaly/)).toBeTruthy()
    expect(screen.getByText(/Overdue since 18 Sept 2026|Overdue since 18 Sep 2026/)).toBeTruthy()
    expect(screen.getByText(/nat-2 \(\+300.00\)/)).toBeTruthy()
  })
})

describe('client-owned accounts (ADR-0018)', () => {
  const role = { role_arn: 'qcs::cam::uin/200048351622:roleName/keel-readonly' }
  // e1 holds a client- and a platform-owned account (mixed), e2 only a client-owned one, e3 none.
  const routes: Routes = {
    ...tenantRoutes,
    [`/v1/tenants/${tat}/projects/p1/environments`]: { items: [{ id: 'e1', project_id: 'p1', name: 'prod' }, { id: 'e2', project_id: 'p1', name: 'dev' }, { id: 'e3', project_id: 'p1', name: 'sandbox' }] },
    [`/v1/tenants/${tat}/cloud-accounts`]: { items: [
      { id: 'a1', environment_id: 'e1', provider: 'tencent', external_id: '200048351622', name: 'tat-crm-prod', ownership: 'client', read_only_role: role },
      { id: 'a2', environment_id: 'e1', provider: 'aws', external_id: '123456789012', name: 'tat-crm-prod-aws', ownership: 'platform', read_only_role: null },
      { id: 'a3', environment_id: 'e2', provider: 'tencent', external_id: '200048351623', name: 'tat-crm-dev', ownership: 'client', read_only_role: role },
    ] },
    [`/v1/tenants/${tat}/cloud-accounts/role-health`]: { items: [
      { cloud_account_id: 'a1', client_payer: true, last_assume_at: '2026-10-10T01:00:00Z', last_ingest_at: '2026-10-10T02:00:00Z',
        findings: [{ id: 'f1', kind: 'client_role_unusable', severity: 'high', title: 'Keel cannot assume tencent read-only role keel-readonly for payer 200048351622' }] },
      { cloud_account_id: 'a3', client_payer: false, last_assume_at: null, last_ingest_at: null, findings: [] },
    ] },
  }
  const description = (el: HTMLElement) => document.getElementById(el.getAttribute('aria-describedby') ?? '')?.textContent ?? ''
  const envRow = async (name: string) => (await screen.findByText(name, { selector: '.env' })).closest('li') as HTMLElement
  const openProjects = async () => {
    await userEvent.click(await screen.findByRole('button', { name: 'TAT' }))
    await userEvent.click(await screen.findByRole('tab', { name: 'Projects' }))
  }

  it('badges Cloud Accounts, Environments and the Project in words, and says mixed when both', async () => {
    mockFetch({ '/auth/me': operator, ...routes })
    render(<App />)
    await openProjects()
    expect((await screen.findByRole('heading', { name: /TAT CRM/ })).textContent).toMatch(/Mixed ownership/)
    const prod = await envRow('prod')
    expect(within(prod).getAllByText('Mixed ownership')).toHaveLength(1)
    expect(within(prod).getAllByText('Client-owned')).toHaveLength(1) // a1
    expect(within(prod).getAllByText('Platform-owned')).toHaveLength(1) // a2
    expect(within(await envRow('dev')).getAllByText('Client-owned')).toHaveLength(2) // the Environment and a3
    expect(within(await envRow('sandbox')).queryByText(/owned|ownership/)).toBeNull()
  })

  it('disables vending and waste cleanup with the reason on client-owned Environments, and vends where Keel may', async () => {
    const calls = mockFetch({ '/auth/me': operator, ...routes, [`/v1/tenants/${tat}/projects/p1/environments/e3/vend`]: { id: 'fl1', state: 'running' } })
    render(<App />)
    await openProjects()
    for (const name of ['prod', 'dev']) {
      const row = await envRow(name)
      const vend = within(row).getByRole('button', { name: 'Vend Tencent account' }) as HTMLButtonElement
      expect(vend.disabled).toBe(true)
      expect(description(vend)).toMatch(/read-only role .* never changes it/)
      const cleanup = within(row).getByRole('checkbox', { name: /Automatic waste cleanup/ }) as HTMLInputElement
      expect(cleanup.disabled).toBe(true)
      expect(description(cleanup)).toMatch(/never changes it/)
    }
    const sandbox = await envRow('sandbox')
    const vend = within(sandbox).getByRole('button', { name: 'Vend Tencent account' }) as HTMLButtonElement
    expect(vend.disabled).toBe(false)
    expect(vend.getAttribute('aria-describedby')).toBeNull()
    expect((within(sandbox).getByRole('checkbox', { name: /Automatic waste cleanup/ }) as HTMLInputElement).disabled).toBe(false)
    await userEvent.click(vend)
    expect(calls).toContain(`/v1/tenants/${tat}/projects/p1/environments/e3/vend`)
  })

  it('shows read-only role health: last assume, last bill ingested and open role Findings', async () => {
    mockFetch({ '/auth/me': operator, ...routes })
    render(<App />)
    await openProjects()
    await waitFor(() => expect(screen.getAllByLabelText('Read-only role health')[0].textContent).toMatch(/Last successful assume10 Oct 2026/))
    const [prodHealth, devHealth] = screen.getAllByLabelText('Read-only role health')
    expect(prodHealth.textContent).toMatch(/qcs::cam::uin\/200048351622:roleName\/keel-readonly/)
    expect(prodHealth.textContent).toMatch(/Last bill ingested10 Oct 2026/)
    expect(within(prodHealth).getByText(/! High/).closest('li')?.textContent).toMatch(/Keel cannot assume tencent read-only role/)
    expect(devHealth.textContent).toMatch(/Last successful assumenever \(Keel assumes this role only to read a client payer’s bills\)/)
    expect(devHealth.textContent).toMatch(/Last bill ingestednever/)
    expect(devHealth.textContent).toMatch(/Open role and delivery Findingsnone/)
  })

  it('lists a client-owned account with no Environment as unassigned client-owned, never as a platform account', async () => {
    mockFetch({
      '/auth/me': operator,
      ...routes,
      [`/v1/tenants/${tat}/cloud-accounts`]: { items: [
        { id: 'a4', environment_id: null, provider: 'tencent', external_id: '200048351699', name: 'tat-payer', ownership: 'client', read_only_role: role },
        { id: 'a5', environment_id: null, provider: 'tencent', external_id: '200046202634', name: 'keel-shared', ownership: 'platform', read_only_role: null },
      ] },
      [`/v1/tenants/${tat}/cloud-accounts/role-health`]: { items: [{ cloud_account_id: 'a4', client_payer: true, last_assume_at: null, last_ingest_at: null, findings: [] }] },
    })
    render(<App />)
    await openProjects()
    const unassigned = (await screen.findByRole('heading', { name: 'Unassigned client-owned accounts' })).closest('article') as HTMLElement
    expect(within(unassigned).getByText(/tat-payer/)).toBeTruthy()
    expect(within(unassigned).queryByText(/keel-shared/)).toBeNull()
    await waitFor(() => expect(within(unassigned).getByLabelText('Read-only role health').textContent).toMatch(/Last successful assumenever.*Last bill ingestednever/))
    const platform = screen.getByRole('heading', { name: 'Platform accounts' }).closest('article') as HTMLElement
    expect(within(platform).getByText(/keel-shared/)).toBeTruthy()
    expect(within(platform).queryByText(/tat-payer/)).toBeNull()
  })

  it('shows a Tenant Member the same status, with no controls', async () => {
    mockFetch({ '/auth/me': member, ...routes })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Projects' }))
    await waitFor(() => expect(screen.getAllByLabelText('Read-only role health')[0].textContent).toMatch(/Last bill ingested10 Oct 2026/))
    expect(screen.getAllByLabelText('Read-only role health')).toHaveLength(2)
    expect(screen.getByRole('heading', { name: /TAT CRM/ }).textContent).toMatch(/Mixed ownership/)
    expect(screen.queryByRole('button', { name: /Vend|Make client-owned|Make platform-owned/ })).toBeNull()
    expect(screen.queryByRole('checkbox')).toBeNull()
  })

  it('lets a platform admin switch ownership and lists the Access Grants a 409 says to end', async () => {
    const bodies: Record<string, unknown> = {}
    const refusal = 'access grants are open in this account: reject or revoke them first: access_grant/0192a5b0-1111-7000-8000-000000000001 (user:ops@harmonyx.co, operator), access_grant/0192a5b0-1111-7000-8000-000000000002 (user:eng@harmonyx.co, read-only)'
    mockFetch({ '/auth/me': operator, ...routes, [`/v1/tenants/${tat}/cloud-accounts/a2`]: new Response(JSON.stringify({ error: refusal }), { status: 409 }) }, bodies)
    render(<App />)
    await openProjects()
    await userEvent.click(await screen.findByRole('button', { name: 'Make client-owned…' }))
    const form = screen.getByRole('form', { name: 'Change ownership of tat-crm-prod-aws' })
    await userEvent.type(within(form).getByLabelText('Role ARN'), 'arn:aws:iam::123456789012:role/keel-readonly')
    await userEvent.type(within(form).getByLabelText('Why'), 'client took the account back')
    await userEvent.click(within(form).getByRole('button', { name: 'Make client-owned' }))
    const alert = await within(form).findByRole('alert')
    expect(alert.textContent).toMatch(/cannot make tat-crm-prod-aws client-owned while these Access Grants are open/)
    expect(within(alert).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      'access_grant/0192a5b0-1111-7000-8000-000000000001 (user:ops@harmonyx.co, operator)',
      'access_grant/0192a5b0-1111-7000-8000-000000000002 (user:eng@harmonyx.co, read-only)',
    ])
    expect(bodies[`/v1/tenants/${tat}/cloud-accounts/a2`]).toEqual({ ownership: 'client', read_only_role: { role_arn: 'arn:aws:iam::123456789012:role/keel-readonly' }, why: 'client took the account back' })
  })

  it('disables an Access Grant request in a client-owned Environment with the reason', async () => {
    mockFetch({
      '/auth/me': operator, ...routes,
      [`/v1/tenants/${tat}/teams`]: { items: [{ id: 't1', slug: 'crm', name: 'CRM' }] },
      [`/v1/tenants/${tat}/access/templates`]: { items: [{ name: 'operator', description: '', write: true, max_hours: 2 }] },
      [`/v1/tenants/${tat}/access/roles`]: { items: [{ id: 'r1', environment_id: 'e2', team_id: 't1', template: 'operator', state: 'active', requested_by: 'u' }] },
      [`/v1/tenants/${tat}/access/grants`]: { items: [] },
      [`/v1/tenants/${tat}/findings`]: { items: [] },
    })
    render(<App />)
    await userEvent.click(await screen.findByRole('button', { name: 'TAT' }))
    await userEvent.click(await screen.findByRole('tab', { name: 'Access' }))
    const request = (await screen.findByRole('button', { name: 'Request access' })) as HTMLButtonElement
    await waitFor(() => expect(request.disabled).toBe(true))
    expect(description(request)).toMatch(/^Client-owned: .* never changes it/)
  })

  it('offers manual steps, not apply, for a recommendation in a client-owned account', async () => {
    mockFetch({
      '/auth/me': member, ...routes,
      [`/v1/tenants/${tat}/findings`]: { items: [{ id: 'f4', kind: 'rightsizing', severity: 'medium', status: 'open', title: 'Right-size ins-dev', detail: {}, first_seen_at: '2026-10-01T00:00:00Z', resolution: null }] },
      [`/v1/tenants/${tat}/recommendations`]: { items: [{ id: 'r4', finding_id: 'f4', pr_url: null, state: 'open', provider: 'tencent', account_id: '200048351623', environment_id: 'e2',
        resource_id: 'ins-dev', resource_type: 'vm', action: 'resize', current: { instance_type: 'S5.2XLARGE16' }, recommended: { instance_type: 'S5.LARGE8' } }] },
    })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Findings' }))
    const steps = await screen.findByText(/^Manual steps:/)
    expect(steps.textContent).toMatch(/resize on vm ins-dev in account 200048351623: change instance_type from S5.2XLARGE16 to S5.LARGE8\. Client-owned: .* never changes it/)
    expect(screen.queryByRole('button', { name: /Open pull request|Apply/ })).toBeNull()
  })
})

describe('visibleTenantIds', () => {
  it('dedupes own tenant and bindings', () => {
    expect(visibleTenantIds(operator)).toEqual([home, tat])
    expect(visibleTenantIds(member)).toEqual([tat])
  })
})
