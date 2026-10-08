import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
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

  it('security tab shows VSA results, approves exceptions, requires VEX justification and lists control gaps', async () => {
    const calls = mockFetch({
      ...routes([]),
      [`/v1/tenants/${tat}/services`]: { items: [{ id: 's1', project_id: 'p1', slug: 'crm-api', name: 'CRM API', repository: '', template: '' }] },
      [`/v1/tenants/${tat}/releases`]: { items: [{ id: 'r1', service_id: 's1', version: '1.5.0', images: [], created_at: '2026-10-01T00:00:00Z' }] },
      [`/v1/tenants/${tat}/releases/r1/attestations`]: { items: [{ id: 'a1', image_digest: 'sha256:aa', passed: false, created_at: '2026-10-01T00:00:00Z',
        checks: [{ name: 'signature', pass: true, detail: 'ok' }, { name: 'trigger', pass: false, detail: 'triggered by pull_request_target' }] }] },
      [`/v1/tenants/${tat}/exceptions`]: { items: [{ id: 'x1', fingerprint: 'vuln:CVE-2026-1:', finding_ids: [], reason: 'patch next sprint', state: 'requested', requested_by: 'user:eng@harmonyx.co', decided_by: null, expires_at: '2026-11-01T00:00:00Z' }] },
      [`/v1/tenants/${tat}/exceptions/x1/approve`]: { id: 'x1', state: 'approved' },
      [`/v1/tenants/${tat}/vex`]: { items: [] },
      [`/v1/tenants/${tat}/controls`]: { version: 'keel-controls@1', services: 1, controls: [
        { id: 'PW.7.2', framework: 'SSDF', title: 'Review code', policies: ['keel-scans@1'], coverage: [{ name: 'keel-scans@1', point: 'pipeline', covered_services: 1 }], gap: false },
        { id: 'PO.1.1', framework: 'SSDF', title: 'Security requirements', policies: [], coverage: [], gap: true }] },
    })
    vi.stubGlobal('prompt', () => 'internal only')
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Security' }))
    expect(await screen.findByText(/VSA failed: trigger/)).toBeTruthy()
    expect(screen.getByText(/triggered by pull_request_target/)).toBeTruthy()
    expect(screen.getByText(/2 controls, 1 without coverage, across 1 services/)).toBeTruthy()
    expect(screen.getByText('no Keel policy yet')).toBeTruthy()
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
      [`/v1/tenants/${tat}/reports`]: [{ period: '2026-09', generated_at: '2026-10-01T01:00:00Z' }],
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
    expect(screen.getByText('Operational')).toBeTruthy() // Q3 trend cell
    expect(screen.getByText('Keel measures Scalable')).toBeTruthy()
    expect((screen.getByRole('combobox') as HTMLSelectElement).value).toBe('3') // pre-filled from the measure
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
    expect(await screen.findByText('report store down')).toBeTruthy()
    expect(create).not.toHaveBeenCalled()
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

  it('findings tab lists anomalies with severity label and contributors', async () => {
    mockFetch({ ...routes([]), [`/v1/tenants/${tat}/findings`]: { items: [{ id: 'f1', kind: 'cost_anomaly', severity: 'critical', status: 'open', title: 'NAT Gateway spend 310.00 USD on 10 Sep', detail: { top_resources: [{ resource_id: 'nat-2', delta: '300.00' }] }, first_seen_at: '2026-09-11T03:00:00Z', resolution: null, due_at: '2026-09-18T03:00:00Z', overdue_at: '2026-09-19T00:00:00Z' }] } })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Findings' }))
    expect(await screen.findByText(/Critical · cost anomaly/)).toBeTruthy()
    expect(screen.getByText(/Overdue since 18 Sept 2026|Overdue since 18 Sep 2026/)).toBeTruthy()
    expect(screen.getByText(/nat-2 \(\+300.00\)/)).toBeTruthy()
  })
})

describe('visibleTenantIds', () => {
  it('dedupes own tenant and bindings', () => {
    expect(visibleTenantIds(operator)).toEqual([home, tat])
    expect(visibleTenantIds(member)).toEqual([tat])
  })
})
