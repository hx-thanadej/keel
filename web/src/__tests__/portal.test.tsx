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
    expect(await screen.findByText('TAT CRM')).toBeTruthy()
    expect(screen.getByText(/tat-crm-prod/)).toBeTruthy()
    expect(screen.getByText('no cloud account')).toBeTruthy() // dev has none
    expect(screen.getByText(/· MFA/)).toBeTruthy()
  })

  it('tenant member sees only their own tenant', async () => {
    const calls = mockFetch({ '/auth/me': member, ...tenantRoutes })
    render(<App />)
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

describe('visibleTenantIds', () => {
  it('dedupes own tenant and bindings', () => {
    expect(visibleTenantIds(operator)).toEqual([home, tat])
    expect(visibleTenantIds(member)).toEqual([tat])
  })
})
