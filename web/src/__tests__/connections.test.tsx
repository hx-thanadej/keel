import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../App'
import { ConnectionsView } from '../ConnectionsView'
import type { CloudConnection, Principal } from '../api'

const home = 'h-1'
const tat = 't-1'

type Call = { method: string; path: string; body?: unknown }
type Handler = (call: Call) => unknown

/** Routes "METHOD /path" to a handler; anything else is a 403. Records every call with its parsed body. */
function mockFetch(routes: Record<string, Handler | unknown>) {
  const calls: Call[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = new URL(input, 'http://keel.test')
      const call: Call = { method: init?.method ?? 'GET', path: url.pathname, body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined }
      calls.push(call)
      const key = `${call.method} ${call.path}`
      if (!(key in routes)) return new Response(JSON.stringify({ error: 'forbidden' }), { status: 403 })
      const v = routes[key]
      const body = typeof v === 'function' ? (v as Handler)(call) : v
      if (body instanceof Response) return body
      if (body === undefined) return new Response(null, { status: 204 })
      return new Response(JSON.stringify(body), { status: 200 })
    }),
  )
  return calls
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const conn: CloudConnection = {
  id: 'c-1',
  provider: 'tencent',
  name: 'HarmonyX payer',
  payer_uin: '100000000001',
  default_region: 'ap-bangkok',
  org_region: 'ap-bangkok',
  member_role: 'OrganizationAccessControlRole',
  mode: 'read_only',
  secret_id: '****FAKE',
  created_at: '2026-10-15T01:00:00Z',
  created_by: 'user:admin@harmonyx.co',
  updated_at: '2026-10-15T01:00:00Z',
  rotated_at: null,
  last_test: null,
}

describe('cloud connections (ADR-0022)', () => {
  it('adds a Tencent connection; the key is write-only and cleared after saving', async () => {
    let stored: CloudConnection[] = []
    const calls = mockFetch({
      'GET /v1/cloud-connections': () => ({ items: stored }),
      'POST /v1/cloud-connections': () => {
        stored = [conn]
        return new Response(JSON.stringify(conn), { status: 201 })
      },
    })
    render(<ConnectionsView />)
    expect(await screen.findByText(/No Tencent connection/)).toBeTruthy()
    await userEvent.type(screen.getByLabelText('Name'), 'HarmonyX payer')
    await userEvent.type(screen.getByLabelText('Payer UIN'), '100000000001')
    await userEvent.type(screen.getByLabelText('Organisation region'), 'ap-bangkok')
    await userEvent.type(screen.getByLabelText('Member role'), 'OrganizationAccessControlRole')
    await userEvent.type(screen.getByLabelText('SecretId'), 'TESTIDz8krbsJ5yKBZQpn74WFkmLPx3FAKE')
    const secret = screen.getByLabelText('SecretKey') as HTMLInputElement
    expect(secret.type).toBe('password')
    expect(secret.autocomplete).toBe('new-password')
    await userEvent.type(secret, 'Gu5t9xGARNpq86cd98joQYCN3EXAMPLEKEY')
    await userEvent.click(screen.getByRole('button', { name: 'Add connection' }))

    const card = await screen.findByRole('article', { name: 'HarmonyX payer' })
    expect(within(card).getByText('Read-only')).toBeTruthy()
    expect(within(card).getByText('****FAKE')).toBeTruthy()
    expect(within(card).getByText('Not tested yet')).toBeTruthy()
    expect(document.body.textContent).not.toContain('Gu5t9xGARNpq86cd98joQYCN3EXAMPLEKEY')
    const post = calls.find((c) => c.method === 'POST')
    expect(post?.body).toEqual({
      provider: 'tencent',
      name: 'HarmonyX payer',
      payer_uin: '100000000001',
      default_region: 'ap-bangkok',
      org_region: 'ap-bangkok',
      member_role: 'OrganizationAccessControlRole',
      keys: { secret_id: 'TESTIDz8krbsJ5yKBZQpn74WFkmLPx3FAKE', secret_key: 'Gu5t9xGARNpq86cd98joQYCN3EXAMPLEKEY' },
    })
    expect(screen.queryByRole('button', { name: 'Add connection' })).toBeNull()
  })

  it('tests a connection and shows the caller UIN, or the failure', async () => {
    let ok = true
    mockFetch({
      'GET /v1/cloud-connections': { items: [conn] },
      'POST /v1/cloud-connections/c-1/test': () => ({
        ...conn,
        last_test: ok
          ? { at: '2026-10-15T02:00:00Z', ok: true, caller_uin: '100000000001', detail: 'the key belongs to payer 100000000001' }
          : { at: '2026-10-15T02:05:00Z', ok: false, caller_uin: '', detail: 'AuthFailure.SecretIdNotFound' },
      }),
    })
    render(<ConnectionsView />)
    await userEvent.click(await screen.findByRole('button', { name: 'Test connection' }))
    expect(await screen.findByText(/Passed: account 100000000001/)).toBeTruthy()
    ok = false
    await userEvent.click(screen.getByRole('button', { name: 'Test connection' }))
    expect(await screen.findByText(/Failed: AuthFailure.SecretIdNotFound/)).toBeTruthy()
  })

  it('rotates keys with both halves and deletes only after confirming', async () => {
    let stored = [conn]
    const calls = mockFetch({
      'GET /v1/cloud-connections': () => ({ items: stored }),
      'PATCH /v1/cloud-connections/c-1': () => ({ ...conn, secret_id: '****9ZZZ', rotated_at: '2026-10-15T03:00:00Z' }),
      'DELETE /v1/cloud-connections/c-1': () => {
        stored = []
        return undefined
      },
    })
    render(<ConnectionsView />)
    await userEvent.click(await screen.findByRole('button', { name: 'Rotate keys' }))
    await userEvent.type(screen.getByLabelText('New SecretId'), 'TESTIDrotatedrotatedrotated9ZZZ')
    await userEvent.type(screen.getByLabelText('New SecretKey'), 'rotated-secret-key-0123456789')
    await userEvent.click(screen.getByRole('button', { name: 'Save new keys' }))
    expect(await screen.findByText('****9ZZZ')).toBeTruthy()
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({ keys: { secret_id: 'TESTIDrotatedrotatedrotated9ZZZ', secret_key: 'rotated-secret-key-0123456789' } })

    await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false)
    await userEvent.click(screen.getByRole('button', { name: 'Delete permanently' }))
    expect(await screen.findByText(/No Tencent connection/)).toBeTruthy()
    expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(1)
  })

  it('shows the server error next to the form', async () => {
    mockFetch({
      'GET /v1/cloud-connections': { items: [] },
      'POST /v1/cloud-connections': new Response(JSON.stringify({ error: 'conflict\nKEEL_SECRETS_KEY is not set, so Keel cannot store or use cloud keys' }), { status: 409 }),
    })
    render(<ConnectionsView />)
    await userEvent.type(await screen.findByLabelText('Name'), 'x')
    await userEvent.type(screen.getByLabelText('Payer UIN'), '100000000001')
    await userEvent.type(screen.getByLabelText('SecretId'), 'TESTIDz8krbsJ5yKBZQpn74WFkmLPx3FAKE')
    await userEvent.type(screen.getByLabelText('SecretKey'), 'Gu5t9xGARNpq86cd98joQYCN3EXAMPLEKEY')
    await userEvent.click(screen.getByRole('button', { name: 'Add connection' }))
    expect((await screen.findByRole('alert')).textContent).toContain('KEEL_SECRETS_KEY is not set')
  })

  it('offers the Connections tab only to platform admins of the home Tenant', async () => {
    const admin: Principal = {
      subject: 'user:admin@harmonyx.co',
      kind: 'human',
      tenant_id: home,
      home: true,
      bindings: [
        { role: 'platform_admin', tenant_id: home },
        { role: 'platform_admin', tenant_id: tat },
      ],
    }
    const tenants = {
      [`GET /v1/tenants/${home}`]: { id: home, slug: 'harmonyx', name: 'HarmonyX', is_home: true },
      [`GET /v1/tenants/${tat}`]: { id: tat, slug: 'tat', name: 'TAT', is_home: false },
      'GET /v1/cloud-connections': { items: [conn] },
    }
    mockFetch({ 'GET /auth/me': admin, ...tenants })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Connections' }))
    expect(await screen.findByRole('article', { name: 'HarmonyX payer' })).toBeTruthy()
    await userEvent.click(screen.getByRole('button', { name: 'TAT' }))
    await waitFor(() => expect(screen.queryByRole('tab', { name: 'Connections' })).toBeNull())

    cleanup()
    const lead: Principal = { ...admin, bindings: [{ role: 'team_lead', tenant_id: home }] }
    mockFetch({ 'GET /auth/me': lead, ...tenants })
    render(<App />)
    expect(await screen.findByRole('tab', { name: 'Budgets' })).toBeTruthy()
    expect(screen.queryByRole('tab', { name: 'Connections' })).toBeNull()
  })
})
