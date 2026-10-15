import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../App'
import type { Principal } from '../api'

const home = 'h-1'
const tat = 't-1'

type Handler = unknown | ((body: unknown) => unknown)

/** Routes keyed "METHOD /path"; a Response is returned as is. */
function mockFetch(routes: Record<string, Handler>) {
  const sent: { method: string; path: string; body: unknown }[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = new URL(input, 'http://keel.test')
      const method = init?.method ?? 'GET'
      const body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined
      sent.push({ method, path: url.pathname, body })
      const v = routes[`${method} ${url.pathname}`]
      if (v === undefined) return new Response(JSON.stringify({ error: 'forbidden' }), { status: 403 })
      const out = typeof v === 'function' ? (v as (b: unknown) => unknown)(body) : v
      return out instanceof Response ? out : new Response(JSON.stringify(out), { status: 200 })
    }),
  )
  return sent
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

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

const seen = { first_seen_at: '2026-10-14T03:00:00Z', last_seen_at: '2026-10-15T03:00:00Z' }
const dev = { provider: 'tencent', external_id: '200046202634', name: 'tat-crm-dev', parent: 'TAT', registered: false, suggestion: { project_slug: 'tat-crm', environment: 'dev' }, ...seen }
const prod = { ...dev, external_id: '200048351622', name: 'tat-crm-prod', suggestion: { project_slug: 'tat-crm', environment: 'prod' } }
const payer = { provider: 'tencent', external_id: '200045645249', name: 'payer', parent: 'root', registered: false, ...seen }
const done = { ...dev, external_id: '200011111111', name: 'already-in', registered: true }

const base = {
  'GET /auth/me': admin,
  [`GET /v1/tenants/${home}`]: { id: home, slug: 'harmonyx', name: 'HarmonyX', is_home: true },
  [`GET /v1/tenants/${tat}`]: { id: tat, slug: 'tat', name: 'TAT', is_home: false },
  [`GET /v1/tenants/${home}/projects`]: { items: [] },
  [`GET /v1/tenants/${home}/cloud-accounts`]: { items: [] },
  [`GET /v1/tenants/${home}/teams`]: { items: [{ id: 'team-p', slug: 'platform', name: 'Platform' }] },
  [`GET /v1/tenants/${tat}/teams`]: { items: [] },
}

const outcome = (a: { provider: string; external_id: string }, extra: object = {}) => ({ provider: a.provider, external_id: a.external_id, status: 'registered', project_created: false, environment_created: false, ...extra })

async function openProjects() {
  render(<App />)
  await userEvent.click(await screen.findByRole('tab', { name: 'Projects' }))
  return screen.findByRole('region', { name: 'Accounts found in your cloud organisations' })
}

describe('discovered accounts', () => {
  it('lists unregistered accounts in plain words with Keel’s suggestion prefilled', async () => {
    mockFetch({ ...base, [`GET /v1/tenants/${home}/discovered-accounts`]: { items: [dev, payer, done] } })
    const region = await openProjects()
    const row = await within(region).findByRole('group', { name: 'tat-crm-dev' })
    expect(within(row).getByText('200046202634')).toBeTruthy()
    expect(within(row).getByText(/Account ID/)).toBeTruthy()
    expect(within(row).getByText(/TAT/)).toBeTruthy()
    expect((within(row).getByLabelText('Project') as HTMLInputElement).value).toBe('tat-crm')
    expect((within(row).getByLabelText('Environment') as HTMLInputElement).value).toBe('dev')
    const noGuess = within(region).getByRole('group', { name: 'payer' })
    expect((within(noGuess).getByLabelText('Project') as HTMLInputElement).value).toBe('')
    expect(within(noGuess).getByText(/Leave both blank/)).toBeTruthy()
    expect(within(region).queryByText('already-in')).toBeNull()
    expect(within(region).getByText(/1 account found earlier is already registered/)).toBeTruthy()
    expect(region.textContent).not.toMatch(/external_id|project_slug/)
  })

  it('registers the selected accounts in one step, with edits, and says what it created', async () => {
    let listed = [dev, prod, payer]
    const sent = mockFetch({
      ...base,
      [`GET /v1/tenants/${home}/discovered-accounts`]: () => ({ items: listed }),
      [`POST /v1/tenants/${home}/cloud-accounts/register`]: () => {
        listed = [prod]
        return { items: [outcome(dev, { project_created: true, environment_created: true }), outcome(payer)] }
      },
    })
    const region = await openProjects()
    const button = await within(region).findByRole('button', { name: 'Select accounts to register' })
    expect((button as HTMLButtonElement).disabled).toBe(true)
    await userEvent.click(within(region).getByRole('checkbox', { name: 'Select tat-crm-dev' }))
    await userEvent.click(within(region).getByRole('checkbox', { name: 'Select payer' }))
    const devRow = within(region).getByRole('group', { name: 'tat-crm-dev' })
    await userEvent.clear(within(devRow).getByLabelText('Environment'))
    await userEvent.type(within(devRow).getByLabelText('Environment'), 'develop')
    await userEvent.click(within(region).getByRole('button', { name: 'Register 2 selected accounts' }))

    expect(await within(region).findByRole('status')).toHaveProperty('textContent', expect.stringMatching(/Registered 2 accounts in HarmonyX\. Created 1 project and 1 environment\./))
    const post = sent.find((r) => r.method === 'POST')!
    expect(post.body).toEqual({
      team_id: 'team-p',
      accounts: [
        { provider: 'tencent', external_id: '200046202634', name: 'tat-crm-dev', project: 'tat-crm', environment: 'develop', ownership: 'platform' },
        { provider: 'tencent', external_id: '200045645249', name: 'payer', project: '', environment: '', ownership: 'platform' },
      ],
    })
    await waitFor(() => expect(within(region).queryByRole('group', { name: 'tat-crm-dev' })).toBeNull())
    expect(within(region).getByRole('group', { name: 'tat-crm-prod' })).toBeTruthy()
  })

  it('creates a team inline when the target organisation has none', async () => {
    const sent = mockFetch({
      ...base,
      [`GET /v1/tenants/${home}/discovered-accounts`]: { items: [dev] },
      [`POST /v1/tenants/${tat}/teams`]: { id: 'team-new', slug: 'tat-crm-team', name: 'TAT CRM team' },
      [`POST /v1/tenants/${tat}/cloud-accounts/register`]: { items: [outcome(dev)] },
    })
    const region = await openProjects()
    await userEvent.selectOptions(await within(region).findByLabelText('Register into'), 'TAT')
    expect(await within(region).findByText(/TAT has no teams yet/)).toBeTruthy()
    await userEvent.type(within(region).getByLabelText('New team name'), 'TAT CRM team')
    await userEvent.click(within(region).getByRole('checkbox', { name: 'Select all' }))
    await userEvent.click(within(region).getByRole('button', { name: 'Register 1 selected account' }))
    await within(region).findByText(/Registered 1 account in TAT/)
    expect(sent.find((r) => r.method === 'POST' && r.path === `/v1/tenants/${tat}/teams`)?.body).toMatchObject({ slug: 'tat-crm-team', name: 'TAT CRM team' })
    expect(sent.find((r) => r.path.endsWith('/register'))?.body).toMatchObject({ team_id: 'team-new' })
  })

  it('explains failures in human terms and keeps the failed accounts selected', async () => {
    mockFetch({
      ...base,
      [`GET /v1/tenants/${home}/discovered-accounts`]: { items: [dev, prod] },
      [`POST /v1/tenants/${home}/cloud-accounts/register`]: {
        items: [
          outcome(dev, { status: 'failed', error: 'already exists: cloud_accounts_environment_id_provider_key' }),
          outcome(prod, { status: 'failed', error: 'already exists: cloud_accounts_provider_external_id_key' }),
        ],
      },
    })
    const region = await openProjects()
    await userEvent.click(await within(region).findByRole('checkbox', { name: 'Select all' }))
    await userEvent.click(within(region).getByRole('button', { name: 'Register 2 selected accounts' }))
    const alert = await within(region).findByRole('alert')
    expect(alert.textContent).toContain('tat-crm-dev: This environment already has a Tencent account. Pick another environment or create one.')
    expect(alert.textContent).toContain('tat-crm-prod: This account is already registered in Keel, possibly in another organisation.')
    expect(alert.textContent).not.toMatch(/_key/)
    expect((within(region).getByRole('checkbox', { name: 'Select tat-crm-dev' }) as HTMLInputElement).checked).toBe(true)
  })

  it('asks for the read-only role when the client manages the accounts', async () => {
    const sent = mockFetch({
      ...base,
      [`GET /v1/tenants/${home}/discovered-accounts`]: { items: [dev] },
      [`POST /v1/tenants/${home}/cloud-accounts/register`]: { items: [outcome(dev)] },
    })
    const region = await openProjects()
    await userEvent.click(await within(region).findByRole('checkbox', { name: 'Select tat-crm-dev' }))
    await userEvent.click(within(region).getByRole('radio', { name: /The client’s organisation/ }))
    await userEvent.type(within(region).getByLabelText('Read-only role ARN'), 'qcs::cam::uin/200046202634:roleName/KeelReadOnly')
    await userEvent.click(within(region).getByRole('button', { name: 'Register 1 selected account' }))
    await within(region).findByRole('status')
    expect(sent.find((r) => r.method === 'POST')?.body).toMatchObject({
      accounts: [{ ownership: 'client', read_only_role: { role_arn: 'qcs::cam::uin/200046202634:roleName/KeelReadOnly' } }],
    })
  })

  it('says what to do next when nothing has been discovered, and why discovery cannot run', async () => {
    mockFetch({
      ...base,
      [`GET /v1/tenants/${home}/discovered-accounts`]: { items: [] },
      [`POST /v1/tenants/${home}/discoveries/tencent`]: new Response(JSON.stringify({ error: 'no discovery source configured for tencent' }), { status: 404 }),
    })
    const region = await openProjects()
    expect(await within(region).findByText(/hasn’t looked for accounts yet/)).toBeTruthy()
    await userEvent.click(within(region).getByRole('button', { name: 'Discover Tencent accounts' }))
    expect((await within(region).findByRole('alert')).textContent).toMatch(/isn’t set up to discover Tencent accounts/)
  })

  it('runs discovery and shows the new accounts', async () => {
    mockFetch({
      ...base,
      [`GET /v1/tenants/${home}/discovered-accounts`]: { items: [] },
      [`POST /v1/tenants/${home}/discoveries/tencent`]: { items: [dev, done] },
    })
    const region = await openProjects()
    await userEvent.click(await within(region).findByRole('button', { name: 'Discover Tencent accounts' }))
    expect(await within(region).findByRole('group', { name: 'tat-crm-dev' })).toBeTruthy()
    expect(within(region).getByRole('status').textContent).toMatch(/Found 2 Tencent accounts; 1 is not registered yet/)
  })

  it('is not offered outside the home organisation or to non-admins', async () => {
    mockFetch({
      ...base,
      'GET /auth/me': { ...admin, bindings: [{ role: 'tenant_viewer', tenant_id: home }] },
      [`GET /v1/tenants/${home}/discovered-accounts`]: { items: [dev] },
    })
    render(<App />)
    await userEvent.click(await screen.findByRole('tab', { name: 'Projects' }))
    await screen.findByText('No projects yet.')
    expect(screen.queryByRole('region', { name: 'Accounts found in your cloud organisations' })).toBeNull()
  })
})
