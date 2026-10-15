import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { explainMonth, explainRun, relativeTime, EMPTY_NEXT, type SyncMonth, type SyncStatus } from '../billSync'
import { BillSyncPanel } from '../BillSyncStatus'
import { CostsView } from '../CostsView'
import { BudgetsView } from '../BudgetsView'
import { ConnectionsView } from '../ConnectionsView'

const tenant = 't-1'
const NOW = new Date('2026-10-15T10:00:00Z')
const ago = (minutes: number) => new Date(NOW.getTime() - minutes * 60_000).toISOString()

function mockFetch(routes: Record<string, unknown>) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string) => {
      const path = new URL(input, 'http://keel.test').pathname
      if (!(path in routes)) return new Response(JSON.stringify({ error: 'forbidden' }), { status: 403 })
      return new Response(JSON.stringify(routes[path]), { status: 200 })
    }),
  )
}

const month = (m: Partial<SyncMonth> & Pick<SyncMonth, 'month' | 'state'>): SyncMonth => ({ lines: 0, since: ago(60), checked_at: ago(12), ...m })
const status = (s: Partial<SyncStatus>): SyncStatus => ({
  provider: 'tencent',
  billing_account_id: '200045645249',
  source: 'api',
  checked_at: ago(12),
  state: 'ok',
  since: ago(60),
  months: [],
  ...s,
})

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] })
  vi.setSystemTime(NOW)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('relativeTime', () => {
  it.each([
    [ago(0.2), 'just now'],
    [ago(12), '12 minutes ago'],
    [ago(1), '1 minute ago'],
    [ago(59.9), '59 minutes ago'],
    [ago(60), '1 hour ago'],
    [ago(60 * 26), '1 day ago'],
    [ago(60 * 24 * 3), '3 days ago'],
    [new Date(NOW.getTime() + 40 * 60_000).toISOString(), 'in 40 minutes'],
  ])('%s reads %s', (iso, want) => expect(relativeTime(iso, NOW.getTime())).toBe(want))
})

describe('explainMonth', () => {
  it('says an empty month found no costs, and why, in plain words', () => {
    const e = explainMonth(month({ month: '2026-09', state: 'empty' }), status({}))
    expect(e.badge).toBe('No costs found')
    expect(e.headline).toBe('No costs found for September 2026')
    expect(e.next).toBe(EMPTY_NEXT)
    expect(EMPTY_NEXT).toBe("If this account belongs to another organisation that pays the bill, Keel can't see its costs. Ask that payer for a read-only bill role.")
  })
  it('counts lines and money for loaded and unchanged months', () => {
    expect(explainMonth(month({ month: '2026-09', state: 'loaded', lines: 302, total: '40.00', currency: 'USD' }), status({}))).toMatchObject({
      badge: 'Up to date',
      tone: 'good',
      headline: 'September 2026: 302 lines, 40.00 USD',
    })
    const e = explainMonth(month({ month: '2026-09', state: 'unchanged', lines: 1, total: '2.00', currency: 'USD' }), status({}))
    expect(e.headline).toBe('September 2026: 1 line, 2.00 USD, no change since the last pull')
    expect(e.next).toBeUndefined()
  })
  it('says what to fix and where for a blocked month', () => {
    const cur = explainMonth(month({ month: '2026-09', state: 'blocked', reason: 'currency_unknown' }), status({}))
    expect(cur.badge).toBe('Needs attention')
    expect(cur.headline).toBe("September 2026 wasn't loaded because Keel couldn't tell which currency the bill is in")
    expect(cur.next).toContain('set KEEL_TENCENT_BILL_CURRENCY')
    const overlap = explainMonth(month({ month: '2026-09', state: 'blocked', reason: 'files_overlap' }), status({ source: 'files' }))
    expect(overlap.headline).toContain('two bill files charge the same account for the same time')
    expect(overlap.next).toContain('Standard bill (FOCUS)')
  })
  it('names the failure, the retry, and keeps the error code out of the headline', () => {
    const e = explainMonth(month({ month: '2026-09', state: 'failed', reason: 'provider', code: 'InternalError' }), status({ checked_at: ago(20) }))
    expect(e.badge).toBe('Failed')
    expect(e.tone).toBe('critical')
    expect(e.headline).toBe("Keel couldn't pull September 2026: the billing service returned an error")
    expect(e.next).toBe('Keel tries again every hour. The next try is in 40 minutes.')
    expect(e.code).toBe('InternalError')
    const denied = explainMonth(month({ month: '2026-09', state: 'failed', reason: 'denied', code: 'AuthFailure.SignatureFailure' }), status({}))
    expect(denied.next).toContain('Test connection')
  })
})

describe('explainRun', () => {
  it.each([
    ['no_bill_files', 'empty', 'No bill files in the bucket', 'Bill Storage'],
    ['no_bucket', 'blocked', 'No bill bucket is set up for this payer', 'Record the bill bucket'],
    ['bucket_unreadable', 'blocked', "Keel signed in to the payer account but couldn't read the bill bucket", 'list and read the bucket'],
    ['role_unusable', 'blocked', "Keel couldn't sign in to the payer account's read-only role", 'External ID'],
    ['keel_identity', 'blocked', "Keel's own cloud sign-in isn't working, so no bills were pulled", "Nothing is wrong on the payer's side"],
  ] as const)('%s: %s', (reason, state, headline, next) => {
    const e = explainRun(status({ state, reason, source: 'files' }))
    expect(e.headline).toBe(headline)
    expect(e.next).toContain(next)
    expect(e.headline + (e.next ?? '')).not.toContain(reason)
  })
  it('reads a healthy run as up to date and an empty run by its empty month', () => {
    expect(explainRun(status({})).badge).toBe('Up to date')
    const e = explainRun(status({ state: 'empty', months: [month({ month: '2026-10', state: 'empty' }), month({ month: '2026-09', state: 'loaded', lines: 3 })] }))
    expect(e.headline).toBe('No costs found for October 2026')
    expect(e.next).toContain(EMPTY_NEXT)
    expect(e.next).toContain("A new month's costs can take up to a day to appear.")
  })
})

describe('BillSyncPanel', () => {
  it('shows each payer with a relative time, the exact time on hover, text badges and next steps', () => {
    render(
      <BillSyncPanel
        statuses={[
          status({ state: 'empty', months: [month({ month: '2026-09', state: 'empty' }), month({ month: '2026-08', state: 'loaded', lines: 302, total: '40.00', currency: 'USD' })] }),
        ]}
      />,
    )
    const payer = screen.getByRole('article', { name: /Tencent payer 200045645249/ })
    expect(within(payer).getByText('Billing API')).toBeTruthy()
    const t = within(payer).getByText('12 minutes ago')
    expect(t.tagName).toBe('TIME')
    expect(t.getAttribute('dateTime')).toBe(ago(12))
    expect(t.getAttribute('title')).toBe(new Date(ago(12)).toLocaleString())
    expect(within(payer).getAllByText('No costs found').length).toBeGreaterThan(0)
    expect(within(payer).getAllByText('No costs found for September 2026')).toHaveLength(1)
    expect(within(payer).getAllByText(EMPTY_NEXT).length).toBeGreaterThan(0)
    expect(within(payer).getByText('August 2026: 302 lines, 40.00 USD')).toBeTruthy()
    expect(payer.textContent).not.toMatch(/empty=|\bempty\b|2026-09/)
  })
  it('says when nothing has been pulled yet', () => {
    render(<BillSyncPanel statuses={[]} />)
    expect(screen.getByText(/Keel hasn't pulled any bills for this organisation yet/)).toBeTruthy()
  })
})

describe('Connections screen', () => {
  it('shows bill sync and discovery status', async () => {
    mockFetch({
      '/v1/cloud-connections': { items: [] },
      [`/v1/tenants/${tenant}/bill-sync`]: { items: [status({ months: [month({ month: '2026-10', state: 'loaded', lines: 5, total: '1.00', currency: 'USD' })] })] },
      [`/v1/tenants/${tenant}/discovered-accounts`]: {
        items: [
          { provider: 'tencent', external_id: '1', name: 'a', last_seen_at: ago(180) },
          { provider: 'tencent', external_id: '2', name: 'b', last_seen_at: ago(180) },
        ],
      },
    })
    render(<ConnectionsView tenantId={tenant} />)
    expect(await screen.findByText('October 2026: 5 lines, 1.00 USD')).toBeTruthy()
    expect(await screen.findByText(/2 accounts found/)).toBeTruthy()
    expect(screen.getByText('3 hours ago')).toBeTruthy()
  })
})

describe('empty Costs and Budgets', () => {
  const emptyRun = status({ state: 'empty', months: [month({ month: '2026-10', state: 'empty' })] })

  it('Costs says why the month has no costs and opens the bill sync status', async () => {
    mockFetch({ [`/v1/tenants/${tenant}/costs/daily`]: { items: [] }, [`/v1/tenants/${tenant}/bill-sync`]: { items: [emptyRun] } })
    render(<CostsView tenantId={tenant} />)
    expect(await screen.findByRole('heading', { name: 'No costs found for October 2026' })).toBeTruthy()
    expect(await screen.findByText(/it had no costs/)).toBeTruthy()
    expect(document.body.textContent).toContain(EMPTY_NEXT)
    await userEvent.click(screen.getByText('Bill sync status'))
    expect(screen.getByRole('article', { name: /Tencent payer 200045645249/ })).toBeTruthy()
  })

  it('Costs explains a loaded month with nothing for this organisation', async () => {
    mockFetch({
      [`/v1/tenants/${tenant}/costs/daily`]: { items: [] },
      [`/v1/tenants/${tenant}/bill-sync`]: { items: [status({ months: [month({ month: '2026-10', state: 'loaded', lines: 9 })] })] },
    })
    render(<CostsView tenantId={tenant} />)
    expect(await screen.findByText(/none of its costs belong to this organisation's projects/)).toBeTruthy()
  })

  it('Costs still says the month is empty when the status cannot load', async () => {
    mockFetch({ [`/v1/tenants/${tenant}/costs/daily`]: { items: [] } })
    render(<CostsView tenantId={tenant} />)
    expect(await screen.findByRole('heading', { name: 'No costs found for October 2026' })).toBeTruthy()
  })

  it('Budgets explains there is no cost data yet', async () => {
    mockFetch({ [`/v1/tenants/${tenant}/budgets`]: { items: [] }, [`/v1/tenants/${tenant}/projects`]: { items: [] }, [`/v1/tenants/${tenant}/bill-sync`]: { items: [emptyRun] } })
    render(<BudgetsView tenantId={tenant} />)
    expect(await screen.findByText('No budgets yet.')).toBeTruthy()
    expect(await screen.findByRole('heading', { name: 'Keel has no cost data for this organisation yet' })).toBeTruthy()
    expect(document.body.textContent).toContain(EMPTY_NEXT)
  })

  it('Budgets adds nothing when cost data exists', async () => {
    mockFetch({
      [`/v1/tenants/${tenant}/budgets`]: { items: [] },
      [`/v1/tenants/${tenant}/projects`]: { items: [] },
      [`/v1/tenants/${tenant}/bill-sync`]: { items: [status({ months: [month({ month: '2026-10', state: 'unchanged', lines: 9 })] })] },
    })
    render(<BudgetsView tenantId={tenant} />)
    expect(await screen.findByText('No budgets yet.')).toBeTruthy()
    await new Promise((r) => setTimeout(r, 20))
    expect(screen.queryByText(/no cost data/)).toBeNull()
  })
})
