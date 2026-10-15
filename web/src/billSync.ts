// Bill sync status (#257): what the latest pull of each payer's bill found,
// and the words that explain it. The API returns codes; every sentence a
// person reads is chosen here.
import { ApiError } from './api'

export type MonthState = 'loaded' | 'unchanged' | 'empty' | 'blocked' | 'failed'
export type RunState = 'ok' | 'empty' | 'blocked' | 'failed'
export type SyncMonth = {
  month: string // YYYY-MM
  state: MonthState
  lines: number
  total?: string
  currency?: string
  reason?: string
  code?: string
  since: string
  checked_at: string
}
export type SyncStatus = {
  provider: string
  billing_account_id: string
  source: 'api' | 'files'
  checked_at: string
  state: RunState
  reason?: string
  code?: string
  since: string
  months: SyncMonth[] // newest first
}
export type DiscoveredAccount = { provider: string; external_id: string; name: string; last_seen_at: string }

async function items<T>(path: string): Promise<T[]> {
  const res = await fetch(path, { credentials: 'same-origin', headers: { 'Content-Type': 'application/json' } })
  if (!res.ok) throw new ApiError(res.status, `HTTP ${res.status}`)
  return (await res.json()).items
}

export const billSync = {
  list: (tenant: string) => items<SyncStatus>(`/v1/tenants/${tenant}/bill-sync`),
  discovered: (tenant: string) => items<DiscoveredAccount>(`/v1/tenants/${tenant}/discovered-accounts`),
}

export type Tone = 'good' | 'warning' | 'critical'
/** One outcome in words: a short badge, what happened, and what to do about it. */
export type Explained = { badge: string; tone: Tone; headline: string; next?: string; code?: string }

const HOUR = 3_600_000

export function relativeTime(iso: string, now = Date.now()): string {
  const s = Math.round((new Date(iso).getTime() - now) / 1000)
  const a = Math.abs(s)
  if (a < 45) return 'just now'
  const [n, unit] = a < 3600 ? [Math.max(1, Math.floor(a / 60)), 'minute'] : a < 86400 ? [Math.floor(a / 3600), 'hour'] : [Math.floor(a / 86400), 'day']
  const words = `${n} ${unit}${n === 1 ? '' : 's'}`
  return s < 0 ? `${words} ago` : `in ${words}`
}

export const monthName = (m: string) => {
  const [y, mo] = m.split('-').map(Number)
  return new Date(Date.UTC(y, mo - 1, 1)).toLocaleString('en-GB', { month: 'long', year: 'numeric', timeZone: 'UTC' })
}

const providerName: Record<string, string> = { tencent: 'Tencent', aws: 'AWS', azure: 'Azure', gcp: 'Google Cloud', alibaba: 'Alibaba Cloud' }
export const providerLabel = (p: string) => providerName[p] ?? p

export function sourceLabel(s: SyncStatus): string {
  if (s.source === 'api') return 'Billing API'
  return { tencent: 'Bill files in COS', aws: 'Data Exports in S3' }[s.provider] ?? 'Bill files'
}

export const EMPTY_NEXT = "If this account belongs to another organisation that pays the bill, Keel can't see its costs. Ask that payer for a read-only bill role."
const NEW_MONTH = "A new month's costs can take up to a day to appear."

const isCurrentMonth = (m: string) => new Date().toISOString().slice(0, 7) === m

const failedWhat: Record<string, string> = {
  timeout: 'the billing service took too long to answer',
  network: "Keel couldn't reach the billing service",
  denied: "the billing service refused Keel's access",
  rate_limited: 'the billing service asked Keel to slow down',
  provider: 'the billing service returned an error',
  internal: 'something went wrong inside Keel',
}

function retry(s: SyncStatus, reason?: string): string {
  const next = new Date(new Date(s.checked_at).getTime() + HOUR).toISOString()
  const when = `Keel tries again every hour. The next try is ${relativeTime(next)}.`
  if (reason === 'denied') return `Check that the connection's key or role still has read-only billing access (use Test connection on the Connections tab). ${when}`
  if (reason === 'internal') return `${when} If this keeps happening, tell the platform team.`
  return when
}

const money = (m: SyncMonth) => (m.total ? `, ${m.total} ${m.currency ?? ''}`.trimEnd() : '')
const lines = (n: number) => `${n} line${n === 1 ? '' : 's'}`

export function explainMonth(m: SyncMonth, s: SyncStatus): Explained {
  const name = monthName(m.month)
  switch (m.state) {
    case 'loaded':
      return { badge: 'Up to date', tone: 'good', headline: `${name}: ${lines(m.lines)}${money(m)}` }
    case 'unchanged':
      return { badge: 'Up to date', tone: 'good', headline: `${name}: ${lines(m.lines)}${money(m)}, no change since the last pull` }
    case 'empty':
      return { badge: 'No costs found', tone: 'warning', headline: `No costs found for ${name}`, next: isCurrentMonth(m.month) ? `${NEW_MONTH} ${EMPTY_NEXT}` : EMPTY_NEXT }
    case 'blocked':
      if (m.reason === 'currency_unknown')
        return {
          badge: 'Needs attention',
          tone: 'warning',
          headline: `${name} wasn't loaded because Keel couldn't tell which currency the bill is in`,
          next: "On keel-api, set KEEL_TENCENT_BILL_CURRENCY to the bill's currency (for example USD). Until then Keel keeps the last costs it loaded.",
        }
      return {
        badge: 'Needs attention',
        tone: 'warning',
        headline: `${name} wasn't loaded because two bill files charge the same account for the same time`,
        next: "So costs aren't counted twice, Keel kept the last costs it loaded. Deliver only the Standard bill (FOCUS) to the bucket prefix, and check the bill mode: KEEL_TENCENT_BILL_MODE for Keel's own payer, or the client payer's mode.",
      }
    case 'failed':
      return { badge: 'Failed', tone: 'critical', headline: `Keel couldn't pull ${name}: ${failedWhat[m.reason ?? ''] ?? failedWhat.internal}`, next: retry(s, m.reason), code: m.code }
  }
}

const deliveryHelp: Record<string, string> = {
  tencent: 'In the payer account, open Billing Center, Bill Storage, and deliver the Standard bill (FOCUS) to the bucket.',
  aws: 'In the management account, create a Data Export of FOCUS 1.2 to the bucket.',
}

const runHelp: Record<string, (s: SyncStatus) => Explained> = {
  no_bill_files: (s) => ({
    badge: 'No bill files',
    tone: 'warning',
    headline: 'No bill files in the bucket',
    next: `${deliveryHelp[s.provider] ?? 'Turn on bill delivery to the bucket.'} The first files can take a day to arrive.`,
  }),
  no_bucket: () => ({
    badge: 'Needs attention',
    tone: 'warning',
    headline: 'No bill bucket is set up for this payer',
    next: "Record the bill bucket, prefix and region on the payer's cloud account in Keel (Projects tab).",
  }),
  bucket_unreadable: () => ({
    badge: 'Needs attention',
    tone: 'warning',
    headline: "Keel signed in to the payer account but couldn't read the bill bucket",
    next: "In the payer account, let Keel's read-only role list and read the bucket, and check the bucket name and region recorded in Keel.",
  }),
  role_unusable: () => ({
    badge: 'Needs attention',
    tone: 'warning',
    headline: "Keel couldn't sign in to the payer account's read-only role",
    next: "In the payer account, check that the read-only role exists and that its trust policy allows Keel with the External ID shown on the payer's cloud account (Projects tab).",
  }),
  keel_identity: () => ({
    badge: 'Needs attention',
    tone: 'warning',
    headline: "Keel's own cloud sign-in isn't working, so no bills were pulled",
    next: "Nothing is wrong on the payer's side. Keel's platform team needs to fix keel-api's cloud identity.",
  }),
}

/** The payer as a whole: what stopped the run, else its worst month. */
export function explainRun(s: SyncStatus): Explained {
  if (s.reason && runHelp[s.reason]) return runHelp[s.reason](s)
  if (s.state === 'failed' && !s.months.some((m) => m.state === 'failed'))
    return { badge: 'Failed', tone: 'critical', headline: `Keel couldn't pull bills: ${failedWhat[s.reason ?? ''] ?? failedWhat.internal}`, next: retry(s, s.reason), code: s.code }
  const worst = s.months.find((m) => m.state === 'failed') ?? s.months.find((m) => m.state === 'blocked') ?? s.months.find((m) => m.state === 'empty')
  if (worst) return explainMonth(worst, s)
  return { badge: 'Up to date', tone: 'good', headline: 'Bills are up to date' }
}

export const hasCosts = (statuses: SyncStatus[]) => statuses.some((s) => s.months.some((m) => m.state === 'loaded' || m.state === 'unchanged'))
