import { useEffect, useId, useState } from 'react'
import {
  billSync,
  explainMonth,
  explainRun,
  hasCosts,
  monthName,
  providerLabel,
  relativeTime,
  sourceLabel,
  type DiscoveredAccount,
  type Explained,
  type SyncStatus,
} from './billSync'

const NOT_PULLED = "Keel hasn't pulled any bills for this organisation yet. Bills are pulled every hour once a payer account is connected."

/** A relative time, with the exact time on hover and for assistive tech. */
export function TimeAgo({ iso }: { iso: string }) {
  const exact = new Date(iso).toLocaleString()
  return (
    <time dateTime={iso} title={exact}>
      {relativeTime(iso)}
    </time>
  )
}

/** Status as words; the colour only repeats them. */
function Badge({ e }: { e: Explained }) {
  return (
    <span className={`status ${e.tone}`}>
      <span className="dot" aria-hidden="true" />
      {e.badge}
    </span>
  )
}

function Explanation({ e, headline = true }: { e: Explained; headline?: boolean }) {
  return (
    <>
      {headline && <p className="sync-headline">{e.headline}</p>}
      {e.next && <p className="sync-next">{e.next}</p>}
      {e.code && <p className="muted sync-code">Error code from the provider: {e.code}</p>}
    </>
  )
}

function useStatuses(tenantId: string) {
  const [statuses, setStatuses] = useState<SyncStatus[] | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    let stale = false
    billSync
      .list(tenantId)
      .then((s) => !stale && setStatuses(s))
      .catch(() => !stale && setFailed(true))
    return () => {
      stale = true
    }
  }, [tenantId])
  return { statuses, failed }
}

export function BillSyncPanel({ statuses }: { statuses: SyncStatus[] }) {
  if (statuses.length === 0) return <p className="muted">{NOT_PULLED}</p>
  return (
    <div className="sync-list">
      {statuses.map((s) => (
        <PayerStatus key={s.provider + s.billing_account_id} s={s} />
      ))}
    </div>
  )
}

function PayerStatus({ s }: { s: SyncStatus }) {
  const titleId = useId()
  const run = explainRun(s)
  const months = s.months.map((m) => ({ m, e: explainMonth(m, s) }))
  // A run that only reflects its worst month is explained on that month.
  const ownWords = run.tone !== 'good' && !months.some(({ e }) => e.headline === run.headline)
  return (
    <article className="card sync-payer" aria-labelledby={titleId}>
      <div className="sync-head">
        <h3 id={titleId}>
          {providerLabel(s.provider)} payer {s.billing_account_id}
        </h3>
        <Badge e={run} />
      </div>
      <p className="muted sync-meta">
        <span>{sourceLabel(s)}</span>
        <span>
          Last pull <TimeAgo iso={s.checked_at} />
        </span>
      </p>
      {ownWords && <Explanation e={run} />}
      {months.length > 0 && (
        <ul className="sync-months" aria-label="Months">
          {months.map(({ m, e }) => (
            <li key={m.month}>
              <Badge e={e} />
              <div>
                <Explanation e={e} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </article>
  )
}

function Discovery({ tenantId }: { tenantId: string }) {
  const [accounts, setAccounts] = useState<DiscoveredAccount[] | null>(null)
  useEffect(() => {
    let stale = false
    billSync
      .discovered(tenantId)
      .then((a) => !stale && setAccounts(a))
      .catch(() => undefined)
    return () => {
      stale = true
    }
  }, [tenantId])
  if (!accounts) return null
  if (accounts.length === 0) return <p className="muted">Account discovery hasn't found any accounts yet. Run it from the Projects tab.</p>
  const byProvider = new Map<string, DiscoveredAccount[]>()
  for (const a of accounts) byProvider.set(a.provider, [...(byProvider.get(a.provider) ?? []), a])
  return (
    <ul className="sync-discovery">
      {[...byProvider].map(([provider, as]) => {
        const last = as.reduce((x, a) => (a.last_seen_at > x ? a.last_seen_at : x), as[0].last_seen_at)
        return (
          <li key={provider}>
            {providerLabel(provider)} account discovery: {as.length} account{as.length === 1 ? '' : 's'} found, last run <TimeAgo iso={last} />
          </li>
        )
      })}
    </ul>
  )
}

/** The Connections screen's status section: every payer's bill sync, and account discovery. */
export function BillSyncSection({ tenantId }: { tenantId: string }) {
  const { statuses, failed } = useStatuses(tenantId)
  return (
    <section id="bill-sync" aria-labelledby="bill-sync-title" className="sync">
      <h2 id="bill-sync-title">Bill sync</h2>
      {failed && <p className="muted">Bill sync status couldn't be loaded. Reload the page to try again.</p>}
      {!statuses && !failed && <p className="muted">Loading bill sync status…</p>}
      {statuses && <BillSyncPanel statuses={statuses} />}
      <h2>Account discovery</h2>
      <Discovery tenantId={tenantId} />
    </section>
  )
}

function StatusDetails({ statuses }: { statuses: SyncStatus[] }) {
  return (
    <details className="sync-details">
      <summary>Bill sync status</summary>
      <BillSyncPanel statuses={statuses} />
    </details>
  )
}

/** Why a month has no costs, and what to do about it. */
export function NoCostsForMonth({ tenantId, month }: { tenantId: string; month: string }) {
  const { statuses } = useStatuses(tenantId)
  const name = monthName(month)
  let why: React.ReactNode = null
  if (statuses) {
    const found = statuses.flatMap((s) => s.months.filter((m) => m.month === month).map((m) => ({ s, m })))
    const rank = { failed: 0, blocked: 1, empty: 2, loaded: 3, unchanged: 3 }
    found.sort((a, b) => rank[a.m.state] - rank[b.m.state])
    const hit = found[0]
    const troubled = statuses.find((s) => s.state !== 'ok')
    if (statuses.length === 0) why = <p>{NOT_PULLED}</p>
    else if (hit?.m.state === 'loaded' || hit?.m.state === 'unchanged')
      why = (
        <>
          <p>Keel loaded the bill for {name}, but none of its costs belong to this organisation's projects.</p>
          <p className="sync-next">Check that this organisation's cloud accounts are registered on the Projects tab.</p>
        </>
      )
    else if (hit?.m.state === 'empty')
      why = (
        <>
          <p>
            Keel pulled the bill for {providerLabel(hit.s.provider)} payer {hit.s.billing_account_id} <TimeAgo iso={hit.m.checked_at} /> and it had no costs.
          </p>
          <Explanation e={explainMonth(hit.m, hit.s)} headline={false} />
        </>
      )
    else if (hit) why = <Explanation e={explainMonth(hit.m, hit.s)} />
    else if (troubled) why = <Explanation e={explainRun(troubled)} />
    else why = <p>Keel has no bill pulls on record for {name}.</p>
  }
  return (
    <div className="card sync-empty">
      <h2>No costs found for {name}</h2>
      {why}
      {statuses && statuses.length > 0 && <StatusDetails statuses={statuses} />}
    </div>
  )
}

/** Shown beside an empty Budgets list when Keel has no costs at all for the Tenant. */
export function NoCostData({ tenantId }: { tenantId: string }) {
  const { statuses } = useStatuses(tenantId)
  if (!statuses || hasCosts(statuses)) return null
  const troubled = statuses.find((s) => s.state !== 'ok')
  return (
    <div className="card sync-empty">
      <h2>Keel has no cost data for this organisation yet</h2>
      <p>Budgets track spending from the cloud bill, so there is nothing to compare against yet.</p>
      {statuses.length === 0 ? <p>{NOT_PULLED}</p> : troubled && <Explanation e={explainRun(troubled)} />}
      {statuses.length > 0 && <StatusDetails statuses={statuses} />}
    </div>
  )
}
