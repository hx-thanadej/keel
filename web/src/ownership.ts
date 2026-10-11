import type { CloudAccount, Recommendation } from './api'

/** Whose organisation a scope's Cloud Accounts sit in (ADR-0018). A scope is read-only once any of them is client-owned. */
export type Ownership = 'platform' | 'client' | 'mixed'

export function ownershipOf(accounts: CloudAccount[]): Ownership | null {
  if (accounts.length === 0) return null
  const client = accounts.some((a) => a.ownership === 'client')
  const platform = accounts.some((a) => a.ownership === 'platform')
  return client && platform ? 'mixed' : client ? 'client' : 'platform'
}

export const accountsIn = (accounts: CloudAccount[], envIds: string[]) => accounts.filter((a) => a.environment_id !== null && envIds.includes(a.environment_id))

/** Why Keel will not change anything in this scope, or null when it may. */
export function readOnlyReason(o: Ownership | null): string | null {
  if (o === 'client') return "Client-owned: Keel holds only a read-only role in the client's organisation and never changes it."
  if (o === 'mixed') return "Includes a client-owned Cloud Account: Keel holds only a read-only role there and never changes it."
  return null
}

/** Keel opens pull requests only for Kubernetes request changes and off-hours schedules (internal/apply). */
export const opensPullRequest = (r: Recommendation) => r.resource_type === 'k8s_workload' && (r.action === 'resize_requests' || r.action === 'schedule')

/** The Cloud Accounts a recommendation's resource lives in: its own account when known, else its Environment's. */
export function recommendationAccounts(r: Recommendation, accounts: CloudAccount[]): CloudAccount[] {
  const own = accounts.filter((a) => r.account_id !== '' && a.provider === r.provider && a.external_id === r.account_id)
  if (own.length > 0) return own
  return r.environment_id ? accountsIn(accounts, [r.environment_id]) : []
}

/** Human steps for a recommendation Keel will not apply itself. */
export function manualSteps(r: Recommendation): string {
  const cur = r.current ?? {}
  const rec = r.recommended ?? {}
  const changes = Object.keys(rec).map((k) => `${k} from ${String(cur[k] ?? '—')} to ${String(rec[k])}`)
  const what = `${r.resource_type} ${r.resource_id}${r.account_id ? ` in account ${r.account_id}` : ''}`
  return changes.length > 0 ? `${r.action.replace(/_/g, ' ')} on ${what}: change ${changes.join(', ')}.` : `${r.action.replace(/_/g, ' ')} on ${what}.`
}

/** The open Access Grants a refused switch names, as "access_grant/<id> (<requester>, <template>)". */
export const grantsBlocking = (message: string) => message.match(/access_grant\/[0-9a-f-]+ \([^)]*\)/g) ?? []
