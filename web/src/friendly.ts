import { ApiError } from './api'

const providerNames: Record<string, string> = { tencent: 'Tencent', aws: 'AWS', azure: 'Azure', gcp: 'Google Cloud', alibaba: 'Alibaba Cloud' }

export const providerName = (p: string) => providerNames[p] ?? p

/** What the message is about, so a rewrite can name it. */
export type ErrorContext = { provider?: string; org?: string }

/** Database constraint and policy errors, rewritten as what the person should do next. */
const known: [RegExp, (c: ErrorContext) => string][] = [
  [/cloud_accounts_environment_id_provider_key/, (c) => `This environment already has a ${providerName(c.provider ?? '')} account. Pick another environment or create one.`],
  [/cloud_accounts_provider_external_id_key/, () => 'This account is already registered in Keel, possibly in another organisation.'],
  [/teams_tenant_id_slug_key/, () => 'A team with this name already exists here. Pick it from the team list instead.'],
  [/read_only_role/, () => 'Enter the read-only role ARN the client created for Keel, like qcs::cam::uin/100000000001:roleName/KeelReadOnly.'],
  [/^forbidden$/, (c) => `You don’t have permission to do this${c.org ? ` in ${c.org}` : ''}. Ask a platform admin.`],
  [/^internal error$|^HTTP 5\d\d$/, () => 'Keel hit an unexpected error. Try again in a minute; if it keeps happening, check the server logs.'],
]

export function friendly(e: unknown, c: ErrorContext = {}): string {
  const raw = e instanceof Error ? e.message : String(e)
  const hit = known.find(([re]) => re.test(raw))
  if (hit) return hit[1](c)
  if (e instanceof TypeError) return 'Keel could not be reached. Check your connection and try again.'
  const text = raw.replace(/^(already exists|invalid|not found): /, '')
  return text.charAt(0).toUpperCase() + text.slice(1) + (/[.!?]$/.test(text) ? '' : '.')
}

export const isStatus = (e: unknown, status: number) => e instanceof ApiError && e.status === status
