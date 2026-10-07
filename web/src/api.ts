// Thin client for the Keel API. The session cookie is sent automatically;
// tokens never live in the browser.

export type Binding = { role: string; tenant_id: string; team_ids?: string[] }
export type Principal = { subject: string; kind: string; tenant_id: string; home: boolean; mfa?: boolean; bindings: Binding[] }
export type Tenant = { id: string; slug: string; name: string; is_home: boolean }
export type Project = { id: string; tenant_id: string; team_id: string; slug: string; name: string }
export type Environment = { id: string; project_id: string; name: string }
export type CloudAccount = { id: string; environment_id: string | null; provider: string; external_id: string; name: string }
export type Activity = {
  id: string
  seq: number
  occurred_at: string
  type: string
  actor_uid: string
  operation: string
  event: { data: { status_id: number; status_detail?: string; why?: { reason?: string } } }
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: 'same-origin', ...init, headers: { 'Content-Type': 'application/json', ...init?.headers } })
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      msg = (await res.json()).error ?? msg
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, msg)
  }
  return res.status === 204 ? (undefined as T) : res.json()
}

const list = async <T,>(path: string) => (await request<{ items: T[] }>(path)).items

export const api = {
  me: () => request<Principal>('/auth/me'),
  logout: () => request<void>('/auth/logout', { method: 'POST' }),
  tenant: (id: string) => request<Tenant>(`/v1/tenants/${id}`),
  projects: (t: string) => list<Project>(`/v1/tenants/${t}/projects`),
  environments: (t: string, p: string) => list<Environment>(`/v1/tenants/${t}/projects/${p}/environments`),
  cloudAccounts: (t: string) => list<CloudAccount>(`/v1/tenants/${t}/cloud-accounts`),
  activities: (t: string, f: { actor?: string; type?: string; since?: string; before?: number; limit?: number }) => {
    const q = new URLSearchParams()
    if (f.actor) q.set('actor', f.actor)
    if (f.type) q.set('type', f.type)
    if (f.since) q.set('since', f.since)
    if (f.before) q.set('before', String(f.before))
    q.set('limit', String(f.limit ?? 50))
    return list<Activity>(`/v1/tenants/${t}/activities?${q}`)
  },
}

/** Tenants the principal can see: its own plus every Tenant it holds a binding in. */
export function visibleTenantIds(p: Principal): string[] {
  return [...new Set([p.tenant_id, ...p.bindings.map((b) => b.tenant_id)])]
}
