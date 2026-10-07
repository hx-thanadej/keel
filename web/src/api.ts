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

export type FlowStep = { seq: number; name: string; state: string; attempts: number; error: string | null }
export type Flow = { id: string; kind: string; subject: string; state: string; error: string | null; created_by: string; created_at: string; steps?: FlowStep[] }
export type ServiceEntry = { id: string; project_id: string; slug: string; name: string; repository: string; template: string }
export type Template = { name: string; repo: string; ref: string; description: string }
export type Release = { id: string; service_id: string; version: string; images: { name: string; digest: string }[]; created_at: string }
export type Decision = { allow: boolean; reasons: string[]; needs_approval: boolean; policy: string }
export type Promotion = {
  id: string
  release_id: string
  environment_id: string
  state: string
  decision: Decision
  pr_url: string | null
  error: string | null
  requested_by: string
  requested_at: string
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

export type Threshold = { pct: number; basis: 'actual' | 'forecast' }
export type Budget = {
  id: string
  project_id: string
  environment_id: string | null
  provider: string | null
  name: string
  year: number
  amount: string
  currency: string
  cost_basis: 'effective' | 'billed'
  thresholds: Threshold[]
}
export type Period = 'day' | 'month' | 'year'
export type BudgetStatus = {
  period: Period
  start: string
  as_of: string
  currency: string
  cost_basis: string
  budget: string
  budget_to_date: string
  actual: string
  forecast: string
  forecast_p10: string
  forecast_p90: string
  forecast_method: string
  history_days: number
  backtest_mape?: number
  variance: string
  final: boolean
  providers: { provider: string; final: boolean }[]
  missing_fx: boolean
  series: { start: string; budget: string; actual: string }[] | null
}
export type BreakdownRow = { key: string; service: string; billed: string; effective: string; currency: string }
export type DailyCost = {
  day: string
  project_slug: string | null
  environment_name: string
  provider: string
  currency: string
  billed: string
  effective: string | null
}
export type Finding = {
  id: string
  kind: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  status: string
  title: string
  detail: Record<string, unknown>
  first_seen_at: string
  resolution: string | null
  due_at?: string | null
  overdue_at?: string | null
}

export type Savings = {
  currency: string
  open: string
  accepted: string
  applied: string
  realised: string
  regressions: number
  items: {
    id: string
    resource_id: string
    action: string
    project_id: string | null
    recommended: string
    realised: string | null
    method: 'measured' | 'estimated' | null
    regression: string | null
    applied_at: string
  }[]
}

const send = <T,>(path: string, method: string, body: unknown) => request<T>(path, { method, body: JSON.stringify(body) })

export const finops = {
  budgets: (t: string) => list<Budget>(`/v1/tenants/${t}/budgets`),
  createBudget: (t: string, b: { project_id: string; environment_id?: string; name: string; year: number; amount: string }) =>
    send<Budget>(`/v1/tenants/${t}/budgets`, 'POST', b),
  status: (t: string, b: string, period: Period, date: string) =>
    request<BudgetStatus>(`/v1/tenants/${t}/budgets/${b}/status?period=${period}&date=${date}`),
  breakdown: (t: string, q: { from: string; to: string; by: 'service' | 'resource'; project?: string; environment?: string }) => {
    const p = new URLSearchParams({ from: q.from, to: q.to, by: q.by, limit: '10' })
    if (q.project) p.set('project', q.project)
    if (q.environment) p.set('environment', q.environment)
    return list<BreakdownRow>(`/v1/tenants/${t}/costs/breakdown?${p}`)
  },
  daily: (t: string, from: string, to: string) => list<DailyCost>(`/v1/tenants/${t}/costs/daily?from=${from}&to=${to}`),
  dailyCsvUrl: (t: string, from: string, to: string) => `/v1/tenants/${t}/costs/daily?from=${from}&to=${to}&format=csv`,
  findings: (t: string) => list<Finding>(`/v1/tenants/${t}/findings`),
  resolve: (t: string, id: string, resolution: string) => send<Finding>(`/v1/tenants/${t}/findings/${id}/resolve`, 'POST', { resolution }),
  recommendations: (t: string) => list<{ id: string; finding_id: string; pr_url: string | null; state: string }>(`/v1/tenants/${t}/recommendations`),
  savings: (t: string, project?: string) => request<Savings>(`/v1/tenants/${t}/savings${project ? `?project=${project}` : ''}`),
  applyRecommendation: (t: string, id: string) => send<{ pr_url: string }>(`/v1/tenants/${t}/recommendations/${id}/apply`, 'POST', {}),
}

const post = <T,>(path: string, body: unknown) => request<T>(path, { method: 'POST', body: JSON.stringify(body) })

export const delivery = {
  flows: (t: string) => list<Flow>(`/v1/tenants/${t}/flows`),
  flow: (t: string, id: string) => request<Flow>(`/v1/tenants/${t}/flows/${id}`),
  retryFlow: (t: string, id: string) => post<Flow>(`/v1/tenants/${t}/flows/${id}/retry`, {}),
  services: (t: string) => list<ServiceEntry>(`/v1/tenants/${t}/services`),
  templates: (t: string) => list<Template>(`/v1/tenants/${t}/templates`),
  createService: (t: string, project: string, b: { slug: string; title: string; template: string; tier: string }) =>
    post<Flow>(`/v1/tenants/${t}/projects/${project}/services`, b),
  releases: (t: string) => list<Release>(`/v1/tenants/${t}/releases`),
  promotions: (t: string) => list<Promotion>(`/v1/tenants/${t}/promotions`),
  preview: (t: string, release: string, env: string) => post<Decision>(`/v1/tenants/${t}/releases/${release}/preview`, { environment_id: env }),
  promote: (t: string, release: string, env: string) => post<Promotion>(`/v1/tenants/${t}/releases/${release}/promote`, { environment_id: env }),
  approve: (t: string, id: string) => post<Promotion>(`/v1/tenants/${t}/promotions/${id}/approve`, {}),
}

export type ControlView = {
  id: string
  framework: string
  title: string
  policies: string[]
  coverage: { name: string; point: string; covered_services: number }[]
  gap: boolean
}
export type ControlReport = { version: string; services: number; controls: ControlView[] }
export type Exception = {
  id: string
  fingerprint: string
  finding_ids: string[]
  reason: string
  state: string
  requested_by: string
  decided_by: string | null
  expires_at: string
}
export type VexStatement = {
  id: string
  vulnerability: string
  service_id: string
  status: string
  justification: string | null
  impact_statement: string | null
  action_statement: string | null
  author: string
  created_at: string
}
export type Attestation = { id: string; image_digest: string; passed: boolean; checks: { name: string; pass: boolean; detail: string }[]; created_at: string }

export const security = {
  controls: (t: string) => request<ControlReport>(`/v1/tenants/${t}/controls`),
  exceptions: (t: string) => list<Exception>(`/v1/tenants/${t}/exceptions`),
  requestException: (t: string, b: { fingerprint: string; reason: string; expires_at: string }) => post<Exception>(`/v1/tenants/${t}/exceptions`, b),
  decideException: (t: string, id: string, decision: 'approve' | 'reject', note: string) => post<Exception>(`/v1/tenants/${t}/exceptions/${id}/${decision}`, { note }),
  vex: (t: string) => list<VexStatement>(`/v1/tenants/${t}/vex`),
  recordVex: (t: string, b: { vulnerability: string; service_id: string; status: string; justification?: string; impact_statement?: string; action_statement?: string }) =>
    post<VexStatement>(`/v1/tenants/${t}/vex`, b),
  attestations: (t: string, release: string) => list<Attestation>(`/v1/tenants/${t}/releases/${release}/attestations`),
}

export type AccessTemplate = { name: string; description: string; write: boolean; max_hours: number }
export type AccessRole = { id: string; environment_id: string; team_id: string; template: string; state: string; requested_by: string }
export type AccessGrant = {
  id: string
  role_id: string
  requester: string
  reason: string
  hours: number
  state: string
  decision: { allow: boolean; reasons: string[]; approvals: string[]; policy: string }
  approvals: { role: string; by: string; at: string }[]
  error: string | null
  expires_at: string | null
}
export type Team = { id: string; slug: string; name: string }

export const accessApi = {
  templates: (t: string) => list<AccessTemplate>(`/v1/tenants/${t}/access/templates`),
  roles: (t: string) => list<AccessRole>(`/v1/tenants/${t}/access/roles`),
  requestRole: (t: string, b: { environment_id: string; team_id: string; template: string }) => post<AccessRole>(`/v1/tenants/${t}/access/roles`, b),
  decideRole: (t: string, id: string, approve: boolean) => post<AccessRole>(`/v1/tenants/${t}/access/roles/${id}/decide`, { approve }),
  grants: (t: string) => list<AccessGrant>(`/v1/tenants/${t}/access/grants`),
  requestGrant: (t: string, b: { role_id: string; hours: number; reason: string }) => post<AccessGrant>(`/v1/tenants/${t}/access/grants`, b),
  approve: (t: string, id: string) => post<AccessGrant>(`/v1/tenants/${t}/access/grants/${id}/approve`, {}),
  reject: (t: string, id: string, reason: string) => post<AccessGrant>(`/v1/tenants/${t}/access/grants/${id}/reject`, { reason }),
  revoke: (t: string, id: string, reason: string) => post<AccessGrant>(`/v1/tenants/${t}/access/grants/${id}/revoke`, { reason }),
  teams: (t: string) => list<Team>(`/v1/tenants/${t}/teams`),
}

/** Money for display: grouped, two decimals, currency code after. */
export function fmtMoney(v: string | number | null | undefined, currency?: string): string {
  if (v === null || v === undefined || v === '') return '—'
  const n = typeof v === 'number' ? v : Number(v)
  const s = n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })
  return currency ? `${s} ${currency}` : s
}

/** Window [from, to) for a period containing date (YYYY-MM-DD). */
export function windowFor(period: Period, date: string): { from: string; to: string } {
  const d = new Date(date + 'T00:00:00Z')
  const iso = (x: Date) => x.toISOString().slice(0, 10)
  if (period === 'day') return { from: iso(d), to: iso(new Date(d.getTime() + 86400000)) }
  if (period === 'month') return { from: iso(new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1))), to: iso(new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1))) }
  return { from: `${d.getUTCFullYear()}-01-01`, to: `${d.getUTCFullYear() + 1}-01-01` }
}
