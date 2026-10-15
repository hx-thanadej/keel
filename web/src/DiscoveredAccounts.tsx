import { useEffect, useId, useState } from 'react'
import { accessApi, api, type DiscoveredAccount, type Registration, type RegistrationOutcome, type Team, type Tenant } from './api'
import { friendly, isStatus, providerName } from './friendly'

/** Providers Keel can list member accounts for. */
const discoverable = ['tencent']

type Draft = { project: string; environment: string; role: string }
type Load = { state: 'loading' } | { state: 'error'; message: string } | { state: 'ready'; accounts: DiscoveredAccount[] }
type Report = { done?: string; failures: string[] }
/** The Team that will own new Projects: an existing one, or one to create first. */
type TeamChoice = { kind: 'existing'; id: string } | { kind: 'new'; name: string }

const keyOf = (a: { provider: string; external_id: string }) => `${a.provider}/${a.external_id}`
const day = (iso: string) => new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`
const slugify = (name: string) =>
  name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)

/**
 * Accounts discovery found that are not in the catalog yet, registered in
 * one step into any organisation the admin manages. Rendered only for a
 * platform admin of the home Tenant, where discovery runs.
 */
export function DiscoveredAccounts({ home, targets, onRegistered }: { home: Tenant; targets: Tenant[]; onRegistered: () => void }) {
  const [load, setLoad] = useState<Load>({ state: 'loading' })
  const [drafts, setDrafts] = useState<Record<string, Draft>>({})
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [target, setTarget] = useState(home.id)
  const [loadedTeams, setLoadedTeams] = useState<{ target: string; teams: Team[] } | null>(null)
  const [team, setTeam] = useState<TeamChoice>({ kind: 'new', name: '' })
  const [ownership, setOwnership] = useState<'platform' | 'client'>('platform')
  const [busy, setBusy] = useState<'discovering' | 'registering' | null>(null)
  const [report, setReport] = useState<Report | null>(null)
  const [reload, setReload] = useState(0)
  const headingId = useId()
  const targetName = targets.find((t) => t.id === target)?.name ?? home.name

  useEffect(() => {
    api.discovered(home.id).then(
      (accounts) => setLoad({ state: 'ready', accounts }),
      (e) => setLoad({ state: 'error', message: friendly(e, { org: home.name }) }),
    )
  }, [home.id, home.name, reload])

  useEffect(() => {
    const loaded = (ts: Team[]) => {
      setLoadedTeams({ target, teams: ts })
      setTeam(ts.length > 0 ? { kind: 'existing', id: ts[0].id } : { kind: 'new', name: '' })
    }
    accessApi.teams(target).then(loaded, () => loaded([]))
  }, [target])
  const teams = loadedTeams?.target === target ? loadedTeams.teams : null

  const draftOf = (a: DiscoveredAccount): Draft => drafts[keyOf(a)] ?? { project: a.suggestion?.project_slug ?? '', environment: a.suggestion?.environment ?? '', role: '' }
  const edit = (a: DiscoveredAccount, patch: Partial<Draft>) => setDrafts((d) => ({ ...d, [keyOf(a)]: { ...draftOf(a), ...patch } }))
  const toggle = (k: string, on: boolean) =>
    setSelected((s) => {
      const next = new Set(s)
      if (on) next.add(k)
      else next.delete(k)
      return next
    })

  const discover = async (provider: string) => {
    setBusy('discovering')
    setReport(null)
    try {
      const found = await api.discover(home.id, provider)
      const open = found.filter((a) => !a.registered).length
      setLoad({ state: 'ready', accounts: found })
      setReport({ done: `Found ${plural(found.length, `${providerName(provider)} account`)}; ${open === 1 ? '1 is' : `${open} are`} not registered yet.`, failures: [] })
    } catch (e) {
      const message = isStatus(e, 404)
        ? `Keel isn’t set up to discover ${providerName(provider)} accounts yet. Ask whoever runs Keel to set KEEL_TENCENT_ORG_REGION and add a ${providerName(provider)} connection on the Connections tab.`
        : friendly(e, { org: home.name })
      setReport({ failures: [message] })
    } finally {
      setBusy(null)
    }
  }

  const accounts = load.state === 'ready' ? load.accounts : []
  const open = accounts.filter((a) => !a.registered)
  const chosen = open.filter((a) => selected.has(keyOf(a)))

  const register = async () => {
    setBusy('registering')
    setReport(null)
    try {
      let teamId: string
      if (team.kind === 'new') {
        const name = team.name.trim()
        if (!slugify(name)) {
          setReport({ failures: ['Give the new team a name, like “CRM team”.'] })
          return
        }
        try {
          const created = await api.createTeam(target, slugify(name), name)
          setLoadedTeams({ target, teams: [...(teams ?? []), created] })
          setTeam({ kind: 'existing', id: created.id })
          teamId = created.id
        } catch (e) {
          setReport({ failures: [`Could not create the team: ${friendly(e, { org: targetName })}`] })
          return
        }
      } else {
        teamId = team.id
      }
      const regs: Registration[] = chosen.map((a) => {
        const d = draftOf(a)
        const common = { provider: a.provider, external_id: a.external_id, name: a.name, project: d.project.trim(), environment: d.environment.trim() }
        return ownership === 'client' ? { ...common, ownership, read_only_role: { role_arn: d.role.trim() } } : { ...common, ownership }
      })
      const outcomes = await api.register(target, teamId, regs)
      setReport(summarise(outcomes, chosen, targetName))
      setSelected(new Set(outcomes.filter((o) => o.status === 'failed').map(keyOf)))
      if (outcomes.some((o) => o.status === 'registered')) onRegistered()
      setReload((n) => n + 1)
    } catch (e) {
      setReport({ failures: [friendly(e, { org: targetName })] })
    } finally {
      setBusy(null)
    }
  }

  const allOn = open.length > 0 && chosen.length === open.length
  return (
    <section className="card discovered" aria-labelledby={headingId}>
      <h2 id={headingId}>Accounts found in your cloud organisations</h2>
      <p className="muted">Keel lists the accounts in your cloud organisations here until they are registered. Check where each one belongs, select them, then register them in one step. Keel creates any project or environment that doesn’t exist yet.</p>
      <div className="toolbar">
        {discoverable.map((p) => (
          <button key={p} className="secondary" disabled={busy !== null} onClick={() => void discover(p)}>
            {busy === 'discovering' ? `Looking for ${providerName(p)} accounts…` : `Discover ${providerName(p)} accounts`}
          </button>
        ))}
      </div>

      {report?.done && (
        <p className="notice good" role="status">
          {report.done}
        </p>
      )}
      {report && report.failures.length > 0 && (
        <div className="notice error" role="alert">
          {report.failures.length === 1 ? (
            <p>{report.failures[0]}</p>
          ) : (
            <ul>
              {report.failures.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      {load.state === 'loading' && <p className="muted">Loading discovered accounts…</p>}
      {load.state === 'error' && <p className="notice error">Could not load discovered accounts. {load.message}</p>}
      {load.state === 'ready' && accounts.length === 0 && <p className="muted">Keel hasn’t looked for accounts yet. Choose Discover to list the accounts in your organisation; nothing is registered until you say so.</p>}
      {load.state === 'ready' && accounts.length > 0 && open.length === 0 && <p className="muted">Every discovered account is registered. Run discovery again after you add accounts in your cloud console.</p>}

      {open.length > 0 && (
        <form
          aria-label="Register discovered accounts"
          onSubmit={(ev) => {
            ev.preventDefault()
            void register()
          }}
        >
          <fieldset className="register-settings">
            <legend>Where they go</legend>
            <label htmlFor={`${headingId}-target`}>Register into</label>
            <select id={`${headingId}-target`} value={target} onChange={(ev) => setTarget(ev.target.value)}>
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
            </select>
            <TeamPicker org={targetName} teams={teams} choice={team} onChange={setTeam} />
            <fieldset className="ownership">
              <legend>Whose organisation are these accounts in?</legend>
              <label>
                <input type="radio" name="ownership" checked={ownership === 'platform'} onChange={() => setOwnership('platform')} /> Ours (Keel manages them)
              </label>
              <label>
                <input type="radio" name="ownership" checked={ownership === 'client'} onChange={() => setOwnership('client')} /> The client’s organisation (Keel only reads, through a role they grant)
              </label>
            </fieldset>
          </fieldset>

          <label className="select-all">
            <input type="checkbox" checked={allOn} onChange={(ev) => setSelected(ev.target.checked ? new Set(open.map(keyOf)) : new Set())} /> Select all
          </label>
          <ul className="discovered-list">
            {open.map((a) => (
              <DiscoveredRow key={keyOf(a)} account={a} draft={draftOf(a)} selected={selected.has(keyOf(a))} client={ownership === 'client'} onToggle={(on) => toggle(keyOf(a), on)} onEdit={(patch) => edit(a, patch)} />
            ))}
          </ul>
          {accounts.length > open.length && <p className="muted">{plural(accounts.length - open.length, 'account')} found earlier {accounts.length - open.length === 1 ? 'is' : 'are'} already registered and not shown.</p>}

          <button className="primary" type="submit" disabled={chosen.length === 0 || busy !== null}>
            {busy === 'registering' ? 'Registering…' : chosen.length === 0 ? 'Select accounts to register' : `Register ${plural(chosen.length, 'selected account')}`}
          </button>
        </form>
      )}
    </section>
  )
}

function TeamPicker({ org, teams, choice, onChange }: { org: string; teams: Team[] | null; choice: TeamChoice; onChange: (c: TeamChoice) => void }) {
  const selectId = useId()
  if (teams === null) return <p className="muted">Loading teams…</p>
  const newTeam = (
    <label>
      New team name
      <input value={choice.kind === 'new' ? choice.name : ''} onChange={(ev) => onChange({ kind: 'new', name: ev.target.value })} placeholder="e.g. CRM team" required />
    </label>
  )
  if (teams.length === 0)
    return (
      <div>
        <p className="muted">{org} has no teams yet. Name one and Keel creates it to own the new projects.</p>
        {newTeam}
      </div>
    )
  return (
    <>
      <label htmlFor={selectId}>Team that owns new projects</label>
      <select id={selectId} value={choice.kind === 'new' ? 'new' : choice.id} onChange={(ev) => onChange(ev.target.value === 'new' ? { kind: 'new', name: '' } : { kind: 'existing', id: ev.target.value })}>
          {teams.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
          <option value="new">New team…</option>
      </select>
      {choice.kind === 'new' && newTeam}
    </>
  )
}

function DiscoveredRow({ account: a, draft, selected, client, onToggle, onEdit }: { account: DiscoveredAccount; draft: Draft; selected: boolean; client: boolean; onToggle: (on: boolean) => void; onEdit: (patch: Partial<Draft>) => void }) {
  const nameId = useId()
  const hintId = useId()
  return (
    <li role="group" aria-labelledby={nameId} className={selected ? 'selected' : undefined}>
      <label className="pick">
        <input type="checkbox" checked={selected} onChange={(ev) => onToggle(ev.target.checked)} aria-label={`Select ${a.name}`} />
        <span>
          <strong id={nameId}>{a.name}</strong>
          <span className="muted">
            {' '}
            {providerName(a.provider)} · Account ID <span className="mono">{a.external_id}</span>
            {a.parent && ` · in ${a.parent}`}
          </span>
          <span className="muted seen">
            First seen {day(a.first_seen_at)}, last seen {day(a.last_seen_at)}
          </span>
        </span>
      </label>
      <div className="placement">
        <label>
          Project
          <input value={draft.project} onChange={(ev) => onEdit({ project: ev.target.value })} placeholder="e.g. tat-crm" aria-describedby={hintId} />
        </label>
        <label>
          Environment
          <input value={draft.environment} onChange={(ev) => onEdit({ environment: ev.target.value })} placeholder="e.g. prod" aria-describedby={hintId} />
        </label>
        {client && (
          <label>
            Read-only role ARN
            <input value={draft.role} onChange={(ev) => onEdit({ role: ev.target.value })} placeholder={`qcs::cam::uin/${a.external_id}:roleName/KeelReadOnly`} required={selected} />
          </label>
        )}
      </div>
      <p id={hintId} className="muted hint">
        {a.suggestion ? 'Keel suggested this from the account name; change it if it’s wrong.' : 'Keel couldn’t guess from the name. Leave both blank to register it without an environment (shared tooling, logging or billing), or type where it belongs.'}
      </p>
    </li>
  )
}

function summarise(outcomes: RegistrationOutcome[], chosen: DiscoveredAccount[], org: string): Report {
  const nameOf = (o: RegistrationOutcome) => chosen.find((a) => keyOf(a) === keyOf(o))?.name ?? o.external_id
  const ok = outcomes.filter((o) => o.status === 'registered')
  const same = outcomes.filter((o) => o.status === 'already_registered')
  const projects = ok.filter((o) => o.project_created).length
  const envs = ok.filter((o) => o.environment_created).length
  const parts = [
    ok.length > 0 && `Registered ${plural(ok.length, 'account')} in ${org}.`,
    (projects > 0 || envs > 0) && `Created ${[projects > 0 && plural(projects, 'project'), envs > 0 && plural(envs, 'environment')].filter(Boolean).join(' and ')}.`,
    same.length > 0 && `${plural(same.length, 'account')} ${same.length === 1 ? 'was' : 'were'} already registered there; nothing changed.`,
  ].filter(Boolean)
  return {
    done: parts.length > 0 ? parts.join(' ') : undefined,
    failures: outcomes.filter((o) => o.status === 'failed').map((o) => `${nameOf(o)}: ${friendly(new Error(o.error ?? ''), { provider: o.provider, org })}`),
  }
}
