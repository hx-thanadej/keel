import { useEffect, useId, useState } from 'react'
import { connections, type CloudConnection, type ConnectionKeys } from './api'

const when = (iso: string) => new Date(iso).toLocaleString()
const message = (e: unknown) => String((e as Error)?.message ?? e)

/**
 * Cloud connections (ADR-0022): Tencent keys a platform admin stores in Keel.
 * Key fields are write-only: they are sent once and cleared, and the API never returns the secret key.
 */
export function ConnectionsView() {
  const [items, setItems] = useState<CloudConnection[] | null>(null)
  const [error, setError] = useState<string>()

  useEffect(() => {
    connections
      .list()
      .then(setItems)
      .catch((e) => setError(message(e)))
  }, [])

  const replace = (c: CloudConnection) => setItems((xs) => (xs ?? []).map((x) => (x.id === c.id ? c : x)))

  return (
    <section className="delivery">
      <p className="muted">
        A stored key is Keel's Tencent identity and only reads. Vending, guardrail remediation and other writes still need keyless identity.
      </p>
      {error && (
        <p className="notice error" role="alert">
          {error}
        </p>
      )}
      {items === null && !error && <p className="muted">Loading connections…</p>}
      {items?.length === 0 && <p className="muted">No Tencent connection. Keel uses its keyless identity (TKE or CVM role).</p>}
      {items?.map((c) => (
        <ConnectionCard key={c.id} connection={c} onChange={replace} onDeleted={() => setItems((xs) => (xs ?? []).filter((x) => x.id !== c.id))} />
      ))}
      {items?.length === 0 && <AddConnection onAdded={(c) => setItems([c])} />}
    </section>
  )
}

function ConnectionCard({
  connection: c,
  onChange,
  onDeleted,
}: {
  connection: CloudConnection
  onChange: (c: CloudConnection) => void
  onDeleted: () => void
}) {
  const titleId = useId()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const [rotating, setRotating] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)

  const run = async (fn: () => Promise<void>) => {
    setBusy(true)
    setError(undefined)
    try {
      await fn()
    } catch (e) {
      setError(message(e))
    } finally {
      setBusy(false)
    }
  }
  const test = () => run(async () => onChange(await connections.test(c.id)))
  const remove = () =>
    run(async () => {
      await connections.remove(c.id)
      onDeleted()
    })
  const rotate = (keys: ConnectionKeys) =>
    run(async () => {
      onChange(await connections.update(c.id, { keys }))
      setRotating(false)
    })

  return (
    <article className="card" aria-labelledby={titleId}>
      <h2 id={titleId}>{c.name}</h2>
      <div className="badges">
        <span className="badge">Tencent</span>
        <span className="badge">Read-only</span>
      </div>
      <dl className="meta">
        <dt>Payer UIN</dt>
        <dd>{c.payer_uin}</dd>
        <dt>Default region</dt>
        <dd>{c.default_region}</dd>
        <dt>Organisation region</dt>
        <dd>{c.org_region || 'none'}</dd>
        <dt>Member role</dt>
        <dd>{c.member_role || 'none'}</dd>
        <dt>SecretId</dt>
        <dd>{c.secret_id}</dd>
        <dt>Added</dt>
        <dd>
          {when(c.created_at)} by {c.created_by.replace(/^user:/, '')}
        </dd>
        <dt>Keys rotated</dt>
        <dd>{c.rotated_at ? when(c.rotated_at) : 'never'}</dd>
        <dt>Last test</dt>
        <dd>
          {!c.last_test
            ? 'Not tested yet'
            : c.last_test.ok
              ? `Passed: account ${c.last_test.caller_uin}, ${when(c.last_test.at)}`
              : `Failed: ${c.last_test.detail}, ${when(c.last_test.at)}`}
        </dd>
      </dl>
      {error && (
        <p className="notice error" role="alert">
          {error}
        </p>
      )}
      <div className="toolbar">
        <button type="button" className="primary" onClick={test} disabled={busy}>
          Test connection
        </button>
        <button type="button" onClick={() => setRotating((r) => !r)} disabled={busy}>
          Rotate keys
        </button>
        {confirmDelete ? (
          <>
            <button type="button" onClick={remove} disabled={busy}>
              Delete permanently
            </button>
            <button type="button" onClick={() => setConfirmDelete(false)}>
              Cancel
            </button>
          </>
        ) : (
          <button type="button" onClick={() => setConfirmDelete(true)} disabled={busy}>
            Delete
          </button>
        )}
      </div>
      {rotating && <KeyFields label="New " submit="Save new keys" onSubmit={rotate} />}
    </article>
  )
}

/** The two key fields. They clear on submit so the key does not linger in the page. */
function KeyFields({ label, submit, onSubmit }: { label: string; submit: string; onSubmit: (k: ConnectionKeys) => void }) {
  const [id, setId] = useState('')
  const [key, setKey] = useState('')
  return (
    <form
      className="card toolbar"
      onSubmit={(e) => {
        e.preventDefault()
        onSubmit({ secret_id: id.trim(), secret_key: key.trim() })
        setId('')
        setKey('')
      }}
    >
      <label>
        {label}SecretId <input value={id} onChange={(e) => setId(e.target.value)} required autoComplete="off" spellCheck={false} />
      </label>
      <label>
        {label}SecretKey <input type="password" value={key} onChange={(e) => setKey(e.target.value)} required autoComplete="new-password" />
      </label>
      <button className="primary" type="submit">
        {submit}
      </button>
    </form>
  )
}

function AddConnection({ onAdded }: { onAdded: (c: CloudConnection) => void }) {
  const [name, setName] = useState('')
  const [payer, setPayer] = useState('')
  const [region, setRegion] = useState('ap-bangkok')
  const [orgRegion, setOrgRegion] = useState('')
  const [memberRole, setMemberRole] = useState('')
  const [secretId, setSecretId] = useState('')
  const [secretKey, setSecretKey] = useState('')
  const [error, setError] = useState<string>()

  const add = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(undefined)
    const keys = { secret_id: secretId.trim(), secret_key: secretKey.trim() }
    setSecretKey('')
    try {
      const c = await connections.create({
        provider: 'tencent',
        name: name.trim(),
        payer_uin: payer.trim(),
        default_region: region.trim(),
        org_region: orgRegion.trim(),
        member_role: memberRole.trim(),
        keys,
      })
      setSecretId('')
      onAdded(c)
    } catch (err) {
      setError(message(err))
    }
  }

  return (
    <form className="card inline" onSubmit={add} aria-label="Add Tencent connection">
      <h2>Add Tencent connection</h2>
      <label>
        Name <input value={name} onChange={(e) => setName(e.target.value)} required maxLength={100} />
      </label>
      <label>
        Payer UIN <input value={payer} onChange={(e) => setPayer(e.target.value)} required pattern="[0-9]{5,20}" inputMode="numeric" />
      </label>
      <label>
        Default region <input value={region} onChange={(e) => setRegion(e.target.value)} required />
      </label>
      <label>
        Organisation region <input value={orgRegion} onChange={(e) => setOrgRegion(e.target.value)} placeholder="optional" />
      </label>
      <label>
        Member role <input value={memberRole} onChange={(e) => setMemberRole(e.target.value)} placeholder="optional" />
      </label>
      <label>
        SecretId <input value={secretId} onChange={(e) => setSecretId(e.target.value)} required autoComplete="off" spellCheck={false} />
      </label>
      <label>
        SecretKey <input type="password" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} required autoComplete="new-password" />
      </label>
      <p className="muted">Keel seals the key and never shows it again. Give its CAM user read-only policies.</p>
      {error && (
        <p className="notice error" role="alert">
          {error}
        </p>
      )}
      <button className="primary" type="submit">
        Add connection
      </button>
    </form>
  )
}
