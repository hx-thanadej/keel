import { useEffect, useState } from 'react'
import { api, type Activity } from './api'

const PAGE = 50

export function ActivityFeed({ tenantId }: { tenantId: string }) {
  const [actor, setActor] = useState('')
  const [type, setType] = useState('')
  const [since, setSince] = useState('')
  const [items, setItems] = useState<Activity[]>([])
  const [more, setMore] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const filter = (before?: number) => ({
    actor: actor.trim() || undefined,
    type: type.trim() || undefined,
    since: since ? new Date(since).toISOString() : undefined,
    before,
    limit: PAGE,
  })

  // Refetch the first page whenever a filter changes; ignore stale responses.
  useEffect(() => {
    let stale = false
    api
      .activities(tenantId, filter())
      .then((page) => {
        if (stale) return
        setItems(page)
        setMore(page.length === PAGE)
        setError(null)
      })
      .catch((e: Error) => !stale && setError(e.message))
    return () => {
      stale = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- filter() is derived from these
  }, [tenantId, actor, type, since])

  const loadOlder = async () => {
    try {
      const page = await api.activities(tenantId, filter(items[items.length - 1]?.seq))
      setItems((prev) => [...prev, ...page])
      setMore(page.length === PAGE)
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <section>
      <form className="filters" onSubmit={(e) => e.preventDefault()}>
        <label>
          Actor
          <input value={actor} onChange={(e) => setActor(e.target.value)} placeholder="user:alice@example.com" />
        </label>
        <label>
          Type
          <input value={type} onChange={(e) => setType(e.target.value)} placeholder="keel.project.created" />
        </label>
        <label>
          Since
          <input type="date" value={since} onChange={(e) => setSince(e.target.value)} />
        </label>
      </form>
      {error && <p className="notice error">{error}</p>}
      {items.length === 0 && !error ? (
        <p className="muted">No activity.</p>
      ) : (
        <ol className="feed">
          {items.map((a) => {
            const failed = a.event.data.status_id !== 1
            return (
              <li key={a.id} className={failed ? 'failed' : undefined}>
                <time dateTime={a.occurred_at}>{new Date(a.occurred_at).toLocaleString()}</time>
                <span className="type">{a.type}</span>
                <span className="actor">{a.actor_uid}</span>
                {a.event.data.why?.reason && <span className="why">“{a.event.data.why.reason}”</span>}
                {failed && <span className="detail">{a.event.data.status_detail}</span>}
              </li>
            )
          })}
        </ol>
      )}
      {more && (
        <button className="secondary" onClick={loadOlder}>
          Load older
        </button>
      )}
    </section>
  )
}
