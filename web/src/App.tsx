import { useEffect, useState } from 'react'

type Health = { status: string; version: string }

export default function App() {
  const [health, setHealth] = useState<Health | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/healthz')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then(setHealth)
      .catch((e: Error) => setError(e.message))
  }, [])

  return (
    <main>
      <h1>Keel</h1>
      <p>DevSecOps platform — portal scaffold.</p>
      <p>
        API:{' '}
        {error ? `unreachable (${error})` : health ? `${health.status}, version ${health.version}` : 'checking…'}
      </p>
    </main>
  )
}
