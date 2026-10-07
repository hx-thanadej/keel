import { useEffect, useState } from 'react'
import { api, ApiError, type Principal } from './api'
import { SignIn } from './SignIn'
import { Shell } from './Shell'

export default function App() {
  const [me, setMe] = useState<Principal | null | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .me()
      .then(setMe)
      .catch((e) => (e instanceof ApiError && e.status === 401 ? setMe(null) : setError(String(e.message ?? e))))
  }, [])

  if (error) return <p className="notice error">Keel is unreachable: {error}</p>
  if (me === undefined) return <p className="notice">Loading…</p>
  if (me === null) return <SignIn />
  return <Shell me={me} onSignedOut={() => setMe(null)} />
}
