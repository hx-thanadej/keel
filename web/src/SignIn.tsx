import { useState } from 'react'

export function SignIn() {
  const [tenant, setTenant] = useState('')
  const go = (e: React.FormEvent) => {
    e.preventDefault()
    const t = tenant.trim().toLowerCase()
    if (t) window.location.assign(`/auth/login?tenant=${encodeURIComponent(t)}&return_to=/`)
  }
  return (
    <main className="signin">
      <h1>Keel</h1>
      <p>Sign in through your organisation’s identity provider.</p>
      <form onSubmit={go}>
        <label htmlFor="tenant">Organisation</label>
        <input id="tenant" value={tenant} onChange={(e) => setTenant(e.target.value)} placeholder="e.g. harmonyx" autoComplete="organization" />
        <button type="submit" disabled={!tenant.trim()}>
          Continue
        </button>
      </form>
    </main>
  )
}
