import { useId, type ButtonHTMLAttributes } from 'react'
import type { Ownership } from './ownership'

const labels: Record<Ownership, string> = { platform: 'Platform-owned', client: 'Client-owned', mixed: 'Mixed ownership' }

export function OwnershipBadge({ ownership }: { ownership: Ownership | null }) {
  if (!ownership) return null
  return <span className={`badge own-${ownership}`}>{labels[ownership]}</span>
}

/** A button that, when refused, stays visible and disabled with its reason as its accessible description. */
export function GuardedButton({ reason, children, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { reason: string | null }) {
  const id = useId()
  return (
    <>
      <button {...props} disabled={props.disabled || reason !== null} aria-describedby={reason ? id : undefined}>
        {children}
      </button>
      {reason && (
        <span id={id} className="reason">
          {reason}
        </span>
      )}
    </>
  )
}
