import { useState } from 'react'
import { fmtMoney } from './api'

type Point = { start: string; budget: string; actual: string }

const W = 640
const H = 220
const M = { top: 12, right: 8, bottom: 22, left: 52 }

function niceMax(v: number): number {
  if (v <= 0) return 1
  const p = Math.pow(10, Math.floor(Math.log10(v)))
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p
  return 10 * p
}

const compact = (n: number) => n.toLocaleString(undefined, { notation: 'compact', maximumFractionDigits: 1 })

/**
 * Actual spend as bars, the budget as a dashed reference line. One axis,
 * single hue; hover a column for exact values; "Show table" for the numbers.
 */
export function BudgetChart({ series, currency, unit }: { series: Point[]; currency: string; unit: 'day' | 'month' }) {
  const [hover, setHover] = useState<number | null>(null)
  const [table, setTable] = useState(false)
  const n = series.length
  const max = niceMax(Math.max(...series.map((p) => Math.max(Number(p.budget), Number(p.actual || 0)))))
  const iw = W - M.left - M.right
  const ih = H - M.top - M.bottom
  const band = iw / n
  const bw = Math.min(24, band * 0.7)
  const x = (i: number) => M.left + band * i + band / 2
  const y = (v: number) => M.top + ih - (v / max) * ih
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * max)
  const label = (p: Point) =>
    unit === 'day'
      ? new Date(p.start).toLocaleDateString(undefined, { day: 'numeric', month: 'short', timeZone: 'UTC' })
      : new Date(p.start).toLocaleDateString(undefined, { month: 'short', timeZone: 'UTC' })
  const every = unit === 'day' ? 5 : 1
  const budgetPath = series.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i) - band / 2},${y(Number(p.budget))}H${x(i) + band / 2}`).join('')

  return (
    <figure className="chart" aria-label={`Actual spend versus budget per ${unit}`}>
      <div className="legend">
        <span>
          <span className="sw" aria-hidden />
          Actual
        </span>
        <span>
          <span className="sw line" aria-hidden />
          Budget
        </span>
        <button className="link" style={{ marginLeft: 'auto' }} onClick={() => setTable((t) => !t)}>
          {table ? 'Show chart' : 'Show table'}
        </button>
      </div>
      {table ? (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>{unit === 'day' ? 'Day' : 'Month'}</th>
                <th>Budget ({currency})</th>
                <th>Actual ({currency})</th>
              </tr>
            </thead>
            <tbody>
              {series.map((p) => (
                <tr key={p.start}>
                  <td>{label(p)}</td>
                  <td>{fmtMoney(p.budget)}</td>
                  <td>{fmtMoney(p.actual)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <>
          <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" onMouseLeave={() => setHover(null)}>
            {ticks.map((t) => (
              <g key={t}>
                <line x1={M.left} x2={W - M.right} y1={y(t)} y2={y(t)} stroke={t === 0 ? 'var(--baseline)' : 'var(--gridline)'} strokeWidth={1} vectorEffect="non-scaling-stroke" />
                <text x={M.left - 6} y={y(t)} dy="0.32em" textAnchor="end" fontSize={11} fill="var(--ink-muted)">
                  {compact(t)}
                </text>
              </g>
            ))}
            {series.map((p, i) => {
              if (p.actual === '') return null
              const v = Number(p.actual)
              const top = y(v)
              const h = Math.max(0, M.top + ih - top)
              const r = Math.min(4, h, bw / 2)
              const x0 = x(i) - bw / 2
              const base = M.top + ih
              return (
                <path
                  key={p.start}
                  d={`M${x0},${base}V${top + r}Q${x0},${top} ${x0 + r},${top}H${x0 + bw - r}Q${x0 + bw},${top} ${x0 + bw},${top + r}V${base}Z`}
                  fill="var(--series-1)"
                  opacity={hover === null || hover === i ? 1 : 0.55}
                />
              )
            })}
            <path d={budgetPath} fill="none" stroke="var(--ink-muted)" strokeWidth={2} strokeDasharray="5 4" vectorEffect="non-scaling-stroke" />
            {series.map((p, i) =>
              i % every === 0 ? (
                <text key={p.start} x={x(i)} y={H - 6} textAnchor="middle" fontSize={11} fill="var(--ink-muted)">
                  {label(p)}
                </text>
              ) : null,
            )}
            {series.map((p, i) => (
              <rect key={p.start} x={x(i) - band / 2} y={M.top} width={band} height={ih} fill="transparent" onMouseEnter={() => setHover(i)} onFocus={() => setHover(i)} tabIndex={0} aria-label={`${label(p)}: actual ${fmtMoney(p.actual, currency)}, budget ${fmtMoney(p.budget, currency)}`} />
            ))}
          </svg>
          {hover !== null && (
            <div className="tip" style={{ left: `${(x(hover) / W) * 100}%`, top: `${(y(Math.max(Number(series[hover].actual || 0), Number(series[hover].budget))) / H) * 220 + 34}px` }}>
              <strong>{label(series[hover])}</strong>
              <br />
              Actual {fmtMoney(series[hover].actual, currency)}
              <br />
              Budget {fmtMoney(series[hover].budget, currency)}
            </div>
          )}
        </>
      )}
    </figure>
  )
}
