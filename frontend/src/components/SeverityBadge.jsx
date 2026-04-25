const classes = {
  low: 'bg-emerald-500/20 text-emerald-300',
  medium: 'bg-amber-500/20 text-amber-300',
  high: 'bg-orange-500/20 text-orange-300',
  critical: 'bg-rose-500/20 text-rose-300',
}

function SeverityBadge({ severity }) {
  return (
    <span
      className={`rounded px-2 py-1 text-xs font-semibold uppercase ${classes[severity] ?? classes.low}`}
    >
      {severity}
    </span>
  )
}

export default SeverityBadge
