interface CoverageGaugeProps {
  percent: number
  confidence: number
}

export default function CoverageGauge({ percent, confidence }: CoverageGaugeProps) {
  const getColor = (pct: number) => {
    if (pct >= 70) return { primary: '#22c55e', glow: 'rgba(34, 197, 94, 0.4)' } // green
    if (pct >= 40) return { primary: '#eab308', glow: 'rgba(234, 179, 8, 0.4)' } // yellow
    return { primary: '#ef4444', glow: 'rgba(239, 68, 68, 0.4)' } // red
  }

  const getStatusLabel = (pct: number) => {
    if (pct >= 70) return { text: 'Strong', class: 'text-green-400' }
    if (pct >= 40) return { text: 'Moderate', class: 'text-yellow-400' }
    return { text: 'Needs Work', class: 'text-red-400' }
  }

  const { primary: color, glow } = getColor(percent)
  const status = getStatusLabel(percent)
  const circumference = 2 * Math.PI * 90
  const strokeDashoffset = circumference - (percent / 100) * circumference

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-48 h-48">
        {/* Glow effect behind the gauge */}
        <div
          className="absolute inset-0 rounded-full blur-xl opacity-30"
          style={{ backgroundColor: color }}
        />
        <svg className="w-full h-full transform -rotate-90 relative z-10">
          {/* Background circle - dark theme compatible */}
          <circle
            cx="96"
            cy="96"
            r="90"
            fill="none"
            stroke="#374151"
            strokeWidth="12"
            opacity="0.6"
          />
          {/* Progress circle with glow filter */}
          <defs>
            <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
              <feMerge>
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
          </defs>
          <circle
            cx="96"
            cy="96"
            r="90"
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            filter="url(#glow)"
            style={{
              transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1)',
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center z-20">
          <span
            className="text-4xl font-bold text-white tracking-tight"
            style={{ textShadow: `0 0 20px ${glow}` }}
          >
            {percent.toFixed(1)}%
          </span>
          <span className={`text-sm font-medium ${status.class} mt-1`}>
            {status.text}
          </span>
        </div>
      </div>
      <div className="mt-4 text-center space-y-1">
        <p className="text-xs uppercase tracking-wider text-gray-500">
          Detection Coverage
        </p>
        <p className="text-sm text-gray-400">
          Confidence: <span className="font-semibold text-gray-200">{(confidence * 100).toFixed(0)}%</span>
        </p>
      </div>
    </div>
  )
}
