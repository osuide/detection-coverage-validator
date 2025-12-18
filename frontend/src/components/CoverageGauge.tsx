interface CoverageGaugeProps {
  percent: number
  confidence: number
}

export default function CoverageGauge({ percent, confidence }: CoverageGaugeProps) {
  const getColor = (pct: number) => {
    if (pct >= 70) return '#22c55e' // green
    if (pct >= 40) return '#eab308' // yellow
    return '#ef4444' // red
  }

  const color = getColor(percent)
  const circumference = 2 * Math.PI * 90
  const strokeDashoffset = circumference - (percent / 100) * circumference

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-48 h-48">
        <svg className="w-full h-full transform -rotate-90">
          {/* Background circle */}
          <circle
            cx="96"
            cy="96"
            r="90"
            fill="none"
            stroke="#e5e7eb"
            strokeWidth="12"
          />
          {/* Progress circle */}
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
            style={{ transition: 'stroke-dashoffset 0.5s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-bold text-gray-900">{percent.toFixed(1)}%</span>
          <span className="text-sm text-gray-500">coverage</span>
        </div>
      </div>
      <div className="mt-4 text-center">
        <p className="text-sm text-gray-600">
          Avg Confidence: <span className="font-medium">{(confidence * 100).toFixed(0)}%</span>
        </p>
      </div>
    </div>
  )
}
