import { useId } from 'react'
import { Link } from 'react-router'

interface A13ELogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl'
  showText?: boolean
  showTagline?: boolean
  variant?: 'full' | 'icon' | 'wordmark'
  linkTo?: string | null
  className?: string
}

const sizes = {
  sm: { icon: 32, text: 'text-lg', tagline: 'text-[10px]' },
  md: { icon: 40, text: 'text-xl', tagline: 'text-xs' },
  lg: { icon: 48, text: 'text-2xl', tagline: 'text-sm' },
  xl: { icon: 64, text: 'text-4xl', tagline: 'text-base' },
}

function LogoIcon({ size = 40, instanceId }: { size?: number; instanceId: string }) {
  // Use unique IDs to prevent SVG gradient conflicts when multiple logos are on the page
  const gradId = `a13e-grad-${instanceId}`
  const glowGradId = `a13e-glow-${instanceId}`
  const glowFilterId = `glow-${instanceId}`

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="shrink-0"
    >
      <defs>
        <linearGradient id={gradId} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#3B82F6" />
          <stop offset="50%" stopColor="#06B6D4" />
          <stop offset="100%" stopColor="#8B5CF6" />
        </linearGradient>
        <linearGradient id={glowGradId} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#60A5FA" />
          <stop offset="100%" stopColor="#A78BFA" />
        </linearGradient>
        <filter id={glowFilterId} x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="2" result="coloredBlur" />
          <feMerge>
            <feMergeNode in="coloredBlur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      {/* Hexagonal shield shape */}
      <path
        d="M24 2L44 14V34L24 46L4 34V14L24 2Z"
        fill={`url(#${gradId})`}
        stroke={`url(#${glowGradId})`}
        strokeWidth="1"
        filter={`url(#${glowFilterId})`}
      />
      {/* Stylized "A" */}
      <path
        d="M24 10L34 30H28L26 26H22L20 30H14L24 10Z"
        fill="white"
        fillOpacity="0.95"
      />
      <path d="M24 18L26.5 24H21.5L24 18Z" fill={`url(#${gradId})`} />
      {/* Three accent lines (representing 13 / trinity / stability) */}
      <line
        x1="12"
        y1="36"
        x2="18"
        y2="36"
        stroke="white"
        strokeWidth="2"
        strokeLinecap="round"
        opacity="0.8"
      />
      <line
        x1="21"
        y1="36"
        x2="27"
        y2="36"
        stroke="white"
        strokeWidth="2"
        strokeLinecap="round"
        opacity="0.8"
      />
      <line
        x1="30"
        y1="36"
        x2="36"
        y2="36"
        stroke="white"
        strokeWidth="2"
        strokeLinecap="round"
        opacity="0.8"
      />
    </svg>
  )
}

export default function A13ELogo({
  size = 'md',
  showText = true,
  showTagline = false,
  variant = 'full',
  linkTo = '/',
  className = '',
}: A13ELogoProps) {
  const instanceId = useId()
  const sizeConfig = sizes[size]

  const content = (
    <div className={`flex items-center gap-3 ${className}`}>
      {variant !== 'wordmark' && <LogoIcon size={sizeConfig.icon} instanceId={instanceId} />}

      {variant !== 'icon' && showText && (
        <div className="flex flex-col">
          <div className="flex items-baseline gap-1">
            <span
              className={`font-black tracking-tight bg-linear-to-r from-blue-400 via-cyan-400 to-purple-400 bg-clip-text text-transparent ${sizeConfig.text}`}
            >
              A13E
            </span>
            {showTagline && (
              <span className={`text-gray-500 font-medium ${sizeConfig.tagline}`}>
                Security
              </span>
            )}
          </div>
          {showTagline && (
            <span className={`text-gray-400 ${sizeConfig.tagline} -mt-0.5`}>
              Detection Coverage Validator
            </span>
          )}
        </div>
      )}
    </div>
  )

  if (linkTo) {
    return (
      <Link
        to={linkTo}
        className="hover:opacity-90 transition-opacity focus:outline-hidden focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-900 rounded-lg"
      >
        {content}
      </Link>
    )
  }

  return content
}

// Compact version for tight spaces
export function A13ELogoCompact({ className = '' }: { className?: string }) {
  const instanceId = useId()
  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <LogoIcon size={28} instanceId={instanceId} />
      <span className="font-bold text-sm bg-linear-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
        A13E
      </span>
    </div>
  )
}

// Just the icon
export function A13EIcon({ size = 40 }: { size?: number }) {
  const instanceId = useId()
  return <LogoIcon size={size} instanceId={instanceId} />
}
