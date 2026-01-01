import { useState, useEffect } from 'react'
import { Link } from 'react-router'
import {
  Shield,
  Target,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  BarChart3,
  FileText,
  Clock,
  Zap,
  Bell,
  Code,
  ChevronRight,
  Sparkles,
  Eye,
  Search,
  Calendar,
  ArrowRight,
  X,
  Menu
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import A13ELogo from '../components/A13ELogo'

export default function Landing() {
  const { isAuthenticated } = useAuth()
  const [scrollY, setScrollY] = useState(0)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  useEffect(() => {
    const handleScroll = () => setScrollY(window.scrollY)
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  return (
    <div className="min-h-screen bg-linear-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Navigation */}
      <nav className={`fixed top-0 w-full z-50 transition-all duration-300 ${scrollY > 50 ? 'bg-slate-950/95 backdrop-blur-lg border-b border-slate-800' : 'bg-transparent'}`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <A13ELogo size="sm" showTagline={false} />
            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center space-x-8">
              <a href="#features" className="text-gray-300 hover:text-white transition-colors">Features</a>
              <a href="#pricing" className="text-gray-300 hover:text-white transition-colors">Pricing</a>
              <a href="#demo" className="text-gray-300 hover:text-white transition-colors">Demo</a>
              <Link to="/docs" className="text-gray-300 hover:text-white transition-colors">Docs</Link>
              {isAuthenticated ? (
                <Link to="/dashboard" className="bg-linear-to-r from-blue-600 to-cyan-600 text-white px-5 py-2 rounded-lg font-medium hover:from-blue-700 hover:to-cyan-700 transition-all shadow-lg shadow-blue-500/25">
                  Go to Dashboard
                </Link>
              ) : (
                <>
                  <Link to="/login" className="text-gray-300 hover:text-white transition-colors">Sign In</Link>
                  <Link
                    to="/signup"
                    className="bg-linear-to-r from-blue-600 to-cyan-600 text-white px-5 py-2 rounded-lg font-medium hover:from-blue-700 hover:to-cyan-700 transition-all shadow-lg shadow-blue-500/25"
                  >
                    Start Free Scan
                  </Link>
                </>
              )}
            </div>

            {/* Mobile Menu Button */}
            <button
              className="md:hidden p-2 text-gray-300 hover:text-white transition-colors"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>

          {/* Mobile Menu */}
          {mobileMenuOpen && (
            <div className="md:hidden border-t border-slate-800 bg-slate-950/95 backdrop-blur-lg">
              <div className="px-4 py-4 space-y-3">
                <a
                  href="#features"
                  onClick={() => setMobileMenuOpen(false)}
                  className="block text-gray-300 hover:text-white transition-colors py-2"
                >
                  Features
                </a>
                <a
                  href="#pricing"
                  onClick={() => setMobileMenuOpen(false)}
                  className="block text-gray-300 hover:text-white transition-colors py-2"
                >
                  Pricing
                </a>
                <a
                  href="#demo"
                  onClick={() => setMobileMenuOpen(false)}
                  className="block text-gray-300 hover:text-white transition-colors py-2"
                >
                  Demo
                </a>
                <Link
                  to="/docs"
                  onClick={() => setMobileMenuOpen(false)}
                  className="block text-gray-300 hover:text-white transition-colors py-2"
                >
                  Docs
                </Link>
                <div className="pt-3 border-t border-slate-800 space-y-3">
                  {isAuthenticated ? (
                    <Link
                      to="/dashboard"
                      onClick={() => setMobileMenuOpen(false)}
                      className="block w-full text-center bg-linear-to-r from-blue-600 to-cyan-600 text-white px-5 py-3 rounded-lg font-medium"
                    >
                      Go to Dashboard
                    </Link>
                  ) : (
                    <>
                      <Link
                        to="/login"
                        onClick={() => setMobileMenuOpen(false)}
                        className="block text-gray-300 hover:text-white transition-colors py-2"
                      >
                        Sign In
                      </Link>
                      <Link
                        to="/signup"
                        onClick={() => setMobileMenuOpen(false)}
                        className="block w-full text-center bg-linear-to-r from-blue-600 to-cyan-600 text-white px-5 py-3 rounded-lg font-medium"
                      >
                        Start Free Scan
                      </Link>
                    </>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 overflow-hidden">
        {/* Animated background gradient orbs */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-1/4 -left-48 w-96 h-96 bg-blue-600/20 rounded-full blur-3xl animate-pulse" style={{ animationDuration: '4s' }} />
          <div className="absolute bottom-1/4 -right-48 w-96 h-96 bg-cyan-600/20 rounded-full blur-3xl animate-pulse" style={{ animationDuration: '6s' }} />
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-purple-600/10 rounded-full blur-3xl animate-pulse" style={{ animationDuration: '5s' }} />
        </div>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
          <div className="text-center max-w-4xl mx-auto">
            {/* Badge */}
            <div className="inline-flex items-center space-x-2 bg-linear-to-r from-blue-600/10 to-cyan-600/10 border border-blue-500/20 rounded-full px-4 py-2 mb-8 backdrop-blur-xs">
              <Sparkles className="h-4 w-4 text-blue-400" />
              <span className="text-sm text-blue-300 font-medium">AWS + GCP Security Coverage Analysis</span>
            </div>

            {/* Headline */}
            <h1 className="text-5xl md:text-7xl font-extrabold text-white mb-6 leading-tight">
              Don't Let Security
              <span className="block bg-linear-to-r from-blue-500 via-cyan-500 to-purple-500 text-transparent bg-clip-text animate-gradient">
                Blind Spots
              </span>
              Expose Your Cloud
            </h1>

            <p className="text-xl md:text-2xl text-gray-400 mb-12 max-w-3xl mx-auto leading-relaxed">
              Instantly map your AWS and GCP security detections to MITRE ATT&CK framework.
              Identify coverage gaps before attackers do.
            </p>

            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mb-12">
              <Link
                to="/signup"
                className="group bg-linear-to-r from-blue-600 to-cyan-600 text-white px-8 py-4 rounded-xl font-semibold hover:from-blue-700 hover:to-cyan-700 transition-all shadow-2xl shadow-blue-500/50 hover:shadow-blue-500/75 hover:scale-105 flex items-center space-x-2"
              >
                <span>Start Free Scan</span>
                <ArrowRight className="h-5 w-5 group-hover:translate-x-1 transition-transform" />
              </Link>
              <a
                href="#demo"
                className="group border border-gray-700 text-white px-8 py-4 rounded-xl font-semibold hover:bg-slate-800/50 transition-all backdrop-blur-xs flex items-center space-x-2"
              >
                <span>View Demo</span>
                <ChevronRight className="h-5 w-5 group-hover:translate-x-1 transition-transform" />
              </a>
            </div>

            {/* Trust Indicators */}
            <div className="flex flex-wrap justify-center items-center gap-8 text-sm text-gray-500">
              <div className="flex items-center space-x-2">
                <CheckCircle className="h-5 w-5 text-green-500" />
                <span>No Credit Card Required</span>
              </div>
              <div className="flex items-center space-x-2">
                <Shield className="h-5 w-5 text-blue-500" />
                <span>AWS + GCP Support</span>
              </div>
              <div className="flex items-center space-x-2">
                <Zap className="h-5 w-5 text-yellow-500" />
                <span>Results in Minutes</span>
              </div>
            </div>
          </div>

          {/* Hero Visual - Animated MITRE Matrix Preview */}
          <div className="mt-20 max-w-5xl mx-auto">
            <div className="relative rounded-2xl overflow-hidden border border-slate-800 shadow-2xl shadow-blue-500/20 bg-linear-to-br from-slate-900/90 to-slate-950/90 backdrop-blur-xl">
              {/* Simulated Dashboard Preview */}
              <div className="p-8">
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <h3 className="text-white font-semibold text-lg">Coverage Heatmap</h3>
                    <p className="text-gray-400 text-sm">MITRE ATT&CK Technique Coverage</p>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-sm text-gray-400">Coverage:</span>
                    <span className="text-2xl font-bold text-green-400">68%</span>
                  </div>
                </div>

                {/* Mini Heatmap Grid */}
                <div className="grid grid-cols-12 gap-1">
                  {Array.from({ length: 108 }).map((_, i) => {
                    const coverage = Math.random()
                    const bgColor =
                      coverage > 0.7 ? 'bg-green-600' :
                      coverage > 0.4 ? 'bg-yellow-600' :
                      coverage > 0.2 ? 'bg-orange-600' :
                      'bg-red-600/20'
                    return (
                      <div
                        key={i}
                        className={`h-8 rounded-sm ${bgColor} transition-all hover:scale-110 cursor-pointer`}
                        style={{
                          animationDelay: `${i * 10}ms`,
                          opacity: 0.3 + coverage * 0.7
                        }}
                      />
                    )
                  })}
                </div>

                {/* Legend */}
                <div className="flex items-center justify-center space-x-6 mt-6 text-xs text-gray-400">
                  <div className="flex items-center space-x-2">
                    <div className="w-4 h-4 bg-green-600 rounded-sm" />
                    <span>Covered</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-4 h-4 bg-yellow-600 rounded-sm" />
                    <span>Partial</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-4 h-4 bg-orange-600 rounded-sm" />
                    <span>Minimal</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-4 h-4 bg-red-600/20 rounded-sm" />
                    <span>No Coverage</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Problem/Solution Section */}
      <section className="py-20 bg-linear-to-b from-slate-950 to-slate-900">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-2 gap-12 items-center">
            {/* Problem */}
            <div className="relative">
              <div className="absolute -top-4 -left-4 w-24 h-24 bg-red-600/10 rounded-full blur-2xl" />
              <div className="relative bg-linear-to-br from-slate-900 to-slate-950 border border-red-900/50 rounded-2xl p-8">
                <AlertTriangle className="h-12 w-12 text-red-500 mb-4" />
                <h3 className="text-2xl font-bold text-white mb-4">The Problem</h3>
                <ul className="space-y-3 text-gray-400">
                  <li className="flex items-start space-x-3">
                    <X className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
                    <span>Security teams don't know what they're missing</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <X className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
                    <span>Critical gaps in detection coverage go unnoticed</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <X className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
                    <span>Manual MITRE mapping takes weeks of effort</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <X className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
                    <span>No visibility into coverage changes over time</span>
                  </li>
                </ul>
              </div>
            </div>

            {/* Solution */}
            <div className="relative">
              <div className="absolute -top-4 -right-4 w-24 h-24 bg-green-600/10 rounded-full blur-2xl" />
              <div className="relative bg-linear-to-br from-slate-900 to-slate-950 border border-green-900/50 rounded-2xl p-8">
                <CheckCircle className="h-12 w-12 text-green-500 mb-4" />
                <h3 className="text-2xl font-bold text-white mb-4">The Solution</h3>
                <ul className="space-y-3 text-gray-400">
                  <li className="flex items-start space-x-3">
                    <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 shrink-0" />
                    <span>Instant visualization of your detection coverage</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 shrink-0" />
                    <span>Automated gap analysis with prioritized recommendations</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 shrink-0" />
                    <span>AWS & GCP integration via CloudWatch, EventBridge, Cloud Logging & SCC</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 shrink-0" />
                    <span>Track improvements and prove ROI over time</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 bg-slate-950">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
              Everything You Need to
              <span className="block bg-linear-to-r from-blue-500 to-cyan-500 text-transparent bg-clip-text">
                Secure Your Cloud
              </span>
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              Powerful features designed for modern security teams
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {/* Feature Cards */}
            {[
              {
                icon: Target,
                title: 'Interactive Heatmap',
                description: 'Visualize your MITRE ATT&CK coverage with an intuitive, color-coded heatmap',
                gradient: 'from-blue-500 to-cyan-500'
              },
              {
                icon: Search,
                title: 'Gap Analysis',
                description: 'Identify critical blind spots in your detection coverage instantly',
                gradient: 'from-cyan-500 to-purple-500'
              },
              {
                icon: TrendingUp,
                title: 'Historical Trends',
                description: 'Track coverage improvements over time and measure security ROI',
                gradient: 'from-purple-500 to-pink-500'
              },
              {
                icon: FileText,
                title: 'PDF Reports',
                description: 'Export professional reports for compliance and executive review',
                gradient: 'from-pink-500 to-red-500'
              },
              {
                icon: Calendar,
                title: 'Scheduled Scans',
                description: 'Automate coverage analysis with recurring scans',
                gradient: 'from-red-500 to-orange-500'
              },
              {
                icon: Bell,
                title: 'Smart Alerts',
                description: 'Get notified when coverage drops or new gaps are detected',
                gradient: 'from-orange-500 to-yellow-500'
              },
              {
                icon: Code,
                title: 'API Access',
                description: 'Integrate coverage data into your existing security workflows',
                gradient: 'from-yellow-500 to-green-500'
              },
              {
                icon: Clock,
                title: 'Real-time Updates',
                description: 'See coverage changes as you deploy new detections',
                gradient: 'from-green-500 to-teal-500'
              },
              {
                icon: BarChart3,
                title: 'Actionable Insights',
                description: 'Get prioritized recommendations on which gaps to fix first',
                gradient: 'from-teal-500 to-blue-500'
              }
            ].map((feature, index) => (
              <div
                key={index}
                className="group relative bg-linear-to-br from-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-6 hover:border-slate-700 transition-all hover:shadow-xl hover:shadow-blue-500/10 hover:-translate-y-1"
              >
                <div className={`inline-flex p-3 rounded-xl bg-linear-to-br ${feature.gradient} mb-4`}>
                  <feature.icon className="h-6 w-6 text-white" />
                </div>
                <h3 className="text-xl font-semibold text-white mb-2">{feature.title}</h3>
                <p className="text-gray-400">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Interactive Demo Section */}
      <section id="demo" className="py-20 bg-linear-to-b from-slate-900 to-slate-950">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
              See It In Action
            </h2>
            <p className="text-xl text-gray-400">
              Real-time detection coverage analysis
            </p>
          </div>

          <div className="grid lg:grid-cols-2 gap-8">
            {/* Demo Card 1 */}
            <div className="bg-linear-to-br from-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-8">
              <div className="flex items-center space-x-3 mb-6">
                <div className="p-2 bg-blue-600/20 rounded-lg">
                  <Eye className="h-6 w-6 text-blue-400" />
                </div>
                <div>
                  <h3 className="text-white font-semibold text-lg">Coverage Overview</h3>
                  <p className="text-gray-400 text-sm">At-a-glance security posture</p>
                </div>
              </div>
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Total Techniques</span>
                  <span className="text-white font-semibold">196</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Covered</span>
                  <span className="text-green-400 font-semibold">134 (68%)</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Partial</span>
                  <span className="text-yellow-400 font-semibold">28 (14%)</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">No Coverage</span>
                  <span className="text-red-400 font-semibold">34 (18%)</span>
                </div>
                <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden mt-4">
                  <div className="flex h-full">
                    <div className="bg-green-600" style={{ width: '68%' }} />
                    <div className="bg-yellow-600" style={{ width: '14%' }} />
                    <div className="bg-red-600" style={{ width: '18%' }} />
                  </div>
                </div>
              </div>
            </div>

            {/* Demo Card 2 */}
            <div className="bg-linear-to-br from-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-8">
              <div className="flex items-center space-x-3 mb-6">
                <div className="p-2 bg-orange-600/20 rounded-lg">
                  <AlertTriangle className="h-6 w-6 text-orange-400" />
                </div>
                <div>
                  <h3 className="text-white font-semibold text-lg">Critical Gaps</h3>
                  <p className="text-gray-400 text-sm">High-priority missing detections</p>
                </div>
              </div>
              <div className="space-y-3">
                {[
                  { id: 'T1078', name: 'Valid Accounts', severity: 'Critical' },
                  { id: 'T1486', name: 'Data Encrypted for Impact', severity: 'Critical' },
                  { id: 'T1098', name: 'Account Manipulation', severity: 'High' },
                  { id: 'T1547', name: 'Boot or Logon Autostart', severity: 'High' }
                ].map((gap, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                    <div>
                      <span className="text-white font-medium">{gap.id}</span>
                      <p className="text-gray-400 text-sm">{gap.name}</p>
                    </div>
                    <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                      gap.severity === 'Critical' ? 'bg-red-600/20 text-red-400' : 'bg-orange-600/20 text-orange-400'
                    }`}>
                      {gap.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className="py-20 bg-slate-950">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
              Simple, Transparent Pricing
            </h2>
            <p className="text-xl text-gray-400">
              Start free, scale as you grow
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 max-w-7xl mx-auto">
            {/* Free Tier */}
            <div className="relative bg-linear-to-br from-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-6 flex flex-col">
              <div className="mb-6">
                <h3 className="text-xl font-bold text-white mb-2">Free</h3>
                <div className="flex items-baseline">
                  <span className="text-4xl font-bold text-white">£0</span>
                  <span className="text-gray-400 ml-2">forever</span>
                </div>
              </div>

              <ul className="space-y-3 mb-8 text-sm flex-1">
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                  <span className="text-gray-300">1 cloud account (AWS or GCP)</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                  <span className="text-gray-300">1 scan per week</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                  <span className="text-gray-300">30-day data retention</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                  <span className="text-gray-300">Coverage heatmap</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                  <span className="text-gray-300">Gap analysis list</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                  <span className="text-gray-300">PDF export (watermarked)</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                  <span className="text-gray-300">Remediation templates</span>
                </li>
              </ul>

              <Link
                to="/signup"
                className="block w-full text-center border border-blue-600 text-blue-400 px-4 py-2.5 rounded-xl font-semibold hover:bg-blue-600/10 transition-all text-sm mt-auto"
              >
                Start Free
              </Link>
            </div>

            {/* Individual Tier */}
            <div className="relative bg-linear-to-br from-blue-600 to-cyan-600 rounded-2xl p-6 shadow-2xl shadow-blue-500/30 flex flex-col">
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-linear-to-r from-yellow-500 to-orange-500 text-white px-3 py-0.5 rounded-full text-xs font-semibold">
                Most Popular
              </div>

              <div className="mb-6">
                <h3 className="text-xl font-bold text-white mb-2">Individual</h3>
                <div className="flex items-baseline">
                  <span className="text-4xl font-bold text-white">£29</span>
                  <span className="text-blue-100 ml-2">/month</span>
                </div>
              </div>

              <ul className="space-y-3 mb-8 text-sm flex-1">
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-white mt-0.5 shrink-0" />
                  <span className="text-white">Up to 6 accounts (AWS + GCP)</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-white mt-0.5 shrink-0" />
                  <span className="text-white">90-day data retention</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-white mt-0.5 shrink-0" />
                  <span className="text-white">Unlimited scans</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-white mt-0.5 shrink-0" />
                  <span className="text-white">Scheduled scans & alerts</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-white mt-0.5 shrink-0" />
                  <span className="text-white">Historical trends & analytics</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-white mt-0.5 shrink-0" />
                  <span className="text-white">API access</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-white mt-0.5 shrink-0" />
                  <span className="text-white">Code analysis</span>
                </li>
              </ul>

              <Link
                to="/signup"
                className="block w-full text-center bg-white text-blue-600 px-4 py-2.5 rounded-xl font-semibold hover:bg-blue-50 transition-all shadow-lg text-sm mt-auto"
              >
                Get Started
              </Link>
            </div>

            {/* Pro Tier */}
            <div className="relative bg-linear-to-br from-slate-900 to-slate-950 border border-cyan-500/50 rounded-2xl p-6 flex flex-col">
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-linear-to-r from-cyan-500 to-blue-500 text-white px-3 py-0.5 rounded-full text-xs font-semibold">
                For Organisations
              </div>

              <div className="mb-6">
                <h3 className="text-xl font-bold text-white mb-2">Pro</h3>
                <div className="flex items-baseline">
                  <span className="text-4xl font-bold text-white">£250</span>
                  <span className="text-gray-400 ml-2">/month</span>
                </div>
              </div>

              <ul className="space-y-3 mb-8 text-sm flex-1">
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-cyan-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">Up to 500 accounts</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-cyan-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">1-year data retention</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-cyan-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">All Individual features</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-cyan-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">AWS/GCP Organisation connection</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-cyan-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">Auto-discovery of accounts</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-cyan-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">Unified coverage dashboard</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-cyan-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">Delegated scanning</span>
                </li>
              </ul>

              <Link
                to="/signup"
                className="block w-full text-center border border-cyan-500 text-cyan-400 px-4 py-2.5 rounded-xl font-semibold hover:bg-cyan-600/10 transition-all text-sm mt-auto"
              >
                Get Started
              </Link>
            </div>

            {/* Enterprise Tier */}
            <div className="relative bg-linear-to-br from-slate-900 to-slate-950 border border-purple-500/50 rounded-2xl p-6 flex flex-col">
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-linear-to-r from-purple-500 to-pink-500 text-white px-3 py-0.5 rounded-full text-xs font-semibold">
                Unlimited
              </div>

              <div className="mb-6">
                <h3 className="text-xl font-bold text-white mb-2">Enterprise</h3>
                <div className="flex items-baseline">
                  <span className="text-4xl font-bold text-white">Custom</span>
                </div>
                <p className="text-gray-400 text-sm mt-1">Contact sales</p>
              </div>

              <ul className="space-y-3 mb-8 text-sm flex-1">
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-purple-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">Unlimited accounts</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-purple-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">Unlimited data retention</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-purple-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">All Pro features</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-purple-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">SSO / SAML integration</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-purple-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">Dedicated support & SLA</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-purple-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">Custom integrations</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-4 w-4 text-purple-400 mt-0.5 shrink-0" />
                  <span className="text-gray-300">Unlimited team members</span>
                </li>
              </ul>

              <Link
                to="/signup"
                className="block w-full text-center border border-purple-500 text-purple-400 px-4 py-2.5 rounded-xl font-semibold hover:bg-purple-600/10 transition-all text-sm mt-auto"
              >
                Contact Sales
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Social Proof Section */}
      <section className="py-20 bg-linear-to-b from-slate-900 to-slate-950">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          {/* Stats */}
          <div className="grid md:grid-cols-3 gap-8 mb-16">
            {[
              { value: '10K+', label: 'Detections Analyzed' },
              { value: '200+', label: 'Critical Gaps Identified' },
              { value: '32%', label: 'Average Coverage Improvement' }
            ].map((stat, index) => (
              <div key={index} className="text-center">
                <div className="text-5xl font-bold bg-linear-to-r from-blue-500 to-cyan-500 text-transparent bg-clip-text mb-2">
                  {stat.value}
                </div>
                <div className="text-gray-400">{stat.label}</div>
              </div>
            ))}
          </div>

          {/* Built by Security Professionals */}
          <div className="text-center max-w-4xl mx-auto">
            <h3 className="text-3xl font-bold text-white mb-6">Built by Security Professionals, for Security Professionals</h3>
            <div className="bg-linear-to-br from-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-8">
              <div className="flex justify-center mb-6">
                <div className="w-16 h-16 bg-linear-to-br from-blue-500 to-cyan-500 rounded-full flex items-center justify-center">
                  <Shield className="w-8 h-8 text-white" />
                </div>
              </div>
              <p className="text-lg text-gray-300 mb-6">
                A13E was founded by security practitioners who understand the challenges of maintaining comprehensive detection coverage across complex cloud environments. We built the tool we wished existed.
              </p>
              <div className="grid md:grid-cols-3 gap-6 text-left">
                <div className="p-4">
                  <div className="text-blue-400 font-semibold mb-2">Security-First Architecture</div>
                  <p className="text-gray-400 text-sm">Every design decision prioritises the security of your data. We practise what we preach.</p>
                </div>
                <div className="p-4">
                  <div className="text-blue-400 font-semibold mb-2">Practitioner-Driven Development</div>
                  <p className="text-gray-400 text-sm">Features are built based on real-world security operations experience, not theoretical requirements.</p>
                </div>
                <div className="p-4">
                  <div className="text-blue-400 font-semibold mb-2">Transparent & Accountable</div>
                  <p className="text-gray-400 text-sm">We believe in honest communication about capabilities and limitations. No marketing fluff.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Final CTA Section */}
      <section className="py-20 bg-slate-950">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
            Ready to Eliminate Your
            <span className="block bg-linear-to-r from-blue-500 to-cyan-500 text-transparent bg-clip-text">
              Security Blind Spots?
            </span>
          </h2>
          <p className="text-xl text-gray-400 mb-8">
            Join security teams using A13E's DCV to strengthen their cloud detection coverage
          </p>
          <Link
            to="/signup"
            className="inline-flex items-center space-x-2 bg-linear-to-r from-blue-600 to-cyan-600 text-white px-10 py-5 rounded-xl font-semibold hover:from-blue-700 hover:to-cyan-700 transition-all shadow-2xl shadow-blue-500/50 hover:shadow-blue-500/75 hover:scale-105 text-lg"
          >
            <span>Start Your Free Scan Now</span>
            <ArrowRight className="h-6 w-6" />
          </Link>
          <p className="text-gray-500 text-sm mt-4">
            No credit card required • Results in minutes • Cancel anytime
          </p>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-slate-950 border-t border-slate-800 py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-4 gap-8">
            <div>
              <div className="mb-4">
                <A13ELogo size="sm" showTagline linkTo={null} />
              </div>
              <p className="text-gray-400 text-sm">
                Detection Coverage Validator by A13E helps security teams visualize and improve their MITRE ATT&CK coverage.
              </p>
              <p className="text-gray-500 text-xs mt-2">
                a13e.com
              </p>
            </div>
            <div>
              <h4 className="text-white font-semibold mb-4">Product</h4>
              <ul className="space-y-2 text-gray-400 text-sm">
                <li><a href="#features" className="hover:text-white transition-colors">Features</a></li>
                <li><a href="#pricing" className="hover:text-white transition-colors">Pricing</a></li>
                <li><Link to="/signup" className="hover:text-white transition-colors">Sign Up</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="text-white font-semibold mb-4">Resources</h4>
              <ul className="space-y-2 text-gray-400 text-sm">
                <li><Link to="/docs" className="hover:text-white transition-colors">Documentation</Link></li>
                <li><Link to="/support" className="hover:text-white transition-colors">Support</Link></li>
                <li><Link to="/security" className="hover:text-white transition-colors">Security</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="text-white font-semibold mb-4">Legal</h4>
              <ul className="space-y-2 text-gray-400 text-sm">
                <li><Link to="/privacy" className="hover:text-white transition-colors">Privacy</Link></li>
                <li><Link to="/terms" className="hover:text-white transition-colors">Terms</Link></li>
                <li><Link to="/compliance-info" className="hover:text-white transition-colors">Compliance</Link></li>
              </ul>
            </div>
          </div>
          <div className="border-t border-slate-800 mt-8 pt-8 text-center text-gray-500 text-sm">
            &copy; {new Date().getFullYear()} A13E. All rights reserved. DCV is a product of A13E - An OSUIDE INC Company.
          </div>
        </div>
      </footer>

      <style>{`
        @keyframes gradient {
          0%, 100% { background-position: 0% 50%; }
          50% { background-position: 100% 50%; }
        }

        .animate-gradient {
          background-size: 200% 200%;
          animation: gradient 3s ease infinite;
        }
      `}</style>
    </div>
  )
}
