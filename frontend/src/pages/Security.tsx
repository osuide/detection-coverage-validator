import { Link } from 'react-router'
import { ArrowLeft, Shield, Lock, Server, Eye, Users, AlertTriangle, RefreshCw, FileCheck, Globe } from 'lucide-react'
import A13ELogo from '../components/A13ELogo'

export default function Security() {
  const lastUpdated = '1 January 2026'

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Navigation */}
      <nav className="fixed top-0 w-full z-50 bg-slate-950/95 backdrop-blur-lg border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <Link to="/">
              <A13ELogo size="sm" showTagline={false} />
            </Link>
            <Link
              to="/"
              className="flex items-center gap-2 text-gray-300 hover:text-white transition-colors"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to Home
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <div className="pt-24 pb-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-full mb-6">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-4xl font-bold text-white mb-4">Security at A13E</h1>
          <p className="text-xl text-gray-400 mb-4">
            Built by security professionals, for security professionals. Security is not just a feature—it is foundational to everything we build.
          </p>
          <p className="text-gray-500 text-sm">Last updated: {lastUpdated}</p>
        </div>
      </div>

      {/* Content */}
      <div className="pb-16 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <div className="prose prose-invert prose-lg max-w-none space-y-12">

            {/* Security Commitment */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <Shield className="w-6 h-6 text-cyan-400" />
                Our Security Commitment
              </h2>
              <p className="text-gray-300">
                A13E was founded by security practitioners who have spent their careers protecting organisations from cyber threats. We understand that entrusting your cloud security data to a third party requires the highest levels of assurance.
              </p>
              <p className="text-gray-300">
                We apply the same rigorous security standards to our own infrastructure that we help our customers achieve. Security is embedded in our culture, our development practices, and our operations—not bolted on as an afterthought.
              </p>
              <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6 mt-4">
                <p className="text-gray-300 font-medium mb-2">Our Security Principles:</p>
                <ul className="text-gray-300 space-y-1">
                  <li>Defence in depth with multiple layers of protection</li>
                  <li>Zero trust architecture—verify explicitly, use least privilege access</li>
                  <li>Security by design in all development processes</li>
                  <li>Continuous monitoring and rapid incident response</li>
                  <li>Transparency about our security posture and practices</li>
                </ul>
              </div>
            </section>

            {/* Infrastructure Security */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <Server className="w-6 h-6 text-cyan-400" />
                Infrastructure Security
              </h2>

              <h3 className="text-xl font-medium text-white mt-6">Cloud Infrastructure</h3>
              <p className="text-gray-300">
                A13E is hosted on Amazon Web Services (AWS) in the EU (London) region, leveraging AWS's world-class physical and infrastructure security controls:
              </p>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">Data Centre Security:</strong> AWS data centres feature 24/7 security, biometric access controls, CCTV monitoring, and environmental controls</li>
                <li><strong className="text-white">UK Data Residency:</strong> All customer data is processed and stored within the UK (eu-west-2 region)</li>
                <li><strong className="text-white">AWS Compliance:</strong> AWS maintains ISO 27001, SOC 2, and numerous other certifications</li>
              </ul>

              <h3 className="text-xl font-medium text-white mt-6">Network Security</h3>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">Web Application Firewall (WAF):</strong> AWS WAF with OWASP Core Rule Set protects against common web exploits</li>
                <li><strong className="text-white">DDoS Protection:</strong> AWS Shield provides automatic DDoS mitigation</li>
                <li><strong className="text-white">Network Isolation:</strong> VPC with private subnets for databases and caching; no direct internet access to backend services</li>
                <li><strong className="text-white">TLS Encryption:</strong> All traffic encrypted with TLS 1.3; HSTS enforced with minimum 1-year policy</li>
                <li><strong className="text-white">Security Headers:</strong> Comprehensive security headers including CSP, X-Frame-Options, and X-Content-Type-Options</li>
              </ul>

              <h3 className="text-xl font-medium text-white mt-6">Database Security</h3>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">Encryption at Rest:</strong> All databases encrypted using AES-256</li>
                <li><strong className="text-white">Private Networking:</strong> Databases accessible only from within the VPC; no public endpoints</li>
                <li><strong className="text-white">Automated Backups:</strong> Daily automated backups with point-in-time recovery</li>
                <li><strong className="text-white">Connection Security:</strong> SSL/TLS required for all database connections</li>
              </ul>
            </section>

            {/* Application Security */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <Lock className="w-6 h-6 text-cyan-400" />
                Application Security
              </h2>

              <h3 className="text-xl font-medium text-white mt-6">Secure Development Lifecycle</h3>
              <p className="text-gray-300">
                Security is integrated throughout our software development lifecycle:
              </p>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">Security-Focused Code Reviews:</strong> All code changes require peer review with security considerations</li>
                <li><strong className="text-white">Static Application Security Testing (SAST):</strong> Automated security scanning on every commit</li>
                <li><strong className="text-white">Dependency Scanning:</strong> Continuous monitoring for vulnerabilities in third-party dependencies</li>
                <li><strong className="text-white">Container Security:</strong> Container images scanned for vulnerabilities before deployment</li>
                <li><strong className="text-white">Infrastructure as Code:</strong> Terraform security scanning with Trivy for misconfigurations</li>
              </ul>

              <h3 className="text-xl font-medium text-white mt-6">Authentication &amp; Authorisation</h3>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">Multi-Factor Authentication:</strong> TOTP-based MFA available for all accounts; enforced for administrators</li>
                <li><strong className="text-white">Single Sign-On:</strong> Support for Google and GitHub SSO via industry-standard OAuth 2.0</li>
                <li><strong className="text-white">Password Security:</strong> Strong password requirements; passwords hashed using bcrypt with appropriate cost factor</li>
                <li><strong className="text-white">Session Management:</strong> Secure, HttpOnly, SameSite cookies; configurable session timeouts</li>
                <li><strong className="text-white">Role-Based Access Control:</strong> Granular permissions with Owner, Admin, and Member roles</li>
              </ul>

              <h3 className="text-xl font-medium text-white mt-6">API Security</h3>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">API Key Authentication:</strong> Cryptographically secure API keys with configurable expiration</li>
                <li><strong className="text-white">Rate Limiting:</strong> Tiered rate limits to prevent abuse (varies by subscription tier)</li>
                <li><strong className="text-white">Input Validation:</strong> Strict input validation and sanitisation on all endpoints</li>
                <li><strong className="text-white">CORS Policy:</strong> Restrictive cross-origin resource sharing configuration</li>
              </ul>
            </section>

            {/* Data Protection */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <Eye className="w-6 h-6 text-cyan-400" />
                Data Protection
              </h2>

              <h3 className="text-xl font-medium text-white mt-6">Encryption</h3>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">In Transit:</strong> All data encrypted using TLS 1.3</li>
                <li><strong className="text-white">At Rest:</strong> AES-256 encryption for all stored data</li>
                <li><strong className="text-white">Key Management:</strong> AWS Key Management Service (KMS) for encryption key management</li>
                <li><strong className="text-white">Secrets Management:</strong> AWS Secrets Manager for secure credential storage</li>
              </ul>

              <h3 className="text-xl font-medium text-white mt-6">Cloud Credential Handling</h3>
              <p className="text-gray-300">
                When you connect your AWS or GCP accounts, we follow security best practices:
              </p>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">Read-Only Access:</strong> We request only the minimum permissions required for security analysis</li>
                <li><strong className="text-white">Cross-Account Roles (AWS):</strong> We recommend using IAM roles with external ID for secure cross-account access</li>
                <li><strong className="text-white">Workload Identity Federation (GCP):</strong> Support for keyless authentication where possible</li>
                <li><strong className="text-white">Credential Encryption:</strong> All stored credentials encrypted with customer-specific keys</li>
                <li><strong className="text-white">No Data Access:</strong> We access only cloud configuration metadata—never your workloads, data, or secrets</li>
              </ul>

              <h3 className="text-xl font-medium text-white mt-6">Data Retention &amp; Deletion</h3>
              <ul className="text-gray-300 space-y-1">
                <li>Customer data retained only for the duration of the subscription</li>
                <li>Data deleted within 30 days of account termination</li>
                <li>Customers can request immediate data deletion</li>
                <li>Audit logs retained for 12 months for security purposes</li>
              </ul>
            </section>

            {/* Access Controls */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <Users className="w-6 h-6 text-cyan-400" />
                Access Controls
              </h2>

              <h3 className="text-xl font-medium text-white mt-6">Employee Access</h3>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">Least Privilege:</strong> Employees granted minimum access required for their role</li>
                <li><strong className="text-white">MFA Required:</strong> All employee accounts require multi-factor authentication</li>
                <li><strong className="text-white">Access Reviews:</strong> Regular access reviews to ensure appropriate permissions</li>
                <li><strong className="text-white">Audit Logging:</strong> All administrative access logged and monitored</li>
                <li><strong className="text-white">Background Checks:</strong> Security background checks for all employees with data access</li>
              </ul>

              <h3 className="text-xl font-medium text-white mt-6">Production Access</h3>
              <ul className="text-gray-300 space-y-1">
                <li>Production environment access restricted to essential personnel only</li>
                <li>All production access requires additional authentication</li>
                <li>No direct database access; all queries through application layer</li>
                <li>Customer data accessed only when required for support (with consent)</li>
              </ul>
            </section>

            {/* Incident Response */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <AlertTriangle className="w-6 h-6 text-cyan-400" />
                Incident Response
              </h2>
              <p className="text-gray-300">
                We maintain a comprehensive incident response programme:
              </p>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">24/7 Monitoring:</strong> Continuous security monitoring and alerting</li>
                <li><strong className="text-white">Incident Response Plan:</strong> Documented procedures for security incident handling</li>
                <li><strong className="text-white">Notification:</strong> Customers notified of security incidents affecting their data within 72 hours as required by UK GDPR</li>
                <li><strong className="text-white">Post-Incident Review:</strong> Root cause analysis and remediation for all incidents</li>
                <li><strong className="text-white">Lessons Learned:</strong> Security improvements implemented based on incident learnings</li>
              </ul>

              <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6 mt-4">
                <p className="text-gray-300 mb-2"><strong className="text-white">Report a Security Vulnerability:</strong></p>
                <p className="text-gray-300">
                  If you discover a security vulnerability, please report it responsibly to{' '}
                  <a href="mailto:security@a13e.com" className="text-cyan-400 hover:text-cyan-300">security@a13e.com</a>.
                  We appreciate security researchers who help us keep our platform safe.
                </p>
              </div>
            </section>

            {/* Business Continuity */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <RefreshCw className="w-6 h-6 text-cyan-400" />
                Business Continuity
              </h2>

              <h3 className="text-xl font-medium text-white mt-6">Availability</h3>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">High Availability:</strong> Multi-availability zone deployment for resilience</li>
                <li><strong className="text-white">Auto-Scaling:</strong> Automatic scaling to handle demand</li>
                <li><strong className="text-white">Health Monitoring:</strong> Continuous health checks with automatic failover</li>
                <li><strong className="text-white">Uptime Target:</strong> 99.9% availability SLA for paid tiers</li>
              </ul>

              <h3 className="text-xl font-medium text-white mt-6">Disaster Recovery</h3>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">Automated Backups:</strong> Daily backups with 30-day retention</li>
                <li><strong className="text-white">Point-in-Time Recovery:</strong> Database recovery to any point within backup window</li>
                <li><strong className="text-white">Disaster Recovery Plan:</strong> Documented procedures for service restoration</li>
                <li><strong className="text-white">Recovery Testing:</strong> Regular testing of backup and recovery procedures</li>
              </ul>
            </section>

            {/* Vendor Security */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <Globe className="w-6 h-6 text-cyan-400" />
                Third-Party Security
              </h2>
              <p className="text-gray-300">
                We carefully evaluate the security posture of all third-party services we use:
              </p>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">Vendor Assessment:</strong> Security review before engaging any vendor with data access</li>
                <li><strong className="text-white">Data Processing Agreements:</strong> DPAs in place with all sub-processors</li>
                <li><strong className="text-white">Minimal Data Sharing:</strong> Only essential data shared with third parties</li>
                <li><strong className="text-white">Ongoing Monitoring:</strong> Regular review of vendor security posture</li>
              </ul>
              <p className="text-gray-300 mt-4">
                See our <Link to="/compliance-info" className="text-cyan-400 hover:text-cyan-300">Compliance page</Link> for a list of sub-processors.
              </p>
            </section>

            {/* Security Training */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <FileCheck className="w-6 h-6 text-cyan-400" />
                Security Training &amp; Awareness
              </h2>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">Security Onboarding:</strong> All employees complete security training upon joining</li>
                <li><strong className="text-white">Annual Training:</strong> Mandatory annual security awareness training</li>
                <li><strong className="text-white">Phishing Simulations:</strong> Regular phishing awareness exercises</li>
                <li><strong className="text-white">Secure Development Training:</strong> Specialised training for development team</li>
                <li><strong className="text-white">Security Culture:</strong> Security embedded as a core company value</li>
              </ul>
            </section>

            {/* Contact */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">Questions?</h2>
              <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
                <p className="text-gray-300 mb-4">
                  For security-related enquiries or to request additional security documentation:
                </p>
                <ul className="text-gray-300 space-y-2">
                  <li><strong className="text-white">Security Team:</strong> <a href="mailto:security@a13e.com" className="text-cyan-400 hover:text-cyan-300">security@a13e.com</a></li>
                  <li><strong className="text-white">Compliance:</strong> <Link to="/compliance-info" className="text-cyan-400 hover:text-cyan-300">View our compliance certifications</Link></li>
                  <li><strong className="text-white">Privacy:</strong> <Link to="/privacy" className="text-cyan-400 hover:text-cyan-300">Read our Privacy Policy</Link></li>
                </ul>
              </div>
            </section>

          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col sm:flex-row justify-between items-center gap-4">
            <p className="text-gray-500 text-sm">
              &copy; {new Date().getFullYear()} A13E Limited. All rights reserved. An OSUIDE INC Company.
            </p>
            <div className="flex gap-6">
              <Link to="/terms" className="text-gray-400 hover:text-white text-sm transition-colors">
                Terms
              </Link>
              <Link to="/privacy" className="text-gray-400 hover:text-white text-sm transition-colors">
                Privacy
              </Link>
              <Link to="/security" className="text-gray-400 hover:text-white text-sm transition-colors">
                Security
              </Link>
              <Link to="/compliance-info" className="text-gray-400 hover:text-white text-sm transition-colors">
                Compliance
              </Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
