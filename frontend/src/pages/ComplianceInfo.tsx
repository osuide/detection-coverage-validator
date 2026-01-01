import { Link } from 'react-router'
import { ArrowLeft, FileCheck, Shield, Globe, Database, Users, CheckCircle, Clock, MapPin } from 'lucide-react'
import A13ELogo from '../components/A13ELogo'

export default function ComplianceInfo() {
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
            <FileCheck className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-4xl font-bold text-white mb-4">Compliance</h1>
          <p className="text-xl text-gray-400 mb-4">
            A13E is committed to meeting the highest standards of security, privacy, and regulatory compliance.
          </p>
          <p className="text-gray-500 text-sm">Last updated: {lastUpdated}</p>
        </div>
      </div>

      {/* Content */}
      <div className="pb-16 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <div className="prose prose-invert prose-lg max-w-none space-y-12">

            {/* Compliance Overview */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <Shield className="w-6 h-6 text-cyan-400" />
                Compliance Overview
              </h2>
              <p className="text-gray-300">
                As a security-focused SaaS provider, we understand that our customers need confidence in our compliance posture. We maintain rigorous internal controls and are pursuing industry-recognised certifications to demonstrate our commitment to security and privacy.
              </p>
            </section>

            {/* Certifications Grid */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">Certifications &amp; Frameworks</h2>

              <div className="grid md:grid-cols-2 gap-6 mt-6">

                {/* UK GDPR */}
                <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center">
                      <CheckCircle className="w-5 h-5 text-green-400" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">UK GDPR</h3>
                      <span className="text-xs text-green-400 font-medium">COMPLIANT</span>
                    </div>
                  </div>
                  <p className="text-gray-400 text-sm">
                    Fully compliant with the UK General Data Protection Regulation and Data Protection Act 2018. Our data processing activities adhere to all seven GDPR principles.
                  </p>
                </div>

                {/* Data Protection Act 2018 */}
                <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center">
                      <CheckCircle className="w-5 h-5 text-green-400" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">Data Protection Act 2018</h3>
                      <span className="text-xs text-green-400 font-medium">COMPLIANT</span>
                    </div>
                  </div>
                  <p className="text-gray-400 text-sm">
                    Compliant with the UK's implementation of data protection legislation, including requirements for lawful processing, data subject rights, and accountability measures.
                  </p>
                </div>

                {/* Cyber Essentials */}
                <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                      <Clock className="w-5 h-5 text-yellow-400" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">Cyber Essentials</h3>
                      <span className="text-xs text-yellow-400 font-medium">IN PROGRESS</span>
                    </div>
                  </div>
                  <p className="text-gray-400 text-sm">
                    Working towards Cyber Essentials certification, the UK government-backed scheme that guards against the most common cyber attacks. Expected Q2 2026.
                  </p>
                </div>

                {/* ISO 27001 */}
                <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                      <Clock className="w-5 h-5 text-yellow-400" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">ISO 27001</h3>
                      <span className="text-xs text-yellow-400 font-medium">ROADMAP</span>
                    </div>
                  </div>
                  <p className="text-gray-400 text-sm">
                    Our information security management system (ISMS) is designed with ISO 27001 principles. Formal certification planned for 2026.
                  </p>
                </div>

                {/* SOC 2 Type II */}
                <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                      <Clock className="w-5 h-5 text-yellow-400" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">SOC 2 Type II</h3>
                      <span className="text-xs text-yellow-400 font-medium">ROADMAP</span>
                    </div>
                  </div>
                  <p className="text-gray-400 text-sm">
                    SOC 2 Type II audit planned for 2026, covering Security, Availability, and Confidentiality trust service criteria.
                  </p>
                </div>

                {/* MITRE ATT&CK */}
                <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center">
                      <CheckCircle className="w-5 h-5 text-green-400" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">MITRE ATT&amp;CK</h3>
                      <span className="text-xs text-green-400 font-medium">ALIGNED</span>
                    </div>
                  </div>
                  <p className="text-gray-400 text-sm">
                    Our detection coverage analysis is built on the MITRE ATT&amp;CK framework, the globally recognised knowledge base of adversary tactics and techniques.
                  </p>
                </div>

              </div>
            </section>

            {/* Data Residency */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <MapPin className="w-6 h-6 text-cyan-400" />
                Data Residency
              </h2>
              <p className="text-gray-300">
                We understand that data sovereignty is critical for many organisations. A13E is designed with UK data residency as a core principle:
              </p>
              <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6 mt-4">
                <ul className="text-gray-300 space-y-2">
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" />
                    <span><strong className="text-white">Primary Region:</strong> All customer data processed and stored in AWS EU (London) - eu-west-2</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" />
                    <span><strong className="text-white">Database:</strong> Amazon RDS PostgreSQL in eu-west-2 with encryption at rest</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" />
                    <span><strong className="text-white">Caching:</strong> Amazon ElastiCache Redis in eu-west-2</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" />
                    <span><strong className="text-white">Backups:</strong> Stored within the same AWS region</span>
                  </li>
                </ul>
              </div>
              <p className="text-gray-300 mt-4">
                Where data must be transferred outside the UK (e.g., for specific third-party services), appropriate safeguards are in place including Standard Contractual Clauses (SCCs).
              </p>
            </section>

            {/* Sub-processors */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <Globe className="w-6 h-6 text-cyan-400" />
                Sub-processors
              </h2>
              <p className="text-gray-300">
                We engage the following sub-processors to help deliver the Service. All sub-processors are bound by data processing agreements:
              </p>

              <div className="overflow-x-auto mt-6">
                <table className="w-full text-gray-300 border border-slate-700">
                  <thead className="bg-slate-800">
                    <tr>
                      <th className="text-left p-3 border-b border-slate-700 text-white">Sub-processor</th>
                      <th className="text-left p-3 border-b border-slate-700 text-white">Purpose</th>
                      <th className="text-left p-3 border-b border-slate-700 text-white">Location</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-slate-700">
                      <td className="p-3 font-medium">Amazon Web Services (AWS)</td>
                      <td className="p-3">Cloud infrastructure hosting</td>
                      <td className="p-3">UK (London)</td>
                    </tr>
                    <tr className="border-b border-slate-700">
                      <td className="p-3 font-medium">Stripe</td>
                      <td className="p-3">Payment processing</td>
                      <td className="p-3">EU/US (with SCCs)</td>
                    </tr>
                    <tr className="border-b border-slate-700">
                      <td className="p-3 font-medium">Amazon Cognito</td>
                      <td className="p-3">Identity and authentication</td>
                      <td className="p-3">UK (London)</td>
                    </tr>
                    <tr className="border-b border-slate-700">
                      <td className="p-3 font-medium">Amazon SES</td>
                      <td className="p-3">Transactional email</td>
                      <td className="p-3">EU (Ireland)</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-medium">GitHub</td>
                      <td className="p-3">OAuth authentication (optional)</td>
                      <td className="p-3">US (with SCCs)</td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <p className="text-gray-400 text-sm mt-4">
                We will notify customers of any new sub-processors at least 30 days before they begin processing data.
              </p>
            </section>

            {/* Data Processing Agreement */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <Database className="w-6 h-6 text-cyan-400" />
                Data Processing Agreement
              </h2>
              <p className="text-gray-300">
                A13E acts as a data processor when processing personal data on behalf of customers. Our Data Processing Agreement (DPA) is available for customers who require one:
              </p>
              <ul className="text-gray-300 space-y-1 mt-4">
                <li><strong className="text-white">Scope:</strong> Covers all personal data processed as part of the Service</li>
                <li><strong className="text-white">UK GDPR Compliant:</strong> Includes all Article 28 requirements</li>
                <li><strong className="text-white">SCCs Included:</strong> Standard Contractual Clauses for international transfers</li>
                <li><strong className="text-white">Security Measures:</strong> Technical and organisational measures documented</li>
              </ul>
              <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6 mt-4">
                <p className="text-gray-300">
                  To request a Data Processing Agreement, contact us at{' '}
                  <a href="mailto:legal@a13e.com" className="text-cyan-400 hover:text-cyan-300">legal@a13e.com</a>.
                </p>
              </div>
            </section>

            {/* Security Questionnaires */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2 flex items-center gap-3">
                <Users className="w-6 h-6 text-cyan-400" />
                Security Questionnaires &amp; Due Diligence
              </h2>
              <p className="text-gray-300">
                We understand that our customers need to conduct security due diligence. We are happy to support your vendor assessment process:
              </p>
              <ul className="text-gray-300 space-y-2 mt-4">
                <li className="flex items-start gap-3">
                  <CheckCircle className="w-5 h-5 text-cyan-400 mt-0.5 flex-shrink-0" />
                  <span><strong className="text-white">Standard Questionnaires:</strong> We can complete CAIQ, SIG Lite, and similar industry-standard questionnaires</span>
                </li>
                <li className="flex items-start gap-3">
                  <CheckCircle className="w-5 h-5 text-cyan-400 mt-0.5 flex-shrink-0" />
                  <span><strong className="text-white">Custom Questionnaires:</strong> We respond to customer-specific security questionnaires</span>
                </li>
                <li className="flex items-start gap-3">
                  <CheckCircle className="w-5 h-5 text-cyan-400 mt-0.5 flex-shrink-0" />
                  <span><strong className="text-white">Security Documentation:</strong> Architecture diagrams, security policies, and controls documentation available on request</span>
                </li>
                <li className="flex items-start gap-3">
                  <CheckCircle className="w-5 h-5 text-cyan-400 mt-0.5 flex-shrink-0" />
                  <span><strong className="text-white">Security Calls:</strong> Available for Enterprise customers to discuss security requirements</span>
                </li>
              </ul>
              <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6 mt-4">
                <p className="text-gray-300">
                  For security questionnaires and due diligence requests, contact{' '}
                  <a href="mailto:security@a13e.com" className="text-cyan-400 hover:text-cyan-300">security@a13e.com</a>.
                </p>
              </div>
            </section>

            {/* Penetration Testing */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">Vulnerability Management</h2>
              <ul className="text-gray-300 space-y-2">
                <li><strong className="text-white">Continuous Scanning:</strong> Automated vulnerability scanning of infrastructure and dependencies</li>
                <li><strong className="text-white">Dependency Monitoring:</strong> Real-time alerts for vulnerabilities in third-party packages</li>
                <li><strong className="text-white">Penetration Testing:</strong> Annual third-party penetration tests (reports available to Enterprise customers under NDA)</li>
                <li><strong className="text-white">Responsible Disclosure:</strong> We welcome security researchers to report vulnerabilities to <a href="mailto:security@a13e.com" className="text-cyan-400 hover:text-cyan-300">security@a13e.com</a></li>
              </ul>
            </section>

            {/* Audit Rights */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">Audit Rights</h2>
              <p className="text-gray-300">
                For Enterprise customers, we support reasonable audit rights as follows:
              </p>
              <ul className="text-gray-300 space-y-1 mt-4">
                <li>Annual audit right with 30 days' written notice</li>
                <li>Scope limited to data processing activities covered by the DPA</li>
                <li>Third-party audit reports (when available) provided in lieu of on-site audits</li>
                <li>Customer bears the cost of any requested audits</li>
              </ul>
            </section>

            {/* Contact */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">Contact</h2>
              <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
                <p className="text-gray-300 mb-4">
                  For compliance-related enquiries:
                </p>
                <ul className="text-gray-300 space-y-2">
                  <li><strong className="text-white">Security:</strong> <a href="mailto:security@a13e.com" className="text-cyan-400 hover:text-cyan-300">security@a13e.com</a></li>
                  <li><strong className="text-white">Privacy &amp; DPA:</strong> <a href="mailto:privacy@a13e.com" className="text-cyan-400 hover:text-cyan-300">privacy@a13e.com</a></li>
                  <li><strong className="text-white">Legal:</strong> <a href="mailto:legal@a13e.com" className="text-cyan-400 hover:text-cyan-300">legal@a13e.com</a></li>
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
              &copy; {new Date().getFullYear()} A13E. All rights reserved. An OSUIDE INC Company.
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
