import { Link } from 'react-router'
import { ArrowLeft } from 'lucide-react'
import A13ELogo from '../components/A13ELogo'

export default function Privacy() {
  const effectiveDate = '1 January 2026'

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

      {/* Content */}
      <div className="pt-24 pb-16 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-4xl font-bold text-white mb-4">Privacy Policy</h1>
          <p className="text-gray-400 mb-8">Effective Date: {effectiveDate}</p>

          <div className="prose prose-invert prose-lg max-w-none space-y-8">

            {/* Introduction */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">1. Introduction</h2>
              <p className="text-gray-300">
                A13E Limited ("A13E", "we", "us", or "our") is committed to protecting and respecting your privacy. This Privacy Policy explains how we collect, use, disclose, and safeguard personal data when you use the A13E Detection Coverage Validator platform and related services (the "Service").
              </p>
              <p className="text-gray-300">
                A13E Limited is registered in England and Wales and operates as a data controller for the personal data we collect directly from you. When processing data on behalf of our customers, we act as a data processor.
              </p>
              <p className="text-gray-300">
                This policy is designed to comply with the UK General Data Protection Regulation (UK GDPR) and the Data Protection Act 2018.
              </p>
            </section>

            {/* Data Controller */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">2. Data Controller</h2>
              <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
                <p className="text-gray-300 mb-2"><strong className="text-white">Data Controller:</strong> A13E Limited</p>
                <p className="text-gray-300 mb-2"><strong className="text-white">Contact Email:</strong> <a href="mailto:privacy@a13e.com" className="text-cyan-400 hover:text-cyan-300">privacy@a13e.com</a></p>
                <p className="text-gray-300"><strong className="text-white">Registered in:</strong> England and Wales</p>
              </div>
            </section>

            {/* Data We Collect */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">3. Personal Data We Collect</h2>

              <h3 className="text-xl font-medium text-white mt-4">3.1 Information You Provide</h3>
              <ul className="text-gray-300 space-y-2">
                <li><strong className="text-white">Account Information:</strong> Name, email address, organisation name, job title, and password when you create an account.</li>
                <li><strong className="text-white">Payment Information:</strong> Billing address and payment card details (processed securely by our payment processor, Stripe).</li>
                <li><strong className="text-white">Communications:</strong> Information you provide when contacting support or providing feedback.</li>
                <li><strong className="text-white">Team Information:</strong> Names and email addresses of team members you invite to your organisation.</li>
              </ul>

              <h3 className="text-xl font-medium text-white mt-4">3.2 Information Collected Automatically</h3>
              <ul className="text-gray-300 space-y-2">
                <li><strong className="text-white">Usage Data:</strong> Pages visited, features used, actions taken, and time spent in the Service.</li>
                <li><strong className="text-white">Device Information:</strong> Browser type, operating system, device identifiers, and IP address.</li>
                <li><strong className="text-white">Log Data:</strong> Access times, error logs, and referring URLs.</li>
                <li><strong className="text-white">Authentication Data:</strong> Login timestamps, multi-factor authentication events, and session information.</li>
              </ul>

              <h3 className="text-xl font-medium text-white mt-4">3.3 Cloud Configuration Data</h3>
              <p className="text-gray-300">
                To provide the Service, we access and process metadata from your connected cloud accounts (AWS, GCP), including:
              </p>
              <ul className="text-gray-300 space-y-1">
                <li>Security detection configurations (GuardDuty, Security Hub, CloudWatch, etc.)</li>
                <li>Resource identifiers and ARNs</li>
                <li>Detection rules and alert configurations</li>
                <li>Compliance posture data</li>
              </ul>
              <p className="text-gray-300 mt-2">
                <strong className="text-white">Important:</strong> We request and use only read-only access permissions. We do not access, store, or process the contents of your cloud resources, customer data within those resources, or production workloads.
              </p>
            </section>

            {/* Lawful Basis */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">4. Lawful Basis for Processing</h2>
              <p className="text-gray-300">We process your personal data on the following legal bases under UK GDPR:</p>

              <div className="overflow-x-auto mt-4">
                <table className="w-full text-gray-300 border border-slate-700">
                  <thead className="bg-slate-800">
                    <tr>
                      <th className="text-left p-3 border-b border-slate-700 text-white">Purpose</th>
                      <th className="text-left p-3 border-b border-slate-700 text-white">Lawful Basis</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-slate-700">
                      <td className="p-3">Providing the Service</td>
                      <td className="p-3">Contract performance</td>
                    </tr>
                    <tr className="border-b border-slate-700">
                      <td className="p-3">Processing payments</td>
                      <td className="p-3">Contract performance</td>
                    </tr>
                    <tr className="border-b border-slate-700">
                      <td className="p-3">Customer support</td>
                      <td className="p-3">Contract performance / Legitimate interests</td>
                    </tr>
                    <tr className="border-b border-slate-700">
                      <td className="p-3">Service improvements</td>
                      <td className="p-3">Legitimate interests</td>
                    </tr>
                    <tr className="border-b border-slate-700">
                      <td className="p-3">Security monitoring</td>
                      <td className="p-3">Legitimate interests</td>
                    </tr>
                    <tr className="border-b border-slate-700">
                      <td className="p-3">Marketing communications</td>
                      <td className="p-3">Consent (opt-in)</td>
                    </tr>
                    <tr>
                      <td className="p-3">Legal compliance</td>
                      <td className="p-3">Legal obligation</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>

            {/* How We Use Data */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">5. How We Use Your Data</h2>
              <p className="text-gray-300">We use your personal data to:</p>
              <ul className="text-gray-300 space-y-2">
                <li><strong className="text-white">Provide the Service:</strong> Authenticate your access, analyse your cloud security posture, generate reports, and deliver detection coverage insights.</li>
                <li><strong className="text-white">Process Transactions:</strong> Bill your subscription, process payments, and send invoices.</li>
                <li><strong className="text-white">Communicate:</strong> Send service notifications, security alerts, product updates, and respond to support requests.</li>
                <li><strong className="text-white">Improve the Service:</strong> Analyse usage patterns to enhance features, fix issues, and develop new functionality.</li>
                <li><strong className="text-white">Ensure Security:</strong> Detect and prevent fraud, abuse, and security threats to protect you and other users.</li>
                <li><strong className="text-white">Comply with Law:</strong> Meet legal obligations, respond to lawful requests, and protect our rights.</li>
              </ul>
            </section>

            {/* Data Sharing */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">6. Data Sharing and Disclosure</h2>
              <p className="text-gray-300">We do not sell your personal data. We share data only in the following circumstances:</p>

              <h3 className="text-xl font-medium text-white mt-4">6.1 Service Providers (Sub-processors)</h3>
              <p className="text-gray-300">We engage trusted third parties to help operate the Service:</p>
              <ul className="text-gray-300 space-y-1">
                <li><strong className="text-white">Cloud Infrastructure:</strong> Amazon Web Services (AWS) - EU/UK regions</li>
                <li><strong className="text-white">Payment Processing:</strong> Stripe</li>
                <li><strong className="text-white">Email Services:</strong> For transactional and service communications</li>
                <li><strong className="text-white">Authentication:</strong> Auth0/Cognito for secure identity management</li>
              </ul>
              <p className="text-gray-300 mt-2">
                All sub-processors are bound by data processing agreements ensuring UK GDPR compliance.
              </p>

              <h3 className="text-xl font-medium text-white mt-4">6.2 Legal Requirements</h3>
              <p className="text-gray-300">
                We may disclose data when required by law, court order, or government request, or to protect the rights, property, or safety of A13E, our users, or others.
              </p>

              <h3 className="text-xl font-medium text-white mt-4">6.3 Business Transfers</h3>
              <p className="text-gray-300">
                In the event of a merger, acquisition, or sale of assets, personal data may be transferred to the acquiring entity, subject to this Privacy Policy.
              </p>
            </section>

            {/* International Transfers */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">7. International Data Transfers</h2>
              <p className="text-gray-300">
                Our primary data processing occurs within the United Kingdom and European Economic Area. Where data is transferred outside the UK/EEA (for example, to service providers in the United States), we ensure appropriate safeguards are in place:
              </p>
              <ul className="text-gray-300 space-y-1">
                <li>Standard Contractual Clauses (SCCs) approved by the UK Information Commissioner's Office</li>
                <li>Adequacy decisions where applicable</li>
                <li>Additional technical and organisational measures</li>
              </ul>
            </section>

            {/* Data Retention */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">8. Data Retention</h2>
              <p className="text-gray-300">We retain personal data only as long as necessary for the purposes outlined in this policy:</p>

              <div className="overflow-x-auto mt-4">
                <table className="w-full text-gray-300 border border-slate-700">
                  <thead className="bg-slate-800">
                    <tr>
                      <th className="text-left p-3 border-b border-slate-700 text-white">Data Type</th>
                      <th className="text-left p-3 border-b border-slate-700 text-white">Retention Period</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-slate-700">
                      <td className="p-3">Account information</td>
                      <td className="p-3">Duration of account + 30 days after deletion</td>
                    </tr>
                    <tr className="border-b border-slate-700">
                      <td className="p-3">Cloud configuration data</td>
                      <td className="p-3">Duration of account + 30 days after deletion</td>
                    </tr>
                    <tr className="border-b border-slate-700">
                      <td className="p-3">Payment records</td>
                      <td className="p-3">7 years (legal requirement)</td>
                    </tr>
                    <tr className="border-b border-slate-700">
                      <td className="p-3">Security logs</td>
                      <td className="p-3">12 months</td>
                    </tr>
                    <tr>
                      <td className="p-3">Support communications</td>
                      <td className="p-3">3 years</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>

            {/* Your Rights */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">9. Your Rights</h2>
              <p className="text-gray-300">Under UK GDPR, you have the following rights regarding your personal data:</p>
              <ul className="text-gray-300 space-y-2">
                <li><strong className="text-white">Right of Access:</strong> Request a copy of the personal data we hold about you.</li>
                <li><strong className="text-white">Right to Rectification:</strong> Request correction of inaccurate or incomplete data.</li>
                <li><strong className="text-white">Right to Erasure:</strong> Request deletion of your data in certain circumstances ("right to be forgotten").</li>
                <li><strong className="text-white">Right to Restriction:</strong> Request we limit processing of your data in certain circumstances.</li>
                <li><strong className="text-white">Right to Data Portability:</strong> Receive your data in a structured, machine-readable format.</li>
                <li><strong className="text-white">Right to Object:</strong> Object to processing based on legitimate interests or for direct marketing.</li>
                <li><strong className="text-white">Rights Related to Automated Decisions:</strong> Not be subject to decisions based solely on automated processing that significantly affect you.</li>
                <li><strong className="text-white">Right to Withdraw Consent:</strong> Where processing is based on consent, withdraw consent at any time.</li>
              </ul>
              <p className="text-gray-300 mt-4">
                To exercise any of these rights, contact us at <a href="mailto:privacy@a13e.com" className="text-cyan-400 hover:text-cyan-300">privacy@a13e.com</a>. We will respond within one month as required by law.
              </p>
            </section>

            {/* Security */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">10. Data Security</h2>
              <p className="text-gray-300">
                We implement robust technical and organisational measures to protect your personal data:
              </p>
              <ul className="text-gray-300 space-y-2">
                <li><strong className="text-white">Encryption:</strong> Data encrypted in transit (TLS 1.3) and at rest (AES-256).</li>
                <li><strong className="text-white">Access Controls:</strong> Role-based access, multi-factor authentication, and principle of least privilege.</li>
                <li><strong className="text-white">Infrastructure Security:</strong> Hosted in AWS with WAF, VPC isolation, and regular security assessments.</li>
                <li><strong className="text-white">Monitoring:</strong> Continuous security monitoring, logging, and incident detection.</li>
                <li><strong className="text-white">Secure Development:</strong> Security-focused development practices, code reviews, and vulnerability scanning.</li>
                <li><strong className="text-white">Employee Training:</strong> Regular security awareness training for all staff.</li>
              </ul>
              <p className="text-gray-300 mt-2">
                While we implement industry-standard security measures, no system is completely secure. We encourage you to use strong passwords and enable multi-factor authentication.
              </p>
            </section>

            {/* Cookies */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">11. Cookies and Tracking</h2>
              <p className="text-gray-300">We use cookies and similar technologies for:</p>
              <ul className="text-gray-300 space-y-2">
                <li><strong className="text-white">Essential Cookies:</strong> Required for authentication, security, and basic functionality.</li>
                <li><strong className="text-white">Functional Cookies:</strong> Remember your preferences and settings.</li>
                <li><strong className="text-white">Analytics Cookies:</strong> Understand how you use the Service to improve it.</li>
              </ul>
              <p className="text-gray-300 mt-2">
                You can control cookies through your browser settings. Disabling essential cookies may affect Service functionality.
              </p>
            </section>

            {/* Children */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">12. Children's Privacy</h2>
              <p className="text-gray-300">
                The Service is not intended for individuals under 18 years of age. We do not knowingly collect personal data from children. If you believe we have collected data from a child, please contact us immediately.
              </p>
            </section>

            {/* Changes */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">13. Changes to This Policy</h2>
              <p className="text-gray-300">
                We may update this Privacy Policy periodically. Material changes will be communicated via email or prominent notice in the Service at least 30 days before taking effect. The "Effective Date" at the top indicates when this policy was last revised.
              </p>
            </section>

            {/* Complaints */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">14. Complaints</h2>
              <p className="text-gray-300">
                If you have concerns about how we handle your personal data, please contact us first at <a href="mailto:privacy@a13e.com" className="text-cyan-400 hover:text-cyan-300">privacy@a13e.com</a>. We will work to resolve your concerns.
              </p>
              <p className="text-gray-300 mt-2">
                You also have the right to lodge a complaint with the UK Information Commissioner's Office (ICO):
              </p>
              <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6 mt-4">
                <p className="text-gray-300 mb-2"><strong className="text-white">Information Commissioner's Office</strong></p>
                <p className="text-gray-300 mb-2">Wycliffe House, Water Lane, Wilmslow, Cheshire SK9 5AF</p>
                <p className="text-gray-300 mb-2">Telephone: 0303 123 1113</p>
                <p className="text-gray-300">Website: <a href="https://ico.org.uk" target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:text-cyan-300">ico.org.uk</a></p>
              </div>
            </section>

            {/* Contact */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">15. Contact Us</h2>
              <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
                <p className="text-gray-300 mb-4">
                  For questions about this Privacy Policy or our data practices:
                </p>
                <ul className="text-gray-300 space-y-2">
                  <li><strong className="text-white">Email:</strong> <a href="mailto:privacy@a13e.com" className="text-cyan-400 hover:text-cyan-300">privacy@a13e.com</a></li>
                  <li><strong className="text-white">General Support:</strong> <Link to="/support" className="text-cyan-400 hover:text-cyan-300">app.a13e.com/support</Link></li>
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
