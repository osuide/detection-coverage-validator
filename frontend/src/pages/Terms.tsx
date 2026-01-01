import { Link } from 'react-router'
import { ArrowLeft } from 'lucide-react'
import A13ELogo from '../components/A13ELogo'

export default function Terms() {
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
          <h1 className="text-4xl font-bold text-white mb-4">Terms of Service</h1>
          <p className="text-gray-400 mb-8">Effective Date: {effectiveDate}</p>

          <div className="prose prose-invert prose-lg max-w-none space-y-8">

            {/* Introduction */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">1. Introduction and Acceptance</h2>
              <p className="text-gray-300">
                These Terms of Service ("Terms") constitute a legally binding agreement between you ("Customer", "you", or "your") and A13E Limited, a company registered in England and Wales ("A13E", "we", "us", or "our"), governing your access to and use of the A13E Detection Coverage Validator platform and related services (collectively, the "Service").
              </p>
              <p className="text-gray-300">
                By creating an account, accessing, or using the Service, you acknowledge that you have read, understood, and agree to be bound by these Terms. If you are entering into these Terms on behalf of an organisation, you represent and warrant that you have the authority to bind that organisation to these Terms.
              </p>
              <p className="text-gray-300">
                If you do not agree to these Terms, you must not access or use the Service.
              </p>
            </section>

            {/* Definitions */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">2. Definitions</h2>
              <ul className="text-gray-300 space-y-2">
                <li><strong className="text-white">"Authorised Users"</strong> means individuals authorised by you to access and use the Service under your account.</li>
                <li><strong className="text-white">"Customer Data"</strong> means any data, information, or material you submit to the Service, including cloud configuration data, detection rules, and security findings.</li>
                <li><strong className="text-white">"Documentation"</strong> means the user guides, help files, and other technical documentation made available by A13E.</li>
                <li><strong className="text-white">"Service"</strong> means the A13E Detection Coverage Validator cloud-based software-as-a-service platform.</li>
                <li><strong className="text-white">"Subscription"</strong> means the specific tier, features, and usage limits applicable to your account.</li>
              </ul>
            </section>

            {/* Service Description */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">3. Service Description</h2>
              <p className="text-gray-300">
                The Service provides cloud security detection coverage analysis, including:
              </p>
              <ul className="text-gray-300 space-y-1">
                <li>Scanning and analysis of AWS and GCP security detection configurations</li>
                <li>Mapping of detections to the MITRE ATT&amp;CK framework</li>
                <li>Identification of coverage gaps and remediation guidance</li>
                <li>Infrastructure-as-Code templates for implementing security controls</li>
                <li>Compliance framework mapping and reporting</li>
              </ul>
              <p className="text-gray-300">
                The Service is provided on an "as-is" and "as-available" basis. We continuously improve the Service and may modify features, functionality, or interfaces at any time. Material changes will be communicated via email or in-app notification.
              </p>
            </section>

            {/* Account and Access */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">4. Account Registration and Security</h2>
              <h3 className="text-xl font-medium text-white mt-4">4.1 Account Creation</h3>
              <p className="text-gray-300">
                To use the Service, you must create an account providing accurate and complete information. You agree to keep your account information current and accurate.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">4.2 Account Security</h3>
              <p className="text-gray-300">
                You are responsible for maintaining the confidentiality of your account credentials and for all activities that occur under your account. You agree to:
              </p>
              <ul className="text-gray-300 space-y-1">
                <li>Use strong, unique passwords and enable multi-factor authentication where available</li>
                <li>Immediately notify us of any unauthorised access or security breach</li>
                <li>Ensure Authorised Users comply with these Terms</li>
                <li>Not share account credentials or allow multiple individuals to use a single account</li>
              </ul>
              <h3 className="text-xl font-medium text-white mt-4">4.3 Cloud Account Credentials</h3>
              <p className="text-gray-300">
                The Service requires read-only access to your cloud provider accounts (AWS, GCP) to perform security analysis. You are responsible for:
              </p>
              <ul className="text-gray-300 space-y-1">
                <li>Ensuring credentials provided follow the principle of least privilege</li>
                <li>Regularly rotating and reviewing access credentials</li>
                <li>Revoking access promptly when no longer required</li>
              </ul>
            </section>

            {/* Subscription and Fees */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">5. Subscription and Fees</h2>
              <h3 className="text-xl font-medium text-white mt-4">5.1 Subscription Tiers</h3>
              <p className="text-gray-300">
                The Service is offered under various subscription tiers (Free, Individual, Pro, Enterprise) with different features, usage limits, and pricing. Current pricing is available on our <Link to="/#pricing" className="text-cyan-400 hover:text-cyan-300">pricing page</Link>.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">5.2 Payment Terms</h3>
              <p className="text-gray-300">
                Paid subscriptions are billed in advance on a monthly basis. All fees are quoted and payable in British Pounds Sterling (GBP) unless otherwise specified. Fees are non-refundable except as expressly stated in these Terms or required by law.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">5.3 Price Changes</h3>
              <p className="text-gray-300">
                We may modify pricing with 30 days' written notice. Price changes will take effect at the start of your next billing cycle following the notice period.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">5.4 Taxes</h3>
              <p className="text-gray-300">
                All fees are exclusive of VAT and other applicable taxes, which will be added where required by law.
              </p>
            </section>

            {/* Acceptable Use */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">6. Acceptable Use</h2>
              <h3 className="text-xl font-medium text-white mt-4">6.1 Permitted Use</h3>
              <p className="text-gray-300">
                You may use the Service solely for your internal business purposes to analyse and improve your organisation's cloud security detection coverage.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">6.2 Prohibited Conduct</h3>
              <p className="text-gray-300">You agree not to:</p>
              <ul className="text-gray-300 space-y-1">
                <li>Use the Service to analyse cloud accounts you do not own or have explicit authorisation to assess</li>
                <li>Attempt to gain unauthorised access to the Service, other accounts, or related systems</li>
                <li>Reverse engineer, decompile, or disassemble any part of the Service</li>
                <li>Use the Service to develop a competing product or service</li>
                <li>Resell, sublicense, or provide access to the Service to third parties without authorisation</li>
                <li>Introduce malicious code, viruses, or harmful components</li>
                <li>Interfere with or disrupt the Service's infrastructure or other users' access</li>
                <li>Use the Service in violation of applicable laws, regulations, or third-party rights</li>
                <li>Circumvent usage limits, authentication mechanisms, or security controls</li>
                <li>Use automated means to access the Service except through our documented APIs</li>
              </ul>
            </section>

            {/* Customer Data */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">7. Customer Data</h2>
              <h3 className="text-xl font-medium text-white mt-4">7.1 Ownership</h3>
              <p className="text-gray-300">
                You retain all rights, title, and interest in your Customer Data. A13E claims no ownership over Customer Data.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">7.2 Licence Grant</h3>
              <p className="text-gray-300">
                You grant A13E a limited, non-exclusive licence to process Customer Data solely to provide and improve the Service. This licence terminates upon termination of your account.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">7.3 Data Processing</h3>
              <p className="text-gray-300">
                Our processing of personal data within Customer Data is governed by our <Link to="/privacy" className="text-cyan-400 hover:text-cyan-300">Privacy Policy</Link> and, where applicable, a Data Processing Agreement. We process data in accordance with the UK GDPR and Data Protection Act 2018.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">7.4 Data Retention and Deletion</h3>
              <p className="text-gray-300">
                Upon account termination, we will delete your Customer Data within 30 days, except where retention is required by law. You may request data export before termination.
              </p>
            </section>

            {/* Intellectual Property */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">8. Intellectual Property</h2>
              <h3 className="text-xl font-medium text-white mt-4">8.1 A13E Ownership</h3>
              <p className="text-gray-300">
                The Service, including all software, algorithms, interfaces, documentation, and MITRE ATT&amp;CK mappings created by A13E, are owned by A13E and protected by intellectual property laws. These Terms do not grant you any rights to A13E's intellectual property except the limited right to use the Service.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">8.2 Feedback</h3>
              <p className="text-gray-300">
                If you provide feedback, suggestions, or ideas regarding the Service, you grant A13E a perpetual, irrevocable, royalty-free licence to use, modify, and incorporate such feedback into the Service without obligation to you.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">8.3 Third-Party Materials</h3>
              <p className="text-gray-300">
                The Service incorporates the MITRE ATT&amp;CK framework, which is provided under MITRE's terms of use. Other third-party components are subject to their respective licences.
              </p>
            </section>

            {/* Confidentiality */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">9. Confidentiality</h2>
              <p className="text-gray-300">
                Each party agrees to protect the other party's confidential information with the same degree of care it uses to protect its own confidential information, but no less than reasonable care. Confidential information excludes information that: (a) is or becomes publicly available through no fault of the receiving party; (b) was rightfully known prior to disclosure; (c) is rightfully obtained from third parties; or (d) is independently developed without use of confidential information.
              </p>
            </section>

            {/* Warranties and Disclaimers */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">10. Warranties and Disclaimers</h2>
              <h3 className="text-xl font-medium text-white mt-4">10.1 Service Warranty</h3>
              <p className="text-gray-300">
                A13E warrants that the Service will perform substantially in accordance with the Documentation. Your sole remedy for breach of this warranty is for A13E to correct the non-conforming Service or, if correction is not commercially reasonable, terminate your subscription and refund prepaid fees for the affected period.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">10.2 Disclaimer</h3>
              <p className="text-gray-300">
                EXCEPT AS EXPRESSLY PROVIDED HEREIN, THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTY OF ANY KIND. A13E DISCLAIMS ALL IMPLIED WARRANTIES, INCLUDING WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. A13E DOES NOT WARRANT THAT THE SERVICE WILL BE UNINTERRUPTED, ERROR-FREE, OR COMPLETELY SECURE.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">10.3 Security Limitations</h3>
              <p className="text-gray-300">
                The Service provides security analysis and recommendations but does not guarantee prevention of all security incidents. You remain solely responsible for your overall security posture, incident response, and compliance obligations.
              </p>
            </section>

            {/* Limitation of Liability */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">11. Limitation of Liability</h2>
              <h3 className="text-xl font-medium text-white mt-4">11.1 Exclusion of Damages</h3>
              <p className="text-gray-300">
                TO THE MAXIMUM EXTENT PERMITTED BY LAW, A13E SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, INCLUDING LOSS OF PROFITS, DATA, BUSINESS, OR GOODWILL, REGARDLESS OF THE CAUSE OF ACTION OR WHETHER A13E HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">11.2 Liability Cap</h3>
              <p className="text-gray-300">
                A13E's total aggregate liability arising from or relating to these Terms shall not exceed the fees paid by you to A13E in the twelve (12) months preceding the claim.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">11.3 Exceptions</h3>
              <p className="text-gray-300">
                Nothing in these Terms excludes or limits liability for: (a) death or personal injury caused by negligence; (b) fraud or fraudulent misrepresentation; (c) breach of data protection obligations; or (d) any other liability that cannot be excluded by law.
              </p>
            </section>

            {/* Indemnification */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">12. Indemnification</h2>
              <p className="text-gray-300">
                You agree to indemnify, defend, and hold harmless A13E and its officers, directors, employees, and agents from any claims, damages, losses, and expenses (including reasonable legal fees) arising from: (a) your use of the Service; (b) your violation of these Terms; (c) your violation of applicable laws; or (d) your Customer Data.
              </p>
            </section>

            {/* Term and Termination */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">13. Term and Termination</h2>
              <h3 className="text-xl font-medium text-white mt-4">13.1 Term</h3>
              <p className="text-gray-300">
                These Terms commence upon account creation and continue until terminated.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">13.2 Termination by You</h3>
              <p className="text-gray-300">
                You may terminate your account at any time through the account settings. Termination does not entitle you to a refund of prepaid fees.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">13.3 Termination by A13E</h3>
              <p className="text-gray-300">
                A13E may suspend or terminate your account immediately if you: (a) breach these Terms; (b) engage in fraudulent or illegal activity; (c) fail to pay fees when due; or (d) pose a security risk to the Service or other users. We will provide notice where practicable.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">13.4 Effect of Termination</h3>
              <p className="text-gray-300">
                Upon termination: (a) your right to access the Service ceases immediately; (b) you must cease all use of the Service; (c) A13E will delete your Customer Data in accordance with Section 7.4; (d) provisions that by their nature should survive will survive termination.
              </p>
            </section>

            {/* General */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">14. General Provisions</h2>
              <h3 className="text-xl font-medium text-white mt-4">14.1 Governing Law</h3>
              <p className="text-gray-300">
                These Terms are governed by the laws of England and Wales. Any disputes shall be subject to the exclusive jurisdiction of the courts of England and Wales.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">14.2 Amendments</h3>
              <p className="text-gray-300">
                We may amend these Terms by posting updated terms on our website. Material changes will be notified via email at least 30 days before taking effect. Continued use of the Service after changes take effect constitutes acceptance.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">14.3 Assignment</h3>
              <p className="text-gray-300">
                You may not assign these Terms without our prior written consent. A13E may assign these Terms to an affiliate or in connection with a merger, acquisition, or sale of assets.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">14.4 Severability</h3>
              <p className="text-gray-300">
                If any provision of these Terms is found unenforceable, the remaining provisions will continue in full force and effect.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">14.5 Entire Agreement</h3>
              <p className="text-gray-300">
                These Terms, together with our Privacy Policy and any applicable Data Processing Agreement, constitute the entire agreement between you and A13E regarding the Service.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">14.6 No Waiver</h3>
              <p className="text-gray-300">
                Failure to enforce any provision of these Terms shall not constitute a waiver of that provision.
              </p>
              <h3 className="text-xl font-medium text-white mt-4">14.7 Force Majeure</h3>
              <p className="text-gray-300">
                Neither party shall be liable for delays or failures in performance resulting from circumstances beyond their reasonable control, including natural disasters, acts of government, or infrastructure failures.
              </p>
            </section>

            {/* Contact */}
            <section>
              <h2 className="text-2xl font-semibold text-white border-b border-slate-700 pb-2">15. Contact Information</h2>
              <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
                <p className="text-gray-300 mb-4">
                  For questions regarding these Terms of Service, please contact us:
                </p>
                <ul className="text-gray-300 space-y-2">
                  <li><strong className="text-white">Email:</strong> <a href="mailto:legal@a13e.com" className="text-cyan-400 hover:text-cyan-300">legal@a13e.com</a></li>
                  <li><strong className="text-white">Support:</strong> <Link to="/support" className="text-cyan-400 hover:text-cyan-300">app.a13e.com/support</Link></li>
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
