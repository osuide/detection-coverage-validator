// Documentation content configuration
// Each doc has metadata and a markdown content string

export interface DocPage {
  slug: string;
  title: string;
  description: string;
  readTime: string;
  icon: string;
  order: number;
}

export const docPages: DocPage[] = [
  {
    slug: 'getting-started',
    title: 'Getting Started',
    description: 'New to A13E? Start here for account creation and first steps.',
    readTime: '10 min',
    icon: 'BookOpen',
    order: 1,
  },
  {
    slug: 'connecting-aws',
    title: 'Connecting AWS Accounts',
    description: 'Securely connect your AWS accounts for scanning.',
    readTime: '8 min',
    icon: 'Cloud',
    order: 2,
  },
  {
    slug: 'connecting-gcp',
    title: 'Connecting GCP Accounts',
    description: 'Connect GCP projects using Workload Identity Federation.',
    readTime: '10 min',
    icon: 'Cloud',
    order: 3,
  },
  {
    slug: 'connecting-azure',
    title: 'Connecting Azure Accounts',
    description: 'Connect Azure subscriptions using Workload Identity Federation.',
    readTime: '10 min',
    icon: 'Cloud',
    order: 4,
  },
  {
    slug: 'running-scans',
    title: 'Running Scans',
    description: 'Learn how to scan your cloud accounts for detections.',
    readTime: '12 min',
    icon: 'Play',
    order: 5,
  },
  {
    slug: 'understanding-coverage',
    title: 'Understanding Coverage',
    description: 'Deep dive into MITRE ATT&CK coverage analysis.',
    readTime: '15 min',
    icon: 'BarChart3',
    order: 6,
  },
  {
    slug: 'using-dashboards',
    title: 'Using the Dashboards',
    description: 'Navigate coverage visualisations and identify security gaps.',
    readTime: '12 min',
    icon: 'BarChart3',
    order: 7,
  },
  {
    slug: 'team-management',
    title: 'Team Management',
    description: 'Manage users, roles, and permissions.',
    readTime: '6 min',
    icon: 'Users',
    order: 8,
  },
  {
    slug: 'billing',
    title: 'Billing & Subscription',
    description: 'Understand plans, pricing, and manage your subscription.',
    readTime: '8 min',
    icon: 'CreditCard',
    order: 9,
  },
  {
    slug: 'api-keys',
    title: 'API Keys',
    description: 'Generate and manage API keys for programmatic access.',
    readTime: '5 min',
    icon: 'Key',
    order: 10,
  },
  {
    slug: 'security-policy',
    title: 'Security Policy',
    description: 'Our vulnerability disclosure policy and security commitments.',
    readTime: '5 min',
    icon: 'Shield',
    order: 11,
  },
  {
    slug: 'security-thanks',
    title: 'Security Thanks',
    description: 'Recognising security researchers who help keep A13E secure.',
    readTime: '2 min',
    icon: 'Award',
    order: 12,
  },
];

export function getDocBySlug(slug: string): DocPage | undefined {
  return docPages.find((doc) => doc.slug === slug);
}

export function getNextDoc(currentSlug: string): DocPage | undefined {
  const currentIndex = docPages.findIndex((doc) => doc.slug === currentSlug);
  if (currentIndex >= 0 && currentIndex < docPages.length - 1) {
    return docPages[currentIndex + 1];
  }
  return undefined;
}

export function getPrevDoc(currentSlug: string): DocPage | undefined {
  const currentIndex = docPages.findIndex((doc) => doc.slug === currentSlug);
  if (currentIndex > 0) {
    return docPages[currentIndex - 1];
  }
  return undefined;
}
