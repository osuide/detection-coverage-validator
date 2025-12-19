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
    slug: 'running-scans',
    title: 'Running Scans',
    description: 'Learn how to scan your cloud accounts for detections.',
    readTime: '12 min',
    icon: 'Play',
    order: 3,
  },
  {
    slug: 'understanding-coverage',
    title: 'Understanding Coverage',
    description: 'Deep dive into MITRE ATT&CK coverage analysis.',
    readTime: '15 min',
    icon: 'BarChart3',
    order: 4,
  },
  {
    slug: 'team-management',
    title: 'Team Management',
    description: 'Manage users, roles, and permissions.',
    readTime: '6 min',
    icon: 'Users',
    order: 5,
  },
  {
    slug: 'billing',
    title: 'Billing & Subscription',
    description: 'Understand plans, pricing, and manage your subscription.',
    readTime: '8 min',
    icon: 'CreditCard',
    order: 6,
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
