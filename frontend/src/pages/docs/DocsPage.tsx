import { useParams, Link, Navigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkBreaks from 'remark-breaks';
import { ArrowLeft, ArrowRight, Clock, BookOpen, ChevronRight, List, AlertCircle, Info, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { DocsLayout } from '../../components/docs/DocsLayout';
import { CodeBlock } from '../../components/docs/CodeBlock';
import { getDocBySlug, getNextDoc, getPrevDoc } from './docs-content';

// Map of slug to markdown file path
const markdownFiles: Record<string, string> = {
  'getting-started': '/docs/getting-started.md',
  'connecting-aws': '/docs/connecting-aws-accounts.md',
  'connecting-gcp': '/docs/connecting-gcp-accounts.md',
  'running-scans': '/docs/running-scans.md',
  'understanding-coverage': '/docs/understanding-coverage.md',
  'team-management': '/docs/team-management.md',
  'billing': '/docs/billing-subscription.md',
  'api-keys': '/docs/api-keys.md',
};

// Parse headings for Table of Contents
interface Heading {
  id: string;
  text: string;
  level: number;
}

function parseHeadings(content: string): Heading[] {
  const lines = content.split('\n');
  const headings: Heading[] = [];

  lines.forEach((line) => {
    const match = line.match(/^(#{2,3})\s+(.+)$/);
    if (match) {
      const level = match[1].length;
      const text = match[2].replace(/[#*`[\]]/g, '').trim();
      const id = text.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]/g, '');
      headings.push({ id, text, level });
    }
  });

  return headings;
}

// Table of Contents Component
function TableOfContents({ headings, activeId }: { headings: Heading[]; activeId: string }) {
  if (headings.length < 3) return null;

  return (
    <nav className="hidden xl:block w-56 flex-shrink-0 pl-8">
      <div className="sticky top-24">
        <div className="flex items-center gap-2 text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
          <List className="h-3.5 w-3.5" />
          On this page
        </div>
        <ul className="space-y-1 text-[13px] border-l border-slate-800">
          {headings.map((heading) => (
            <li key={heading.id} style={{ paddingLeft: `${(heading.level - 2) * 12 + 12}px` }}>
              <a
                href={`#${heading.id}`}
                className={`block py-1 transition-colors border-l-2 -ml-px ${
                  activeId === heading.id
                    ? 'border-cyan-500 text-cyan-400 font-medium'
                    : 'border-transparent text-slate-500 hover:text-slate-300 hover:border-slate-600'
                }`}
              >
                {heading.text}
              </a>
            </li>
          ))}
        </ul>
      </div>
    </nav>
  );
}

// Callout component for blockquotes
function Callout({ children, type = 'info' }: { children: React.ReactNode; type?: 'info' | 'warning' | 'tip' | 'note' }) {
  const styles = {
    info: {
      bg: 'bg-blue-500/10',
      border: 'border-blue-500/30',
      icon: <Info className="h-4 w-4 text-blue-400 flex-shrink-0 mt-0.5" />,
    },
    warning: {
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/30',
      icon: <AlertTriangle className="h-4 w-4 text-amber-400 flex-shrink-0 mt-0.5" />,
    },
    tip: {
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/30',
      icon: <CheckCircle2 className="h-4 w-4 text-emerald-400 flex-shrink-0 mt-0.5" />,
    },
    note: {
      bg: 'bg-slate-500/10',
      border: 'border-slate-500/30',
      icon: <AlertCircle className="h-4 w-4 text-slate-400 flex-shrink-0 mt-0.5" />,
    },
  };

  const style = styles[type];

  return (
    <div className={`flex gap-3 ${style.bg} ${style.border} border rounded-lg p-4 my-4`}>
      {style.icon}
      <div className="text-sm text-slate-300 leading-relaxed [&>p]:m-0">{children}</div>
    </div>
  );
}

export function DocsPage() {
  const { slug } = useParams<{ slug: string }>();
  const [content, setContent] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeHeadingId, setActiveHeadingId] = useState<string>('');

  const doc = slug ? getDocBySlug(slug) : undefined;
  const nextDoc = slug ? getNextDoc(slug) : undefined;
  const prevDoc = slug ? getPrevDoc(slug) : undefined;
  const headings = parseHeadings(content);

  // Scroll to top when navigating to a new page
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [slug]);

  useEffect(() => {
    if (!slug || !markdownFiles[slug]) {
      setError('Document not found');
      setLoading(false);
      return;
    }

    fetch(markdownFiles[slug])
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load document');
        return res.text();
      })
      .then((text) => {
        setContent(text);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, [slug]);

  // Track active heading on scroll
  useEffect(() => {
    if (headings.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveHeadingId(entry.target.id);
          }
        });
      },
      { rootMargin: '-80px 0px -70%' }
    );

    headings.forEach(({ id }) => {
      const element = document.getElementById(id);
      if (element) observer.observe(element);
    });

    return () => observer.disconnect();
  }, [headings]);

  if (!doc) {
    return <Navigate to="/docs" replace />;
  }

  // Generate heading ID from text
  const generateId = (text: string) => {
    return String(text).toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]/g, '');
  };

  // Detect callout type from blockquote content
  const getCalloutType = (text: string): 'info' | 'warning' | 'tip' | 'note' => {
    const lowerText = text.toLowerCase();
    if (lowerText.includes('warning') || lowerText.includes('important')) return 'warning';
    if (lowerText.includes('tip') || lowerText.includes('best')) return 'tip';
    if (lowerText.includes('note')) return 'note';
    return 'info';
  };

  return (
    <DocsLayout>
      <div className="flex gap-0">
        {/* Main content area */}
        <div className="flex-1 min-w-0 max-w-3xl">
          {/* Breadcrumb */}
          <nav className="flex items-center gap-2 text-[13px] text-slate-500 mb-6">
            <Link to="/docs" className="hover:text-slate-300 transition-colors flex items-center gap-1">
              <BookOpen className="h-3.5 w-3.5" />
              Docs
            </Link>
            <ChevronRight className="h-3 w-3" />
            <span className="text-slate-300">{doc.title}</span>
          </nav>

          {/* Header */}
          <header className="mb-8 pb-6 border-b border-slate-800">
            <h1 className="text-3xl font-bold text-white mb-3">{doc.title}</h1>
            <p className="text-base text-slate-400 leading-relaxed">{doc.description}</p>
            <div className="flex items-center gap-3 mt-4 text-[13px] text-slate-500">
              <span className="flex items-center gap-1.5">
                <Clock className="h-3.5 w-3.5" />
                {doc.readTime} read
              </span>
            </div>
          </header>

          {/* Content */}
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500" />
            </div>
          ) : error ? (
            <div className="p-4 bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg">
              <p className="font-medium text-sm">Error loading document</p>
              <p className="text-sm mt-1 opacity-80">{error}</p>
            </div>
          ) : (
            <article className="prose prose-sm max-w-none
              prose-headings:scroll-mt-20
              prose-headings:font-semibold
              prose-h1:text-2xl prose-h1:mb-6 prose-h1:!text-white
              prose-h2:text-xl prose-h2:mt-10 prose-h2:mb-4 prose-h2:!text-white prose-h2:pt-2 prose-h2:border-t prose-h2:border-slate-800/50
              prose-h3:text-lg prose-h3:mt-8 prose-h3:mb-3 prose-h3:!text-white
              prose-h4:text-base prose-h4:mt-6 prose-h4:mb-2 prose-h4:!text-slate-200
              prose-p:!text-slate-400 prose-p:leading-relaxed prose-p:text-[15px] prose-p:mb-4
              prose-a:!text-cyan-400 prose-a:no-underline prose-a:font-medium hover:prose-a:!text-cyan-300 hover:prose-a:underline
              prose-strong:!text-slate-200 prose-strong:font-semibold
              prose-code:!text-amber-400 prose-code:bg-slate-800/80 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:font-mono prose-code:text-[13px] prose-code:border prose-code:border-slate-700/50
              prose-code:before:content-none prose-code:after:content-none
              prose-pre:bg-transparent prose-pre:p-0 prose-pre:m-0
              prose-ul:!text-slate-400 prose-ol:!text-slate-400 prose-ul:my-4 prose-ol:my-4 prose-ul:space-y-1 prose-ol:space-y-1
              prose-li:marker:!text-cyan-500 prose-li:!text-slate-400 prose-li:mb-1 prose-li:leading-relaxed
              prose-blockquote:border-0 prose-blockquote:p-0 prose-blockquote:m-0 prose-blockquote:!text-slate-400 prose-blockquote:not-italic
              prose-hr:border-slate-800 prose-hr:my-8
              prose-img:rounded-lg prose-img:border prose-img:border-slate-700
              prose-table:text-sm prose-table:w-full prose-table:my-4
              prose-thead:bg-slate-800/50 prose-thead:!text-slate-300
              prose-th:px-4 prose-th:py-2.5 prose-th:text-left prose-th:font-medium prose-th:!text-slate-300 prose-th:text-[13px]
              prose-tbody:!text-slate-400
              prose-tr:border-b prose-tr:border-slate-800
              prose-td:px-4 prose-td:py-2.5 prose-td:text-[14px] prose-td:!text-slate-400
            ">
              <ReactMarkdown
                remarkPlugins={[remarkGfm, remarkBreaks]}
                components={{
                  // Custom code block renderer
                  code({ className, children, ...props }) {
                    const match = /language-(\w+)/.exec(className || '');
                    const isInline = !match && !String(children).includes('\n');

                    return !isInline && match ? (
                      <CodeBlock
                        language={match[1]}
                        value={String(children).replace(/\n$/, '')}
                      />
                    ) : !isInline ? (
                      <CodeBlock
                        language="text"
                        value={String(children).replace(/\n$/, '')}
                      />
                    ) : (
                      <code className={className} {...props}>
                        {children}
                      </code>
                    );
                  },
                  // Custom heading renderer with anchor links
                  h2: ({ children, ...props }) => {
                    const id = generateId(String(children));
                    return (
                      <h2 id={id} className="group relative" {...props}>
                        <a href={`#${id}`} className="absolute -left-5 opacity-0 group-hover:opacity-100 text-slate-600 hover:text-cyan-400 transition-all" aria-label="Link to section">#</a>
                        {children}
                      </h2>
                    );
                  },
                  h3: ({ children, ...props }) => {
                    const id = generateId(String(children));
                    return (
                      <h3 id={id} className="group relative" {...props}>
                        <a href={`#${id}`} className="absolute -left-4 opacity-0 group-hover:opacity-100 text-slate-600 hover:text-cyan-400 transition-all text-sm" aria-label="Link to section">#</a>
                        {children}
                      </h3>
                    );
                  },
                  h4: ({ children, ...props }) => {
                    const id = generateId(String(children));
                    return (
                      <h4 id={id} className="group relative" {...props}>
                        {children}
                      </h4>
                    );
                  },
                  // Custom blockquote as callout
                  blockquote: ({ children }) => {
                    const textContent = String(children);
                    const type = getCalloutType(textContent);
                    return <Callout type={type}>{children}</Callout>;
                  },
                  // Custom link renderer to transform .md links to /docs/ routes
                  a: ({ href, children, ...props }) => {
                    // Transform relative .md links to /docs/ routes
                    let transformedHref = href || '';
                    if (transformedHref.startsWith('./') && transformedHref.endsWith('.md')) {
                      // Extract filename without extension: ./connecting-aws-accounts.md -> connecting-aws-accounts
                      const filename = transformedHref.slice(2, -3);
                      // Map filenames to slugs
                      const slugMap: Record<string, string> = {
                        'getting-started': 'getting-started',
                        'connecting-aws-accounts': 'connecting-aws',
                        'connecting-gcp-accounts': 'connecting-gcp',
                        'running-scans': 'running-scans',
                        'understanding-coverage': 'understanding-coverage',
                        'team-management': 'team-management',
                        'billing-subscription': 'billing',
                        'api-keys': 'api-keys',
                      };
                      const slug = slugMap[filename] || filename;
                      transformedHref = `/docs/${slug}`;
                    }

                    // Use React Router Link for internal links
                    if (transformedHref.startsWith('/docs/') || transformedHref.startsWith('#')) {
                      return (
                        <Link to={transformedHref} {...props}>
                          {children}
                        </Link>
                      );
                    }

                    // External links open in new tab
                    return (
                      <a href={transformedHref} target="_blank" rel="noopener noreferrer" {...props}>
                        {children}
                      </a>
                    );
                  },
                  // Enhanced table wrapper
                  table: ({ children, ...props }) => (
                    <div className="overflow-x-auto rounded-lg border border-slate-800 my-4">
                      <table className="w-full" {...props}>
                        {children}
                      </table>
                    </div>
                  ),
                }}
              >
                {content}
              </ReactMarkdown>
            </article>
          )}

          {/* Navigation */}
          <div className="flex justify-between items-center mt-12 pt-6 border-t border-slate-800">
            {prevDoc ? (
              <Link
                to={`/docs/${prevDoc.slug}`}
                className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors group text-sm"
              >
                <ArrowLeft className="h-4 w-4 group-hover:-translate-x-0.5 transition-transform" />
                <div>
                  <div className="text-[11px] text-slate-500 mb-0.5">Previous</div>
                  <div className="font-medium">{prevDoc.title}</div>
                </div>
              </Link>
            ) : (
              <div />
            )}
            {nextDoc ? (
              <Link
                to={`/docs/${nextDoc.slug}`}
                className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors text-right group text-sm"
              >
                <div>
                  <div className="text-[11px] text-slate-500 mb-0.5">Next</div>
                  <div className="font-medium">{nextDoc.title}</div>
                </div>
                <ArrowRight className="h-4 w-4 group-hover:translate-x-0.5 transition-transform" />
              </Link>
            ) : (
              <div />
            )}
          </div>
        </div>

        {/* Table of Contents */}
        <TableOfContents headings={headings} activeId={activeHeadingId} />
      </div>
    </DocsLayout>
  );
}
