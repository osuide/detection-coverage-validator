import { useParams, Link, Navigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { ArrowLeft, ArrowRight, Clock, BookOpen, ChevronRight } from 'lucide-react';
import { DocsLayout } from '../../components/docs/DocsLayout';
import { CodeBlock } from '../../components/docs/CodeBlock';
import { TableOfContents } from '../../components/docs/TableOfContents';
import { getDocBySlug, getNextDoc, getPrevDoc } from './docs-content';

// Map of slug to markdown file path
const markdownFiles: Record<string, string> = {
  'getting-started': '/docs/getting-started.md',
  'connecting-aws': '/docs/connecting-aws-accounts.md',
  'running-scans': '/docs/running-scans.md',
  'understanding-coverage': '/docs/understanding-coverage.md',
  'team-management': '/docs/team-management.md',
  'billing': '/docs/billing-subscription.md',
};

export function DocsPage() {
  const { slug } = useParams<{ slug: string }>();
  const [content, setContent] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const doc = slug ? getDocBySlug(slug) : undefined;
  const nextDoc = slug ? getNextDoc(slug) : undefined;
  const prevDoc = slug ? getPrevDoc(slug) : undefined;

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

  if (!doc) {
    return <Navigate to="/docs" replace />;
  }

  // Generate heading ID from text
  const generateId = (text: string) => {
    return String(text).toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]/g, '');
  };

  return (
    <DocsLayout>
      {/* Breadcrumb */}
      <nav className="flex items-center gap-2 text-sm text-gray-400 mb-8 pb-6 border-b border-slate-800">
        <Link to="/docs" className="hover:text-blue-400 transition-colors flex items-center gap-1.5">
          <BookOpen className="h-4 w-4" />
          Documentation
        </Link>
        <ChevronRight className="h-3 w-3 text-gray-600" />
        <span className="text-white font-medium">{doc.title}</span>
      </nav>

      <div className="flex gap-10">
        {/* Main content */}
        <div className="flex-1 min-w-0">
          {/* Header */}
          <header className="mb-10">
            <h1 className="text-4xl font-bold text-white mb-4">{doc.title}</h1>
            <p className="text-lg text-gray-400 mb-4">{doc.description}</p>
            <div className="flex items-center gap-4 text-sm text-gray-500">
              <span className="flex items-center gap-1.5">
                <Clock className="h-4 w-4" />
                {doc.readTime} read
              </span>
            </div>
          </header>

          {/* Content */}
          {loading ? (
            <div className="flex items-center justify-center py-20">
              <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-500" />
            </div>
          ) : error ? (
            <div className="p-6 bg-red-900/20 border border-red-500/30 text-red-400 rounded-xl">
              <p className="font-medium">Error loading document</p>
              <p className="text-sm mt-1 text-red-300">{error}</p>
            </div>
          ) : (
            <article className="prose prose-invert max-w-none
              prose-headings:scroll-mt-24
              prose-headings:font-bold
              prose-h1:text-3xl prose-h1:mb-8 prose-h1:pb-4 prose-h1:border-b prose-h1:border-slate-800 prose-h1:text-white
              prose-h2:text-2xl prose-h2:mt-12 prose-h2:mb-6 prose-h2:text-blue-400
              prose-h3:text-xl prose-h3:mt-8 prose-h3:mb-4 prose-h3:text-cyan-400
              prose-h4:text-lg prose-h4:mt-6 prose-h4:mb-3 prose-h4:text-gray-200
              prose-p:text-gray-300 prose-p:leading-relaxed
              prose-a:text-blue-400 prose-a:no-underline prose-a:font-medium hover:prose-a:text-blue-300 hover:prose-a:underline
              prose-strong:text-white prose-strong:font-semibold
              prose-code:text-cyan-400 prose-code:bg-slate-800 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:font-mono prose-code:text-sm
              prose-code:before:content-none prose-code:after:content-none
              prose-pre:bg-transparent prose-pre:p-0 prose-pre:m-0
              prose-ul:text-gray-300 prose-ol:text-gray-300
              prose-li:marker:text-blue-400
              prose-blockquote:border-l-4 prose-blockquote:border-blue-500 prose-blockquote:bg-slate-800/50 prose-blockquote:py-1 prose-blockquote:px-4 prose-blockquote:rounded-r-lg prose-blockquote:text-gray-300 prose-blockquote:not-italic
              prose-hr:border-slate-800
              prose-img:rounded-xl prose-img:shadow-lg prose-img:border prose-img:border-slate-800
              prose-table:text-sm prose-table:w-full
              prose-thead:bg-slate-800 prose-thead:text-white
              prose-th:p-3 prose-th:text-left prose-th:font-semibold
              prose-tbody:text-gray-300
              prose-tr:border-b prose-tr:border-slate-700
              prose-td:p-3
            ">
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                  // Custom code block renderer
                  code({ node, className, children, ...props }) {
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
                      <h2 id={id} className="group flex items-center gap-2" {...props}>
                        {children}
                        <a
                          href={`#${id}`}
                          className="opacity-0 group-hover:opacity-100 text-blue-500 hover:text-blue-400 transition-opacity"
                          aria-label="Link to section"
                        >
                          #
                        </a>
                      </h2>
                    );
                  },
                  h3: ({ children, ...props }) => {
                    const id = generateId(String(children));
                    return (
                      <h3 id={id} className="group flex items-center gap-2" {...props}>
                        {children}
                        <a
                          href={`#${id}`}
                          className="opacity-0 group-hover:opacity-100 text-cyan-500 hover:text-cyan-400 transition-opacity"
                          aria-label="Link to section"
                        >
                          #
                        </a>
                      </h3>
                    );
                  },
                  // Enhanced table wrapper
                  table: ({ children, ...props }) => (
                    <div className="overflow-x-auto rounded-xl border border-slate-700 my-6">
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
          <div className="flex justify-between items-center mt-16 pt-8 border-t border-slate-800">
            {prevDoc ? (
              <Link
                to={`/docs/${prevDoc.slug}`}
                className="flex items-center gap-3 text-gray-400 hover:text-white transition-colors group"
              >
                <ArrowLeft className="h-5 w-5 group-hover:-translate-x-1 transition-transform" />
                <div>
                  <div className="text-xs text-gray-500 mb-1">Previous</div>
                  <div className="font-medium">{prevDoc.title}</div>
                </div>
              </Link>
            ) : (
              <div />
            )}
            {nextDoc ? (
              <Link
                to={`/docs/${nextDoc.slug}`}
                className="flex items-center gap-3 text-gray-400 hover:text-white transition-colors text-right group"
              >
                <div>
                  <div className="text-xs text-gray-500 mb-1">Next</div>
                  <div className="font-medium">{nextDoc.title}</div>
                </div>
                <ArrowRight className="h-5 w-5 group-hover:translate-x-1 transition-transform" />
              </Link>
            ) : (
              <div />
            )}
          </div>
        </div>

        {/* Table of Contents */}
        {!loading && !error && <TableOfContents content={content} />}
      </div>
    </DocsLayout>
  );
}
