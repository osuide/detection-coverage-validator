import { useParams, Link, Navigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { ArrowLeft, ArrowRight, Clock } from 'lucide-react';
import { DocsLayout } from '../../components/docs/DocsLayout';
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

  return (
    <DocsLayout>
      {/* Breadcrumb */}
      <nav className="flex items-center gap-2 text-sm text-gray-500 mb-6">
        <Link to="/docs" className="hover:text-gray-700">
          Docs
        </Link>
        <span>/</span>
        <span className="text-gray-900">{doc.title}</span>
      </nav>

      {/* Header */}
      <header className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">{doc.title}</h1>
        <div className="flex items-center gap-4 text-sm text-gray-500">
          <span className="flex items-center gap-1">
            <Clock className="h-4 w-4" />
            {doc.readTime} read
          </span>
        </div>
      </header>

      {/* Content */}
      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
        </div>
      ) : error ? (
        <div className="p-6 bg-red-50 text-red-700 rounded-lg">
          <p className="font-medium">Error loading document</p>
          <p className="text-sm mt-1">{error}</p>
        </div>
      ) : (
        <article className="prose prose-gray max-w-none prose-headings:scroll-mt-20 prose-h1:text-2xl prose-h2:text-xl prose-h3:text-lg prose-a:text-blue-600 prose-a:no-underline hover:prose-a:underline prose-pre:bg-gray-900 prose-code:text-sm prose-code:before:content-none prose-code:after:content-none prose-table:text-sm">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
        </article>
      )}

      {/* Navigation */}
      <div className="flex justify-between items-center mt-12 pt-8 border-t border-gray-200">
        {prevDoc ? (
          <Link
            to={`/docs/${prevDoc.slug}`}
            className="flex items-center gap-2 text-gray-600 hover:text-blue-600"
          >
            <ArrowLeft className="h-4 w-4" />
            <div>
              <div className="text-xs text-gray-400">Previous</div>
              <div className="font-medium">{prevDoc.title}</div>
            </div>
          </Link>
        ) : (
          <div />
        )}
        {nextDoc ? (
          <Link
            to={`/docs/${nextDoc.slug}`}
            className="flex items-center gap-2 text-gray-600 hover:text-blue-600 text-right"
          >
            <div>
              <div className="text-xs text-gray-400">Next</div>
              <div className="font-medium">{nextDoc.title}</div>
            </div>
            <ArrowRight className="h-4 w-4" />
          </Link>
        ) : (
          <div />
        )}
      </div>
    </DocsLayout>
  );
}
