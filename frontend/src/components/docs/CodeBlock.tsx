import { useState } from 'react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Copy, Check } from 'lucide-react';

interface CodeBlockProps {
  language?: string;
  value: string;
}

export function CodeBlock({ language = 'text', value }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const lineCount = value.split('\n').length;

  return (
    <div className="relative group my-6">
      {/* Copy button */}
      <button
        onClick={handleCopy}
        className="absolute top-3 right-3 p-2 bg-slate-700 hover:bg-slate-600 text-gray-300 rounded-lg opacity-0 group-hover:opacity-100 transition-all z-10"
        title="Copy code"
      >
        {copied ? <Check className="h-4 w-4 text-green-400" /> : <Copy className="h-4 w-4" />}
      </button>

      {/* Language badge */}
      {language && language !== 'text' && (
        <div className="absolute top-0 left-0 px-3 py-1 bg-slate-700 text-xs text-gray-400 rounded-tl-xl rounded-br-lg font-mono uppercase">
          {language}
        </div>
      )}

      <SyntaxHighlighter
        language={language}
        style={vscDarkPlus}
        customStyle={{
          margin: 0,
          borderRadius: '0.75rem',
          border: '1px solid rgb(51, 65, 85)',
          background: 'rgb(15, 23, 42)',
          fontSize: '0.875rem',
          padding: language && language !== 'text' ? '2.5rem 1rem 1rem 1rem' : '1rem',
        }}
        showLineNumbers={lineCount > 5}
        wrapLines={true}
        lineNumberStyle={{
          color: 'rgb(100, 116, 139)',
          paddingRight: '1rem',
          minWidth: '2.5rem',
        }}
      >
        {value}
      </SyntaxHighlighter>
    </div>
  );
}
