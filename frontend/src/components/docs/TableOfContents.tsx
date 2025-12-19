import { useEffect, useState } from 'react';
import { List } from 'lucide-react';

interface Heading {
  id: string;
  text: string;
  level: number;
}

interface TableOfContentsProps {
  content: string;
}

export function TableOfContents({ content }: TableOfContentsProps) {
  const [headings, setHeadings] = useState<Heading[]>([]);
  const [activeId, setActiveId] = useState<string>('');

  useEffect(() => {
    // Parse headings from markdown content
    const lines = content.split('\n');
    const parsed: Heading[] = [];

    lines.forEach((line) => {
      const match = line.match(/^(#{2,3})\s+(.+)$/);
      if (match) {
        const level = match[1].length;
        const text = match[2].replace(/[#*`\[\]]/g, '').trim();
        const id = text.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]/g, '');
        parsed.push({ id, text, level });
      }
    });

    setHeadings(parsed);
  }, [content]);

  useEffect(() => {
    // Track active heading on scroll
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveId(entry.target.id);
          }
        });
      },
      { rootMargin: '-100px 0px -66%' }
    );

    headings.forEach(({ id }) => {
      const element = document.getElementById(id);
      if (element) observer.observe(element);
    });

    return () => observer.disconnect();
  }, [headings]);

  if (headings.length < 3) return null;

  return (
    <div className="hidden xl:block w-64 flex-shrink-0">
      <nav className="sticky top-28">
        <div className="flex items-center gap-2 text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">
          <List className="h-4 w-4" />
          On This Page
        </div>
        <ul className="space-y-2 text-sm border-l border-slate-800">
          {headings.map((heading) => (
            <li key={heading.id} style={{ paddingLeft: `${(heading.level - 2) * 0.75 + 0.75}rem` }}>
              <a
                href={`#${heading.id}`}
                className={`block py-1 transition-colors border-l-2 -ml-px pl-3 ${
                  activeId === heading.id
                    ? 'border-blue-500 text-blue-400 font-medium'
                    : 'border-transparent text-gray-500 hover:text-gray-300 hover:border-slate-600'
                }`}
              >
                {heading.text}
              </a>
            </li>
          ))}
        </ul>
      </nav>
    </div>
  );
}
