/** Minimal markdown renderer for the run report preview.
 *  Everything is escaped first, then a whitelist of block and inline
 *  constructs is rebuilt, so a report can never inject markup. */

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function inline(text: string): string {
  return text
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|\s)\*([^*]+)\*(?=\s|$|[.,;:!?])/g, '$1<em>$2</em>')
    .replace(
      /\[([^\]]+)\]\((https?:\/\/[^\s)]+|\/[^\s)]*)\)/g,
      '<a href="$2" rel="noreferrer noopener" target="_blank">$1</a>'
    );
}

export function renderMarkdown(markdown: string): string {
  const out: string[] = [];
  const lines = String(markdown ?? '').split(/\r?\n/);
  let fence: string[] | null = null;
  let list: 'ul' | 'ol' | null = null;
  let paragraph: string[] = [];

  const closeList = () => {
    if (list) {
      out.push(`</${list}>`);
      list = null;
    }
  };
  const closeParagraph = () => {
    if (paragraph.length) {
      out.push(`<p>${paragraph.map((line) => inline(escapeHtml(line))).join(' ')}</p>`);
      paragraph = [];
    }
  };
  const flush = () => {
    closeParagraph();
    closeList();
  };

  for (const raw of lines) {
    const line = raw.replace(/\s+$/, '');
    if (fence !== null) {
      if (line.startsWith('```')) {
        out.push(`<pre>${escapeHtml(fence.join('\n'))}</pre>`);
        fence = null;
      } else {
        fence.push(line);
      }
      continue;
    }
    if (line.startsWith('```')) {
      flush();
      fence = [];
      continue;
    }
    if (!line.trim()) {
      flush();
      continue;
    }
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      flush();
      const level = heading[1].length;
      out.push(`<h${level}>${inline(escapeHtml(heading[2].trim()))}</h${level}>`);
      continue;
    }
    if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      flush();
      out.push('<hr />');
      continue;
    }
    const bullet = /^\s*[-*]\s+(.*)$/.exec(line);
    if (bullet) {
      closeParagraph();
      if (list !== 'ul') {
        closeList();
        out.push('<ul>');
        list = 'ul';
      }
      out.push(`<li>${inline(escapeHtml(bullet[1]))}</li>`);
      continue;
    }
    const numbered = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (numbered) {
      closeParagraph();
      if (list !== 'ol') {
        closeList();
        out.push('<ol>');
        list = 'ol';
      }
      out.push(`<li>${inline(escapeHtml(numbered[1]))}</li>`);
      continue;
    }
    closeList();
    paragraph.push(line.trim());
  }
  if (fence !== null) out.push(`<pre>${escapeHtml(fence.join('\n'))}</pre>`);
  flush();
  return out.join('\n');
}
