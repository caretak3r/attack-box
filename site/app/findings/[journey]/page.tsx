import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import Link from 'next/link'
import { notFound } from 'next/navigation'
import { compileMdx } from 'nextra/compile'
import { MDXRemote } from 'nextra/mdx-remote'
import { Mermaid } from '../../diagram'
import { journeys } from '../journeys'

export const dynamicParams = false
export const generateStaticParams = () => journeys.map(({ slug }) => ({ journey: slug }))
type Props = { params: Promise<{ journey: string }> }

type RequestEvidence = {
  time: string
  request: string
  query: string
  headers: Record<string, string | number>
  status: number
  retainedBytes: number
  finalUser: { field: string; text: string; characters: number } | null
  body: object | null
}

export async function generateMetadata({ params }: Props) {
  const { journey } = await params
  return { title: journeys.find(c => c.slug === journey)?.title }
}

export default async function Journey({ params }: Props) {
  const { journey } = await params
  const report = journeys.find(c => c.slug === journey) ?? notFound()
  const base = join(process.cwd(), '..', 'findings', report.date, report.slug)
  const markdown = await readFile(`${base}.md`, 'utf8')
  const records: RequestEvidence[] = JSON.parse(await readFile(`${base}.requests.json`, 'utf8'))
  const promptCount = records.filter(r => r.finalUser && r.finalUser.characters > 0).length
  const compiledSource = await compileMdx(markdown, { mdxOptions: { format: 'md' } })
  return <main style={{ maxWidth: '76rem', margin: '2rem auto', padding: '0 1.25rem 3rem', minWidth: 0 }}>
    <nav aria-label="Findings"><Link href="/findings/">← All findings</Link> · <a href="#request-details">{promptCount} of {records.length} requests contain prompts ↓</a></nav>
    <article data-pagefind-body><MDXRemote compiledSource={compiledSource} components={{ Mermaid }} scope={{ Mermaid }} /></article>
    <section aria-labelledby="request-details">
      <h2 id="request-details">Request details · UTC</h2>
      <p><strong>Prompt in body</strong> marks requests with captured user input, even when the wording is withheld. Open a timestamp to inspect it. Headers are normalized; message lengths count characters before redaction.</p>
      {records.map(({ time, request, query, headers, status, retainedBytes, finalUser, body }, i) => (
        <details key={time} id={`request-${i + 1}`} style={{ padding: '.65rem 0', borderBottom: '1px solid currentColor', scrollMarginTop: '5rem' }}>
          <summary style={{ cursor: 'pointer' }}>#{i + 1} · {finalUser && finalUser.characters > 0
            ? <mark><strong><time dateTime={time}>{time}</time> · Prompt in body</strong></mark>
            : <time dateTime={time}>{time}</time>} · {request} → {status}</summary>
          {finalUser && <p><strong>Final user input</strong> · <code>{finalUser.field}</code> · {finalUser.characters.toLocaleString('en-US')} characters: {finalUser.text === '[redacted]' ? 'wording withheld pending private review' : <code>{finalUser.text}</code>}</p>}
          <p>Query string: {query || 'none'} · Captured request body: {retainedBytes.toLocaleString('en-US')} bytes</p>
          <pre style={{ overflowX: 'auto' }}>{[request, ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`)].join('\n')}</pre>
          {body ? <pre style={{ overflowX: 'auto' }}>{JSON.stringify(body, null, 2)}</pre> : <p>{status === 413 ? 'Body not retained: rejected for size. The prompt is unknown.' : 'No request body recorded.'}</p>}
        </details>
      ))}
    </section>
  </main>
}
