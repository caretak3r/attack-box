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

export async function generateMetadata({ params }: Props) {
  const { journey } = await params
  return { title: journeys.find(c => c.slug === journey)?.title }
}

export default async function Journey({ params }: Props) {
  const { journey } = await params
  const report = journeys.find(c => c.slug === journey) ?? notFound()
  const markdown = await readFile(join(process.cwd(), '..', 'findings', report.date, `${report.slug}.md`), 'utf8')
  const compiledSource = await compileMdx(markdown, { mdxOptions: { format: 'md' } })
  return <main style={{ maxWidth: '76rem', margin: '2rem auto', padding: '0 1.25rem 3rem', minWidth: 0 }}>
    <nav aria-label="Findings"><Link href="/findings/">← All findings and peer journeys</Link></nav>
    <article data-pagefind-body><MDXRemote compiledSource={compiledSource} components={{ Mermaid }} scope={{ Mermaid }} /></article>
  </main>
}
