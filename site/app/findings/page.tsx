import { access, readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { FindingsViewer, type DayData } from './viewer'

export const dynamic = 'force-static'
export const metadata = { title: 'Historical traffic | AttackBox' }

const categories = new Set(['Environment files', 'Version control', 'WordPress', 'AI discovery (unmatched)', 'Model list', 'AI generation', 'Other'])
const metrics = ['Outside HTTP requests', 'Distinct outside addresses', 'HTTP 2xx', 'HTTP 4xx', 'HTTP 5xx', 'Retained Falco events', 'OUTPUT-DROP:', 'CONTAINER-EGRESS-BLOCK:', 'METADATA-BLOCK:', 'METADATA-BLOCK-OUT:']

export default async function FindingsPage() {
  const root = join(process.cwd(), '..', 'findings')
  const days: DayData[] = []
  const entries = await readdir(root, { withFileTypes: true })
  for (const date of entries.filter(e => e.isDirectory() && /^\d{4}-\d\d-\d\d$/.test(e.name)).map(e => e.name).sort()) {
    await access(join(root, date, 'README.md'))
    let text: string
    try {
      text = await readFile(join(root, date, 'map.json'), 'utf8')
    } catch (err) {
      if (!(err instanceof Error && 'code' in err && err.code === 'ENOENT')) throw err
      days.push({ date, hasMap: false })
      continue
    }
    const data = JSON.parse(text)
    const invalid = new Error(`Invalid public snapshot for ${date}`)
    if (data?.date !== date || typeof data.until !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(data.until) || !Array.isArray(data.flows)) throw invalid
    const counts: Record<string, number> = {}
    for (const key of metrics) {
      const value = data.counts?.[key]
      if (!Number.isSafeInteger(value) || value < 0) throw invalid
      counts[key] = value
    }
    const flows: NonNullable<DayData['flows']> = []
    let total = 0
    for (const row of data.flows) {
      if (!Array.isArray(row) || row.length !== 4) throw invalid
      const [port, category, status, requests] = row
      if (!Number.isInteger(port) || port < 0 || port > 65535 || !categories.has(category) || !Number.isInteger(status) || status < 100 || status > 599 || !Number.isSafeInteger(requests) || requests < 1) throw invalid
      flows.push([port, category, status, requests])
      total += requests
    }
    if (total !== counts['Outside HTTP requests']) throw invalid
    days.push({ date, until: data.until, counts, flows, hasMap: true })
  }
  return <FindingsViewer days={days} />
}
