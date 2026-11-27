'use client'

import { useState, useEffect } from 'react'
import styles from './findings.module.css'

export type DayData = {
  date: string
  hasMap: boolean
  until?: string
  counts?: Record<string, number>
  flows?: Array<[number, string, number, number]>
}

type ViewerProps = {
  days: DayData[]
}

function count(n: number): string {
  return n.toLocaleString('en-US')
}

function formatDate(iso: string): string {
  const d = new Date(iso + 'T00:00:00Z')
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' })
}

function clip(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

type FlowNode = {
  id: string | number
  label: string
  count: number
}

type FlowLink = {
  source: string | number
  target: string
  count: number
}

function buildFlowGraph(flows: Array<[number, string, number, number]>) {
  const portCounts = new Map<number, number>()
  const endpointCounts = new Map<string, number>()
  const links: FlowLink[] = []

  for (const [port, endpoint, _, requests] of flows) {
    portCounts.set(port, (portCounts.get(port) || 0) + requests)
    endpointCounts.set(endpoint, (endpointCounts.get(endpoint) || 0) + requests)
    
    const existing = links.find(l => l.source === port && l.target === endpoint)
    if (existing) {
      existing.count += requests
    } else {
      links.push({ source: port, target: endpoint, count: requests })
    }
  }

  const sources: FlowNode[] = Array.from(portCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([port, cnt]) => ({ id: port, label: port ? String(port) : 'unknown', count: cnt }))

  const targets: FlowNode[] = Array.from(endpointCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([endpoint, cnt]) => ({ id: endpoint, label: endpoint, count: cnt }))

  return { sources, targets, links }
}

function FlowDiagram({ flows, onFilterPort, onFilterEndpoint }: {
  flows: Array<[number, string, number, number]>
  onFilterPort: (port: number) => void
  onFilterEndpoint: (endpoint: string) => void
}) {
  if (!flows.length) {
    return <p className={styles.empty}>No traffic recorded.</p>
  }

  const { sources, targets, links } = buildFlowGraph(flows)
  
  const rowH = 26
  const padL = 190
  const padR = 320
  const width = Math.max(720, sources.length * 30 + targets.length * 40 + padL + padR)
  const height = Math.max(sources.length, targets.length) * rowH + 6
  const xl = padL
  const xr = width - padR
  
  const y = (i: number) => i * rowH + rowH / 2 + 3
  const sourceY = new Map(sources.map((s, i) => [s.id, y(i)]))
  const targetY = new Map(targets.map((t, i) => [t.id, y(i)]))
  const maxCount = Math.max(...links.map(l => l.count))

  return (
    <svg 
      width={width} 
      height={height} 
      viewBox={`0 0 ${width} ${height}`}
      role="group"
      aria-label="Flow of requests from listener ports to endpoints"
      style={{ display: 'block' }}
    >
      {links.map((link, i) => {
        const ya = sourceY.get(link.source)
        const yb = targetY.get(link.target)
        if (ya === undefined || yb === undefined) return null
        
        const mid = (xl + xr) / 2
        const strokeWidth = 1 + 11 * Math.sqrt(link.count / maxCount)
        
        return (
          <g key={i}>
            <path
              d={`M${xl + 6},${ya} C${mid},${ya} ${mid},${yb} ${xr},${yb}`}
              fill="none"
              stroke="var(--request)"
              strokeWidth={strokeWidth}
              opacity={0.42}
            >
              <title>{link.source} to {link.target}: {count(link.count)} request{link.count !== 1 ? 's' : ''}</title>
            </path>
          </g>
        )
      })}
      
      {sources.map((node, i) => {
        const yy = sourceY.get(node.id)
        if (yy === undefined) return null
        
        return (
          <g
            key={`src-${node.id}`}
            className={styles.node}
            role="button"
            tabIndex={0}
            aria-label={`Show only port ${node.label}`}
            onClick={() => onFilterPort(Number(node.id))}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onFilterPort(Number(node.id))
              }
            }}
          >
            <rect x={0} y={yy - rowH / 2} width={xl + 6} height={rowH} fill="transparent" />
            <rect x={xl} y={yy - 9} width={6} height={18} rx={2} fill="var(--muted)" />
            <text x={xl - 10} y={yy + 4} textAnchor="end" fill="var(--fg)" fontSize="12" fontFamily="var(--mono)">
              {clip(node.label, 20)}
            </text>
            <text x={8} y={yy + 4} fill="var(--muted)" fontSize="12" fontFamily="var(--mono)">
              {count(node.count)}
            </text>
            <title>{node.label}: {count(node.count)} request{node.count !== 1 ? 's' : ''}</title>
          </g>
        )
      })}
      
      {targets.map((node, i) => {
        const yy = targetY.get(node.id)
        if (yy === undefined) return null
        
        const maxChars = Math.floor((padR - 80) / 7.3)
        
        return (
          <g
            key={`tgt-${node.id}`}
            className={styles.node}
            role="button"
            tabIndex={0}
            aria-label={`Show only endpoint ${node.label}`}
            onClick={() => onFilterEndpoint(String(node.id))}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onFilterEndpoint(String(node.id))
              }
            }}
          >
            <rect x={xr} y={yy - rowH / 2} width={padR} height={rowH} fill="transparent" />
            <rect x={xr} y={yy - 9} width={6} height={18} rx={2} fill="var(--muted)" />
            <text x={xr + 14} y={yy + 4} fill="var(--fg)" fontSize="12" fontFamily="var(--mono)">
              {clip(node.label, maxChars)}
            </text>
            <text x={width - 6} y={yy + 4} textAnchor="end" fill="var(--muted)" fontSize="12" fontFamily="var(--mono)">
              {count(node.count)}
            </text>
            <title>{node.label}: {count(node.count)} request{node.count !== 1 ? 's' : ''}</title>
          </g>
        )
      })}
    </svg>
  )
}

export function FindingsViewer({ days }: ViewerProps) {
  const [selected, setSelected] = useState<string | null>(null)
  const emptyFilter = { port: -1, endpoint: '' }
  const [filter, setFilter] = useState(emptyFilter)

  useEffect(() => {
    const sync = () => {
      setSelected(new URLSearchParams(window.location.search).get('day'))
      setFilter({ port: -1, endpoint: '' })
    }
    sync()
    window.addEventListener('popstate', sync)
    return () => window.removeEventListener('popstate', sync)
  }, [])

  const pick = (day: string | null) => {
    const url = new URL(window.location.href)
    if (day) url.searchParams.set('day', day)
    else url.searchParams.delete('day')
    if (url.href !== window.location.href) window.history.pushState(null, '', url)
    setSelected(day)
    setFilter(emptyFilter)
  }

  const pickFilterPort = (port: number) => {
    setFilter({ port: filter.port === port ? -1 : port, endpoint: '' })
  }

  const pickFilterEndpoint = (endpoint: string) => {
    setFilter({ port: -1, endpoint: filter.endpoint === endpoint ? '' : endpoint })
  }


  if (!days.length) {
    return (
      <div className={styles.container}>
        <header className={styles.bar}>
          <h1>AttackBox findings archive</h1>
        </header>
        <main className={styles.main}>
          <p className={styles.notice}>No findings data available yet. Daily snapshots will appear here once generated.</p>
        </main>
      </div>
    )
  }

  const day = days.find(d => d.date === selected)
  const mapped = (day ? [day] : days).filter(d => d.hasMap)
  const flows = mapped.flatMap(d => d.flows ?? []).filter(([port, endpoint]) =>
    (filter.port < 0 || port === filter.port) && (!filter.endpoint || endpoint === filter.endpoint))
  const reportUrl = day && `https://github.com/caretak3r/attack-box/blob/main/findings/${day.date}/README.md`
  if (selected && !day) return <main className={styles.container}><h1>Report not found</h1><button onClick={() => pick(null)}>All days</button></main>

  const portCounts = new Map<number, number>()
  const endpointCounts = new Map<string, number>()
  const statusCounts = new Map<number, number>()

  for (const [port, endpoint, status, requests] of flows) {
    portCounts.set(port, (portCounts.get(port) || 0) + requests)
    endpointCounts.set(endpoint, (endpointCounts.get(endpoint) || 0) + requests)
    statusCounts.set(status, (statusCounts.get(status) || 0) + requests)
  }

  const ports = Array.from(portCounts.entries()).sort((a, b) => b[1] - a[1])
  const endpoints = Array.from(endpointCounts.entries()).sort((a, b) => b[1] - a[1])
  const statuses = Array.from(statusCounts.entries()).sort((a, b) => a[0] - b[0])

  const totalRequests = flows.reduce((sum, row) => sum + row[3], 0)

  const isPartial = day && day.hasMap && day.until 
    ? day.until.startsWith(day.date)
    : false

  return (
    <div className={styles.container}>
      <header className={styles.bar}>
        <h1>AttackBox findings archive</h1>
        <div className={styles.controls}>
          <div className={styles.segment} role="group" aria-label="Day selection">
            <button 
              aria-pressed={selected === null}
              onClick={() => pick(null)}
            >
              All days
            </button>
            {days.map(d => (
              <button 
                key={d.date}
                aria-pressed={selected === d.date}
                onClick={() => pick(d.date)}
              >
                {formatDate(d.date)}
              </button>
            ))}
          </div>
        </div>
      </header>

      <main className={styles.main}>
        {day && (
          <section className={styles.scope} aria-label="Selected day">
            <div>
              <div className={styles.subject}>{day.date}</div>
              <div className={styles.facts}>
                {!day.hasMap ? (
                  <p style={{ margin: 0 }}>
                    No preserved public traffic map · <a href={reportUrl} className={styles.link}>View report</a>
                  </p>
                ) : (
                  <p style={{ margin: 0 }}>
                    {isPartial && <><span className={styles.partial}>Partial day</span> · </>}
                    Through {day.until?.replace('T', ' ').replace('Z', '')} UTC · <a href={reportUrl} className={styles.link}>Full report</a>
                  </p>
                )}
              </div>
            </div>
          </section>
        )}

        {!day && <p className={styles.hint}>{days.length} reports · {mapped.length} public maps · includes partial days. Written reports without a map do not contribute to totals.</p>}
        {(filter.port >= 0 || filter.endpoint) && <p className={styles.hint}>Showing {filter.endpoint || `port ${filter.port || 'unknown'}`} · <button className={styles.link} onClick={() => setFilter(emptyFilter)}>Clear filter</button></p>}
        {(!day || day.hasMap) && (
          <section className={styles.overview} aria-label="Volume">
            <dl className={styles.totals}>
              <div>
                <dd>{count(totalRequests)}</dd>
                <dt>Outside requests in selection</dt>
              </div>
              {day && day.hasMap && filter.port < 0 && !filter.endpoint && (
                <>
                  <div>
                    <dd>{count(day.counts?.['Distinct outside addresses'] || 0)}</dd>
                    <dt>Addresses</dt>
                  </div>
                  <div>
                    <dd>{count(day.counts?.['HTTP 2xx'] || 0)}</dd>
                    <dt>2xx</dt>
                  </div>
                  <div>
                    <dd>{count(day.counts?.['HTTP 4xx'] || 0)}</dd>
                    <dt>4xx</dt>
                  </div>
                  <div>
                    <dd>{count(day.counts?.['HTTP 5xx'] || 0)}</dd>
                    <dt>5xx</dt>
                  </div>
                </>
              )}
            </dl>
          </section>
        )}

        {day && !day.hasMap ? (
          <section>
            <h2>Traffic patterns</h2>
            <div className={styles.flow}>
              <p className={styles.empty}>This day has a findings report but no preserved public traffic map.</p>
            </div>
          </section>
        ) : (
          <>
            <section>
              <h2>Traffic patterns</h2>
              <p className={styles.hint}>Line width shows request count. Click port or endpoint to filter.</p>
              <div className={styles.flow}>
                <FlowDiagram 
                  flows={flows} 
                  onFilterPort={pickFilterPort}
                  onFilterEndpoint={pickFilterEndpoint}
                />
              </div>
            </section>

            <section>
              <h2>Listener ports</h2>
              <div className={styles.scroll}>
                <table>
                  <thead>
                    <tr>
                      <th>Port</th>
                      <th className={styles.num}>Requests</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ports.map(([port, requests]) => (
                      <tr key={port} className={filter.port === port ? styles.selected : ''}>
                        <td>
                          <button className={styles.link} onClick={() => pickFilterPort(port)}>
                            {port || 'unknown'}
                          </button>
                        </td>
                        <td className={styles.num}>{count(requests)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <div className={styles.split}>
              <section>
                <h2>Endpoints</h2>
                <div className={styles.scroll}>
                  <table>
                    <thead>
                      <tr>
                        <th>Endpoint</th>
                        <th className={styles.num}>Requests</th>
                      </tr>
                    </thead>
                    <tbody>
                      {endpoints.map(([endpoint, requests]) => (
                        <tr key={endpoint} className={filter.endpoint === endpoint ? styles.selected : ''}>
                          <td className={styles.wide}>
                            <button className={styles.link} onClick={() => pickFilterEndpoint(endpoint)}>
                              {endpoint}
                            </button>
                          </td>
                          <td className={styles.num}>{count(requests)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>

              <section>
                <h2>Status codes</h2>
                <div className={styles.scroll}>
                  <table>
                    <thead>
                      <tr>
                        <th>Status</th>
                        <th className={styles.num}>Requests</th>
                      </tr>
                    </thead>
                    <tbody>
                      {statuses.map(([status, requests]) => {
                        const code = status || 0
                        const cls = code >= 200 && code < 300 ? styles.s2 : code >= 400 && code < 500 ? styles.s4 : code >= 500 ? styles.s5 : ''
                        return (
                          <tr key={status}>
                            <td className={cls}>{code || 'unknown'}</td>
                            <td className={styles.num}>{count(requests)}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </section>
            </div>
            <section>
              <h2>Host security logs</h2>
              <p className={styles.hint}>Totals for the selected dates. These events are not linked to individual HTTP requests.</p>
              <div className={styles.scroll}><table><thead><tr><th>Signal</th><th className={styles.num}>Records</th></tr></thead><tbody>
                {['Retained Falco events', 'OUTPUT-DROP:', 'CONTAINER-EGRESS-BLOCK:', 'METADATA-BLOCK:', 'METADATA-BLOCK-OUT:'].map(k =>
                  <tr key={k}><td>{k}</td><td className={styles.num}>{count(mapped.reduce((sum, d) => sum + (d.counts?.[k] ?? 0), 0))}</td></tr>)}
              </tbody></table></div>
            </section>
          </>
        )}
      </main>
    </div>
  )
}
