'use client'

import mermaid from 'mermaid'
import { useEffect, useId, useState } from 'react'

export function Mermaid({ chart }: { chart: string }) {
  const id = useId()
  const [result, setResult] = useState<{ chart: string; svg: string | null }>()

  useEffect(() => {
    let obsolete = false
    async function renderDiagram() {
      try {
        await document.fonts.ready
        if (obsolete) return

        mermaid.initialize({ startOnLoad: false, securityLevel: 'strict', fontFamily: 'inherit' })
        // Render outside React's container. Mermaid clears any container it receives.
        const rendered = await mermaid.render(`mermaid-${id.replaceAll(':', '')}`, chart.replaceAll('\\n', '\n'))
        if (!obsolete) setResult({ chart, svg: rendered.svg })
      } catch (error) {
        if (!obsolete) {
          console.error('Cannot render Mermaid diagram', error)
          setResult({ chart, svg: null })
        }
      }
    }
    void renderDiagram()
    return () => { obsolete = true }
  }, [chart, id])

  if (result?.chart !== chart) return <p role="status">Loading diagram…</p>
  if (result.svg === null) return <p role="status">Diagram unavailable.</p>

  return (
    <figure className="diagram">
      <div style={{ overflowX: 'auto' }} dangerouslySetInnerHTML={{ __html: result.svg }} />
      <button
        type="button"
        aria-haspopup="dialog"
        data-diagram-zoom
        style={{ padding: '0.25rem 0.6rem', border: '1px solid currentColor', borderRadius: '0.3rem', cursor: 'pointer' }}
      >
        Enlarge diagram
      </button>
    </figure>
  )
}
