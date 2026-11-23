import type { ReactNode } from 'react'
import { Footer, Layout, Navbar } from 'nextra-theme-docs'
import { Head } from 'nextra/components'
import { getPageMap } from 'nextra/page-map'
import 'nextra-theme-docs/style.css'
import 'katex/dist/katex.min.css'
import DiagramZoom from './diagram-zoom'

export const metadata = {
  title: { default: 'AttackBox', template: '%s – AttackBox' },
  description: 'Goals, architecture, and local development for the AttackBox defensive honeypot.'
}

const navbar = <Navbar logo={<b>AttackBox</b>} />
const footer = <Footer>AttackBox documentation</Footer>

export default async function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <Head />
      <body>
        <Layout navbar={navbar} pageMap={await getPageMap()} footer={footer}>
          {children}
        </Layout>
        <DiagramZoom />
      </body>
    </html>
  )
}
