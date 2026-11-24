import { resolve } from 'node:path'
import nextra from 'nextra'
import remarkMermaidTheme from './remark-mermaid-theme.mjs'

const withNextra = nextra({
  latex: true,                       // KaTeX — $inline$ and $$display$$ math
  defaultShowCopyCode: true,
  search: { codeblocks: false },
  contentDirBasePath: '/',
  mdxOptions: {
    remarkPlugins: [remarkMermaidTheme] // Okabe-Ito palette on every diagram
  }
})

export default withNextra({
  agentRules: false,
  reactStrictMode: true,
  basePath: process.env.PAGES_BASE_PATH ?? '',
  output: 'export',
  images: { unoptimized: true },
  trailingSlash: true,
  webpack(config) {
    config.resolve.alias['@theguild/remark-mermaid/mermaid$'] = resolve('app/diagram.tsx')
    return config
  }
})
