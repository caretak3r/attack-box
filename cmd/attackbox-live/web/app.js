'use strict';
// Every captured value reaches the page through textContent or an SVG text node. Never use innerHTML here.

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text) e.textContent = text;
  return e;
};
const svg = (tag, attrs, text) => {
  const e = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  if (text) e.textContent = text;
  return e;
};
const clip = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
const count = (n) => n.toLocaleString('en-US');
const plural = (n, word) => `${count(n)} ${word}${n === 1 ? '' : 's'}`;

const view = { window: '1h', who: '', q: '', ip: '', endpoint: '', port: 0, paused: false, feedKey: '', selected: 0, opener: null };
const windows = [['15m', '15 min'], ['1h', '1 h'], ['6h', '6 h'], ['24h', '24 h'], ['7d', '7 d']];

const drawn = {};
function changed(name, data) {
  const key = JSON.stringify(data);
  if (drawn[name] === key) return false;
  drawn[name] = key;
  return true;
}

function clock(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

function ago(iso, now) {
  const ms = new Date(now) - new Date(iso);
  if (ms < 1000) return 'just now';
  if (ms < 60000) return `${Math.floor(ms / 1000)}s ago`;
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ago`;
  if (ms < 86400000) return `${Math.floor(ms / 3600000)}h ago`;
  return `${Math.floor(ms / 86400000)}d ago`;
}

const sourceName = (ip) => ip || 'unattributed';

function pick(change) {
  Object.assign(view, change);
  if ('paused' in change && !view.paused) tick(true);
}

function ipButton(ip, own) {
  const btn = el('button', 'link ip', sourceName(ip));
  btn.type = 'button';
  btn.title = 'Filter to this source';
  if (own) btn.classList.add('own');
  btn.addEventListener('click', () => pick({ ip, endpoint: '', port: 0 }));
  return btn;
}

function renderWho(v) {
  const total = v.internet_events + v.test_events;
  const totalSources = v.internet_sources + v.test_sources;
  if (total === 0) {
    $('who').replaceChildren(el('p', 'empty', 'No events in this window.'));
    return;
  }
  const btn = (label, val, n, s) => {
    const b = el('button', '', label);
    b.type = 'button';
    b.disabled = view.who === val;
    b.addEventListener('click', () => pick({ who: val, ip: '', endpoint: '', port: 0 }));
    b.append(el('span', 'num', count(n)), el('span', 'dim', ` (${plural(s, 'source')})`));
    return b;
  };
  $('who').replaceChildren(
    btn('Internet', '', v.internet_events, v.internet_sources),
    btn('Test', 'own', v.test_events, v.test_sources),
    btn('Both', 'all', total, totalSources)
  );
}

function table(target, heads, rows) {
  const thead = el('thead');
  const tr = el('tr');
  for (const h of heads) {
    const th = el('th', typeof h === 'string' ? '' : h[1], typeof h === 'string' ? h : h[0]);
    tr.append(th);
  }
  thead.append(tr);
  const tbody = el('tbody');
  tbody.append(...rows);
  $(target).replaceChildren(thead, tbody);
}

function row(cells) {
  const tr = el('tr');
  for (const c of cells) {
    const td = el('td', typeof c[1] === 'string' ? c[1] : '');
    if (typeof c[0] === 'string') td.textContent = c[0];
    else td.append(c[0]);
    tr.append(td);
  }
  return tr;
}

function emptyRow(text, span) {
  const tr = el('tr');
  const td = el('td', 'empty', text);
  td.colSpan = span;
  tr.append(td);
  return tr;
}

function renderSources(v) {
  const c = v.sources_status.capture || {}, o = v.sources_status.otel || {}, s = v.sources_status.shipper || {};
  const item = (tone, name, text, title) => {
    const li = el('li');
    li.append(el('span', `dot ${tone}`), el('strong', '', name), el('span', '', text));
    if (title) li.title = title;
    return li;
  };
  const seenC = c.last && !c.last.startsWith('0001');
  let capture;
  if (c.state === 'following') capture = item('good', 'Capture', seenC ? `live, last ${ago(c.last, v.now)}` : 'connected');
  else capture = item('wait', 'Capture', c.detail ? `waiting: ${clip(c.detail, 90)}` : 'connecting', c.detail);
  const seenO = o.last && !o.last.startsWith('0001');
  let otel;
  if (o.state === 'following') otel = item('good', 'OTLP traces', seenO ? `live, last ${ago(o.last, v.now)}` : 'connected');
  else otel = item('wait', 'OTLP traces', o.detail ? `waiting: ${clip(o.detail, 90)}` : 'connecting', o.detail);
  const seenS = s.last && !s.last.startsWith('0001');
  let shipper;
  if (s.state === 'following') shipper = item('good', 'Shipper events', seenS ? `live, last ${ago(s.last, v.now)}` : 'connected');
  else shipper = item('wait', 'Shipper events', s.detail ? `waiting: ${clip(s.detail, 90)}` : 'connecting', s.detail);
  $('sources').replaceChildren(capture, otel, shipper);
}

function renderScope(v) {
  const box = $('scope');
  const parts = [];
  if (view.ip) parts.push(`Source: ${view.ip}`);
  if (view.endpoint) parts.push(`Endpoint: ${view.endpoint}`);
  if (view.port) parts.push(`Port: ${view.port}`);
  if (view.q) parts.push(`Text: ${view.q}`);
  if (parts.length) {
    const p = el('p');
    p.append(el('strong', '', 'Filters: '), parts.join(' • '));
    const clear = el('button', '', 'Clear');
    clear.type = 'button';
    clear.addEventListener('click', () => pick({ ip: '', endpoint: '', port: 0, q: '' }));
    p.append(' ', clear);
    box.replaceChildren(p);
  } else {
    box.replaceChildren();
  }
}

function renderTotals(v) {
  let events = v.internet_events, sources = v.internet_sources;
  if (view.who === 'own') {
    events = v.test_events;
    sources = v.test_sources;
  } else if (view.who === 'all') {
    events += v.test_events;
    sources += v.test_sources;
  }
  $('totals').textContent = `${plural(events, 'event')} from ${plural(sources, 'source')}`;
}

function renderTimeline(v) {
  if (!changed('timeline', [v.timeline, v.since, v.now])) return;
  const g = $('timeline'), n = v.timeline.length, h = 64;
  const max = Math.max(1, ...v.timeline.map(([requests, connections]) => requests + connections));
  g.setAttribute('viewBox', `0 0 ${n * 10} ${h}`);
  const bars = [svg('rect', { x: 0, y: h - 1, width: n * 10, height: 1, class: 'fill-request', opacity: 0.25 })];
  const span = (new Date(v.now) - new Date(v.since)) / n;
  v.timeline.forEach(([requests, connections], i) => {
    const at = clock(new Date(new Date(v.since).getTime() + i * span).toISOString());
    const requestHeight = (requests / max) * (h - 2);
    const connectionHeight = (connections / max) * (h - 2);
    if (requests) {
      bars.push(svg('rect', { x: i * 10 + 1, y: h - 1 - requestHeight, width: 8, height: requestHeight, class: 'fill-request' }));
    }
    if (connections) {
      bars.push(svg('rect', {
        x: i * 10 + 1,
        y: h - 1 - requestHeight - connectionHeight,
        width: 8,
        height: connectionHeight,
        class: 'fill-connection'
      }));
    }
    if (requests || connections) {
      const hit = svg('rect', { x: i * 10, y: 0, width: 10, height: h, fill: 'transparent' });
      hit.append(svg('title', {}, `${at}: ${plural(requests, 'request')}, ${plural(connections, 'pre-HTTP connection')}`));
      bars.push(hit);
    }
  });
  g.replaceChildren(...bars);
  const key = (cls, text) => {
    const item = el('span', 'key');
    item.append(el('i', cls), text);
    return item;
  };
  const legend = el('span');
  legend.append(key('fill-request', 'HTTP requests'), key('fill-connection', 'Pre-HTTP connections'));
  $('timeline-caption').replaceChildren(
    legend,
    el('span', '', `${clock(v.since)} to ${clock(v.now)}, peak ${count(max)} per bar`)
  );
}

function renderFlow(v) {
  const box = $('flow');
  if (!changed('flow', [v.flow, box.clientWidth])) return;
  const { nodes, links } = v.flow;
  if (!links.length) {
    box.replaceChildren(el('p', 'empty', 'No flow in this selection.'));
    return;
  }
  const sources = nodes.filter((node) => node.side === 'source');
  const targets = nodes.filter((node) => node.side === 'target');
  const width = Math.max(720, box.clientWidth - 8), rowHeight = 26;
  const leftPadding = 190, rightPadding = Math.min(430, width * 0.45);
  const leftX = leftPadding, rightX = width - rightPadding;
  const height = Math.max(sources.length, targets.length) * rowHeight + 6;
  const graph = svg('svg', {
    width,
    height,
    viewBox: `0 0 ${width} ${height}`,
    role: 'img',
    'aria-label': 'Flow of events from source addresses to endpoints. The two tables below hold the same data.'
  });
  const y = (i) => i * rowHeight + rowHeight / 2 + 3;
  const leftY = new Map(sources.map((node, i) => [node.id, y(i)]));
  const rightY = new Map(targets.map((node, i) => [node.id, y(i)]));
  const sourceByID = new Map(sources.map((node) => [node.id, node]));
  const targetByID = new Map(targets.map((node) => [node.id, node]));
  const max = Math.max(...links.map((link) => link.value));
  for (const link of links) {
    const sourceY = leftY.get(link.source), targetY = rightY.get(link.target);
    const source = sourceByID.get(link.source), target = targetByID.get(link.target);
    const middle = (leftX + rightX) / 2;
    const path = svg('path', {
      d: `M${leftX + 6},${sourceY} C${middle},${sourceY} ${middle},${targetY} ${rightX},${targetY}`,
      'stroke-width': 1 + 11 * Math.sqrt(link.value / max),
      class: target.name.includes(' pre-HTTP ') ? 'pre' : ''
    });
    path.append(svg('title', {}, `${sourceName(source.name)} to ${target.name}: ${plural(link.value, 'event')}`));
    graph.append(path);
  }
  const nodeGroup = (node, side) => {
    const fixed = node.other;
    const group = svg('g', { class: fixed ? 'node fixed' : 'node' });
    const yy = side === 'source' ? leftY.get(node.id) : rightY.get(node.id);
    const label = node.name;
    if (side === 'source') {
      group.append(svg('rect', { x: leftX, y: yy - 9, width: 6, height: 18, rx: 2 }));
      group.append(svg('text', { x: leftX - 10, y: yy + 4, 'text-anchor': 'end' }, clip(sourceName(label), 20)));
      group.append(svg('text', { x: 8, y: yy + 4, class: 'count' }, count(node.count)));
    } else {
      group.append(svg('rect', { x: rightX, y: yy - 9, width: 6, height: 18, rx: 2 }));
      group.append(svg('text', { x: rightX + 14, y: yy + 4 }, clip(label, Math.floor((rightPadding - 80) / 7.3))));
      group.append(svg('text', { x: width - 6, y: yy + 4, 'text-anchor': 'end', class: 'count' }, count(node.count)));
    }
    group.append(svg('title', {}, `${label}: ${plural(node.count, 'event')}`));
    if (!fixed) {
      const go = () => pick(side === 'source'
        ? { ip: node.name, endpoint: '' }
        : { endpoint: node.name, ip: '' });
      group.setAttribute('tabindex', '0');
      group.setAttribute('role', 'button');
      group.setAttribute('aria-label', `Show only ${label}`);
      group.addEventListener('click', go);
      group.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          go();
        }
      });
    }
    return group;
  };
  for (const source of sources) graph.append(nodeGroup(source, 'source'));
  for (const target of targets) graph.append(nodeGroup(target, 'target'));
  box.replaceChildren(graph);
}

function renderTables(v) {
  if (changed('sources-table', v.sources)) {
    const rows = v.sources.slice(0, 20).map((r) => {
      const btn = ipButton(r.ip, r.own);
      return row([[btn], [count(r.count), 'num'], [clock(r.last)], [clip(r.ua, 60)]]);
    });
    table('sources-table', [['Source IP'], ['Events', 'num'], ['Last seen'], ['User-agent']], rows.length ? rows : [emptyRow('No sources in this selection.', 4)]);
  }
  if (changed('endpoints-table', v.endpoints)) {
    const rows = v.endpoints.slice(0, 20).map((r) => {
      const btn = el('button', 'link', r.endpoint);
      btn.type = 'button';
      btn.addEventListener('click', () => pick({ endpoint: r.endpoint, ip: '', port: 0 }));
      return row([[btn, 'wide'], [count(r.count), 'num']]);
    });
    table('endpoints-table', [['Endpoint', 'wide'], ['Events', 'num']], rows.length ? rows : [emptyRow('No endpoints in this selection.', 2)]);
  }
}

function renderPorts(v) {
  if (!changed('ports', v.ports)) return;
  const rows = v.ports.map((r) => {
    const btn = el('button', 'link', String(r.port));
    btn.type = 'button';
    btn.disabled = view.port === r.port;
    btn.addEventListener('click', () => pick({ port: r.port, ip: '', endpoint: '' }));
    const last = r.last && !r.last.startsWith('0001') ? clock(r.last) : '—';
    return row([[btn], [count(r.requests), 'num'], [count(r.connections), 'num'], [count(r.sources), 'num'], [last]]);
  });
  table('ports', [['Port'], ['Requests', 'num'], ['Pre-HTTP', 'num'], ['Sources', 'num'], ['Last seen']], rows);
}

function renderFeed(v) {
  const key = `${view.window}|${view.who}|${view.q}|${view.ip}|${view.endpoint}|${view.port}|${v.feed ? v.feed.length : 0}|${v.feed && v.feed[0] ? v.feed[0].seq : 0}`;
  if (key === view.feedKey) return;
  view.feedKey = key;
  const rows = (v.feed || []).map((e) => {
    const what = el('span');
    if (e.kind === 'connection') {
      what.append(el('span', 'pre', `no HTTP: ${e.outcome}`), e.sni ? ` (${e.sni})` : '');
    } else if (e.kind === 'security') {
      what.append(el('span', 'pre', e.rule_name || e.block_type), e.priority ? ` [${e.priority}]` : '');
    } else if (e.kind === 'bait') {
      const line = el('div');
      line.append(el('span', 'method', e.method || '?'), el('span', 'mono', e.route));
      what.append(line);
    } else {
      const line1 = el('div');
      line1.append(el('span', 'method', e.method || '?'), el('span', 'mono', e.target || e.route));
      what.append(line1);
      if (e.preview) {
        const line2 = el('div', 'preview', e.preview);
        what.append(line2);
      }
    }
    const open = el('button', 'link');
    const time = clock(e.time);
    open.append(e.has_prompt ? el('mark', '', `${time} · Prompt in body`) : time);
    open.type = 'button';
    open.title = `${e.time} · Open full event`;
    const tr = row([[open], [ipButton(e.ip, e.origin === 'test')], [what, 'wide'],
      [e.status ? String(e.status) : '', e.status ? `num s${Math.floor(e.status / 100)}` : 'num'],
      [e.kind === 'connection' ? 'pre-HTTP' : (e.probe || e.route || e.kind)],
      [e.user_agent || '', 'ua'], [e.body_bytes ? count(e.body_bytes) : '', 'num']]);
    if (e.seq === view.selected) tr.className = 'selected';
    tr.addEventListener('click', () => openDetail(e.seq, open));
    return tr;
  });
  table('feed', [['Time'], ['Source IP'], ['Request'], ['Status', 'num'], ['Route'], ['User-agent'], ['Body', 'num']],
    rows.length ? rows : [emptyRow('No events match.', 7)]);
}

function closeDetail() {
  $('detail').hidden = true;
  document.body.classList.remove('detail-open');
  if (view.opener) view.opener.focus();
}

async function openDetail(seq, opener) {
  const res = await fetch(`api/event?seq=${seq}`);
  if (!res.ok) return;
  const e = await res.json();
  view.selected = seq;
  view.opener = opener;
  view.feedKey = '';
  const box = $('detail');
  const head = el('header');
  const title = el('h2', '', e.kind === 'connection' ? `Connection: ${e.outcome}` : e.kind === 'security' ? `Security: ${e.rule_name || e.block_type}` : `${e.method} ${e.target || e.route}`);
  title.id = 'detail-title';
  title.tabIndex = -1;
  const close = el('button', '', 'Close');
  close.type = 'button';
  close.addEventListener('click', closeDetail);
  head.append(title, close);

  const facts = el('dl');
  const fact = (name, value) => { if (value !== '' && value != null) facts.append(el('dt', '', name), typeof value === 'string' ? el('dd', '', value) : value); };
  const d = new Date(e.time);
  const src = el('dd');
  src.append(ipButton(e.ip, e.origin === 'test'));
  fact('Time', `${d.toISOString()} (${clock(e.time)} local)`);
  fact('Origin', e.origin === 'internet' ? 'Internet' : 'Test');
  fact('Source IP', src);
  fact('Port', String(e.port));
  fact('Protocol', e.proto);
  fact('Host', e.host);
  fact('User-agent', e.user_agent);
  fact('Status', e.status ? String(e.status) : '');
  fact('Route', e.route);
  fact('Probe', e.probe);
  fact('SNI', e.sni);
  fact('Outcome', e.outcome);
  fact('Content type', e.content_type);
  fact('Model', e.model);
  fact('Stream', e.stream ? 'yes' : '');
  fact('Tools', e.tools);
  fact('System message', e.system_msg ? 'yes' : '');
  fact('MCP method', e.mcp_method);
  fact('Canary key', e.canary_key);
  fact('Credential', e.credential);
  fact('Rule', e.rule_name);
  fact('Priority', e.priority);
  fact('Block type', e.block_type);
  fact('Data source', e.source);
  const parts = [head, facts];
  if (e.has_prompt) parts.push(el('h3', '', 'User prompt preview'), el('pre', '', e.preview));

  const pairs = (heading, list) => {
    if (!list.length) return;
    parts.push(el('h3', '', heading));
    const t = el('table');
    const body = el('tbody');
    body.append(...list.map(([k, val]) => row([[k], [val]])));
    t.append(body);
    parts.push(t);
  };
  const query = (e.target || '').split('?').slice(1).join('?');
  if (query) pairs('Query string', [...new URLSearchParams(query)]);
  if (e.headers) pairs('Request headers', e.headers);

  if (e.body) {
    const line = el('div', 'row');
    const copy = el('button', '', 'Copy body');
    copy.type = 'button';
    copy.addEventListener('click', async () => { await navigator.clipboard.writeText(e.body); copy.textContent = 'Copied'; });
    line.append(el('h3', '', `Request body, ${plural(e.body_bytes, 'byte')}${e.body_truncated ? ' (stored part only)' : ''}`), copy);
    parts.push(line, el('pre', '', e.body));
    if (e.body_sha256) parts.push(el('p', 'note mono', `SHA-256 ${e.body_sha256}`));
  } else if (e.body_bytes) {
    parts.push(el('p', 'note', `The client sent ${plural(e.body_bytes, 'byte')}. This record does not hold its content.`));
  }
  box.replaceChildren(...parts);
  box.hidden = false;
  document.body.classList.add('detail-open');
  title.focus();
  tick(true);
}

function renderAIActivity(v) {
  if (!changed('ai-activity', v.ai_activity)) return;
  const rows = v.ai_activity.map((r) => {
    const btn = ipButton(r.ip, false);
    const models = r.models.join(', ') || '—';
    const tools = r.tools.length ? r.tools.join(', ') : '—';
    const flags = [];
    if (r.has_system) flags.push('system');
    if (r.has_stream) flags.push('stream');
    const uas = r.user_agents.join(', ') || '—';
    return row([[btn], [count(r.chat), 'num'], [count(r.gen), 'num'], [models, 'wide'], [tools, 'wide'], [flags.join(', ')], [uas, 'ua']]);
  });
  table('ai-activity', [['Source IP'], ['Chat', 'num'], ['Generation', 'num'], ['Models', 'wide'], ['Tools', 'wide'], ['Flags'], ['User-agents']],
    rows.length ? rows : [emptyRow('No AI activity in this selection.', 7)]);
}

function renderChains(v) {
  if (!changed('chains', v.chains)) return;
  const rows = v.chains.map((c) => {
    const btn = ipButton(c.ip, false);
    const kind = c.chain.replace(/_/g, ' ');
    const steps = [];
    if (c.chain === 'open_webui') {
      steps.push(`signup: ${clock(c.signup)}`, `create: ${clock(c.create)}`, `delete: ${clock(c.delete)}`);
    } else if (c.chain === 'litellm') {
      steps.push(`generate: ${clock(c.generate)}`);
      if (c.use) steps.push(`use: ${clock(c.use)}`);
    } else if (c.chain === 'canary_reuse') {
      steps.push(`served: ${clock(c.served)}`, `reused: ${clock(c.reused)}`);
    } else if (c.chain === 'mcp') {
      steps.push(`initialize: ${clock(c.initialize)}`, `tools/list: ${clock(c.tools_list)}`, `tools/call: ${clock(c.tools_call)}`);
    }
    const complete = c.complete ? 'complete' : 'partial';
    return row([[btn], [kind], [steps.join(', '), 'wide'], [complete]]);
  });
  table('chains', [['Source IP'], ['Chain'], ['Steps', 'wide'], ['Status']],
    rows.length ? rows : [emptyRow('No exploit chains in this selection.', 4)]);
}

function renderHostSecurity(v) {
  if (!changed('host-security', v.host_security)) return;
  const hs = v.host_security;
  const rows = [];
  const sortedRules = Object.entries(hs.falco_rules).sort((a, b) => b[1] - a[1]);
  for (const [rule, cnt] of sortedRules) {
    rows.push(row([['Falco rule'], [rule, 'wide'], [count(cnt), 'num']]));
  }
  const sortedPriorities = Object.entries(hs.falco_priorities).sort((a, b) => b[1] - a[1]);
  for (const [priority, cnt] of sortedPriorities) {
    rows.push(row([['Falco priority'], [priority], [count(cnt), 'num']]));
  }
  const sortedBlocks = Object.entries(hs.egress_blocks).sort((a, b) => b[1] - a[1]);
  for (const [blockType, cnt] of sortedBlocks) {
    const label = blockType === 'reply' ? 'Egress reply noise' : 'Egress container-initiated';
    rows.push(row([['Egress block'], [label], [count(cnt), 'num']]));
  }
  table('host-security', [['Type'], ['Detail', 'wide'], ['Count', 'num']],
    rows.length ? rows : [emptyRow('No host security events in this selection.', 3)]);
}

function renderTestEnv(v) {
  if (!changed('test-env', v.test_env)) return;
  const te = v.test_env;
  const rows = [
    row([['Own/test traffic'], [count(te.own_traffic), 'num']]),
    row([['Private bait events'], [count(te.private_bait), 'num']])
  ];
  table('test-env', [['Metric'], ['Count', 'num']], rows);
}

let timer = 0;
async function tick(force) {
  clearTimeout(timer);
  if (!force && view.paused) return;
  try {
    const params = new URLSearchParams({ window: view.window, who: view.who, q: view.q, ip: view.ip, endpoint: view.endpoint, port: view.port });
    const res = await fetch(`api/state?${params}`);
    if (!res.ok) return;
    const v = await res.json();
    try { renderSources(v); } catch (e) { console.error('renderSources:', e); }
    try { renderWho(v); } catch (e) { console.error('renderWho:', e); }
    try { renderScope(v); } catch (e) { console.error('renderScope:', e); }
    try { renderTotals(v); } catch (e) { console.error('renderTotals:', e); }
    try { renderTimeline(v); } catch (e) { console.error('renderTimeline:', e); }
    try { renderFlow(v); } catch (e) { console.error('renderFlow:', e); }
    try { renderPorts(v); } catch (e) { console.error('renderPorts:', e); }
    try { renderTables(v); } catch (e) { console.error('renderTables:', e); }
    try { renderAIActivity(v); } catch (e) { console.error('renderAIActivity:', e); }
    try { renderChains(v); } catch (e) { console.error('renderChains:', e); }
    try { renderHostSecurity(v); } catch (e) { console.error('renderHostSecurity:', e); }
    try { renderTestEnv(v); } catch (e) { console.error('renderTestEnv:', e); }
    try { renderFeed(v); } catch (e) { console.error('renderFeed:', e); }
  } finally {
    if (!view.paused) timer = setTimeout(() => tick(false), 2000);
  }
}

for (const [id, label] of windows) {
  const btn = el('button', '', label);
  btn.type = 'button';
  btn.addEventListener('click', () => {
    view.window = id;
    for (const b of $('windows').children) b.disabled = b === btn;
    tick(true);
  });
  btn.disabled = id === view.window;
  $('windows').append(btn);
}

let typing = 0;
$('q').addEventListener('input', (ev) => {
  clearTimeout(typing);
  typing = setTimeout(() => pick({ q: ev.target.value }), 300);
});
$('pause').addEventListener('click', () => {
  view.paused = !view.paused;
  $('pause').textContent = view.paused ? 'Resume' : 'Pause';
  if (!view.paused) tick(true);
});
document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && !$('detail').hidden) closeDetail(); });
tick(true);
