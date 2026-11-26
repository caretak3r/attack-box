'use strict';
// Every captured value reaches the page through textContent or an SVG text node. Never use innerHTML here.

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};
const svg = (tag, attrs, text) => {
  const n = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const k in attrs) n.setAttribute(k, attrs[k]);
  if (text != null) n.textContent = text;
  return n;
};
const clip = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
const count = (n) => n.toLocaleString('en-US');
const plural = (n, word) => `${count(n)} ${word}${n === 1 ? '' : 's'}`;

const view = { window: '1h', who: '', q: '', ip: '', endpoint: '', port: 0, paused: false, feedKey: '', selected: 0, opener: null };
const windows = [['15m', '15 min'], ['1h', '1 h'], ['6h', '6 h'], ['24h', '24 h'], ['7d', '7 d']];

// Redraw a block only when its data changed, so keyboard focus and text selection survive the two-second refresh.
const drawn = {};
function changed(name, data) {
  const key = JSON.stringify(data);
  if (drawn[name] === key) return false;
  drawn[name] = key;
  return true;
}

function clock(iso) {
  const d = new Date(iso);
  const time = d.toLocaleTimeString('en-GB');
  return d.toDateString() === new Date().toDateString() ? time : `${d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })} ${time}`;
}

function ago(iso, now) {
  const s = Math.max(0, Math.round((new Date(now) - new Date(iso)) / 1000));
  if (s < 90) return `${s} s ago`;
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  return `${Math.round(s / 3600)} h ago`;
}

const sourceName = (ip) => ip || 'unattributed';

function pick(change) {
  Object.assign(view, change);
  view.feedKey = '';
  tick(true);
}

function ipButton(ip, own) {
  if (!ip) return el('span', 'mono', sourceName(ip));
  const b = el('button', 'link', ip);
  b.type = 'button';
  b.title = 'Show only this source';
  b.addEventListener('click', (ev) => { ev.stopPropagation(); pick({ ip, endpoint: '', port: 0 }); });
  if (!own) return b;
  const box = el('span');
  box.append(b, el('span', 'tag', 'own'));
  return box;
}

// The split is counted over the whole window, so it also shows what the current selection hides.
function renderWho(v) {
  const own = v.own_addresses || [];
  if (!changed('who', [v.outside, v.own, own, view.who])) return;
  const box = $('who'), hadFocus = box.contains(document.activeElement);
  const fact = (cls, label, t, more) => {
    const p = el('p', cls);
    p.append(el('strong', '', label), ` ${plural(t.events, 'event')} from ${plural(t.ips, 'source')}${more}`);
    return p;
  };
  const seg = el('div', 'segment');
  seg.setAttribute('role', 'group');
  seg.setAttribute('aria-label', 'Traffic shown');
  for (const [id, label] of [['', 'Outside world'], ['own', 'Own machines'], ['all', 'Both']]) {
    const b = el('button', '', label);
    b.type = 'button';
    b.setAttribute('aria-pressed', String(view.who === id));
    b.addEventListener('click', () => pick({ who: id, ip: '', endpoint: '', port: 0 }));
    seg.append(b);
  }
  const parts = [fact('outside', 'Outside world:', v.outside, ''), fact('', 'Your own machines:', v.own, own.length ? ` (${own.join(', ')})` : ''), seg];
  if (!own.length) parts.push(el('p', 'warn', 'No own address is set, so your tests count as outside traffic. Start attackbox-live with -own and your egress address and the host address.'));
  box.replaceChildren(...parts);
  if (hadFocus) seg.querySelector('[aria-pressed="true"]').focus();
}

function table(target, heads, rows) {
  const t = $(target);
  const head = el('tr');
  for (const [label, cls] of heads) {
    const th = el('th', cls, label);
    th.scope = 'col';
    head.append(th);
  }
  const thead = el('thead');
  thead.append(head);
  const tbody = el('tbody');
  tbody.append(...rows);
  t.replaceChildren(thead, tbody);
}

function row(cells) {
  const tr = el('tr');
  for (const [content, cls] of cells) {
    const td = el('td', cls);
    td.append(content);
    tr.append(td);
  }
  return tr;
}

function emptyRow(text, span) {
  const td = el('td', 'empty', text);
  td.colSpan = span;
  const tr = el('tr');
  tr.append(td);
  return tr;
}

function renderSources(v) {
  const c = v.sources.capture || {}, n = v.sources.newrelic || {};
  const item = (tone, name, text, title) => {
    const li = el('li');
    li.append(el('span', `dot ${tone}`), el('strong', '', name), el('span', '', text));
    if (title) li.title = title;
    return li;
  };
  const seen = c.last && !c.last.startsWith('0001');
  let capture;
  if (c.state === 'following') capture = item('good', 'Host capture', seen ? `live, last record ${ago(c.last, v.now)}` : 'connected, no new record yet');
  else capture = item('wait', 'Host capture', c.detail ? `waiting: ${clip(c.detail, 90)}` : 'connecting', c.detail);
  let relic;
  if (n.state === 'ok') relic = item('good', 'New Relic', `polled ${ago(n.last, v.now)}`);
  else if (n.state === 'error') relic = item('fail', 'New Relic', `error: ${n.detail}`);
  else if (n.state === 'off') relic = item('', 'New Relic', 'off', n.detail);
  else relic = item('wait', 'New Relic', 'first query');
  $('sources').replaceChildren(capture, relic);
}

function renderScope(v) {
  const box = $('scope');
  if (!view.ip && !view.endpoint && !view.port) { box.hidden = true; return; }
  const parts = [];
  if (view.ip) {
    const r = v.top.find((t) => t.ip === view.ip);
    parts.push(el('span', 'subject', `Source ${sourceName(view.ip)}`));
    parts.push(el('span', 'facts', r
      ? `${plural(r.requests, 'request')}, ${plural(r.connections, 'pre-HTTP connection')}, ${plural(r.endpoints, 'endpoint')}, ${plural(r.user_agents, 'user-agent')}. First seen ${clock(r.first)}, last seen ${clock(r.last)}.`
      : 'No event from this source in the window.'));
  } else if (view.port) {
    const r = v.ports.find((p) => p.port === view.port);
    parts.push(el('span', 'subject', `Port ${view.port}`));
    parts.push(el('span', 'facts', r
      ? `${plural(r.requests, 'request')}, ${plural(r.connections, 'pre-HTTP connection')}, ${plural(r.ips, 'source')}.${r.last ? ` Last seen ${clock(r.last)}.` : ''}`
      : 'No event on this port in the window.'));
  } else {
    parts.push(el('span', 'subject', `Endpoint ${view.endpoint}`));
    parts.push(el('span', 'facts', `${plural(v.requests + v.connections, 'event')} from ${plural(v.ips, 'source')}.`));
  }
  const clear = el('button', '', 'Show all traffic');
  clear.type = 'button';
  clear.addEventListener('click', () => pick({ ip: '', endpoint: '', port: 0 }));
  box.replaceChildren(...parts, clear);
  box.hidden = false;
}

function renderTotals(v) {
  const stat = (n, label) => {
    const d = el('div');
    d.append(el('dt', '', label), el('dd', '', count(n)));
    return d;
  };
  $('totals').replaceChildren(stat(v.requests, 'HTTP requests'), stat(v.connections, 'Pre-HTTP connections'), stat(v.ips, 'Sources'));
}

function renderTimeline(v) {
  const g = $('timeline'), n = v.timeline.length, h = 64;
  const max = Math.max(1, ...v.timeline.map(([a, b]) => a + b));
  g.setAttribute('viewBox', `0 0 ${n * 10} ${h}`);
  const bars = [svg('rect', { x: 0, y: h - 1, width: n * 10, height: 1, class: 'fill-request', opacity: 0.25 })];
  const span = (new Date(v.now) - new Date(v.since)) / n;
  v.timeline.forEach(([req, con], i) => {
    const at = clock(new Date(new Date(v.since).getTime() + i * span).toISOString());
    const rh = (req / max) * (h - 2), ch = (con / max) * (h - 2);
    if (req) bars.push(svg('rect', { x: i * 10 + 1, y: h - 1 - rh, width: 8, height: rh, class: 'fill-request' }));
    if (con) bars.push(svg('rect', { x: i * 10 + 1, y: h - 1 - rh - ch, width: 8, height: ch, class: 'fill-connection' }));
    if (req || con) {
      const hit = svg('rect', { x: i * 10, y: 0, width: 10, height: h, fill: 'transparent' });
      hit.append(svg('title', {}, `${at}: ${plural(req, 'request')}, ${plural(con, 'pre-HTTP connection')}`));
      bars.push(hit);
    }
  });
  g.replaceChildren(...bars);
  const key = (cls, text) => { const s = el('span', 'key'); s.append(el('i', cls), text); return s; };
  const left = el('span');
  left.append(key('fill-request', 'HTTP requests'), key('fill-connection', 'Pre-HTTP connections'));
  $('timeline-caption').replaceChildren(left, el('span', '', `${clock(v.since)} to ${clock(v.now)}, peak ${count(max)} per bar`));
}

function renderFlow(v) {
  const box = $('flow');
  if (!changed('flow', [v.flow_sources, v.flow_targets, v.flow_links, box.clientWidth])) return;
  if (!v.flow_links) {
    box.replaceChildren(el('p', 'empty', 'No traffic in this window. Select a longer window, or wait: the page reads new data every two seconds.'));
    return;
  }
  const width = Math.max(720, box.clientWidth - 8), rowH = 26, padL = 190, padR = Math.min(430, width * 0.45);
  const xl = padL, xr = width - padR;
  const height = Math.max(v.flow_sources.length, v.flow_targets.length) * rowH + 6;
  const g = svg('svg', { width, height, viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': 'Flow of events from source addresses to endpoints. The two tables below hold the same data.' });
  const y = (i) => i * rowH + rowH / 2 + 3;
  const ly = new Map(v.flow_sources.map((s, i) => [s.id, y(i)]));
  const ry = new Map(v.flow_targets.map((t, i) => [t.id, y(i)]));
  const max = Math.max(...v.flow_links.map((l) => l.count));
  for (const l of v.flow_links) {
    const a = ly.get(l.source), b = ry.get(l.target), mid = (xl + xr) / 2;
    const p = svg('path', { d: `M${xl + 6},${a} C${mid},${a} ${mid},${b} ${xr},${b}`, 'stroke-width': 1 + 11 * Math.sqrt(l.count / max), class: l.target.includes(' pre-HTTP ') ? 'pre' : '' });
    p.append(svg('title', {}, `${sourceName(l.source)} to ${l.target}: ${plural(l.count, 'event')}`));
    g.append(p);
  }
  const nodeGroup = (n, side) => {
    const fixed = n.id === 'other';
    const grp = svg('g', { class: fixed ? 'node fixed' : 'node' });
    const yy = side === 'l' ? ly.get(n.id) : ry.get(n.id);
    const label = fixed ? (side === 'l' ? 'other sources' : 'other endpoints') : (side === 'l' ? sourceName(n.id) : n.id);
    if (side === 'l') {
      grp.append(svg('rect', { x: xl, y: yy - 9, width: 6, height: 18, rx: 2 }));
      grp.append(svg('text', { x: xl - 10, y: yy + 4, 'text-anchor': 'end' }, clip(label, 20)));
      grp.append(svg('text', { x: 8, y: yy + 4, class: 'count' }, count(n.count)));
    } else {
      grp.append(svg('rect', { x: xr, y: yy - 9, width: 6, height: 18, rx: 2 }));
      grp.append(svg('text', { x: xr + 14, y: yy + 4 }, clip(label, Math.floor((padR - 80) / 7.3))));
      grp.append(svg('text', { x: width - 6, y: yy + 4, 'text-anchor': 'end', class: 'count' }, count(n.count)));
    }
    grp.append(svg('title', {}, `${label}: ${plural(n.count, 'event')}`));
    if (!fixed) {
      const go = () => pick(side === 'l' ? { ip: n.id, endpoint: '' } : { endpoint: n.id, ip: '' });
      grp.setAttribute('tabindex', '0');
      grp.setAttribute('role', 'button');
      grp.setAttribute('aria-label', `Show only ${label}`);
      grp.addEventListener('click', go);
      grp.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); go(); } });
    }
    return grp;
  };
  for (const s of v.flow_sources) g.append(nodeGroup(s, 'l'));
  for (const t of v.flow_targets) g.append(nodeGroup(t, 'r'));
  box.replaceChildren(g);
}

function renderTables(v) {
  if (!changed('tables', [v.top, v.endpoints])) return;
  table('ips', [['Source IP'], ['Requests', 'num'], ['Pre-HTTP', 'num'], ['Endpoints', 'num'], ['Last seen'], ['Most used user-agent']],
    v.top.length ? v.top.map((r) => row([[ipButton(r.ip, r.own)], [count(r.requests), 'num'], [count(r.connections), 'num'], [count(r.endpoints), 'num'],
      [clock(r.last)], [r.user_agent ? (r.user_agents > 1 ? `${r.user_agent} (+${r.user_agents - 1} more)` : r.user_agent) : 'not recorded', 'ua']]))
      : [emptyRow('No source in this window.', 6)]);
  table('endpoints', [['Port and endpoint'], ['Events', 'num'], ['Sources', 'num']],
    v.endpoints.length ? v.endpoints.map((e) => {
      const b = el('button', 'link', e.id);
      b.type = 'button';
      b.title = 'Show only this endpoint';
      b.addEventListener('click', () => pick({ endpoint: e.id, ip: '', port: 0 }));
      return row([[b, 'wide'], [count(e.count), 'num'], [count(e.ips), 'num']]);
    }) : [emptyRow('No endpoint in this window.', 3)]);
}

function renderPorts(v) {
  if (!changed('ports', [v.ports, view.port])) return;
  table('ports', [['Port'], ['Requests', 'num'], ['Pre-HTTP', 'num'], ['Sources', 'num'], ['Last seen']],
    v.ports.length ? v.ports.map((p) => {
      const b = el('button', 'link', String(p.port));
      b.type = 'button';
      b.title = 'Show only this port';
      b.setAttribute('aria-pressed', String(p.port === view.port));
      b.addEventListener('click', () => pick({ port: p.port === view.port ? 0 : p.port, ip: '', endpoint: '' }));
      const tr = row([[b], [count(p.requests), 'num'], [count(p.connections), 'num'], [count(p.ips), 'num'], [p.last ? clock(p.last) : '']]);
      if (p.port === view.port) tr.className = 'selected';
      return tr;
    }) : [emptyRow('No port configured.', 5)]);
}

function renderFeed(v) {
  const key = `${view.window}|${view.who}|${view.q}|${view.ip}|${view.endpoint}|${view.port}|${v.feed ? v.feed.length : 0}|${v.feed && v.feed[0] ? v.feed[0].seq : 0}`;
  if (key === view.feedKey) return;
  view.feedKey = key;
  const rows = (v.feed || []).map((e) => {
    const what = el('span');
    if (e.kind === 'connection') {
      what.append(el('span', 'pre', `no HTTP request: ${e.outcome}`), e.sni ? ` (SNI ${e.sni})` : '');
    } else {
      what.append(el('span', 'method', e.method || '?'), el('span', 'mono', e.target || `${e.route} (path not exported)`));
    }
    const open = el('button', 'link', clock(e.time));
    open.type = 'button';
    open.title = 'Open the full event';
    const tr = row([[open], [ipButton(e.ip, e.own)], [what, 'wide'],
      [e.status ? String(e.status) : '', e.status ? `num s${Math.floor(e.status / 100)}` : 'num'],
      [e.kind === 'connection' ? 'pre-HTTP' : (e.probe || e.route || '')],
      [e.user_agent || '', 'ua'], [e.body_bytes ? count(e.body_bytes) : '', 'num']]);
    if (e.seq === view.selected) tr.className = 'selected';
    tr.addEventListener('click', () => openDetail(e.seq, open));
    return tr;
  });
  table('feed', [['Time'], ['Source IP'], ['Request'], ['Status', 'num'], ['Route or probe class'], ['User-agent'], ['Body bytes', 'num']],
    rows.length ? rows : [emptyRow('No event matches. Until the gateway release with host capture is live, New Relic gives only the route label, status and source address.', 7)]);
}

function closeDetail() {
  $('detail').hidden = true;
  document.body.classList.remove('detail-open');
  view.selected = 0;
  for (const tr of document.querySelectorAll('tr.selected')) tr.className = '';
  if (view.opener && view.opener.isConnected) view.opener.focus();
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
  const title = el('h2', '', e.kind === 'connection' ? `Connection without an HTTP request: ${e.outcome}` : `${e.method} ${e.target || e.route}`);
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
  src.append(ipButton(e.ip, e.own));
  fact('Time', `${d.toISOString()} (${clock(e.time)} local)`);
  fact('Source IP', src);
  fact('Listener port', String(e.port));
  fact('Protocol', e.proto);
  fact('Host header', e.host);
  fact('User-agent', e.user_agent);
  fact('Status', e.status ? String(e.status) : '');
  fact('Route', e.route);
  fact('Probe class', e.probe);
  fact('TLS server name', e.sni);
  fact('Content type', e.content_type);
  fact('Model', e.model);
  fact('Data source', e.source === 'capture' ? 'Host capture file' : 'New Relic span');
  const parts = [head, facts];

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
    parts.push(el('p', 'note', `The client sent a body of ${plural(e.body_bytes, 'byte')}. This record does not hold its content.`));
  }
  if (e.source === 'newrelic') {
    parts.push(el('p', 'note', 'New Relic holds labels only. The path, query string, user-agent, headers and body stay in the host capture file and are shown when that source is connected.'));
  }
  box.replaceChildren(...parts);
  box.hidden = false;
  document.body.classList.add('detail-open');
  title.focus();
  tick(true);
}

let timer = 0;
async function tick(force) {
  clearTimeout(timer);
  if (!view.paused || force) {
    try {
      const p = new URLSearchParams({ window: view.window, who: view.who, q: view.q, ip: view.ip, endpoint: view.endpoint, port: view.port || '' });
      const res = await fetch(`api/state?${p}`);
      if (!res.ok) throw new Error(String(res.status));
      const v = await res.json();
      v.top = v.top || [];
      v.endpoints = v.endpoints || [];
      v.ports = v.ports || [];
      renderSources(v);
      renderWho(v);
      renderScope(v);
      renderTotals(v);
      renderTimeline(v);
      renderFlow(v);
      renderTables(v);
      renderPorts(v);
      renderFeed(v);
      $('offline').hidden = true;
    } catch (err) {
      $('offline').hidden = false;
    }
  }
  timer = setTimeout(tick, 2000);
}

for (const [id, label] of windows) {
  const b = el('button', '', label);
  b.type = 'button';
  b.setAttribute('aria-pressed', String(id === view.window));
  b.addEventListener('click', () => {
    for (const other of $('windows').children) other.setAttribute('aria-pressed', String(other === b));
    pick({ window: id });
  });
  $('windows').append(b);
}

let typing = 0;
$('q').addEventListener('input', (ev) => {
  clearTimeout(typing);
  typing = setTimeout(() => pick({ q: ev.target.value.trim() }), 250);
});
$('pause').addEventListener('click', () => {
  view.paused = !view.paused;
  $('pause').setAttribute('aria-pressed', String(view.paused));
  $('pause').textContent = view.paused ? 'Resume' : 'Pause';
  if (!view.paused) tick(true);
});
document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && !$('detail').hidden) closeDetail(); });
tick(true);
