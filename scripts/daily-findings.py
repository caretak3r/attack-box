"""Refresh one local UTC report. Only aggregate counts cross SSH."""
import argparse
import datetime as dt
import ipaddress
import json
import os
import shlex
from pathlib import Path
import subprocess
import sys
import tempfile

UTC = dt.timezone.utc
BLOCKS = ('OUTPUT-DROP:', 'CONTAINER-EGRESS-BLOCK:', 'METADATA-BLOCK:', 'METADATA-BLOCK-OUT:')
LABELS = ('Capture records', 'Known operator or host', 'Local or unknown peer',
          'Outside HTTP requests', 'Distinct outside addresses', 'Environment-file requests',
          'Version-control probes', 'WordPress probes', 'AI discovery probes on unmatched routes',
          'Model-list requests', 'Generation or chat requests', 'HTTP 2xx', 'HTTP 4xx', 'HTTP 5xx',
          'Other HTTP status', 'Retained Falco events', *BLOCKS)
MARK = '<!-- end daily totals -->'
ENDPOINT_CATEGORIES = ('Environment files', 'Version control', 'WordPress', 'AI discovery (unmatched)',
                       'Model list', 'AI generation', 'Other')
# Numeric IDs for SSH transport (index into ENDPOINT_CATEGORIES)
ENDPOINT_ENV = 0
ENDPOINT_VCS = 1
ENDPOINT_WORDPRESS = 2
ENDPOINT_AI_DISCOVERY = 3
ENDPOINT_MODEL_LIST = 4
ENDPOINT_AI_GEN = 5
ENDPOINT_OTHER = 6


def stamp(value):
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(UTC)


def collect(day, own):
    start = dt.datetime.combine(day, dt.time(), UTC)
    end = min(start + dt.timedelta(days=1), dt.datetime.now(UTC).replace(microsecond=0))
    if end <= start:
        raise ValueError('future day')
    counts = dict.fromkeys(LABELS, 0)
    peers = set()
    flows = {}  # (port, endpoint_category, status) -> count
    path = Path('/var/lib/attackbox-public-capture/requests') / f'capture-{day:%Y%m%d}.jsonl'
    with path.open('rb') as stream:
        for line in stream:
            row = json.loads(line)
            when = stamp(row['time'])
            if when.date() != day:
                raise ValueError('capture date mismatch')
            if when >= end:
                continue
            counts['Capture records'] += 1
            try:
                ip = ipaddress.ip_address(row.get('peer', ''))
            except ValueError:
                ip = None
            if ip in own:
                counts['Known operator or host'] += 1
                continue
            if not ip or not ip.is_global or ip.is_multicast:
                counts['Local or unknown peer'] += 1
                continue
            peers.add(ip)
            counts['Outside HTTP requests'] += 1
            route, probe, status = row.get('route', ''), row.get('probe', ''), int(row['status'])
            port = row.get('port', 0)
            counts['Environment-file requests'] += route == '/.env' or probe == 'env_file'
            for key, label in [('vcs', 'Version-control probes'), ('wordpress', 'WordPress probes'),
                               ('llm_api', 'AI discovery probes on unmatched routes')]:
                counts[label] += probe == key
            counts['Model-list requests'] += route.endswith(('/models', '/api/tags'))
            counts['Generation or chat requests'] += route.endswith(('/completions', '/messages', '/api/generate', '/api/chat'))
            label = f"HTTP {status // 100}xx"
            counts[label if label in counts else 'Other HTTP status'] += 1
            # Categorize endpoint for flow tracking (numeric ID for SSH transport)
            if route == '/.env' or probe == 'env_file':
                endpoint_id = ENDPOINT_ENV
            elif probe == 'vcs':
                endpoint_id = ENDPOINT_VCS
            elif probe == 'wordpress':
                endpoint_id = ENDPOINT_WORDPRESS
            elif probe == 'llm_api':
                endpoint_id = ENDPOINT_AI_DISCOVERY
            elif route.endswith(('/models', '/api/tags')):
                endpoint_id = ENDPOINT_MODEL_LIST
            elif route.endswith(('/completions', '/messages', '/api/generate', '/api/chat')):
                endpoint_id = ENDPOINT_AI_GEN
            else:
                endpoint_id = ENDPOINT_OTHER
            flows[(port, endpoint_id, status)] = flows.get((port, endpoint_id, status), 0) + 1
    counts['Distinct outside addresses'] = len(peers)
    with open('/var/log/falco-events.jsonl', 'rb') as stream:
        for line in stream:
            row = json.loads(line)
            if not isinstance(row, dict) or not row.get('time'):
                continue  # An undated Falco row cannot belong to a daily count.
            when = stamp(row['time'])
            counts['Retained Falco events'] += start <= when < end
    # The journal's end is inclusive. Exclude the first instant of the next day.
    rows = subprocess.check_output(['journalctl', '-q', '--no-pager', '_TRANSPORT=kernel',
                                    '--since', f'@{int(start.timestamp())}', '--until',
                                    f'@{int(end.timestamp()) - 1}.999999', '-o', 'json', '--output-fields=MESSAGE'])
    for line in rows.splitlines():
        msg = json.loads(line).get('MESSAGE', '')
        if isinstance(msg, str):
            for key in BLOCKS:
                counts[key] += key in msg
    return {'end': int(end.timestamp()), 'counts': [counts[k] for k in LABELS],
            'flows': sorted([[port, endpoint_id, status, count] for (port, endpoint_id, status), count in flows.items()])}


def report(day, snapshot):
    if not isinstance(snapshot, dict) or 'end' not in snapshot or 'counts' not in snapshot:
        raise ValueError('invalid aggregate response')
    values = snapshot['counts']
    if not isinstance(values, list) or len(values) != len(LABELS) or not all(type(v) is int and 0 <= v < 2**48 for v in values):
        raise ValueError('invalid aggregate response')
    end = dt.datetime.fromtimestamp(snapshot['end'], UTC)
    start = dt.datetime.combine(day, dt.time(), UTC)
    if not start < end <= start + dt.timedelta(days=1):
        raise ValueError('unexpected report window')
    counts = dict(zip(LABELS, values))
    classified = sum(counts[k] for k in ('Known operator or host', 'Local or unknown peer', 'Outside HTTP requests'))
    statuses = sum(counts[k] for k in ('HTTP 2xx', 'HTTP 4xx', 'HTTP 5xx', 'Other HTTP status'))
    if counts['Capture records'] != classified or counts['Outside HTTP requests'] != statuses:
        raise ValueError('counts do not reconcile')
    flows = snapshot.get('flows', [])
    if not isinstance(flows, list) or not all(isinstance(f, list) and len(f) == 4 for f in flows):
        raise ValueError('invalid flows')
    if counts['Outside HTTP requests'] > 0 and not flows:
        raise ValueError('missing flows for outside requests')
    for port, endpoint_id, status, count in flows:
        if type(port) is not int or not (0 <= port <= 65535):
            raise ValueError('invalid flow port')
        if type(endpoint_id) is not int or not (0 <= endpoint_id < len(ENDPOINT_CATEGORIES)):
            raise ValueError('invalid flow endpoint')
        if type(status) is not int or not (100 <= status <= 599):
            raise ValueError('invalid flow status')
        if type(count) is not int or count <= 0:
            raise ValueError('invalid flow count')
    if sum(f[3] for f in flows) != counts['Outside HTTP requests']:
        raise ValueError('flow counts do not reconcile')
    text = f'# Daily findings — {day} UTC\n\nWindow: {start:%Y-%m-%d %H:%M:%S} to {end:%Y-%m-%d %H:%M:%S} UTC (end exclusive).\n'
    if end.date() == day:
        text += 'Partial day. The next refresh replaces these totals.\n'
    text += f'\n[View in historical archive](https://silent.engineer/attack-box/findings/?day={day}) | [All findings](https://silent.engineer/attack-box/findings/)\n'
    for title, keys in [('Public request capture', LABELS[:5]), ('Outside request details', LABELS[5:15]), ('Host security logs', LABELS[15:])]:
        text += f'\n## {title}\n\n| Observation | Count |\n|---|---:|\n'
        text += ''.join(f'| {k} | {counts[k]} |\n' for k in keys)
    return text + ('\nRequest categories select known routes and probes. They do not cover every request. '
                   'HTTP status counts cover every outside request. Addresses are not people.\n\n'
                   'Host counts come from the retained Falco file and kernel journal. They are not linked to individual requests. '
                   'Counts exclude undated Falco rows and connections that ended before HTTP. Retention and capture gaps can reduce totals. '
                   'These logs do not establish exploit success.\n\n' + MARK + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('date', type=dt.date.fromisoformat)
    parser.add_argument('--own', type=ipaddress.ip_address, action='append', default=[], help='additional operator address (repeatable)')
    parser.add_argument('--collect', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.collect:
        client, _, host, _ = os.environ['SSH_CONNECTION'].split()
        print(json.dumps(collect(args.date, {*args.own, ipaddress.ip_address(client), ipaddress.ip_address(host)})))
        return
    remote = ['python3', '-I', '-', str(args.date), '--collect']
    for ip in args.own:
        remote.extend(['--own', str(ip)])
    cmd = ['ssh', '-T', '-oBatchMode=yes', '-oConnectTimeout=10', '-oForwardAgent=no',
           '-oClearAllForwardings=yes', 'attackbox', shlex.join(remote)]
    with open(__file__, 'rb') as source:
        result = subprocess.run(cmd, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
    if result.returncode:
        sys.exit('Daily collection failed; report unchanged. Check SSH access and retained source files.')
    snapshot = json.loads(result.stdout)
    text = report(args.date, snapshot)
    path = Path(__file__).resolve().parents[1] / 'findings' / str(args.date) / 'README.md'
    if path.resolve() != path:
        sys.exit('Refusing a symlink in the findings path.')
    path.parent.mkdir(exist_ok=True)
    if path.exists():
        previous = path.read_text()
        old, marker, appendix = previous.partition(MARK + '\n')
        if not marker:
            sys.exit('Existing report has no daily totals marker; refusing to overwrite it.')
        # Rotated sources can lose history. Keep the better daily evidence.
        counts = dict(zip(LABELS, snapshot['counts']))
        for line in old.splitlines():
            cells = line.strip('|').split(' | ')
            if len(cells) == 2 and cells[0].strip() in ('Capture records', 'Retained Falco events', *BLOCKS):
                if int(cells[1]) > counts[cells[0].strip()]:
                    sys.exit('Retained source count decreased; keeping the existing daily report.')
        text += appendix
    # Write map.json
    map_path = path.with_name('map.json')
    if map_path.resolve() != map_path:
        sys.exit('Refusing a symlink in the map path.')
    map_data = {
        'date': str(args.date),
        'until': dt.datetime.fromtimestamp(snapshot['end'], UTC).isoformat().replace('+00:00', 'Z'),
        'counts': dict(zip(LABELS, snapshot['counts'])),
        'flows': [[port, ENDPOINT_CATEGORIES[category], status, count]
                  for port, category, status, count in snapshot['flows']]
    }
    map_json = json.dumps(map_data, separators=(',', ':')) + '\n'
    if path.exists() and map_path.exists():
        if text == path.read_text() and map_json == map_path.read_text():
            print(f'Unchanged: {path}')
            return
    with tempfile.NamedTemporaryFile('w', dir=path.parent, delete=False) as out:
        out.write(map_json)
    map_tmp = out.name
    with tempfile.NamedTemporaryFile('w', dir=path.parent, delete=False) as out:
        out.write(text)
    os.replace(map_tmp, map_path)
    os.replace(out.name, path)
    print(path)


if __name__ == '__main__':
    main()
