import datetime as dt
import io
import ipaddress
import json
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch


module = runpy.run_path(str(Path(__file__).with_name('daily-findings.py')))


class DailyFindings(unittest.TestCase):
    def test_daily_partition_and_privacy(self):
        day = dt.date(2026, 1, 10)
        timestamp = '2026-01-10T23:59:59.999999999Z'
        rows = [dict(time=timestamp, peer=peer, route='/.env', status=200, body='private-marker', port=443)
                for peer in ('8.8.8.8', '8.8.8.8', '1.1.1.1', '::1', 'missing-peer')]
        capture = io.BytesIO(b'\n'.join(json.dumps(r).encode() for r in rows))
        falco = io.BytesIO(b'{}\n{"time":"2026-01-10T00:00:00Z"}\n{"time":"2026-01-11T00:00:00Z"}\n')
        with patch.object(Path, 'open', return_value=capture), patch('builtins.open', return_value=falco), \
                patch('subprocess.check_output', return_value=b'{"MESSAGE":"OUTPUT-DROP: private-marker"}'):
            snapshot = module['collect'](day, {ipaddress.ip_address('1.1.1.1')})
        text = module['report'](day, snapshot)
        for row in ('Known operator or host | 1', 'Local or unknown peer | 2', 'Outside HTTP requests | 2',
                    'Distinct outside addresses | 1', 'Environment-file requests | 2', 'Retained Falco events | 1', 'OUTPUT-DROP: | 1'):
            self.assertIn(row, text)
        self.assertNotIn('private-marker', text)
        self.assertNotIn('8.8.8.8', text)
        snapshot['counts'][0] += 1
        with self.assertRaisesRegex(ValueError, 'reconcile'):
            module['report'](day, snapshot)

    def test_flow_tracking(self):
        day = dt.date(2026, 1, 10)
        rows = [
            dict(time='2026-01-10T12:00:00Z', peer='8.8.8.8', route='/.env', status=200, port=443, probe='env_file'),
            dict(time='2026-01-10T12:01:00Z', peer='1.1.1.1', route='/.git/config', status=404, port=443, probe='vcs'),
            dict(time='2026-01-10T12:02:00Z', peer='2.2.2.2', route='/v1/models', status=200, port=443, probe=''),
            dict(time='2026-01-10T12:03:00Z', peer='3.3.3.3', route='/v1/chat/completions', status=200, port=8080, probe=''),
        ]
        capture = io.BytesIO(b'\n'.join(json.dumps(r).encode() for r in rows))
        falco = io.BytesIO(b'')
        with patch.object(Path, 'open', return_value=capture), patch('builtins.open', return_value=falco), \
                patch('subprocess.check_output', return_value=b''):
            snapshot = module['collect'](day, set())
        self.assertEqual(len(snapshot['flows']), 4)
        # Verify flow structure: [port, endpoint_id, status, count] with numeric IDs
        flows = {(f[0], f[1], f[2]): f[3] for f in snapshot['flows']}
        self.assertEqual(flows[(443, module['ENDPOINT_ENV'], 200)], 1)
        self.assertEqual(flows[(443, module['ENDPOINT_VCS'], 404)], 1)
        self.assertEqual(flows[(443, module['ENDPOINT_MODEL_LIST'], 200)], 1)
        self.assertEqual(flows[(8080, module['ENDPOINT_AI_GEN'], 200)], 1)
        # Verify flow counts reconcile with request counts
        self.assertEqual(sum(f[3] for f in snapshot['flows']), snapshot['counts'][3])  # Outside HTTP requests
        text = module['report'](day, snapshot)
        self.assertIn('Outside HTTP requests | 4', text)

    def test_flow_privacy(self):
        """Flows must not contain raw routes or IP addresses."""
        day = dt.date(2026, 1, 10)
        rows = [dict(time='2026-01-10T12:00:00Z', peer='8.8.8.8', route='/secret/path', status=200, port=443, probe='')]
        capture = io.BytesIO(b'\n'.join(json.dumps(r).encode() for r in rows))
        falco = io.BytesIO(b'')
        with patch.object(Path, 'open', return_value=capture), patch('builtins.open', return_value=falco), \
                patch('subprocess.check_output', return_value=b''):
            snapshot = module['collect'](day, set())
        # Verify flows only have numeric endpoint IDs in [0, len(ENDPOINT_CATEGORIES))
        for port, endpoint_id, status, count in snapshot['flows']:
            self.assertIsInstance(endpoint_id, int)
            self.assertGreaterEqual(endpoint_id, 0)
            self.assertLess(endpoint_id, len(module['ENDPOINT_CATEGORIES']))
            # Verify no raw routes or IPs in the entire snapshot
            self.assertNotIn('secret', json.dumps(snapshot))
            self.assertNotIn('8.8.8.8', json.dumps(snapshot))

    def test_flow_reconciliation(self):
        """Flow sum must match outside request count."""
        day = dt.date(2026, 1, 10)
        rows = [dict(time='2026-01-10T12:00:00Z', peer='8.8.8.8', route='/test', status=200, port=443, probe='')]
        capture = io.BytesIO(b'\n'.join(json.dumps(r).encode() for r in rows))
        falco = io.BytesIO(b'')
        with patch.object(Path, 'open', return_value=capture), patch('builtins.open', return_value=falco), \
                patch('subprocess.check_output', return_value=b''):
            snapshot = module['collect'](day, set())
        # Valid snapshot
        module['report'](day, snapshot)
        # Break reconciliation
        snapshot['flows'][0][3] += 1
        with self.assertRaisesRegex(ValueError, 'reconcile'):
            module['report'](day, snapshot)

    def test_missing_flows_for_outside_requests(self):
        """Empty flows with outside requests > 0 must fail."""
        day = dt.date(2026, 1, 10)
        snapshot = {
            'end': int(dt.datetime(2026, 1, 11, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp()),
            'counts': [0] * len(module['LABELS']),
            'flows': []
        }
        snapshot['counts'][0] = 5  # Capture records (reconciles with sum of classified)
        snapshot['counts'][3] = 5  # Outside HTTP requests
        snapshot['counts'][11] = 5  # HTTP 2xx (reconciles with outside requests)
        with self.assertRaisesRegex(ValueError, 'missing flows'):
            module['report'](day, snapshot)

    def test_port_bounds(self):
        """Port must be 0-65535."""
        day = dt.date(2026, 1, 10)
        rows = [dict(time='2026-01-10T12:00:00Z', peer='8.8.8.8', route='/test', status=200, port=70000, probe='')]
        capture = io.BytesIO(b'\n'.join(json.dumps(r).encode() for r in rows))
        falco = io.BytesIO(b'')
        with patch.object(Path, 'open', return_value=capture), patch('builtins.open', return_value=falco), \
                patch('subprocess.check_output', return_value=b''):
            snapshot = module['collect'](day, set())
        snapshot['flows'][0][0] = 70000
        with self.assertRaisesRegex(ValueError, 'port'):
            module['report'](day, snapshot)

    def test_status_bounds(self):
        """Status must be 100-599."""
        day = dt.date(2026, 1, 10)
        rows = [dict(time='2026-01-10T12:00:00Z', peer='8.8.8.8', route='/test', status=200, port=443, probe='')]
        capture = io.BytesIO(b'\n'.join(json.dumps(r).encode() for r in rows))
        falco = io.BytesIO(b'')
        with patch.object(Path, 'open', return_value=capture), patch('builtins.open', return_value=falco), \
                patch('subprocess.check_output', return_value=b''):
            snapshot = module['collect'](day, set())
        snapshot['flows'][0][2] = 999
        with self.assertRaisesRegex(ValueError, 'status'):
            module['report'](day, snapshot)

    def test_numeric_endpoint_transport(self):
        """SSH transport uses numeric endpoint IDs, not strings."""
        day = dt.date(2026, 1, 10)
        rows = [dict(time='2026-01-10T12:00:00Z', peer='8.8.8.8', route='/.env', status=200, port=443, probe='env_file')]
        capture = io.BytesIO(b'\n'.join(json.dumps(r).encode() for r in rows))
        falco = io.BytesIO(b'')
        with patch.object(Path, 'open', return_value=capture), patch('builtins.open', return_value=falco), \
                patch('subprocess.check_output', return_value=b''):
            snapshot = module['collect'](day, set())
        # Verify flows use numeric IDs
        self.assertEqual(snapshot['flows'][0][1], module['ENDPOINT_ENV'])  # 0 for Environment files
        # Verify report accepts numeric IDs
        text = module['report'](day, snapshot)
        self.assertIn('Environment-file requests | 1', text)


if __name__ == '__main__':
    unittest.main()
