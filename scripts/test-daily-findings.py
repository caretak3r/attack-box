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
        rows = [dict(time=timestamp, peer=peer, route='/.env', status=200, body='private-marker')
                for peer in ('8.8.8.8', '8.8.8.8', '1.1.1.1', '::1', 'missing-peer')]
        capture = io.BytesIO(b'\n'.join(json.dumps(r).encode() for r in rows))
        falco = io.BytesIO(b'{}\n{"time":"2026-01-10T00:00:00Z"}\n{"time":"2026-01-11T00:00:00Z"}\n')
        with patch.object(Path, 'open', return_value=capture), patch('builtins.open', return_value=falco), \
                patch('subprocess.check_output', return_value=b'{"MESSAGE":"OUTPUT-DROP: private-marker"}'):
            values = module['collect'](day, {ipaddress.ip_address('1.1.1.1')})
        text = module['report'](day, values)
        for row in ('Known operator or host | 1', 'Local or unknown peer | 2', 'Outside HTTP requests | 2',
                    'Distinct outside addresses | 1', 'Environment-file requests | 2', 'Retained Falco events | 1', 'OUTPUT-DROP: | 1'):
            self.assertIn(row, text)
        self.assertNotIn('private-marker', text)
        self.assertNotIn('8.8.8.8', text)
        values[1] += 1
        with self.assertRaisesRegex(ValueError, 'reconcile'):
            module['report'](day, values)


if __name__ == '__main__':
    unittest.main()
