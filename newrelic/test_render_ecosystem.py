import unittest
from render_ecosystem import render


class EcosystemContract(unittest.TestCase):
    def test_scope_and_health_semantics(self):
        assets = render(1, 'srv-000000', 'verified-guid')
        occupied = set()
        widgets = assets['dashboard.json']['pages'][0]['widgets']
        for w in widgets:
            layout = w['layout']
            cells = {(x, y) for x in range(layout['column'], layout['column'] + layout['width'])
                     for y in range(layout['row'], layout['row'] + layout['height'])}
            self.assertFalse(occupied & cells)
            self.assertTrue(all(1 <= x <= 12 for x, _ in cells))
            occupied |= cells
            for q in w['rawConfiguration'].get('nrqlQueries', []):
                self.assertEqual(q['accountIds'], [1])
                self.assertIn("sensor_id = 'srv-000000'", q['query'])
                self.assertIn('SINCE 5 minutes ago', q['query'])
        self.assertFalse(any(w['visualization']['id'] == 'topology.service-map' for w in widgets))
        self.assertIn('/automap/verified-guid?account=1', widgets[1]['rawConfiguration']['text'])
        workload = assets['workload-create.graphql']
        self.assertIn("tags.sensor_id = 'srv-000000'", workload)
        self.assertIn("tags.docker.host = 'srv-000000'", workload)
        self.assertIn('tags.attackbox_retired IS NULL', workload)
        queries = ' '.join(q['query'] for w in widgets for q in w['rawConfiguration'].get('nrqlQueries', []))
        self.assertIn('average(host.cpuPercent)', queries)
        self.assertIn('average(host.memoryUsedPercent)', queries)
        self.assertNotIn('system.cpu.utilization', queries)
        self.assertIn('FACET process.name', queries)
        for c in assets['alert-condition-inputs.json']['conditions']:
            self.assertFalse(c['enabled'])
            self.assertEqual(c['signal']['fillOption'], 'NONE')
            self.assertTrue(c['expiration']['openViolationOnExpiration'])
            self.assertNotIn('SINCE', c['nrql']['query'])

    def test_reject_query_injection_and_invalid_scope(self):
        for sensor in ["' OR true", '', '../host', 'a'*65, 'host\nname']:
            with self.assertRaises(ValueError):
                render(1, sensor)
        for account in [0, -1, True, '1']:
            with self.assertRaises(ValueError):
                render(account, 'host')
        with self.assertRaises(ValueError):
            render(1, 'host', 'bad)\n[link](https://example.com)')


if __name__ == '__main__':
    unittest.main()
