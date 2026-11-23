import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('configure_agent', pathlib.Path(__file__).with_name('configure-agent.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class IdentityTests(unittest.TestCase):
    def test_adds_identity_without_replacing_cli_attributes(self):
        result = module.add_identity('license_key: a\ncustom_attributes:\n  nr_deployed_by: cli\n', 'sensor-1', 'campaign-1', 'host-1')
        self.assertIn('  nr_deployed_by: cli\n', result)
        self.assertIn('  sensor_id: "sensor-1"\n', result)
        self.assertIn('display_name: "host-1"\n', result)

    def test_new_map_and_existing_display_name(self):
        result = module.add_identity('license_key: a\ndisplay_name: operator\n', 'sensor', 'campaign', 'host')
        self.assertEqual(result.count('display_name:'), 1)
        self.assertIn('display_name: operator', result)
        self.assertIn('custom_attributes:\n', result)

    def test_duplicate_or_flow_map_requires_review(self):
        for content in ('custom_attributes: {}\n', 'custom_attributes:\ncustom_attributes:\n', 'custom_attributes:\n  sensor_id: operator\n'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                module.add_identity(content, 'sensor', 'campaign', 'host')


if __name__ == '__main__':
    unittest.main()
