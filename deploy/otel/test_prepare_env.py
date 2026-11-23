import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("prepare_env", pathlib.Path(__file__).with_name("prepare-env.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class IdentityContract(unittest.TestCase):
    def text(self, **changes):
        values = {key: "sensor-1" for key in module.FIELDS}
        values["ATTACKBOX_CAMPAIGN_ID"] = "campaign-1"
        values.update(changes)
        return "".join(f"{key}={value}\n" for key, value in values.items())

    def test_shared_log_and_trace_identity(self):
        output = module.shipper_environment(module.parse_identities(self.text()))
        self.assertIn("ATTACKBOX_SENSOR_ID=sensor-1\n", output)
        self.assertIn("ATTACKBOX_DEPLOYMENT_ID=campaign-1\n", output)
        self.assertIn("ATTACKBOX_HOST_ID=sensor-1\n", output)
        self.assertNotIn("LICENSE", output)

    def test_shipper_grammar(self):
        for key in ("ATTACKBOX_HOST_ID", "ATTACKBOX_CAMPAIGN_ID"):
            for value in ("Upper", ".prefix", "-prefix", "x" * 64, "a b", "a/b", "", "$(id)"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    module.parse_identities(self.text(**{key: value}))
            module.parse_identities(self.text(**{key: "x" * 63}))

    def test_duplicate_or_unknown(self):
        for extra in ("ATTACKBOX_HOST_ID=x\n", "ATTACKBOX_NR_LICENSE_KEY=secret\n"):
            with self.assertRaises(ValueError):
                module.parse_identities(self.text() + extra)

    def test_trace_identity_starts_alphanumeric(self):
        for value in (".bad", "_bad", "-bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.parse_identities(self.text(ATTACKBOX_BAIT_INSTANCE_ID=value))

    def test_license_exact_bytes(self):
        module.validate_license("a" * 16)
        for text in ("a" * 16 + "\n", "a" * 16 + "\r\n", " " + "a" * 16, "short"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                module.validate_license(text)

    def test_optional_container(self):
        module.parse_identities(self.text(ATTACKBOX_BAIT_CONTAINER_ID=""))


if __name__ == "__main__":
    unittest.main()
