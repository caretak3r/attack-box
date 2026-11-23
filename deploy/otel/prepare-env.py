#!/usr/bin/env python3
"""Validate operator identities and produce the secret-free shipper overlay."""
import pathlib
import re
import stat
import sys

FIELDS = {
    "ATTACKBOX_HOST_ID", "ATTACKBOX_HOST_NAME", "ATTACKBOX_CAMPAIGN_ID",
    "ATTACKBOX_BAIT_INSTANCE_ID", "ATTACKBOX_SHIPPER_INSTANCE_ID",
    "ATTACKBOX_MONITOR_INSTANCE_ID", "ATTACKBOX_OTEL_INSTANCE_ID",
    "ATTACKBOX_BAIT_CONTAINER_ID", "ATTACKBOX_RELEASE_VERSION",
}


def parse_identities(text):
    values = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or key not in FIELDS or key in values:
            raise ValueError("monitoring.env: unknown or duplicate field")
        pattern = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
        if key in {"ATTACKBOX_HOST_ID", "ATTACKBOX_CAMPAIGN_ID"}:
            # Same grammar as the Go shipper's sensor_id and deployment_id.
            pattern = r"[a-z0-9][a-z0-9_.-]{0,62}"
        if not re.fullmatch(pattern, value) and not (key == "ATTACKBOX_BAIT_CONTAINER_ID" and value == ""):
            raise ValueError(f"monitoring.env: invalid {key}")
        if "REPLACE" in value:
            raise ValueError("monitoring.env: placeholder not replaced")
        values[key] = value
    if set(values) != FIELDS:
        raise ValueError("monitoring.env: required field missing")
    return values


def shipper_environment(values):
    rows = {
        "ATTACKBOX_OTEL_SOCKET": "/run/attackbox-otel/shipper/otlp.sock",
        "ATTACKBOX_HOST_ID": values["ATTACKBOX_HOST_ID"],
        "ATTACKBOX_SERVICE_INSTANCE_ID": values["ATTACKBOX_SHIPPER_INSTANCE_ID"],
        "ATTACKBOX_CAMPAIGN_ID": values["ATTACKBOX_CAMPAIGN_ID"],
        "ATTACKBOX_SENSOR_ID": values["ATTACKBOX_HOST_ID"],
        "ATTACKBOX_DEPLOYMENT_ID": values["ATTACKBOX_CAMPAIGN_ID"],
    }
    return "".join(f"{name}={value}\n" for name, value in rows.items())


def validate_license(text):
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", text):
        raise ValueError("invalid license key format: use exact key bytes with no trailing newline")


def main(args):
    identities, license_key, output = map(pathlib.Path, args)
    for path in (identities, license_key):
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
            raise ValueError(f"{path}: requires root-owned regular file, mode 0600")
    values = parse_identities(identities.read_text())
    validate_license(license_key.read_text())
    with output.open("x") as target:
        target.write(shipper_environment(values))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from None
