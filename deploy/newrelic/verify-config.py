#!/usr/bin/env python3
"""Validate the native agent configuration without exposing the ingest key."""
import os
import re
import stat

fd = os.open('/etc/newrelic-infra.yml', os.O_RDONLY | os.O_NOFOLLOW)
with os.fdopen(fd) as source:
    info = os.fstat(source.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1048576:
        raise SystemExit('native agent config must be root-owned mode0600, <=1MiB')
    text = source.read(1048577)
keys = re.findall(r'^license_key:\s*[\"\']?([A-Za-z0-9_-]+)[\"\']?\s*$', text, re.MULTILINE)
if len(keys) != 1 or not re.fullmatch(r'(?:[a-f0-9]{40}|[A-Za-z0-9]{36}NRAL)', keys[0]):
    raise SystemExit('native agent config requires one Ingest-License key')
if 'NRAK-' in text or 'api_key:' in text:
    raise SystemExit('User API key must not appear in native agent config')
