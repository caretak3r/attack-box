#!/usr/bin/env python3
"""Restrict native credentials and add shared identities without replacing CLI attributes."""
import json
import os
import pathlib
import re
import socket
import stat
import sys
import tempfile


def secure_config(path):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_size > 1048576:
        raise ValueError('native config must be a root-owned regular file, <=1MiB')
    path.chmod(0o600)


def add_identity(text, sensor, deployment, hostname):
    # Quote generated scalars as JSON, a YAML-compatible subset.
    if not re.search(r'^display_name:', text, re.M):
        text = text.rstrip() + '\ndisplay_name: ' + json.dumps(hostname) + '\n'
    fields = {'sensor_id': sensor, 'deployment_id': deployment}
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if re.match(r'^custom_attributes:', line)]
    if len(starts) > 1:
        raise ValueError('duplicate custom_attributes')
    if not starts:
        return text.rstrip() + '\ncustom_attributes:\n' + ''.join(f'  {k}: {json.dumps(v)}\n' for k, v in fields.items())
    start = starts[0]
    if not re.fullmatch(r'custom_attributes:\s*(?:#.*)?\n?', lines[start]):
        raise ValueError('custom_attributes must use a block map for automatic identity additions')
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip() and not lines[i][0].isspace() and not lines[i].startswith('#')), len(lines))
    block = ''.join(lines[start + 1:end])
    indents = [len(line) - len(line.lstrip()) for line in lines[start + 1:end] if line.strip() and not line.lstrip().startswith('#')]
    indent = min(indents) if indents else 2
    for key in fields:
        if re.search(r'^\s+' + key + r':', block, re.M):
            raise ValueError('existing identity attribute requires explicit review')
    lines[start + 1:start + 1] = [' ' * indent + f'{k}: {json.dumps(v)}\n' for k, v in fields.items()]
    return ''.join(lines)


def main():
    path = pathlib.Path('/etc/newrelic-infra.yml')
    secure_config(path)
    if sys.argv[1:] == ['--secure-only']:
        return
    if sys.argv[1:] != ['--fresh']:
        raise ValueError('usage: configure-agent.py --secure-only|--fresh')
    shipper = pathlib.Path('/etc/attackbox/shipper.env')
    st = shipper.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > 65536:
        raise ValueError('shipper.env must be root-owned mode0600 regular file <=64KiB')
    values = {}
    for line in shipper.read_text().splitlines():
        name, sep, value = line.partition('=')
        if name in ('ATTACKBOX_SENSOR_ID', 'ATTACKBOX_DEPLOYMENT_ID', 'ATTACKBOX_HOSTNAME'):
            if not sep or name in values:
                raise ValueError('invalid or duplicate shipper identity')
            values[name] = value
    hostname = socket.gethostname()
    sensor = values.get('ATTACKBOX_SENSOR_ID', values.get('ATTACKBOX_HOSTNAME', hostname).lower())
    deployment = values.get('ATTACKBOX_DEPLOYMENT_ID', 'unset')
    if not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,62}', sensor) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,62}', deployment):
        raise ValueError('shipper identity does not match the approved grammar')
    output = add_identity(path.read_text(), sensor, deployment, hostname)
    fd, tmp = tempfile.mkstemp(prefix='.newrelic-infra-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as target:
            os.fchmod(target.fileno(), 0o600)
            target.write(output)
            target.flush()
            os.fsync(target.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, UnicodeError) as error:
        raise SystemExit(str(error)) from None
