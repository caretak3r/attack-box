#!/usr/bin/env python3
"""Test nft containment in private mount/network namespaces; never alter host rules."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f'{args}: {result.stderr}')
    return result.stdout


def main():
    if len(sys.argv) == 2:
        if os.geteuid() != 0:
            raise SystemExit('Run as root on the Linux verification host; namespaces are mandatory.')
        os.execvp('unshare', ['unshare', '--mount', '--net', '--fork', sys.executable,
                             str(Path(__file__).resolve()), sys.argv[1], '--inside'])
    if len(sys.argv) != 3 or sys.argv[2] != '--inside':
        raise SystemExit('usage: test-containment-netns.py /absolute/path/to/attackbox.nft')
    for namespace in ('net', 'mnt'):
        if os.readlink('/proc/self/ns/' + namespace) == os.readlink('/proc/1/ns/' + namespace):
            raise SystemExit('Refusing to run in the host namespace')
    rules = Path(sys.argv[1]).read_text()
    run('mount', '--make-rprivate', '/')
    run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
    Path('/run/netns').mkdir()
    run('ip', 'link', 'set', 'lo', 'up')
    run('sysctl', '-q', '-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1', 'net.ipv6.conf.default.forwarding=1')
    peers = [('proxy', 'br-proxy', '172.30.0.3', '172.30.0.1'),
             ('bait', 'br-bait', '172.30.0.2', '172.30.0.1'),
             ('other', 'br-other', '172.30.0.4', '172.30.0.1'),
             ('outside', 'wan-test', '192.0.2.2', '192.0.2.1')]
    for name, interface, addr, gateway in peers:
        run('ip', 'netns', 'add', name)
        run('ip', 'link', 'add', interface, 'type', 'veth', 'peer', 'name', 'v-' + name)
        run('ip', 'link', 'set', 'v-' + name, 'netns', name)
        run('ip', 'addr', 'add', gateway + '/32', 'dev', interface)
        run('ip', 'link', 'set', interface, 'up')
        run('ip', 'route', 'add', addr + '/32', 'dev', interface)
        for args in [('link', 'set', 'lo', 'up'),
                     ('addr', 'add', addr + '/32', 'dev', 'v-' + name),
                     ('link', 'set', 'v-' + name, 'up'),
                     ('route', 'add', gateway + '/32', 'dev', 'v-' + name),
                     ('route', 'add', 'default', 'via', gateway)]:
            run('ip', '-n', name, *args)
    for name, interface, addr, gateway in peers:
        addr6 = 'fd00:30::' + addr.split('.')[-1] if name != 'outside' else 'fd00:ff::2'
        gateway6 = 'fd00:30::1' if name != 'outside' else 'fd00:ff::1'
        run('ip', '-6', 'addr', 'add', gateway6 + '/128', 'dev', interface, 'nodad')
        run('ip', '-6', 'route', 'add', addr6 + '/128', 'dev', interface)
        run('ip', '-n', name, '-6', 'addr', 'add', addr6 + '/128', 'dev', 'v-' + name, 'nodad')
        run('ip', '-n', name, '-6', 'route', 'add', gateway6 + '/128', 'dev', 'v-' + name)
        run('ip', '-n', name, '-6', 'route', 'add', 'default', 'via', gateway6)
    server = '''import socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',int(sys.argv[1])));s.listen(20)
while True:
 c,_=s.accept();c.sendall(b'control');c.close()
'''
    server6 = server.replace('s=socket.socket();', 's=socket.socket(socket.AF_INET6);s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);').replace("'0.0.0.0'", "'::'")
    client = '''import socket,sys
s=socket.create_connection((sys.argv[1],int(sys.argv[2])),.7)
assert s.recv(16)==b'control'
'''
    processes = []
    cases = [('proxy', '172.30.0.2', 8080, True),
             ('proxy', '172.30.0.2', 8443, False),
             ('bait', '172.30.0.3', 8443, False),
             ('proxy', '172.30.0.4', 8080, False),
             ('bait', '172.30.0.4', 8443, False),
             ('bait', '192.0.2.2', 443, False),
             ('proxy', '192.0.2.2', 443, False),
             ('bait', '172.30.0.1', 9999, False),
             ('proxy', '172.30.0.1', 9999, False),
             ('outside', '172.30.0.3', 8443, True),
             ('bait', 'fd00:ff::2', 443, False),
             ('bait', 'fd00:30::1', 9999, False),
             ('proxy', 'fd00:30::2', 8080, False),
             ('outside', 'fd00:30::3', 8443, True)]
    try:
        for name, port in [('bait', 8080), ('bait', 8443), ('proxy', 8443),
                           ('other', 8080), ('other', 8443), ('outside', 443), ('', 9999)]:
            prefix = ['ip', 'netns', 'exec', name] if name else []
            processes.append(subprocess.Popen(prefix + [sys.executable, '-c', server, str(port)],
                                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
        for name, port in [('bait', 8080), ('proxy', 8443), ('outside', 443), ('', 9999)]:
            prefix = ['ip', 'netns', 'exec', name] if name else []
            processes.append(subprocess.Popen(prefix + [sys.executable, '-c', server6, str(port)],
                                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
        time.sleep(1.2)  # Let veth link-local IPv6 DAD complete before controls.
        for name, addr, port, _ in cases:
            run('ip', 'netns', 'exec', name, sys.executable, '-c', client.replace(', .7)', ', 3)').replace(',.7)', ',3)'), addr, str(port))
        # Install candidate rules only inside this private network namespace.
        subprocess.run(['nft', '-f', '-'], input=rules, text=True, check=True)
        # Baseline clients used fresh ephemeral ports. TIME_WAIT prevents their
        # immediate reuse, so the following connects cannot inherit those flows.
        results = []
        for name, addr, port, allowed in cases:
            r = subprocess.run(['ip', 'netns', 'exec', name, sys.executable, '-c', client,
                                addr, str(port)], capture_output=True, timeout=3)
            actual = r.returncode == 0
            results.append(dict(source=name, destination=addr, port=port,
                                expected_allowed=allowed, actual_allowed=actual))
            if actual != allowed:
                raise RuntimeError(json.dumps(results))
        print(json.dumps({'passed': len(results), 'positive_controls': len(cases),
                          'scope': 'isolated IPv4/IPv6 routed namespaces; not provider firewall or gVisor',
                          'results': results}, indent=2))
    finally:
        for p in processes:
            p.terminate()
        for p in processes:
            p.communicate(timeout=3)


if __name__ == '__main__':
    main()
