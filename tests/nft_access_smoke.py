"""CI-only network test. Never changes host interfaces, routes or firewall tables."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

if (os.environ.get('GITHUB_ACTIONS') != 'true'
        or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() != 0):
    raise SystemExit('Run only as root on the disposable GitHub Actions runner')
spec = importlib.util.spec_from_file_location('helper', Path(__file__).parents[1] / 'deploy/wireguard/helper.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
base = 'avt-acl-' + str(os.getpid())
client, router, target = [base + '-' + x for x in ('c', 'r', 't')]
created = []
def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout
def ns(name, *args, **kwargs):
    return run('ip', 'netns', 'exec', name, *args, **kwargs)
def ip(name, *args):
    return ns(name, 'ip', *args)
def ping(address, allowed, source='10.30.0.13'):
    result = subprocess.run(['ip', 'netns', 'exec', client, 'ping', '-n', '-c', '1', '-W', '1', '-I', source, address], capture_output=True)
    assert (result.returncode == 0) == allowed, (address, allowed, source, result.stdout)
try:
    for name in (client, router, target):
        run('ip', 'netns', 'add', name)
        created.append(name)
        ip(name, 'link', 'set', 'lo', 'up')
    # Both ends are created directly inside their namespaces.
    ip(client, 'link', 'add', 'eth0', 'type', 'veth', 'peer', 'name', 'wg0', 'netns', router)
    ip(router, 'link', 'add', 'ens18', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', target)
    for name, interface, addresses in (
        (client, 'eth0', ['10.30.0.13/24', '10.30.0.14/24']),
        (router, 'wg0', ['10.30.0.1/24']),
        (router, 'ens18', ['10.20.0.2/24', '10.40.0.2/24']),
        (target, 'eth0', ['10.20.0.20/24', '10.40.0.20/24'])):
        for address in addresses:
            ip(name, 'address', 'add', address, 'dev', interface)
        ip(name, 'link', 'set', interface, 'up')
    ip(client, 'route', 'add', 'default', 'via', '10.30.0.1')
    ns(router, 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
    ns(router, 'nft', '-f', '-', input='''add table ip nat
add chain ip nat POSTROUTING { type nat hook postrouting priority srcnat; policy accept; }
add rule ip nat POSTROUTING ip saddr 10.30.0.0/24 oifname "ens18" masquerade
''')
    nat_before = ns(router, 'nft', 'list', 'table', 'ip', 'nat')
    with tempfile.TemporaryDirectory() as directory:
        h.STATE = Path(directory)
        group = 'a' * 64
        record = {'ip': '10.30.0.13', 'state': 'active', 'group': group}
        for revision, environments in enumerate((['prod'], ['dev', 'prod'], ['dev'])):
            (h.STATE / 'access-users.json').write_text(json.dumps({group: {'revision': revision, 'environments': environments}}))
            rules = h.firewall_text({'test-peer': record})
            ns(router, 'nft', '-c', '-f', '-', input=rules)
            ns(router, 'nft', '-f', '-', input=rules)
            ns(router, 'nft', '-f', '-', input=rules)  # repeat is atomic and idempotent
            ping('10.20.0.20', 'dev' in environments)
            ping('10.40.0.20', 'prod' in environments)
            ping('10.20.0.20', True, '10.30.0.14')  # unmanaged peer unchanged
        record['state'] = 'revoked'
        ns(router, 'nft', '-f', '-', input=h.firewall_text({'test-peer': record}))
        ping('10.20.0.20', False)
        ping('10.40.0.20', False)
        assert ns(router, 'nft', 'list', 'table', 'ip', 'nat') == nat_before
    print('PASS: PROD-only, DEV-only, both, revocation, repeat apply, unmanaged peer and existing NAT')
finally:
    for name in reversed(created):
        subprocess.run(['ip', 'netns', 'delete', name], check=False, capture_output=True)
