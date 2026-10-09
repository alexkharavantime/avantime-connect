#!/usr/bin/python3 -I
"""Root-owned forced-command helper. One bounded JSON request per SSH connection."""
import base64
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

CONF = Path('/etc/wireguard/wg0.conf')
STATE = Path('/var/lib/avantime-wg-state')
WG = '/usr/bin/wg'
IP = '/usr/sbin/ip'
INTERFACE = 'wg0'
POOL = ipaddress.ip_network('10.30.0.0/24')
RESERVED = {'10.30.0.1', '10.30.0.2', '10.30.0.3', '10.30.0.4',
            '10.30.0.5', '10.30.0.6', '10.30.0.10'}

class Refused(Exception):
    pass

def key_ok(key):
    try:
        raw = base64.b64decode(key, validate=True)
        return len(raw) == 32 and any(raw) and base64.b64encode(raw).decode() == key
    except (ValueError, TypeError):
        return False

def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=10, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}).stdout

def atomic(path, text):
    fd, tmp = tempfile.mkstemp(prefix='.avantime-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        d = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def values(block, name):
    return re.findall(r'^\s*' + name + r'\s*=\s*([^#\n]*?)(?:\s*#.*)?$', block, re.M)

def parse_config(text):
    blocks = re.split(r'(?m)(?=^[ \t]*\[(?:Interface|Peer)\][ \t]*(?:#.*)?$)', text)
    peers = {}
    addresses = []
    interfaces = 0
    for b in blocks:
        stripped = b.lstrip()
        if stripped.startswith('[Interface]'):
            interfaces += 1
            if any(v.strip().lower() not in ('false', 'no', '0') for v in values(b, 'SaveConfig')):
                raise Refused('SaveConfig must be disabled')
            for v in values(b, 'Address'):
                addresses.extend(str(ipaddress.ip_interface(x.strip()).ip) for x in v.split(','))
        elif stripped.startswith('[Peer]'):
            keys = values(b, 'PublicKey')
            if len(keys) != 1 or not key_ok(keys[0]) or keys[0] in peers:
                raise Refused('Invalid or duplicate peer in config')
            nets = []
            for v in values(b, 'AllowedIPs'):
                nets.extend(str(ipaddress.ip_network(x.strip(), strict=False)) for x in v.split(','))
            peers[keys[0]] = (b, nets)
        elif '[' in stripped and not stripped.startswith('#'):
            raise Refused('Unsupported config section')
    if interfaces != 1:
        raise Refused('Expected one Interface section')
    return blocks, peers, addresses

def live_peers():
    result = {}
    for line in run([WG, 'show', INTERFACE, 'allowed-ips']).splitlines():
        key, nets = line.split('\t', 1)
        if not key_ok(key):
            raise Refused('Invalid live peer')
        result[key] = [] if nets == '(none)' else [str(ipaddress.ip_network(n, strict=False)) for n in nets.split()]
    return result

def interface_ips():
    data = json.loads(run([IP, '-j', 'address', 'show', 'dev', INTERFACE]))
    return [a['local'] for item in data for a in item.get('addr_info', [])]

def access_policy(environments, revision):
    if (not isinstance(environments, list) or not environments
            or any(type(e) is not str or e not in ('dev', 'prod') for e in environments)
            or environments != sorted(set(environments))
            or type(revision) is not int or not 0 <= revision <= 2147483647):
        raise Refused('Invalid access policy')
    return environments, revision

def access_enabled():
    return (STATE / 'access-enabled').is_file()

def read_groups():
    path = STATE / 'access-users.json'
    return json.loads(path.read_text()) if path.exists() else {}

def write_group(req, allow_newer=False):
    groups = read_groups()
    old = groups.get(req['group'])
    if old and (old['revision'] > req['revision'] or (old['revision'] == req['revision'] and old['environments'] != req['environments'])):
        if allow_newer and old['revision'] > req['revision']:
            return old
        raise Refused('Stale or conflicting user access revision')
    groups[req['group']] = {'revision': req['revision'], 'environments': req['environments']}
    atomic(STATE / 'access-users.json', json.dumps(groups, sort_keys=True))
    return groups[req['group']]

def firewall_text(managed):
    # Dedicated table: never flush the ruleset or modify iptables-nft NAT.
    lines = ['add table inet avantime_access',
             'add chain inet avantime_access forward { type filter hook forward priority -10; policy accept; }',
             'flush chain inet avantime_access forward']
    groups = read_groups()
    for record in sorted(managed.values(), key=lambda r: r['ip']):
        ip = str(ipaddress.IPv4Address(record['ip']))
        if ipaddress.ip_address(ip) not in POOL:
            raise Refused('Invalid access journal address')
        if record.get('group') and record['group'] not in groups:
            raise Refused('Missing user access journal')
        assigned = groups.get(record.get('group'), {})
        envs, _ = access_policy(assigned.get('environments', record.get('environments', ['prod'])), assigned.get('revision', record.get('access_revision', 0)))
        prefix = 'add rule inet avantime_access forward iifname "wg0" ip saddr ' + ip
        if record['state'] in ('active', 'pending_add'):
            # DEV-only peers need domain resolution without access to other PROD
            # services. PROD already permits this destination via its subnet.
            if 'prod' not in envs:
                for protocol in ('udp', 'tcp'):
                    lines.append(prefix + ' ip daddr 10.40.0.10/32 ' + protocol + ' dport 53 counter accept')
            for environment in envs:
                destination = '10.20.0.20/32' if environment == 'dev' else '10.40.0.0/24'
                lines.append(prefix + ' ip daddr ' + destination + ' counter accept')
        lines.append(prefix + ' counter drop')
    return '\n'.join(lines) + '\n'

def enforce_access(managed):
    if not access_enabled():
        raise Refused('Server access control is not enabled')
    subprocess.run(['/usr/sbin/nft', '-f', '-'], input=firewall_text(managed),
        text=True, check=True, capture_output=True, timeout=10,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})

def restore_access():
    # Runs before wg-quick on boot. A failure prevents wg0 starting via Requires.
    with (STATE / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = STATE / 'managed.json'
        enforce_access(json.loads(path.read_text()) if path.exists() else {})

def validate(req):
    if not isinstance(req, dict) or req.get('action') not in ('status', 'add', 'remove', 'access', 'user_access'):
        raise Refused('Invalid action')
    if req['action'] == 'status':
        if set(req) != {'action'}:
            raise Refused('Unexpected fields')
        return
    if req['action'] == 'user_access':
        if set(req) != {'action', 'group', 'environments', 'revision'} or not isinstance(req.get('group'), str) or not re.fullmatch('[a-f0-9]{64}', req['group']):
            raise Refused('Invalid group access request')
        access_policy(req['environments'], req['revision'])
        return
    fields = {'action', 'public_key', 'ip', 'owner'}
    if req['action'] == 'access' or (req['action'] == 'add' and 'environments' in req):
        fields |= {'environments', 'revision', 'group'}
        if not isinstance(req.get('group'), str) or not re.fullmatch('[a-f0-9]{64}', req['group']):
            raise Refused('Invalid group')
        access_policy(req.get('environments'), req.get('revision'))
    if set(req) != fields or not key_ok(req.get('public_key')):
        raise Refused('Invalid request or public key')
    try:
        if str(uuid.UUID(req['owner'])) != req['owner']:
            raise ValueError()
        ip = ipaddress.ip_address(req['ip'])
        if ip.version != 4 or str(ip) != req['ip'] or ip not in POOL or ip in (POOL.network_address, POOL.broadcast_address) or str(ip) in RESERVED:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise Refused('Invalid owner or protected address')

def execute(req):
    validate(req)
    STATE.mkdir(mode=0o700, exist_ok=True)
    with (STATE / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        original = CONF.read_text()
        blocks, configured, addresses = parse_config(original)
        live = live_peers()
        addresses += interface_ips()
        state_path = STATE / 'managed.json'
        managed = json.loads(state_path.read_text()) if state_path.exists() else {}
        occupied = set(RESERVED) | set(addresses)
        for _, nets in configured.values():
            occupied.update(nets)
        for nets in live.values():
            occupied.update(nets)
        occupied.update(v['ip'] for v in managed.values())
        if req['action'] == 'status':
            return {'ok': True, 'occupied': sorted(occupied),
                    'server_public_key': run([WG, 'show', INTERFACE, 'public-key']).strip()}
        if req['action'] == 'user_access':
            if not access_enabled():
                raise Refused('Server access control is not enabled')
            write_group(req)
            enforce_access(managed)
            return {'ok': True, 'enforced': True, 'environments': req['environments'], 'revision': req['revision']}
        key, ip, owner = req['public_key'], req['ip'], req['owner']
        record = managed.get(key)
        if record and (record['owner'] != owner or record['ip'] != ip):
            raise Refused('Peer belongs to another operation')
        if not record and (key in configured or key in live):
            raise Refused('Unmanaged peer: modification forbidden')
        # An absent, never-created peer can be cancelled. Persist its owner and
        # tombstone below so an add delayed in SSH cannot resurrect it.
        if req['action'] == 'add' and record and record['state'] in ('pending_remove', 'revoked'):
            raise Refused('Revoked peer cannot be reactivated')
        if ip in addresses:
            raise Refused('Interface address is protected')
        # Existing owned peer must still have exactly its assigned /32.
        expected = [ip + '/32']
        if key in configured and configured[key][1] != expected:
            raise Refused('Managed config changed externally')
        if key in live and live[key] != expected:
            raise Refused('Managed runtime changed externally')
        if req['action'] == 'access':
            if not record or record['state'] != 'active' or key not in configured or key not in live:
                raise Refused('Only an active owned peer accepts access changes')
            envs, revision = access_policy(req['environments'], req['revision'])
            old_revision = record.get('access_revision', 0)
            if revision < old_revision or (revision == old_revision and envs != record.get('environments', ['prod'])):
                raise Refused('Stale or conflicting access revision')
            if not access_enabled():
                raise Refused('Server access control is not enabled')
            if record.get('group') not in (None, req['group']):
                raise Refused('Peer already belongs to another group')
            write_group(req)
            record.update(environments=envs, access_revision=revision, group=req['group'])
            atomic(state_path, json.dumps(managed, sort_keys=True))
            enforce_access(managed)
            return {'ok': True, 'owner': owner, 'ip': ip, 'environments': envs, 'revision': revision, 'enforced': True}
        if req['action'] == 'add' or not record:
            for other, (_, nets) in configured.items():
                if other != key and any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in nets):
                    raise Refused('Address occupied in config')
            for other, nets in live.items():
                if other != key and any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in nets):
                    raise Refused('Address occupied at runtime')
            if any(k != key and v['ip'] == ip for k, v in managed.items()):
                raise Refused('Address reserved by another operation')
        # Persistent journal precedes mutations: interrupted requests can be retried.
        created = key not in live
        managed[key] = {**(record or {}), 'ip': ip, 'owner': owner, 'state': 'pending_' + req['action']}
        if 'environments' in req:
            if not access_enabled():
                raise Refused('Server access control is not enabled')
            if record and record.get('group') not in (None, req['group']):
                raise Refused('Peer belongs to another group')
            assigned = write_group(req, allow_newer=True)
            managed[key].update(environments=assigned['environments'], access_revision=assigned['revision'], group=req['group'])
        atomic(state_path, json.dumps(managed, sort_keys=True))
        if access_enabled():
            enforce_access(managed)
        if req['action'] == 'add':
            changed = original if key in configured else original.rstrip() + '\n\n[Peer]\nPublicKey = ' + key + '\nAllowedIPs = ' + ip + '/32\n'
        else:
            changed = ''.join(b for b in blocks if key not in configured or b != configured[key][0])
        if changed != original:
            # Backup stays root-only and never appears in response/logs.
            atomic(STATE / 'wg0.conf.previous', original)
            # Detect edits by other tools before replacing the file.
            if CONF.read_text() != original:
                raise Refused('Config changed concurrently; retry after review')
            atomic(CONF, changed)
        if req['action'] == 'add':
            run([WG, 'set', INTERFACE, 'peer', key, 'allowed-ips', ip + '/32'])
        elif key in live:
            run([WG, 'set', INTERFACE, 'peer', key, 'remove'])
        current = live_peers()
        if (req['action'] == 'add' and current.get(key) != expected) or (req['action'] == 'remove' and key in current):
            raise Refused('Runtime verification failed; retry same operation')
        managed[key]['state'] = 'active' if req['action'] == 'add' else 'revoked'
        atomic(state_path, json.dumps(managed, sort_keys=True))
        result = {'ok': True, 'state': managed[key]['state'], 'ip': ip, 'owner': owner}
        if req['action'] == 'add':
            result['created'] = created
        else:
            # A tombstone is retained, not deleted: it is both proof of ownership
            # and a permanent ban on later adds. Verify all three stores.
            _, remaining, _ = parse_config(CONF.read_text())
            saved = json.loads(state_path.read_text()).get(key)
            if key in remaining or key in live_peers() or saved != managed[key]:
                raise Refused('Removal not confirmed; retry same operation')
            result['absence_confirmed'] = True
        return result

def main():
    try:
        if os.geteuid() == 0 and sys.argv[1:] == ['--restore-access']:
            restore_access()
            return
        if os.geteuid() != 0 or len(sys.argv) != 1:
            raise Refused('Root and no arguments required')
        import signal
        def deadline(signum, frame):
            raise TimeoutError("Helper deadline")
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(25)
        line = sys.stdin.buffer.readline(4097)
        if len(line) > 4096 or not line.endswith(b'\n'):
            raise Refused('Request too large or missing newline')
        result = execute(json.loads(line))
    except Refused as exc:
        if sys.argv[1:] == ['--restore-access']:
            print('Access policy restore failed', file=sys.stderr)
            raise SystemExit(1)
        result = {'ok': False, 'error': str(exc)}
    except Exception:
        if sys.argv[1:] == ['--restore-access']:
            print('Access policy restore incomplete', file=sys.stderr)
            raise SystemExit(1)
        result = {'ok': False, 'error': 'Operation incomplete; retry same request or inspect server'}
    print(json.dumps(result), flush=True)

if __name__ == '__main__':
    main()
