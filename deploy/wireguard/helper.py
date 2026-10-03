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

def validate(req):
    if not isinstance(req, dict) or req.get('action') not in ('status', 'add', 'remove'):
        raise Refused('Invalid action')
    if req['action'] == 'status':
        if set(req) != {'action'}:
            raise Refused('Unexpected fields')
        return
    if set(req) != {'action', 'public_key', 'ip', 'owner'} or not key_ok(req['public_key']):
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
        key, ip, owner = req['public_key'], req['ip'], req['owner']
        record = managed.get(key)
        if record and (record['owner'] != owner or record['ip'] != ip):
            raise Refused('Peer belongs to another operation')
        if not record and (key in configured or key in live):
            raise Refused('Unmanaged peer: modification forbidden')
        if not record and req['action'] == 'remove':
            raise Refused('Unknown owner: removal forbidden')
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
        if req['action'] == 'add':
            for other, (_, nets) in configured.items():
                if other != key and any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in nets):
                    raise Refused('Address occupied in config')
            for other, nets in live.items():
                if other != key and any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in nets):
                    raise Refused('Address occupied at runtime')
            if any(k != key and v['ip'] == ip for k, v in managed.items()):
                raise Refused('Address reserved by another operation')
        # Persistent journal precedes mutations: interrupted requests can be retried.
        managed[key] = {'ip': ip, 'owner': owner, 'state': 'pending_' + req['action']}
        atomic(state_path, json.dumps(managed, sort_keys=True))
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
        else:
            run([WG, 'set', INTERFACE, 'peer', key, 'remove'])
        current = live_peers()
        if (req['action'] == 'add' and current.get(key) != expected) or (req['action'] == 'remove' and key in current):
            raise Refused('Runtime verification failed; retry same operation')
        managed[key]['state'] = 'active' if req['action'] == 'add' else 'revoked'
        atomic(state_path, json.dumps(managed, sort_keys=True))
        return {'ok': True, 'state': managed[key]['state'], 'ip': ip, 'owner': owner}

def main():
    try:
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
        result = {'ok': False, 'error': str(exc)}
    except Exception:
        result = {'ok': False, 'error': 'Operation incomplete; retry same request or inspect server'}
    print(json.dumps(result), flush=True)

if __name__ == '__main__':
    main()
