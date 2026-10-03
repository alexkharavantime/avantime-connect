import base64
import importlib.util
import json
from pathlib import Path
import uuid
import pytest

spec = importlib.util.spec_from_file_location('helper', Path(__file__).parents[1] / 'deploy/wireguard/helper.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
OLD = base64.b64encode(b'A' * 32).decode()
NEW = base64.b64encode(b'B' * 32).decode()

@pytest.fixture
def server(tmp_path, monkeypatch):
    conf = tmp_path / 'wg0.conf'
    original = '[Interface]\nPrivateKey = SECRET_NOT_FOR_OUTPUT\nAddress = 10.30.0.1/24\nListenPort = 51820\nPostUp = echo existing-hook\n\n# existing client\n[Peer]\nPublicKey = ' + OLD + '\nAllowedIPs = 10.30.0.2/32\n'
    conf.write_text(original)
    state = tmp_path / 'state'
    monkeypatch.setattr(h, 'CONF', conf)
    monkeypatch.setattr(h, 'STATE', state)
    peers = {OLD: ['10.30.0.2/32']}
    calls = []
    def run(args):
        calls.append(args)
        if args[0] == h.IP:
            return json.dumps([{'addr_info': [{'local': '10.30.0.1'}]}])
        if args[1:4] == ['show', 'wg0', 'allowed-ips']:
            return '\n'.join(k + '\t' + ' '.join(v) for k, v in peers.items())
        if args[1:4] == ['show', 'wg0', 'public-key']:
            return NEW
        if args[1:4] == ['set', 'wg0', 'peer']:
            if args[5] == 'remove':
                peers.pop(args[4], None)
            else:
                peers[args[4]] = [args[6]]
            return ''
        raise AssertionError(args)
    monkeypatch.setattr(h, 'run', run)
    req = {'action': 'add', 'public_key': NEW, 'ip': '10.30.0.7', 'owner': str(uuid.uuid4())}
    return conf, original, peers, calls, req, run

def test_add_remove_idempotent_and_persistent(server):
    conf, original, peers, calls, req, _ = server
    assert h.execute(req)['state'] == 'active'
    assert h.execute(req)['state'] == 'active'
    assert conf.read_text().count('PublicKey = ' + NEW) == 1
    assert conf.read_text().startswith(original.rstrip())
    assert peers[OLD] == ['10.30.0.2/32']
    req['action'] = 'remove'
    assert h.execute(req)['state'] == 'revoked'
    assert h.execute(req)['state'] == 'revoked'
    assert NEW not in conf.read_text() and NEW not in peers
    assert OLD in conf.read_text() and OLD in peers
    req['action'] = 'add'
    with pytest.raises(h.Refused, match='reactivated'):
        h.execute(req)
    assert not any('restart' in c for c in calls)

@pytest.mark.parametrize('change', [
    {'ip': '10.30.0.1'}, {'ip': '10.30.0.2'}, {'ip': '10.40.0.20'},
    {'ip': '10.30.0.255'}, {'public_key': 'x; touch /tmp/pwn'},
    {'owner': '$(id)'}, {'action': 'shell'}, {'extra': 'bad'},
    {'action': 'remove', 'public_key': OLD},
])
def test_invalid_and_unmanaged_do_not_mutate(server, change):
    conf, original, peers, calls, req, _ = server
    req.update(change)
    with pytest.raises(h.Refused):
        h.execute(req)
    assert conf.read_text() == original
    assert not any(c[1] == 'set' for c in calls)

def test_runtime_and_config_network_conflicts(server):
    conf, original, peers, calls, req, _ = server
    peers[OLD] = ['10.30.0.0/24']
    with pytest.raises(h.Refused, match='runtime'):
        h.execute(req)
    peers[OLD] = ['10.30.0.2/32']
    conf.write_text(original.replace('10.30.0.2/32', '10.30.0.0/24'))
    with pytest.raises(h.Refused, match='config'):
        h.execute(req)

def test_unmanaged_key_even_at_unreserved_address(server):
    conf, original, peers, calls, req, _ = server
    peers[NEW] = ['10.30.0.7/32']
    with pytest.raises(h.Refused, match='Unmanaged'):
        h.execute(req)
    assert conf.read_text() == original

def test_lost_runtime_reply_retry_converges(server, monkeypatch):
    conf, original, peers, calls, req, run = server
    def lose(args):
        result = run(args)
        if args[1] == 'set':
            raise TimeoutError('after actual apply')
        return result
    monkeypatch.setattr(h, 'run', lose)
    with pytest.raises(TimeoutError):
        h.execute(req)
    assert NEW in peers and NEW in conf.read_text()
    state = json.loads((h.STATE / 'managed.json').read_text())
    assert state[NEW]['state'] == 'pending_add'
    monkeypatch.setattr(h, 'run', run)
    assert h.execute(req)['state'] == 'active'
    assert conf.read_text().count(NEW) == 1

def test_runtime_failure_before_apply_retry(server, monkeypatch):
    conf, original, peers, calls, req, run = server
    def fail(args):
        if args[1] == 'set':
            raise RuntimeError('offline')
        return run(args)
    monkeypatch.setattr(h, 'run', fail)
    with pytest.raises(RuntimeError):
        h.execute(req)
    assert NEW not in peers and NEW in conf.read_text()
    monkeypatch.setattr(h, 'run', run)
    assert h.execute(req)['state'] == 'active'

def test_owner_and_external_change_protected(server):
    conf, original, peers, calls, req, _ = server
    h.execute(req)
    with pytest.raises(h.Refused, match='another operation'):
        h.execute(dict(req, owner=str(uuid.uuid4())))
    peers[NEW] = ['10.30.0.99/32']
    with pytest.raises(h.Refused, match='changed externally'):
        h.execute(dict(req, action='remove'))
    assert NEW in peers

def test_status_no_secrets_and_reserves_tombstones(server):
    conf, original, peers, calls, req, _ = server
    h.execute(req)
    h.execute(dict(req, action='remove'))
    status = h.execute({'action': 'status'})
    assert '10.30.0.7' in status['occupied']
    assert 'SECRET' not in json.dumps(status)

def test_saveconfig_rejected(server):
    conf, original, peers, calls, req, _ = server
    conf.write_text(original.replace('[Interface]', '[Interface]\nSaveConfig = true'))
    with pytest.raises(h.Refused, match='SaveConfig'):
        h.execute(req)

def test_remove_failure_keeps_journal_and_retries(server, monkeypatch):
    conf, original, peers, calls, req, run = server
    h.execute(req)
    req['action'] = 'remove'
    def fail(args):
        if args[1] == 'set':
            raise TimeoutError()
        return run(args)
    monkeypatch.setattr(h, 'run', fail)
    with pytest.raises(TimeoutError):
        h.execute(req)
    assert NEW in peers and NEW not in conf.read_text()
    monkeypatch.setattr(h, 'run', run)
    assert h.execute(req)['state'] == 'revoked'
    assert NEW not in peers

def test_concurrent_same_ip_only_one_owner(server):
    from concurrent.futures import ThreadPoolExecutor
    conf, original, peers, calls, req, _ = server
    other = dict(req, public_key=base64.b64encode(b'C' * 32).decode(), owner=str(uuid.uuid4()))
    def apply(r):
        try:
            return h.execute(r)['ok']
        except h.Refused:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(apply, [req, other]))
    assert sorted(result) == [False, True]
    assert sum(n == ['10.30.0.7/32'] for n in peers.values()) == 1
