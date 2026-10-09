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
    assert h.execute(req)['created'] is True
    assert h.execute(req)['created'] is False
    assert conf.read_text().count('PublicKey = ' + NEW) == 1
    assert conf.read_text().startswith(original.rstrip())
    assert peers[OLD] == ['10.30.0.2/32']
    req['action'] = 'remove'
    assert h.execute(req)['absence_confirmed'] is True
    assert h.execute(req)['absence_confirmed'] is True
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

@pytest.mark.parametrize('action', ['add', 'remove'])
def test_interruption_after_journal_before_any_mutation_retries(server, monkeypatch, action):
    conf, original, peers, calls, req, _ = server
    if action == 'remove':
        h.execute(req)
    req = dict(req, action=action)
    before_config = conf.read_text()
    before_runtime = {key: list(nets) for key, nets in peers.items()}
    calls.clear()
    atomic = h.atomic

    def interrupt_after_journal(path, text):
        atomic(path, text)
        if path.name == 'managed.json' and json.loads(text)[NEW]['state'] == 'pending_' + action:
            raise RuntimeError('interrupted after durable journal, before mutations')

    monkeypatch.setattr(h, 'atomic', interrupt_after_journal)
    with pytest.raises(RuntimeError, match='after durable journal'):
        h.execute(req)
    assert conf.read_text() == before_config
    assert peers == before_runtime
    assert not any(c[1] == 'set' for c in calls)
    assert json.loads((h.STATE / 'managed.json').read_text())[NEW] == {
        'owner': req['owner'], 'ip': req['ip'], 'state': 'pending_' + action}

    monkeypatch.setattr(h, 'atomic', atomic)
    result = h.execute(req)
    expected_state = 'active' if action == 'add' else 'revoked'
    assert result['ok'] is True and result['state'] == expected_state
    assert result['owner'] == req['owner'] and result['ip'] == req['ip']
    assert json.loads((h.STATE / 'managed.json').read_text())[NEW] == {
        'owner': req['owner'], 'ip': req['ip'], 'state': expected_state}
    if action == 'add':
        assert result['created'] is True
        assert conf.read_text().count(NEW) == 1 and peers[NEW] == [req['ip'] + '/32']
    else:
        assert result['absence_confirmed'] is True
        assert NEW not in conf.read_text() and NEW not in peers
    assert OLD in conf.read_text() and peers[OLD] == ['10.30.0.2/32']

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

def test_cancel_absent_peer_preserves_tombstone_and_blocks_late_add(server):
    conf, original, peers, calls, req, _ = server
    cancelled = h.execute(dict(req, action='remove'))
    assert cancelled['state'] == 'revoked' and cancelled['absence_confirmed'] is True
    assert h.execute(dict(req, action='remove')) == cancelled
    assert conf.read_text() == original and NEW not in peers
    assert not any(c[1] == 'set' for c in calls)
    record = json.loads((h.STATE / 'managed.json').read_text())[NEW]
    assert record == {'owner': req['owner'], 'ip': req['ip'], 'state': 'revoked'}
    with pytest.raises(h.Refused, match='reactivated'):
        h.execute(req)
    with pytest.raises(h.Refused, match='another operation'):
        h.execute(dict(req, action='remove', owner=str(uuid.uuid4())))

@pytest.mark.parametrize('where', ['config', 'runtime'])
def test_remove_refuses_unmanaged_peer(server, where):
    conf, original, peers, calls, req, _ = server
    if where == 'config':
        conf.write_text(original + '\n[Peer]\nPublicKey = ' + NEW + '\nAllowedIPs = 10.30.0.7/32\n')
    else:
        peers[NEW] = ['10.30.0.7/32']
    before = conf.read_text()
    with pytest.raises(h.Refused, match='Unmanaged'):
        h.execute(dict(req, action='remove'))
    assert conf.read_text() == before
    assert not any(c[1] == 'set' for c in calls)

def test_remove_lost_reply_after_runtime_apply(server, monkeypatch):
    conf, original, peers, calls, req, run = server
    h.execute(req)
    def lose(args):
        result = run(args)
        if args[1:4] == ['set', 'wg0', 'peer']:
            raise TimeoutError('remove applied, reply lost')
        return result
    monkeypatch.setattr(h, 'run', lose)
    with pytest.raises(TimeoutError):
        h.execute(dict(req, action='remove'))
    assert NEW not in peers
    assert json.loads((h.STATE / 'managed.json').read_text())[NEW]['state'] == 'pending_remove'
    monkeypatch.setattr(h, 'run', run)
    assert h.execute(dict(req, action='remove'))['absence_confirmed'] is True

def test_remove_runtime_still_present_is_not_confirmed(server, monkeypatch):
    conf, original, peers, calls, req, run = server
    h.execute(req)
    def ignore_remove(args):
        if args[1:4] == ['set', 'wg0', 'peer'] and args[5] == 'remove':
            return ''
        return run(args)
    monkeypatch.setattr(h, 'run', ignore_remove)
    with pytest.raises(h.Refused, match='Runtime verification'):
        h.execute(dict(req, action='remove'))
    assert NEW in peers
    assert json.loads((h.STATE / 'managed.json').read_text())[NEW]['state'] == 'pending_remove'

def test_tombstone_write_failure_cannot_confirm_removal(server, monkeypatch):
    conf, original, peers, calls, req, _ = server
    h.execute(req)
    atomic = h.atomic
    def lose(path, text):
        if path.name == 'managed.json' and json.loads(text)[NEW]['state'] == 'revoked':
            return  # Simulate a journal that did not persist the final state.
        atomic(path, text)
    monkeypatch.setattr(h, 'atomic', lose)
    with pytest.raises(h.Refused, match='Removal not confirmed'):
        h.execute(dict(req, action='remove'))

@pytest.fixture
def acl_server(server, monkeypatch):
    h.STATE.mkdir(exist_ok=True)
    (h.STATE / 'access-enabled').touch()
    rules = []
    monkeypatch.setattr(h, 'enforce_access', lambda managed: rules.append(h.firewall_text(managed)))
    return server, rules

def test_access_policy_migration_and_revocation(acl_server):
    server, rules = acl_server
    conf, original, peers, calls, req, _ = server
    h.execute(req)
    before = conf.read_text()
    assigned = dict(req, action='access', environments=['dev', 'prod'], revision=1, group='a' * 64)
    assert h.execute(assigned)['enforced'] is True
    assert 'ip daddr 10.20.0.20/32 counter accept' in rules[-1]
    assert 'ip daddr 10.40.0.0/24 counter accept' in rules[-1]
    assert '10.30.0.2' not in rules[-1]  # unmanaged peer is untouched
    assert 'masquerade' not in rules[-1] and 'flush ruleset' not in rules[-1]
    assert conf.read_text() == before
    assert h.execute(dict(assigned, environments=['dev'], revision=2))['enforced']
    assert '10.40.0.0/24' not in rules[-1]
    assert 'ip daddr 10.40.0.10/32 udp dport 53 counter accept' in rules[-1]
    assert 'ip daddr 10.40.0.10/32 tcp dport 53 counter accept' in rules[-1]
    assert 'ip daddr 10.40.0.10/32 counter accept' not in rules[-1]
    with pytest.raises(h.Refused, match='revision'):
        h.execute(assigned)
    h.execute(dict(req, action='remove'))
    assert 'counter accept' not in rules[-1] and 'counter drop' in rules[-1]
    assert peers == {OLD: ['10.30.0.2/32']}

def test_late_enrollment_cannot_restore_older_user_grant(acl_server):
    server, rules = acl_server
    req = server[4]
    h.execute({'action': 'user_access', 'group': 'b' * 64, 'environments': ['dev'], 'revision': 2})
    h.execute(dict(req, environments=['dev', 'prod'], revision=1, group='b' * 64))
    assert '10.20.0.20/32' in rules[-1] and '10.40.0.0/24' not in rules[-1]
    record = json.loads((h.STATE / 'managed.json').read_text())[NEW]
    assert record['access_revision'] == 2
    with pytest.raises(h.Refused, match='revision'):
        h.execute({'action': 'user_access', 'group': 'b' * 64, 'environments': ['prod'], 'revision': 1})

def test_group_update_covers_bound_peers_without_config_mutation(acl_server):
    server, rules = acl_server
    req = server[4]
    h.execute(dict(req, environments=['dev', 'prod'], revision=1, group='c' * 64))
    before = server[0].read_text()
    h.execute({'action': 'user_access', 'group': 'c' * 64, 'environments': ['prod'], 'revision': 2})
    assert '10.20.0.20' not in rules[-1] and '10.40.0.0/24' in rules[-1]
    assert server[0].read_text() == before
    (h.STATE / 'access-users.json').unlink()
    with pytest.raises(h.Refused, match='Missing'):
        h.restore_access()

def test_access_disabled_refuses_before_peer_install(server):
    req = server[4]
    with pytest.raises(h.Refused, match='not enabled'):
        h.execute(dict(req, environments=['dev'], revision=1, group='a' * 64))
    assert NEW not in server[2] and server[0].read_text() == server[1]

def test_firewall_failure_never_installs_peer(acl_server, monkeypatch):
    server, rules = acl_server
    def fail(managed):
        raise TimeoutError('nft failed')
    monkeypatch.setattr(h, 'enforce_access', fail)
    req = dict(server[4], environments=['dev'], revision=1, group='d' * 64)
    with pytest.raises(TimeoutError):
        h.execute(req)
    assert NEW not in server[2] and server[0].read_text() == server[1]
    monkeypatch.setattr(h, 'enforce_access', lambda managed: rules.append(h.firewall_text(managed)))
    assert h.execute(req)['state'] == 'active'

@pytest.mark.parametrize('change', [
    {'environments': []}, {'environments': ['dev', 'dev']}, {'environments': ['prod', 'dev']},
    {'environments': ['dev; flush ruleset']}, {'revision': -1}, {'revision': True},
    {'revision': 2147483648}, {'group': 'x; flush ruleset'},
])
def test_access_request_validation(server, change):
    req = dict(server[4], environments=['dev'], revision=1, group='a' * 64)
    req.update(change)
    with pytest.raises(h.Refused):
        h.execute(req)
    assert server[0].read_text() == server[1]

@pytest.mark.parametrize('error', [h.Refused('bad journal'), RuntimeError('nft unavailable')])
def test_boot_restore_failure_has_nonzero_exit(monkeypatch, error):
    monkeypatch.setattr(h.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(h.sys, 'argv', ['helper', '--restore-access'])
    def fail():
        raise error
    monkeypatch.setattr(h, 'restore_access', fail)
    with pytest.raises(SystemExit) as caught:
        h.main()
    assert caught.value.code == 1
