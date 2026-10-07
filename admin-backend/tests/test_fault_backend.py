"""Harness regressions: real test MongoDB, simulated SSH/WireGuard only."""
import asyncio
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import pytest
from app.db.mongo import db
from app.services import wireguard
from integration.fault_backend import FaultController, load_settings, validate_settings
from test_wg_flow import client, invitation, KEY

pytestmark = pytest.mark.asyncio(loop_scope='session')
IP = '10.30.0.7'
REVOKE = '/api/devices/' + KEY + '/revoke'


def install(monkeypatch, tmp_path, mode, timeout=5):
    control = FaultController(KEY, IP, mode, tmp_path / 'control', timeout)
    add, remove = control.wrap(wireguard.add_peer, wireguard.remove_peer)
    monkeypatch.setattr(wireguard, 'add_peer', add)
    monkeypatch.setattr(wireguard, 'remove_peer', remove)
    return control


def events(control):
    return [json.loads(line)['event'] for line in
            (control.control_dir / 'events.jsonl').read_text().splitlines()]


@pytest.mark.parametrize('mode,applied,expected', [
    ('before-add', False, 502), ('delay-add-response', True, 410),
])
async def test_barrier_revoke_and_late_result(client, monkeypatch, fake_wireguard, tmp_path,
                                             mode, applied, expected):
    control = install(monkeypatch, tmp_path, mode)
    body = await invitation(client)
    task = asyncio.create_task(client.post('/api/enroll/', json=body))
    try:
        await asyncio.wait_for(control.reached.wait(), 3)
        dev = await db.devices.find_one({'public_key': KEY})
        assert dev['state'] == 'pending' and dev['wg_owner'] == control.owner
        assert (KEY in fake_wireguard['peers']) == applied
        assert (await client.post(REVOKE)).status_code == 200
    finally:
        (control.control_dir / 'release').touch()
        result = await asyncio.wait_for(task, 3)
    assert result.status_code == expected
    assert (await db.devices.find_one({'public_key': KEY}))['state'] == 'revoked'
    assert KEY not in fake_wireguard['peers']
    tombstone = json.loads((fake_wireguard['helper'].STATE / 'managed.json').read_text())[KEY]
    assert tombstone == {'ip': IP, 'owner': control.owner, 'state': 'revoked'}
    actions = [c['action'] for c in fake_wireguard['calls']]
    assert actions.count('add') == int(applied)
    assert actions.count('remove') == (2 if applied else 1)
    assert events(control).count('remove_confirmed') == (2 if applied else 1)
    assert body['token'] not in (control.control_dir / 'events.jsonl').read_text()


async def test_dropped_response_retains_pending_and_revoke_reconfirms(client, monkeypatch,
                                                                    fake_wireguard, tmp_path):
    control = install(monkeypatch, tmp_path, 'drop-add-response')
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=body)).status_code == 502
    assert KEY in fake_wireguard['peers']
    assert (await db.devices.find_one({'public_key': KEY}))['state'] == 'pending'
    assert not (await db.invites.find_one({'token': body['token']}))['used']
    # Retrying must not silently bypass the one-shot fault and activate the peer.
    assert (await client.post('/api/enroll/', json=body)).status_code == 502
    assert len([c for c in fake_wireguard['calls'] if c['action'] == 'add']) == 1
    for _ in range(2):
        assert (await client.post(REVOKE)).status_code == 200
    assert KEY not in fake_wireguard['peers']
    assert (await db.devices.find_one({'public_key': KEY}))['state'] == 'revoked'
    assert events(control).count('add_response_dropped') == 1
    assert events(control).count('remove_confirmed') == 2


@pytest.mark.parametrize('mode', ['before-add', 'delay-add-response'])
async def test_timeout_never_activates_and_cleanup_remains_available(client, monkeypatch,
                                                                  fake_wireguard, tmp_path, mode):
    control = install(monkeypatch, tmp_path, mode, timeout=0.02)
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=body)).status_code == 502
    assert (await db.devices.find_one({'public_key': KEY}))['state'] == 'pending'
    assert 'barrier_timeout' in events(control)
    assert (KEY in fake_wireguard['peers']) == (mode == 'delay-add-response')
    assert (await client.post(REVOKE)).status_code == 200
    assert KEY not in fake_wireguard['peers']


async def test_scope_and_confirmation_cannot_be_bypassed(client, monkeypatch, fake_wireguard, tmp_path):
    control = install(monkeypatch, tmp_path, 'none')
    body = await invitation(client)
    first = await client.post('/api/enroll/', json=body)
    assert first.status_code == 200
    assert (await client.post('/api/enroll/', json=body)).json() == first.json()
    before = len(fake_wireguard['calls'])
    for key, ip, owner in [(base64.b64encode(b'B' * 32).decode(), IP, control.owner),
                           (KEY, '10.30.0.8', control.owner), (KEY, IP, str(uuid.uuid4()))]:
        for action in (wireguard.add_peer, wireguard.remove_peer):
            with pytest.raises(wireguard.WireGuardError):
                await action(key, ip, owner)
    assert len(fake_wireguard['calls']) == before

    async def unconfirmed(payload):
        result = await fake_wireguard['dispatch'](payload)
        if payload['action'] == 'remove':
            result['absence_confirmed'] = False
        return result
    monkeypatch.setattr(wireguard, 'request', unconfirmed)
    assert (await client.post(REVOKE)).status_code == 502
    assert (await db.devices.find_one({'public_key': KEY}))['state'] == 'revoking'
    assert 'remove_confirmed' not in events(control)
    monkeypatch.setattr(wireguard, 'request', fake_wireguard['dispatch'])
    assert (await client.post(REVOKE)).status_code == 200


async def test_invalid_add_contract_is_not_logged_as_applied(client, monkeypatch, tmp_path):
    control = install(monkeypatch, tmp_path, 'drop-add-response')
    original = wireguard.request
    async def invalid(payload):
        result = await original(payload)
        if payload['action'] == 'add':
            result.pop('created')
        return result
    monkeypatch.setattr(wireguard, 'request', invalid)
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=body)).status_code == 502
    assert 'add_returned' not in events(control)
    assert 'add_response_dropped' not in events(control)
    assert (await client.post(REVOKE)).status_code == 200


def env_file(tmp_path):
    key, known = tmp_path / 'ssh-key', tmp_path / 'known-hosts'
    key.touch()
    known.touch()
    path = tmp_path / 'integration.env'
    path.write_text('\n'.join([
        'mongo_uri=mongodb://127.0.0.1:27018', 'db_name=avantime_connect_vm101_test_guard',
        'vpn_client_pool=10.30.0.7/32', 'wg_mode=ssh', 'admin_api_token=' + 't' * 32,
        'wg_server_public_key=' + KEY, 'wg_ssh_host=example.invalid', 'wg_ssh_user=avantime-wg',
        'wg_ssh_key_file=' + str(key), 'wg_ssh_known_hosts=' + str(known)]))
    path.chmod(0o600)
    return path


async def test_config_ignores_ambient_values_and_refuses_unsafe_settings(tmp_path, monkeypatch):
    path = env_file(tmp_path)
    monkeypatch.setenv('db_name', 'production')
    monkeypatch.setenv('mongo_uri', 'mongodb://production.invalid:27017')
    settings = load_settings(path)
    assert settings.db_name == 'avantime_connect_vm101_test_guard'
    assert settings.mongo_uri == 'mongodb://127.0.0.1:27018'
    for changes in ({'db_name': 'production'}, {'wg_mode': 'disabled'},
                    {'vpn_client_pool': '10.30.0.0/24'}, {'vpn_client_pool': '10.30.0.5/32'},
                    {'vpn_client_pool': '10.40.0.7/32'}, {'admin_api_token': ''}):
        with pytest.raises(ValueError):
            validate_settings(settings.model_copy(update=changes))
    path.chmod(0o644)
    with pytest.raises(ValueError, match='0600'):
        load_settings(path)
    path.chmod(0o600)
    path.write_text(path.read_text() + '\nwg_ssh_port=credential-that-must-not-appear')
    with pytest.raises(ValueError) as exc:
        load_settings(path)
    assert 'credential-that-must-not-appear' not in str(exc.value)


async def test_stale_control_directory_is_refused(tmp_path):
    directory = tmp_path / 'control'
    directory.mkdir()
    (directory / 'release').touch()
    with pytest.raises(FileExistsError):
        FaultController(KEY, IP, 'before-add', directory)


async def test_launcher_uses_selected_settings_and_loopback_without_starting_server(tmp_path):
    path = env_file(tmp_path)
    key = tmp_path / 'public-key'
    key.write_text(KEY)
    control = tmp_path / 'run'
    # Fresh interpreter checks import order. Uvicorn is intercepted before lifespan,
    # so this subprocess cannot open Mongo/SSH/listening sockets.
    script = '''
import sys, uvicorn
def check(app, **options):
    from app.config import settings
    from app.db.mongo import db
    from app.services import wireguard, ipam
    assert db.name == 'avantime_connect_vm101_test_guard'
    assert settings is wireguard.settings is ipam.settings
    assert options == {'host': '127.0.0.1', 'port': 18000, 'workers': 1, 'access_log': False}
    assert wireguard.add_peer.__module__ == 'integration.fault_backend'
uvicorn.run = check
from integration.fault_backend import main
main()
'''
    result = subprocess.run([sys.executable, '-c', script, '--env-file', str(path),
                             '--public-key-file', str(key), '--control-dir', str(control),
                             '--fault', 'before-add'], cwd=Path(__file__).resolve().parents[1],
                            env=dict(os.environ), capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    manifest = json.loads((control / 'manifest.json').read_text())
    assert manifest['listen'] == '127.0.0.1:18000'
    assert 'deploy/wireguard/helper.py' in manifest['source_sha256']
    assert 'admin-backend/app/routers/enroll.py' in manifest['source_sha256']
    assert 'admin_api_token' not in (control / 'manifest.json').read_text()
