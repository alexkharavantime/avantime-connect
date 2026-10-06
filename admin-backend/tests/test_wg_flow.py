import asyncio
import base64
import ipaddress
import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app
from app.db.mongo import db, init_indexes, seed_reserved
from app.services import wireguard
from app.config import settings

pytestmark = pytest.mark.asyncio(loop_scope='session')
KEY = base64.b64encode(bytes([255]) * 32).decode()

@pytest.fixture
async def client():
    for collection in ('users', 'devices', 'invites'):
        await db[collection].delete_many({})
    await init_indexes()
    await seed_reserved()
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
        yield c

async def invitation(c):
    await c.post('/api/users/', json={'login': 'flow', 'full_name': 'Flow', 'app_type': 'desktop'})
    token = (await c.post('/api/invites/flow')).json()['token']
    return {'token': token, 'public_key': KEY, 'device_name': 'test'}

async def test_live_addresses_and_slash_key(client, monkeypatch):
    async def occupied():
        return [ipaddress.ip_network('10.30.0.7/32'), ipaddress.ip_network('10.30.0.8/31')]
    monkeypatch.setattr(wireguard, 'occupied_networks', occupied)
    body = await invitation(client)
    r = await client.post('/api/enroll/', json=body)
    assert r.status_code == 200, r.text
    assert r.json()['vpn_ip'] == '10.30.0.11'
    assert (await client.post('/api/devices/' + KEY + '/revoke')).status_code == 200

async def test_timeout_keeps_ip_owner_and_retry(client, monkeypatch):
    calls = []
    async def add(key, ip, owner):
        calls.append((key, ip, owner))
        if len(calls) == 1:
            raise wireguard.WireGuardError('lost reply')
    monkeypatch.setattr(wireguard, 'add_peer', add)
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=body)).status_code == 502
    dev = await db.devices.find_one({'public_key': KEY})
    assert dev['state'] == 'pending'
    assert not (await db.invites.find_one({'token': body['token']}))['used']
    changed = dict(body, device_name='another')
    assert (await client.post('/api/enroll/', json=changed)).status_code == 409
    assert (await client.post('/api/enroll/', json=body)).status_code == 200
    assert calls[0] == calls[1]
    assert (await client.post('/api/enroll/', json=body)).status_code == 200

async def test_concurrent_token_only_one_peer(client, monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []
    async def add(*args):
        calls.append(args)
        entered.set()
        await release.wait()
    monkeypatch.setattr(wireguard, 'add_peer', add)
    body = await invitation(client)
    first = asyncio.create_task(client.post('/api/enroll/', json=body))
    await asyncio.wait_for(entered.wait(), 2)
    try:
        assert (await client.post('/api/enroll/', json=body)).status_code == 409
    finally:
        release.set()
    assert (await first).status_code == 200
    assert len(calls) == 1

async def test_revoke_timeout_can_retry(client, monkeypatch):
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=body)).status_code == 200
    calls = []
    async def remove(*args):
        calls.append(args)
        if len(calls) == 1:
            raise wireguard.WireGuardError('lost reply')
    monkeypatch.setattr(wireguard, 'remove_peer', remove)
    url = '/api/devices/' + KEY + '/revoke'
    assert (await client.post(url)).status_code == 502
    dev = await db.devices.find_one({'public_key': KEY})
    assert not dev['revoked'] and dev['state'] == 'revoking'
    assert (await client.post(url)).status_code == 200
    assert calls[0] == calls[1]
    assert (await client.post(url)).status_code == 200
    assert len(calls) == 3  # Even an already-revoked retry reconfirms absence.

async def test_invalid_key_and_unavailable_server(client, monkeypatch):
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=dict(body, public_key='UI_TEST_KEY_01'))).status_code == 422
    async def fail():
        raise wireguard.WireGuardError('offline')
    monkeypatch.setattr(wireguard, 'occupied_networks', fail)
    assert (await client.post('/api/enroll/', json=body)).status_code == 503
    assert 'enrollment' not in (await db.invites.find_one({'token': body['token']}))

async def test_auth_gate(client, monkeypatch):
    monkeypatch.setattr(settings, 'wg_mode', 'ssh')
    monkeypatch.setattr(settings, 'admin_api_token', 'x' * 32)
    assert (await client.get('/api/devices/')).status_code == 401
    assert (await client.get('/api/devices/', headers={'Authorization': 'Bearer ' + 'x' * 32})).status_code == 200
    assert (await client.get('/api/health')).status_code == 200
