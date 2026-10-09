import pytest
from app.config import settings
from app.db.mongo import db
from app.services import wireguard
from test_wg_flow import client, invitation, KEY

pytestmark = pytest.mark.asyncio(loop_scope='session')

@pytest.fixture
def enable_access(monkeypatch, fake_wireguard):
    monkeypatch.setattr(settings, 'access_control_enabled', True)
    h = fake_wireguard['helper']
    h.STATE.mkdir(exist_ok=True)
    (h.STATE / 'access-enabled').touch()
    rules = []
    h.enforce_access = lambda managed: rules.append(h.firewall_text(managed))
    return rules

async def test_legacy_upgrade_keeps_identity_and_immutable_snapshot(client, monkeypatch, fake_wireguard):
    body = await invitation(client)
    original = (await client.post('/api/enroll/', json=body)).json()
    monkeypatch.setattr(settings, 'access_control_enabled', True)
    h = fake_wireguard['helper']
    (h.STATE / 'access-enabled').touch()
    rules = []
    h.enforce_access = lambda managed: rules.append(h.firewall_text(managed))
    response = await client.post('/api/users/flow/access', json={'environments': ['prod', 'dev'], 'expected_revision': 0})
    assert response.status_code == 200, response.text
    current = await client.post('/api/enroll/profile', json=body)
    assert current.status_code == 200, current.text
    assert current.json()['vpn_ip'] == original['vpn_ip']
    assert current.json()['server_public_key'] == original['server_public_key']
    assert current.json()['allowed_ips'] == '10.20.0.20/32, 10.40.0.0/24'
    assert current.json()['environments'] == ['dev', 'prod']
    assert (await client.post('/api/enroll/', json=body)).json() == original
    assert len(fake_wireguard['peers']) == 1 and KEY in fake_wireguard['peers']
    assert '10.20.0.20/32' in rules[-1]
    assert (await client.post('/api/users/flow/access', json={'environments': ['dev'], 'expected_revision': 0})).status_code == 409

async def test_refresh_bound_to_device_and_admin_auth(client, enable_access, monkeypatch):
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=body)).status_code == 200
    monkeypatch.setattr(settings, 'admin_api_token', 'test-only-admin-' + 'x' * 32)
    assert (await client.post('/api/users/flow/access', json={'environments': ['dev'], 'expected_revision': 0})).status_code == 401
    for change in ({'token': 'wrong'}, {'device_name': 'other'}, {'public_key': 'other'}):
        assert (await client.post('/api/enroll/profile', json={**body, **change})).status_code == 403
    assert (await client.post('/api/enroll/profile', json=body)).status_code == 200
    await db.devices.update_one({'public_key': KEY}, {'$set': {'state': 'revoking'}})
    assert (await client.post('/api/enroll/profile', json=body)).status_code == 410

async def test_failed_application_requires_retry_before_profile_publication(client, enable_access, monkeypatch):
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=body)).status_code == 200
    original = wireguard.set_access
    async def fail(*args):
        raise wireguard.WireGuardError('test failure')
    monkeypatch.setattr(wireguard, 'set_access', fail)
    r = await client.post('/api/users/flow/access', json={'environments': ['dev'], 'expected_revision': 0})
    assert r.status_code == 502, r.text
    assert (await client.post('/api/enroll/profile', json=body)).status_code == 503
    assert '10.40.0.0/24' not in enable_access[-1]  # group restriction applied first
    monkeypatch.setattr(wireguard, 'set_access', original)
    assert (await client.post('/api/users/flow/access/retry')).status_code == 200
    profile = (await client.post('/api/enroll/profile', json=body)).json()
    assert profile['environments'] == ['dev'] and profile['rdp_host'] == '10.20.0.20'
    assert profile['allowed_ips'] == '10.20.0.20/32, 10.40.0.10/32'

async def test_feature_gate_and_invalid_assignment(client):
    assert (await client.post('/api/users/', json={'login': 'dev', 'full_name': 'Dev', 'app_type': 'desktop', 'environments': ['dev']})).status_code == 503
    for envs in ([], ['all'], ['dev', 'dev']):
        assert (await client.post('/api/users/', json={'login': 'dev', 'full_name': 'Dev', 'app_type': 'desktop', 'environments': envs})).status_code == 422
    assert (await client.post('/api/users/flow/access/retry')).status_code == 503

async def test_new_dev_only_enrollment(client, enable_access):
    r = await client.post('/api/users/', json={'login': 'dev', 'full_name': 'Dev', 'app_type': 'desktop', 'environments': ['dev']})
    assert r.status_code == 200
    token = (await client.post('/api/invites/dev')).json()['token']
    r = await client.post('/api/enroll/', json={'token': token, 'public_key': KEY, 'device_name': 'DEV-PC'})
    assert r.status_code == 200, r.text
    assert r.json()['allowed_ips'] == '10.20.0.20/32, 10.40.0.10/32'
    assert '10.40.0.0/24' not in enable_access[-1]
