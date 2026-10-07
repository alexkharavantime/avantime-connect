"""Real test MongoDB; real helper logic with file/runtime/SSH imitations only."""
import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone
import pytest
from app.config import settings
from app.db.mongo import db
from app.services import wireguard
from test_wg_flow import client, invitation, KEY

pytestmark = pytest.mark.asyncio(loop_scope='session')
REVOKE = '/api/devices/' + KEY + '/revoke'


def assert_absent(fake):
    helper = fake['helper']
    assert KEY not in fake['peers']
    assert KEY not in helper.CONF.read_text()
    assert json.loads((helper.STATE / 'managed.json').read_text())[KEY]['state'] == 'revoked'


@pytest.mark.parametrize('applied', [True, False])
async def test_pending_cancel_after_lost_add(client, monkeypatch, fake_wireguard, applied):
    fake = fake_wireguard
    async def lost(payload):
        if payload['action'] == 'add':
            if applied:
                await fake['dispatch'](payload)
            raise wireguard.WireGuardError('lost add response')
        return await fake['dispatch'](payload)
    monkeypatch.setattr(wireguard, 'request', lost)
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=body)).status_code == 502
    before = await db.devices.find_one({'public_key': KEY})
    assert before['state'] == 'pending'
    assert (await client.post(REVOKE)).status_code == 200
    after = await db.devices.find_one({'public_key': KEY})
    assert after['state'] == 'revoked' and after['revoked_at']
    assert after['vpn_ip'] == before['vpn_ip']
    assert await db.devices.count_documents({'vpn_ip': before['vpn_ip']}) == 1
    assert_absent(fake)
    assert (await client.post('/api/enroll/', json=body)).status_code == 409


@pytest.mark.parametrize('applied_before_revoke', [True, False])
async def test_enroll_revoke_race(client, monkeypatch, fake_wireguard, applied_before_revoke):
    fake = fake_wireguard
    entered, release = asyncio.Event(), asyncio.Event()
    async def delayed(payload):
        if payload['action'] != 'add':
            return await fake['dispatch'](payload)
        result = await fake['dispatch'](payload) if applied_before_revoke else None
        entered.set()
        await asyncio.wait_for(release.wait(), 5)
        return result if applied_before_revoke else await fake['dispatch'](payload)
    monkeypatch.setattr(wireguard, 'request', delayed)
    body = await invitation(client)
    task = asyncio.create_task(client.post('/api/enroll/', json=body))
    await asyncio.wait_for(entered.wait(), 5)
    try:
        assert (await client.post(REVOKE)).status_code == 200
    finally:
        release.set()
    result = await task
    assert result.status_code == (410 if applied_before_revoke else 502)
    assert (await db.devices.find_one({'public_key': KEY}))['state'] == 'revoked'
    assert_absent(fake)
    removes = [c for c in fake['calls'] if c['action'] == 'remove']
    # A successful but delayed add reply must execute enrollment compensation.
    assert len(removes) == (2 if applied_before_revoke else 1)
    assert (await client.post('/api/enroll/', json=body)).status_code == 409


async def test_failed_compensation_stays_revoking(client, monkeypatch, fake_wireguard):
    fake = fake_wireguard
    entered, release = asyncio.Event(), asyncio.Event()
    async def interrupted(payload):
        if payload['action'] == 'remove':
            raise wireguard.WireGuardError('offline')
        result = await fake['dispatch'](payload)
        if payload['action'] == 'add':
            entered.set()
            await asyncio.wait_for(release.wait(), 5)
        return result
    monkeypatch.setattr(wireguard, 'request', interrupted)
    body = await invitation(client)
    task = asyncio.create_task(client.post('/api/enroll/', json=body))
    await asyncio.wait_for(entered.wait(), 5)
    try:
        assert (await client.post(REVOKE)).status_code == 502
    finally:
        release.set()
    assert (await task).status_code == 502
    dev = await db.devices.find_one({'public_key': KEY})
    assert dev['state'] == 'revoking' and not dev['revoked']
    monkeypatch.setattr(wireguard, 'request', fake['dispatch'])
    assert (await client.post(REVOKE)).status_code == 200
    assert_absent(fake)


@pytest.mark.parametrize('failure', ['lost_reply', 'unconfirmed'])
async def test_remove_must_be_confirmed_and_retryable(client, monkeypatch, fake_wireguard, failure):
    fake = fake_wireguard
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=body)).status_code == 200
    async def lost(payload):
        result = await fake['dispatch'](payload)
        if payload['action'] == 'remove':
            if failure == 'lost_reply':
                raise wireguard.WireGuardError('lost remove response')
            result['absence_confirmed'] = False
        return result
    monkeypatch.setattr(wireguard, 'request', lost)
    assert (await client.post(REVOKE)).status_code == 502
    dev = await db.devices.find_one({'public_key': KEY})
    assert dev['state'] == 'revoking' and not dev['revoked']
    assert (await client.post('/api/enroll/', json=body)).status_code == 410
    monkeypatch.setattr(wireguard, 'request', fake['dispatch'])
    assert (await client.post(REVOKE)).status_code == 200
    revoked = await db.devices.find_one({'public_key': KEY})
    assert (await client.post(REVOKE)).status_code == 200
    assert (await db.devices.find_one({'public_key': KEY}))['revoked_at'] == revoked['revoked_at']
    assert_absent(fake)


async def test_recovery_returns_exact_snapshot_without_wg_or_new_ip(client, monkeypatch, fake_wireguard):
    body = await invitation(client)
    first = await client.post('/api/enroll/', json=body)
    assert first.status_code == 200
    snapshot = await db.devices.find_one({'enrolled_token': body['token']})
    calls = list(fake_wireguard['calls'])
    count = await db.devices.count_documents({})
    # Recovery remains available after invitation expiry/config/user changes.
    await db.invites.update_one({'token': body['token']}, {'$set': {
        'expires_at': datetime.now(timezone.utc) - timedelta(days=1)}})
    await db.users.delete_one({'login': 'flow'})
    monkeypatch.setattr(settings, 'wg_endpoint', 'changed.invalid:12345')
    monkeypatch.setattr(settings, 'rdp_host', 'changed.invalid')
    monkeypatch.setattr(settings, 'wg_server_public_key', 'changed')
    async def forbidden(*args):
        pytest.fail('Recovery must not access WireGuard')
    monkeypatch.setattr(wireguard, 'request', forbidden)
    for _ in range(2):
        result = await client.post('/api/enroll/', json=body)
        assert result.status_code == 200 and result.json() == first.json()
    assert fake_wireguard['calls'] == calls
    assert await db.devices.count_documents({}) == count
    assert await db.devices.find_one({'enrolled_token': body['token']}) == snapshot
    devices = (await client.get('/api/devices/')).json()
    assert body['token'] not in json.dumps(devices)


@pytest.mark.parametrize('change', [
    {'public_key': base64.b64encode(b'C' * 32).decode()}, {'device_name': 'other'},
])
async def test_recovery_identity_mismatch(client, fake_wireguard, change):
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=body)).status_code == 200
    assert (await client.post('/api/enroll/', json={**body, **change})).status_code == 409
    assert len([c for c in fake_wireguard['calls'] if c['action'] == 'add']) == 1


async def test_recovery_ttl_and_revoked(client):
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=body)).status_code == 200
    await db.devices.update_one({'enrolled_token': body['token']}, {'$set': {
        'completed_at': datetime.now(timezone.utc) - timedelta(seconds=settings.enroll_recovery_ttl + 1)}})
    assert (await client.post('/api/enroll/', json=body)).status_code == 410
    assert (await client.post(REVOKE)).status_code == 200
    result = await client.post('/api/enroll/', json=body)
    assert result.status_code == 410 and 'отозвано' in result.json()['detail']


async def test_new_expired_invite_is_not_extended_by_recovery(client, fake_wireguard):
    body = await invitation(client)
    await db.invites.update_one({'token': body['token']}, {'$set': {
        'expires_at': datetime.now(timezone.utc) - timedelta(seconds=1)}})
    assert (await client.post('/api/enroll/', json=body)).status_code == 410
    assert not fake_wireguard['calls']
    assert await db.devices.count_documents({'kind': 'client'}) == 0


async def test_crash_between_active_snapshot_and_used(client, monkeypatch, fake_wireguard):
    body = await invitation(client)
    collection_type = type(db.invites)
    update = collection_type.update_one
    async def crash(collection, query, changes, *args, **kwargs):
        if collection.name == 'invites' and changes.get('$set', {}).get('used'):
            raise RuntimeError('simulated process failure before used')
        return await update(collection, query, changes, *args, **kwargs)
    monkeypatch.setattr(collection_type, 'update_one', crash)
    with pytest.raises(RuntimeError, match='simulated process failure'):
        await client.post('/api/enroll/', json=body)
    assert not (await db.invites.find_one({'token': body['token']}))['used']
    dev = await db.devices.find_one({'enrolled_token': body['token']})
    assert dev['state'] == 'active'
    monkeypatch.setattr(collection_type, 'update_one', update)
    result = await client.post('/api/enroll/', json=body)
    assert result.status_code == 200 and result.json()['vpn_ip'] == dev['vpn_ip']
    assert (await db.invites.find_one({'token': body['token']}))['used']
    assert len([c for c in fake_wireguard['calls'] if c['action'] == 'add']) == 1


async def test_concurrent_login_conflict_is_409(client, monkeypatch):
    body = {'login': 'simultaneous', 'full_name': 'Test', 'app_type': 'desktop'}
    collection_type = type(db.users)
    insert = collection_type.insert_one
    waiting = 0
    both_ready = asyncio.Event()
    async def synchronized(collection, document, *args, **kwargs):
        nonlocal waiting
        if collection.name == 'users' and document['login'] == body['login']:
            waiting += 1
            if waiting == 2:
                both_ready.set()
            await asyncio.wait_for(both_ready.wait(), 5)
        return await insert(collection, document, *args, **kwargs)
    monkeypatch.setattr(collection_type, 'insert_one', synchronized)
    results = await asyncio.gather(*(client.post('/api/users/', json=body) for _ in range(2)))
    assert sorted(r.status_code for r in results) == [200, 409]
    assert await db.users.count_documents({'login': body['login']}) == 1


async def test_concurrent_revokes_do_not_downgrade_state(client, monkeypatch, fake_wireguard):
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=body)).status_code == 200
    entered, release = asyncio.Event(), asyncio.Event()
    async def delayed(payload):
        if payload['action'] == 'remove' and not entered.is_set():
            entered.set()
            await asyncio.wait_for(release.wait(), 5)
        return await fake_wireguard['dispatch'](payload)
    monkeypatch.setattr(wireguard, 'request', delayed)
    first = asyncio.create_task(client.post(REVOKE))
    await asyncio.wait_for(entered.wait(), 5)
    try:
        assert (await client.post(REVOKE)).status_code == 200
        completed = await db.devices.find_one({'public_key': KEY})
    finally:
        release.set()
    assert (await first).status_code == 200
    assert (await db.devices.find_one({'public_key': KEY})) == completed
    assert_absent(fake_wireguard)


@pytest.mark.parametrize('age,expected', [(1, 200), (2, 200), (3, 410)])
async def test_recovery_ttl_seconds_inclusive_boundary(client, monkeypatch, age, expected):
    from app.routers import enroll as enroll_router
    body = await invitation(client)
    assert (await client.post('/api/enroll/', json=body)).status_code == 200
    now = datetime.now(timezone.utc).replace(microsecond=0)
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now
    monkeypatch.setattr(enroll_router, 'datetime', Clock)
    monkeypatch.setattr(settings, 'enroll_recovery_ttl', 2)
    await db.devices.update_one({'enrolled_token': body['token']}, {'$set': {
        'completed_at': now - timedelta(seconds=age)}})
    assert (await client.post('/api/enroll/', json=body)).status_code == expected


async def test_expired_lease_late_add_reply_does_not_remove_completed_peer(client, monkeypatch, fake_wireguard):
    entered, release = asyncio.Event(), asyncio.Event()
    async def delayed(payload):
        result = await fake_wireguard['dispatch'](payload)
        if payload['action'] == 'add' and not entered.is_set():
            entered.set()
            await asyncio.wait_for(release.wait(), 5)
        return result
    monkeypatch.setattr(wireguard, 'request', delayed)
    body = await invitation(client)
    first = asyncio.create_task(client.post('/api/enroll/', json=body))
    await asyncio.wait_for(entered.wait(), 5)
    try:
        await db.invites.update_one({'token': body['token']}, {'$set': {
            'lease_until': datetime.now(timezone.utc) - timedelta(seconds=1)}})
        second = await client.post('/api/enroll/', json=body)
        assert second.status_code == 200
        completed = await db.devices.find_one({'enrolled_token': body['token']})
    finally:
        release.set()
    result = await first
    assert result.status_code == 200 and result.json() == second.json()
    assert await db.devices.find_one({'enrolled_token': body['token']}) == completed
    assert await db.devices.count_documents({'kind': 'client'}) == 1
    assert KEY in fake_wireguard['peers']
    assert not any(c['action'] == 'remove' for c in fake_wireguard['calls'])
