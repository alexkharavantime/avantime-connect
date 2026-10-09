import base64
from datetime import datetime, timezone
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.mongo import db
from app.config import settings
from app.services.audit import import_history

pytestmark = pytest.mark.asyncio(loop_scope='session')

@pytest.fixture
async def client():
    for name in ('users', 'devices', 'invites', 'audit_events', 'audit_meta'):
        await db[name].delete_many({})
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            yield c

async def test_audit_lifecycle_and_secret_exclusion(client):
    await client.post('/api/users/', json={'login':'journal-user','full_name':'User','app_type':'desktop'})
    token = (await client.post('/api/invites/journal-user')).json()['token']
    key = base64.b64encode(bytes(range(1,33))).decode()
    body = {'token':token,'public_key':key,'device_name':'Laptop'}
    assert (await client.post('/api/enroll/', json=body)).status_code == 200
    assert (await client.post('/api/enroll/', json=body)).status_code == 200
    assert (await client.post('/api/devices/' + key + '/revoke')).status_code == 200
    events = (await client.get('/api/audit/')).json()
    assert events['total'] == 4
    assert [r['action'] for r in events['items']] == ['revoke','enroll','enroll','invite']
    assert all(r['status'] == 'success' for r in events['items'])
    assert events['items'][0]['vpn_ip']
    assert token not in str(events) and key not in str(events)
    await import_history()
    assert await db.audit_events.count_documents({}) == 4

async def test_history_idempotence_filters_csv_and_auth(client, monkeypatch):
    old = datetime(2020,1,1,tzinfo=timezone.utc)
    await db.devices.insert_one({'kind':'client','login':'=SUM(1)','device_name':'<b>Mac</b>',
        'vpn_ip':'10.30.0.77','public_key':'legacy','completed_at':old,'revoked_at':old})
    await import_history(); await import_history()
    assert await db.audit_events.count_documents({}) == 2
    r = await client.get('/api/audit/', params={'login':'=SUM(1)','limit':1})
    assert r.json()['total'] == 2 and len(r.json()['items']) == 1
    assert (await client.get('/api/audit/', params={'start':'2021-01-01'})).json()['total'] == 0
    assert (await client.get('/api/audit/', params={'start':'bad'})).status_code == 422
    exported = await client.get('/api/audit/export')
    assert "'=SUM(1)" in exported.text and exported.text.count('legacy') == 2
    monkeypatch.setattr(settings, 'admin_api_token', 'secret-admin')
    assert (await client.get('/api/audit/')).status_code == 401
    assert (await client.get('/api/audit/export')).status_code == 401
    assert (await client.get('/api/audit/', headers={'Authorization':'Bearer secret-admin'})).status_code == 200

async def test_invalid_enroll_is_recorded_without_secrets(client):
    response = await client.post('/api/enroll/', json={'token':'bad-secret','public_key':'bad','device_name':'Mac'})
    assert response.status_code == 404
    r = (await client.get('/api/audit/')).json()['items'][0]
    assert r['status'] == 'error' and r['http_status'] == 404
    assert 'bad-secret' not in str(r)

async def test_no_operation_when_intent_cannot_be_saved(monkeypatch):
    from types import SimpleNamespace
    from app.services import audit
    called = []
    async def unavailable(event):
        raise RuntimeError('database unavailable')
    async def operation(request):
        called.append(True)
    monkeypatch.setattr(audit, 'db', SimpleNamespace(audit_events=SimpleNamespace(insert_one=unavailable)))
    request = SimpleNamespace(method='POST', url=SimpleNamespace(path='/api/invites/user'))
    with pytest.raises(RuntimeError):
        await audit.audited(request, operation)
    assert not called
