"""Durable operation receipts. Never store request bodies, tokens or keys."""
from datetime import datetime, timezone
import uuid
from fastapi.responses import JSONResponse
from app.db.mongo import db

async def audited(request, call_next):
    path = request.url.path.rstrip('/')
    action = None
    subject = {}
    body = {}
    if request.method == 'POST':
        if path == '/api/enroll':
            action = 'enroll'
            try:
                body = await request.json()
                if isinstance(body, dict):
                    inv = await db.invites.find_one({'token': body.get('token')}) if isinstance(body.get('token'), str) else None
                    subject = {'login': inv.get('login', '') if inv else '',
                               'device_name': str(body.get('device_name', ''))[:256]}
            except (ValueError, TypeError):
                pass
        elif path.startswith('/api/invites/'):
            action, subject = 'invite', {'login': path[len('/api/invites/'): ]}
        elif path.startswith('/api/users/') and path.endswith(('/access', '/access/retry')):
            action = 'access'
            suffix = '/access/retry' if path.endswith('/access/retry') else '/access'
            subject = {'login': path[len('/api/users/'):-len(suffix)]}
        elif path.startswith('/api/devices/') and path.endswith('/revoke'):
            action = 'revoke'
            dev = await db.devices.find_one({'public_key': path[len('/api/devices/'):-len('/revoke')]})
            subject = {k: dev.get(k, '') for k in ('login', 'device_name', 'vpn_ip')} if dev else {}
    if not action:
        return await call_next(request)
    event_id = str(uuid.uuid4())
    event = {'_id': event_id, 'timestamp': datetime.now(timezone.utc), 'action': action,
             'status': 'unconfirmed', 'source': 'operation',
             'actor': 'device_invitation' if action == 'enroll' else 'shared_admin_key', **subject}
    # Persist intent before any side effect; a crash leaves an explicit unconfirmed receipt.
    await db.audit_events.insert_one(event)
    response = await call_next(request)
    result = {'http_status': response.status_code, 'finished_at': datetime.now(timezone.utc),
              'status': 'success' if 200 <= response.status_code < 300 else 'error'}
    if action == 'enroll' and isinstance(body, dict) and isinstance(body.get('token'), str):
        dev = await db.devices.find_one({'enrolled_token': body['token']})
        if dev:
            result.update({k: dev.get(k, '') for k in ('login', 'device_name', 'vpn_ip')})
    if action == 'access' and subject.get('login'):
        user = await db.users.find_one({'login': subject['login']})
        if user:
            result.update(environments=user.get('environments', ['prod']), access_revision=user.get('access_revision', 0))
    try:
        await db.audit_events.update_one({'_id': event_id}, {'$set': result})
    except Exception:
        return JSONResponse({'detail': 'Операция могла выполниться, запись результата в журнал не подтверждена. Обновите состояние перед повтором.'}, status_code=503)
    return response

async def import_history():
    await db.audit_meta.update_one({'_id': 'started'}, {'$setOnInsert': {'at': datetime.now(timezone.utc)}}, upsert=True)
    cutoff = (await db.audit_meta.find_one({'_id': 'started'}))['at']
    # Only dates actually present in the DB; never invent old access assignments.
    async for dev in db.devices.find({'kind': 'client'}):
        for field, action in (('completed_at', 'enroll'), ('revoked_at', 'revoke')):
            if not isinstance(dev.get(field), datetime) or dev[field] >= cutoff:
                continue
            event = {'timestamp': dev[field], 'action': action, 'status': 'success',
                     'source': 'legacy', 'actor': 'unknown',
                     **{k: dev.get(k, '') for k in ('login', 'device_name', 'vpn_ip')}}
            await db.audit_events.update_one({'_id': 'legacy:' + str(dev['_id']) + ':' + field},
                                            {'$setOnInsert': event}, upsert=True)
