from datetime import datetime, timedelta, timezone
import uuid
from fastapi import APIRouter, HTTPException
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from app.db.mongo import db
from app.models import EnrollRequest, EnrollResponse
from app.services.ipam import next_free_ip
from app.services import wireguard
from app.config import settings

router = APIRouter()

@router.post('/', response_model=EnrollResponse)
async def enroll(req: EnrollRequest):
    inv = await db.invites.find_one({'token': req.token})
    if not inv:
        raise HTTPException(404, 'Токен не найден')
    if inv['used']:
        raise HTTPException(409, 'Токен уже использован')
    previous = inv.get('enrollment')
    if not previous and inv['expires_at'].replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(410, 'Срок действия токена истёк')
    try:
        wireguard.validate_public_key(req.public_key)
    except ValueError:
        raise HTTPException(422, 'Некорректный публичный ключ WireGuard')
    if previous and (previous['public_key'] != req.public_key or previous['device_name'] != req.device_name):
        raise HTTPException(409, 'Приглашение закреплено за другим устройством')
    user = await db.users.find_one({'login': inv['login']})
    if not user:
        raise HTTPException(404, 'Пользователь не найден')
    # Check connectivity and all live/configured addresses BEFORE reserving the token.
    try:
        occupied = await wireguard.occupied_networks()
    except wireguard.WireGuardError:
        raise HTTPException(503, 'WireGuard недоступен или не настроен')
    enrollment = previous or {'owner': str(uuid.uuid4()), 'public_key': req.public_key,
                               'device_name': req.device_name}
    lease = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    query = {'token': req.token, 'used': False,
             '$or': [{'lease_until': {'$exists': False}}, {'lease_until': {'$lte': now}}]}
    # A stale reader must not replace a claim made by another request.
    query['enrollment.owner'] = previous['owner'] if previous else {'$exists': False}
    claimed = await db.invites.find_one_and_update(query, {'$set': {
        'enrollment': enrollment, 'lease': lease, 'lease_until': now + timedelta(seconds=120)}},
        return_document=ReturnDocument.AFTER)
    if not claimed:
        raise HTTPException(409, 'Регистрация уже выполняется; повторите тот же запрос позже')
    owner = enrollment['owner']
    try:
        dev = await db.devices.find_one({'_id': owner})
        if dev and dev.get('state') in ('revoking', 'revoked'):
            raise HTTPException(409, 'Устройство отозвано')
        if dev is None:
            for _ in range(50):
                try:
                    ip = await next_free_ip(occupied)
                except RuntimeError:
                    raise HTTPException(503, 'Пул адресов исчерпан')
                dev = {'_id': owner, 'login': user['login'], 'device_name': req.device_name,
                       'public_key': req.public_key, 'vpn_ip': ip, 'kind': 'client',
                       'revoked': False, 'state': 'pending', 'wg_owner': owner, 'created_at': now}
                try:
                    await db.devices.insert_one(dev)
                    break
                except DuplicateKeyError:
                    if await db.devices.find_one({'public_key': req.public_key}):
                        raise HTTPException(409, 'Устройство с таким ключом уже зарегистрировано')
            else:
                raise HTTPException(503, 'Не удалось выделить адрес')
        if dev['state'] != 'active':
            try:
                await wireguard.add_peer(req.public_key, dev['vpn_ip'], owner)
            except wireguard.WireGuardError:
                # A lost SSH response does NOT mean that the peer was not installed.
                # Keep token binding/IP/owner so retry converges on the same operation.
                raise HTTPException(502, 'Результат VPN-операции не подтверждён. Повторите тот же запрос; адрес сохранён')
            await db.devices.update_one({'_id': owner}, {'$set': {'state': 'active'}})
        await db.invites.update_one({'token': req.token, 'lease': lease}, {'$set': {'used': True}})
        return EnrollResponse(vpn_ip=dev['vpn_ip'], server_public_key=settings.wg_server_public_key,
            endpoint=settings.wg_endpoint, allowed_ips=settings.wg_allowed_ips,
            keepalive=settings.wg_keepalive, app_type=user['app_type'], rdp_host=settings.rdp_host)
    finally:
        await db.invites.update_one({'token': req.token, 'lease': lease},
            {'$unset': {'lease': '', 'lease_until': ''}})
