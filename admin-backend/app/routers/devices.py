from fastapi import APIRouter, HTTPException
from pymongo import ReturnDocument
from app.db.mongo import db
from app.services import wireguard
from app.services.device_lifecycle import finish_revocation

router = APIRouter()

@router.get('/')
async def list_devices():
    return [{k: v for k, v in d.items() if k not in ('_id', 'wg_owner', 'enrolled_token')}
            async for d in db.devices.find({'kind': 'client'})]

# A real base64 public key may contain '/', including encoded slashes.
@router.post('/{public_key:path}/revoke')
async def revoke_device(public_key: str):
    dev = await db.devices.find_one({'public_key': public_key, 'kind': 'client'})
    if not dev:
        raise HTTPException(404, 'Устройство не найдено')
    if not dev.get('wg_owner'):
        raise HTTPException(409, 'Старая тестовая запись: управление реальным VPN запрещено')
    claimed = await db.devices.find_one_and_update(
        {'_id': dev['_id'], 'state': {'$in': ['pending', 'active']}},
        {'$set': {'state': 'revoking'}}, return_document=ReturnDocument.AFTER)
    if claimed is None:
        dev = await db.devices.find_one({'_id': dev['_id']})
        if not dev or dev.get('state') not in ('revoking', 'revoked'):
            raise HTTPException(409, 'Состояние устройства не допускает отзыв')
    else:
        dev = claimed
    try:
        await finish_revocation(dev)
    except (wireguard.WireGuardError, ValueError):
        raise HTTPException(502, 'Отзыв VPN не подтверждён; повторите отзыв')
    current = await db.devices.find_one({'_id': dev['_id'], 'state': 'revoked'})
    if not current:
        raise HTTPException(409, 'Отзыв VPN не подтверждён; повторите отзыв')
    return {'status': 'revoked', 'vpn_ip': dev['vpn_ip']}
