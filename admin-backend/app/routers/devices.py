from fastapi import APIRouter, HTTPException
from app.db.mongo import db
from app.services import wireguard

router = APIRouter()

@router.get('/')
async def list_devices():
    return [{k: v for k, v in d.items() if k not in ('_id', 'wg_owner')}
            async for d in db.devices.find({'kind': 'client'})]

# A real base64 public key may contain '/', including encoded slashes.
@router.post('/{public_key:path}/revoke')
async def revoke_device(public_key: str):
    dev = await db.devices.find_one({'public_key': public_key, 'kind': 'client'})
    if not dev:
        raise HTTPException(404, 'Устройство не найдено')
    if dev.get('revoked'):
        return {'status': 'revoked', 'vpn_ip': dev['vpn_ip']}
    if not dev.get('wg_owner'):
        raise HTTPException(409, 'Старая тестовая запись: управление реальным VPN запрещено')
    if dev.get('state') not in ('active', 'revoking'):
        raise HTTPException(409, 'Сначала завершите регистрацию повтором исходного запроса')
    await db.devices.update_one({'_id': dev['_id']}, {'$set': {'state': 'revoking'}})
    try:
        await wireguard.remove_peer(public_key, dev['vpn_ip'], dev['wg_owner'])
    except (wireguard.WireGuardError, ValueError):
        raise HTTPException(502, 'Отзыв VPN не подтверждён; повторите отзыв')
    await db.devices.update_one({'_id': dev['_id']}, {'$set': {'revoked': True, 'state': 'revoked'}})
    return {'status': 'revoked', 'vpn_ip': dev['vpn_ip']}
