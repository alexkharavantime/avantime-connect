from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pymongo.errors import DuplicateKeyError
from app.db.mongo import db
from app.models import EnrollRequest, EnrollResponse
from app.services.ipam import next_free_ip
from app.services import wireguard
from app.config import settings

router = APIRouter()

@router.post("/", response_model=EnrollResponse)
async def enroll(req: EnrollRequest):
    inv = await db.invites.find_one({"token": req.token})
    if not inv:
        raise HTTPException(404, "Токен не найден")
    if inv["used"]:
        raise HTTPException(409, "Токен уже использован")
    if inv["expires_at"].replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(410, "Срок действия токена истёк")

    user = await db.users.find_one({"login": inv["login"]})
    if not user:
        raise HTTPException(404, "Пользователь не найден")

    # Атомарная выдача адреса: уникальный индекс + retry на следующий
    device_id = None
    ip = None
    for _ in range(50):
        candidate = await next_free_ip()
        try:
            res = await db.devices.insert_one({
                "login": user["login"], "device_name": req.device_name,
                "public_key": req.public_key, "vpn_ip": candidate,
                "kind": "client", "revoked": False,
                "created_at": datetime.now(timezone.utc),
            })
            device_id, ip = res.inserted_id, candidate
            break
        except DuplicateKeyError:
            if await db.devices.find_one({"public_key": req.public_key}):
                raise HTTPException(409, "Устройство с таким ключом уже зарегистрировано")
            continue  # адрес перехватили параллельно — берём следующий
    if device_id is None:
        raise HTTPException(503, "Не удалось выделить адрес, повторите позже")

    # Завести peer; при сбое — откат записи устройства, токен НЕ расходуется
    try:
        await wireguard.add_peer(req.public_key, ip)
    except Exception:
        await db.devices.delete_one({"_id": device_id})
        raise HTTPException(502, "Не удалось завести peer на VPN-сервере; устройство откатано")

    # Токен помечаем использованным только после успеха
    await db.invites.update_one({"token": req.token}, {"$set": {"used": True}})

    return EnrollResponse(
        vpn_ip=ip,
        server_public_key=settings.wg_server_public_key,
        endpoint=settings.wg_endpoint,
        allowed_ips=settings.wg_allowed_ips,
        keepalive=settings.wg_keepalive,
        app_type=user["app_type"],
        rdp_host=settings.rdp_host,
    )
