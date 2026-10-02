from fastapi import APIRouter, HTTPException
from app.db.mongo import db
from app.services import wireguard

router = APIRouter()

@router.get("/")
async def list_devices():
    return [ {k: v for k, v in d.items() if k != "_id"}
             async for d in db.devices.find({"kind": "client"}) ]

@router.post("/{public_key}/revoke")
async def revoke_device(public_key: str):
    dev = await db.devices.find_one({"public_key": public_key, "kind": "client"})
    if not dev:
        raise HTTPException(404, "Устройство не найдено")
    await wireguard.remove_peer(public_key)
    await db.devices.update_one({"public_key": public_key}, {"$set": {"revoked": True}})
    return {"status": "revoked", "vpn_ip": dev["vpn_ip"]}
