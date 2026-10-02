from fastapi import APIRouter
from app.config import settings

router = APIRouter()

@router.get("/")
async def server_profile():
    return {
        "endpoint": settings.wg_endpoint,
        "server_public_key": settings.wg_server_public_key,
        "allowed_ips": settings.wg_allowed_ips,
        "rdp_host": settings.rdp_host,
        "vpn_client_pool": settings.vpn_client_pool,
    }
