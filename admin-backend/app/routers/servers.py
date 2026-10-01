from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def list_servers():
    # TODO: Фаза 1 — реализация
    return []
