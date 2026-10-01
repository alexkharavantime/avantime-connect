from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def list_invites():
    # TODO: Фаза 1 — реализация
    return []
