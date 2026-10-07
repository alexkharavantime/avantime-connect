from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException
from app.db.mongo import db
from app.services.tokens import new_invite_token
from app.config import settings

router = APIRouter()

@router.post("/{login}")
async def create_invite(login: str):
    if not await db.users.find_one({"login": login}):
        raise HTTPException(404, "Пользователь не найден")
    token = new_invite_token()
    expires = datetime.now(timezone.utc) + timedelta(hours=settings.invite_ttl_hours)
    await db.invites.insert_one({"token": token, "login": login,
                                 "expires_at": expires, "used": False})
    return {"token": token, "expires_at": expires.isoformat()}
