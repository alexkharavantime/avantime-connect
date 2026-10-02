from fastapi import APIRouter, HTTPException
from app.db.mongo import db
from app.models import UserCreate

router = APIRouter()

@router.post("/")
async def create_user(u: UserCreate):
    if await db.users.find_one({"login": u.login}):
        raise HTTPException(409, "Пользователь с таким логином уже существует")
    await db.users.insert_one(u.model_dump())
    return {"login": u.login, "status": "created"}

@router.get("/")
async def list_users():
    return [ {k: v for k, v in d.items() if k != "_id"} async for d in db.users.find() ]
