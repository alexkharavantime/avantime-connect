from fastapi import APIRouter, HTTPException
from pymongo.errors import DuplicateKeyError
from app.db.mongo import db
from app.models import UserCreate

router = APIRouter()

@router.post("/")
async def create_user(u: UserCreate):
    try:
        await db.users.insert_one(u.model_dump())
    except DuplicateKeyError:
        raise HTTPException(409, "Пользователь с таким логином уже существует")
    return {"login": u.login, "status": "created"}

@router.get("/")
async def list_users():
    return [ {k: v for k, v in d.items() if k != "_id"} async for d in db.users.find() ]
