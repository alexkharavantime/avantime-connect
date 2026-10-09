from fastapi import APIRouter, HTTPException
from pymongo.errors import DuplicateKeyError
from app.db.mongo import db
from app.models import UserCreate, AccessUpdate
from app.config import settings
from app.services import access, wireguard
from pymongo import ReturnDocument

router = APIRouter()

@router.post("/")
async def create_user(u: UserCreate):
    if not settings.access_control_enabled and u.environments != ['prod']:
        raise HTTPException(503, 'Серверные ограничения доступа ещё не включены')
    try:
        await db.users.insert_one(u.model_dump())
    except DuplicateKeyError:
        raise HTTPException(409, "Пользователь с таким логином уже существует")
    return {"login": u.login, "status": "created"}

@router.get("/")
async def list_users():
    return [ {k: v for k, v in d.items() if k != "_id"} async for d in db.users.find() ]

@router.post('/{login}/access')
async def update_access(login: str, change: AccessUpdate):
    if not settings.access_control_enabled:
        raise HTTPException(503, 'Сначала включите серверные ограничения доступа')
    query = {'login': login, '$or': [{'access_revision': 0}, {'access_revision': {'$exists': False}}]} if change.expected_revision == 0 else {'login': login, 'access_revision': change.expected_revision}
    user = await db.users.find_one_and_update(query,
        {'$set': {'environments': change.environments}, '$inc': {'access_revision': 1}},
        return_document=ReturnDocument.AFTER)
    if not user:
        raise HTTPException(409, 'Обновите список: пользователь или назначение изменились')
    return await apply_access(login)

@router.post('/{login}/access/retry')
async def apply_access(login: str):
    if not settings.access_control_enabled:
        raise HTTPException(503, 'Серверные ограничения доступа не включены')
    user = await db.users.find_one({'login': login})
    if not user:
        raise HTTPException(404, 'Пользователь не найден')
    try:
        envs, revision = access.policy(user)
        await wireguard.set_user_access(access.group(login), envs, revision)
    except wireguard.WireGuardError:
        raise HTTPException(502, 'Назначение сохранено, применение не подтверждено. Повторите применение.')
    failed = []
    async for dev in db.devices.find({'login': login, 'kind': 'client', 'state': 'active'}):
        try:
            await access.reconcile(dev)
        except (wireguard.WireGuardError, HTTPException, ValueError):
            failed.append(dev['device_name'])
    if failed:
        raise HTTPException(502, 'Назначение сохранено, но применение не подтверждено для: ' + ', '.join(failed) + '. Нажмите «Повторить применение».')
    latest = await db.users.find_one({'login': login})
    if not latest or access.policy(latest) != (envs, revision):
        raise HTTPException(409, 'Назначение изменилось; обновите список и повторите применение')
    return {'status': 'applied', 'environments': user.get('environments', ['prod']), 'access_revision': user.get('access_revision', 0)}
