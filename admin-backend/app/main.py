from contextlib import asynccontextmanager
from fastapi import FastAPI
from starlette.responses import JSONResponse
import secrets
from app.config import settings
from app.db.mongo import init_indexes, seed_reserved
from app.routers import users, devices, invites, enroll, servers

@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.wg_mode == "ssh" and len(settings.admin_api_token) < 32:
        raise RuntimeError("SSH mode requires admin_api_token of at least 32 characters")
    await init_indexes()
    await seed_reserved()
    yield

app = FastAPI(title="Avantime Connect Admin API", lifespan=lifespan)
app.include_router(users.router,   prefix="/api/users",   tags=["users"])
app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
app.include_router(invites.router, prefix="/api/invites", tags=["invites"])
app.include_router(enroll.router,  prefix="/api/enroll",  tags=["enroll"])
app.include_router(servers.router, prefix="/api/servers", tags=["servers"])

@app.get("/api/health")
async def health():
    return {"status": "ok"}

@app.middleware("http")
async def admin_auth(request, call_next):
    path = request.url.path.rstrip("/")
    protected = path.startswith("/api/") and path not in ("/api/health", "/api/enroll")
    # A configured token is enforced in every mode; SSH mode fails closed without one.
    if protected and (settings.admin_api_token or settings.wg_mode == "ssh"):
        expected = "Bearer " + settings.admin_api_token
        supplied = request.headers.get("authorization", "")
        if not settings.admin_api_token or not secrets.compare_digest(supplied.encode(), expected.encode()):
            return JSONResponse({"detail": "Требуется ключ администратора"}, status_code=401)
    return await call_next(request)
