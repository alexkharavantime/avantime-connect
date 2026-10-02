from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.db.mongo import init_indexes, seed_reserved
from app.routers import users, devices, invites, enroll, servers

@asynccontextmanager
async def lifespan(app: FastAPI):
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
