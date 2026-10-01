from fastapi import FastAPI
from app.routers import users, devices, invites, enroll, servers

app = FastAPI(title="Avantime Connect Admin API")

app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
app.include_router(invites.router, prefix="/api/invites", tags=["invites"])
app.include_router(enroll.router, prefix="/api/enroll", tags=["enroll"])
app.include_router(servers.router, prefix="/api/servers", tags=["servers"])

@app.get("/api/health")
async def health():
    return {"status": "ok"}
