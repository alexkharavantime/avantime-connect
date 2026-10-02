import os
# отдельная тестовая БД, не трогаем рабочую
os.environ["db_name"] = "avantime_connect_test"

import pytest

pytestmark = pytest.mark.asyncio(loop_scope="session")
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.mongo import db

@pytest.fixture(autouse=True)
async def clean_db():
    for c in ("users", "devices", "invites"):
        await db[c].delete_many({})
    yield
    for c in ("users", "devices", "invites"):
        await db[c].delete_many({})

@pytest.fixture
async def client():
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac

async def test_health(client):
    r = await client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"

async def test_create_user_and_duplicate(client):
    u = {"login": "ivanov", "full_name": "Иванов Иван", "app_type": "desktop"}
    assert (await client.post("/api/users/", json=u)).status_code == 200
    assert (await client.post("/api/users/", json=u)).status_code == 409  # дубль

async def test_invite_and_enroll_flow(client):
    u = {"login": "petrov", "full_name": "Петров Пётр", "app_type": "remoteapp64"}
    await client.post("/api/users/", json=u)
    token = (await client.post("/api/invites/petrov")).json()["token"]

    body = {"token": token, "public_key": "PUBKEY_TEST_1", "device_name": "laptop"}
    r = await client.post("/api/enroll/", json=body)
    assert r.status_code == 200
    ip = r.json()["vpn_ip"]
    # адрес НЕ из серверной сети и НЕ зарезервированный 10.30.0.5
    assert not ip.startswith("10.40.0.")
    assert ip != "10.30.0.5"

    # повторное использование токена запрещено
    r2 = await client.post("/api/enroll/", json=body)
    assert r2.status_code == 409

async def test_enroll_bad_token(client):
    body = {"token": "nope", "public_key": "X", "device_name": "d"}
    assert (await client.post("/api/enroll/", json=body)).status_code == 404

async def test_revoke_device(client):
    u = {"login": "sidorov", "full_name": "Сидоров С", "app_type": "desktop"}
    await client.post("/api/users/", json=u)
    token = (await client.post("/api/invites/sidorov")).json()["token"]
    await client.post("/api/enroll/", json={"token": token, "public_key": "PK2", "device_name": "pc"})
    r = await client.post("/api/devices/PK2/revoke")
    assert r.status_code == 200 and r.json()["status"] == "revoked"
