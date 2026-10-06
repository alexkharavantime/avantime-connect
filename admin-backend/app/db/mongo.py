from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings

client = AsyncIOMotorClient(settings.mongo_uri)
db = client[settings.db_name]

async def init_indexes():
    await db.devices.create_index("vpn_ip", unique=True)
    await db.devices.create_index("public_key", unique=True)
    await db.devices.create_index("enrolled_token", unique=True, sparse=True)
    await db.users.create_index("login", unique=True)
    await db.invites.create_index("token", unique=True)

async def seed_reserved():
    for ip in [x.strip() for x in settings.reserved_ips.split(",") if x.strip()]:
        await db.devices.update_one(
            {"vpn_ip": ip},
            {"$setOnInsert": {"vpn_ip": ip, "kind": "reserved", "public_key": f"reserved:{ip}"}},
            upsert=True,
        )
