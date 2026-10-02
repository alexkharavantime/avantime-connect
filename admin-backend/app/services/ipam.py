import ipaddress
from app.config import settings
from app.db.mongo import db

async def _used_ips():
    cur = db.devices.find({}, {"vpn_ip": 1})
    return {d["vpn_ip"] async for d in cur if d.get("vpn_ip")}

async def next_free_ip() -> str:
    pool = ipaddress.ip_network(settings.vpn_client_pool)
    server_net = ipaddress.ip_network(settings.server_network)
    used = await _used_ips()
    used.update(
        str(ipaddress.ip_address(value.strip()))
        for value in settings.reserved_ips.split(",")
        if value.strip()
    )
    for host in pool.hosts():
        ip = str(host)
        if host in server_net:
            continue
        if ip in used:
            continue
        return ip
    raise RuntimeError("Пул VPN-адресов исчерпан")
