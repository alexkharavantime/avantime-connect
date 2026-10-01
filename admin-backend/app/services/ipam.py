import ipaddress
from app.config import settings

async def allocate_ip(used: set[str]) -> str:
    """Выдать следующий свободный VPN-адрес из пула, минуя занятые."""
    net = ipaddress.ip_network(settings.vpn_client_pool)
    for host in net.hosts():
        ip = str(host)
        if ip not in used:
            return ip
    raise RuntimeError("Пул VPN-адресов исчерпан")
