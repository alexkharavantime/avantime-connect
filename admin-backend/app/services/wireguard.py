# ВНИМАНИЕ: заглушка. Реальное заведение peer подключается после SSH-доступа к WG-серверу.
async def add_peer(public_key: str, client_ip: str) -> None:
    # TODO: wg set wg0 peer <public_key> allowed-ips <client_ip>/32
    return None

async def remove_peer(public_key: str) -> None:
    # TODO: wg set wg0 peer <public_key> remove
    return None
