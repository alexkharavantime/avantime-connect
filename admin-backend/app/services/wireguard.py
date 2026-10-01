async def add_peer(public_key: str, client_ip: str) -> None:
    """TODO: завести peer на WG-сервере (AllowedIPs=client_ip/32)."""
    raise NotImplementedError

async def remove_peer(public_key: str) -> None:
    """TODO: отозвать peer по устройству."""
    raise NotImplementedError
