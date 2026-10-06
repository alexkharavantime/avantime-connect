"""SSH transport: strict host verification, JSON stdin, no shell interpolation."""
import asyncio
import base64
import ipaddress
import json
from app.config import settings

class WireGuardError(RuntimeError):
    pass

def validate_public_key(key):
    try:
        raw = base64.b64decode(key, validate=True)
        if len(raw) != 32 or not any(raw) or base64.b64encode(raw).decode() != key:
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('Expected a canonical WireGuard public key (32 bytes, base64)')

async def request(payload):
    if settings.wg_mode != 'ssh':
        raise WireGuardError('WireGuard integration is disabled')
    if not settings.admin_api_token or len(settings.admin_api_token) < 32:
        raise WireGuardError('Set admin_api_token (at least 32 characters) before SSH mode')
    if not settings.wg_ssh_host or settings.wg_ssh_host.startswith('-'):
        raise WireGuardError('Invalid SSH host')
    args = ['ssh', '-F', '/dev/null', '-T', '-i', settings.wg_ssh_key_file,
            '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + settings.wg_ssh_known_hosts,
            '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
            '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
            '-p', str(settings.wg_ssh_port),
            settings.wg_ssh_user + '@' + settings.wg_ssh_host]
    try:
        proc = await asyncio.create_subprocess_exec(*args, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    except OSError as exc:
        raise WireGuardError('SSH executable unavailable') from exc
    try:
        out, _ = await asyncio.wait_for(proc.communicate((json.dumps(payload) + '\n').encode()), timeout=35)
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
        if isinstance(exc, asyncio.CancelledError):
            raise
        raise WireGuardError('SSH timeout; outcome unknown') from exc
    if proc.returncode != 0:
        raise WireGuardError('SSH failed; outcome unknown')
    try:
        result = json.loads(out)
        if not isinstance(result, dict) or result.get('ok') is not True:
            raise ValueError()
    except (ValueError, TypeError):
        raise WireGuardError('Helper refused request or returned invalid data')
    return result

async def occupied_networks():
    result = await request({'action': 'status'})
    if result.get('server_public_key') != settings.wg_server_public_key:
        raise WireGuardError('WireGuard server public key mismatch')
    try:
        return [ipaddress.ip_network(n, strict=False) for n in result['occupied']]
    except (KeyError, ValueError, TypeError):
        raise WireGuardError('Invalid occupied-address response')

async def add_peer(public_key, client_ip, owner):
    validate_public_key(public_key)
    result = await request({'action': 'add', 'public_key': public_key, 'ip': client_ip, 'owner': owner})
    if (result.get('state') != 'active' or result.get('owner') != owner
            or result.get('ip') != client_ip or type(result.get('created')) is not bool):
        raise WireGuardError('Unexpected add result')
    return result['created']

async def remove_peer(public_key, client_ip, owner):
    validate_public_key(public_key)
    result = await request({'action': 'remove', 'public_key': public_key, 'ip': client_ip, 'owner': owner})
    if (result.get('state') != 'revoked' or result.get('owner') != owner
            or result.get('ip') != client_ip or result.get('absence_confirmed') is not True):
        raise WireGuardError('Unexpected remove result')
