"""Local, single-process backend for real SSH fault experiments. No fake success."""
import argparse
import asyncio
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import uuid
from datetime import datetime, timezone


MODES = ('none', 'before-add', 'drop-add-response', 'delay-add-response')


def load_settings(env_file):
    """Effective settings come only from the explicitly selected file."""
    try:
        from app.config import Settings
    except ValueError:
        raise ValueError('Cannot load settings schema; values suppressed') from None

    class IntegrationSettings(Settings):
        @classmethod
        def settings_customise_sources(cls, settings_cls, init_settings, env_settings,
                                       dotenv_settings, file_secret_settings):
            return init_settings, dotenv_settings

    path = Path(env_file)
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError('Integration env file must exist and have mode 0600')
    try:
        settings = IntegrationSettings(_env_file=path)
    except ValueError:
        # Pydantic validation errors can contain supplied credentials.
        raise ValueError('Invalid integration env file; values suppressed') from None
    required = {'mongo_uri', 'db_name', 'vpn_client_pool', 'wg_mode', 'admin_api_token',
                'wg_server_public_key', 'wg_ssh_host', 'wg_ssh_user',
                'wg_ssh_key_file', 'wg_ssh_known_hosts'}
    if not required <= settings.model_fields_set:
        raise ValueError('Missing explicit integration settings: ' +
                         ', '.join(sorted(required - settings.model_fields_set)))
    validate_settings(settings)
    return settings


def validate_settings(settings):
    from app.services.wireguard import validate_public_key
    if settings.wg_mode != 'ssh' or len(settings.admin_api_token) < 32:
        raise ValueError('Real SSH mode and a separate admin token are required')
    if not re.fullmatch(r'avantime_connect_vm101_test_[a-z0-9_]{1,30}', settings.db_name):
        raise ValueError('Use a dedicated avantime_connect_vm101_test_<run> database')
    pool = ipaddress.ip_network(settings.vpn_client_pool)
    allowed = ipaddress.ip_network('10.30.0.0/24')
    protected = {f'10.30.0.{n}' for n in (0, 1, 2, 3, 4, 5, 6, 10, 255)}
    protected.update(x.strip() for x in settings.reserved_ips.split(',') if x.strip())
    if (pool.version != 4 or pool.prefixlen != 32 or pool.network_address not in allowed
            or str(pool.network_address) in protected
            or pool.network_address in ipaddress.ip_network(settings.server_network)):
        raise ValueError('Use one unprotected helper-compatible test IP as a /32 pool')
    validate_public_key(settings.wg_server_public_key)
    if not settings.wg_ssh_host or settings.wg_ssh_host.startswith('-'):
        raise ValueError('Invalid SSH host')
    for value in (settings.wg_ssh_key_file, settings.wg_ssh_known_hosts):
        if not Path(value).is_file():
            raise ValueError('SSH key and verified known_hosts files must exist')


class FaultController:
    """Scope every peer mutation; inject a fault in at most one add attempt."""

    def __init__(self, public_key, client_ip, mode, control_dir, timeout=60):
        from app.services.wireguard import validate_public_key
        validate_public_key(public_key)
        if mode not in MODES or not 0 < timeout <= 90:
            raise ValueError('Unknown fault mode or timeout outside (0, 90] seconds')
        self.public_key, self.client_ip, self.mode = public_key, client_ip, mode
        self.timeout, self.owner, self.attempted = timeout, None, False
        self.control_dir = Path(control_dir)
        # Never reuse an old release signal or accidentally overwrite an earlier run.
        self.control_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.reached = asyncio.Event()

    def event(self, name):
        record = {'at': datetime.now(timezone.utc).isoformat(), 'event': name,
                  'mode': self.mode, 'ip': self.client_ip, 'owner': self.owner,
                  'public_key_sha256': hashlib.sha256(self.public_key.encode()).hexdigest()}
        fd = os.open(self.control_dir / 'events.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(record) + '\n')

    def check_scope(self, key, ip, owner):
        from app.services.wireguard import WireGuardError
        if key != self.public_key or ip != self.client_ip:
            raise WireGuardError('Integration mutation outside the selected key/IP')
        try:
            valid_owner = str(uuid.UUID(owner)) == owner
        except (ValueError, TypeError, AttributeError):
            valid_owner = False
        if not valid_owner or (self.owner is not None and owner != self.owner):
            raise WireGuardError('Integration owner mismatch')
        self.owner = owner

    async def barrier(self, name):
        from app.services.wireguard import WireGuardError
        self.event(name)
        self.reached.set()

        async def wait_for_release():
            while not (self.control_dir / 'release').is_file():
                await asyncio.sleep(0.05)

        try:
            await asyncio.wait_for(wait_for_release(), self.timeout)
        except asyncio.TimeoutError:
            self.event('barrier_timeout')
            raise WireGuardError('Integration barrier timed out; inspect and revoke') from None
        self.event('barrier_released')

    def wrap(self, add_peer, remove_peer):
        from app.services.wireguard import WireGuardError

        async def add(key, ip, owner):
            self.check_scope(key, ip, owner)
            if self.mode != 'none' and self.attempted:
                raise WireGuardError('Fault attempt already consumed; revoke before ending the run')
            self.attempted = True
            if self.mode == 'before-add':
                await self.barrier('before_add')
                self.event('add_not_sent')
                raise WireGuardError('Injected failure before SSH add; no add was sent')
            self.event('add_started')
            # Original add validates created/owner/ip/state before we drop/delay it.
            created = await add_peer(key, ip, owner)
            self.event('add_returned')
            if self.mode == 'drop-add-response':
                self.event('add_response_dropped')
                raise WireGuardError('Injected loss of validated SSH add response')
            if self.mode == 'delay-add-response':
                await self.barrier('add_response_held')
            return created

        async def remove(key, ip, owner):
            self.check_scope(key, ip, owner)
            self.event('remove_started')
            await remove_peer(key, ip, owner)
            # Only the original transport can validate absence_confirmed.
            self.event('remove_confirmed')

        return add, remove


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    parser.add_argument('--public-key-file', type=Path, required=True)
    parser.add_argument('--control-dir', type=Path, required=True)
    parser.add_argument('--fault', choices=MODES, required=True)
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--port', type=int, default=18000)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('Use an unprivileged local port')
    try:
        settings = load_settings(args.env_file)
        controller = FaultController(args.public_key_file.read_text().strip(),
                                     str(ipaddress.ip_network(settings.vpn_client_pool).network_address),
                                     args.fault, args.control_dir, args.timeout)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    # Bind explicit settings before importing modules that construct the DB client.
    from app import config
    from app.services import wireguard
    config.settings = settings
    wireguard.settings = settings
    from app.main import app
    wireguard.add_peer, wireguard.remove_peer = controller.wrap(wireguard.add_peer, wireguard.remove_peer)

    root = Path(__file__).resolve().parents[2]
    sources = sorted((root / 'admin-backend/app').rglob('*.py'))
    sources += [Path(__file__).resolve(), root / 'deploy/wireguard/helper.py']
    manifest = {'db_name': settings.db_name, 'pool': settings.vpn_client_pool,
                'fault': args.fault, 'listen': f'127.0.0.1:{args.port}',
                'source_sha256': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in sources}}
    fd = os.open(args.control_dir / 'manifest.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(manifest, stream, indent=2)
    controller.event('backend_starting')
    import uvicorn
    # One process, no reload, no access logs that could expose request identifiers.
    uvicorn.run(app, host='127.0.0.1', port=args.port, workers=1, access_log=False)


if __name__ == '__main__':
    main()
